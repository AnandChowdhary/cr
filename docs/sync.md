# Import data with sync adapters

A sync adapter is an ordinary executable: a shell script, Python program, compiled Rust binary, or any other local command. It fetches or computes data and writes one JSON object per line to stdout. `cr` owns the database writes, schema validation, audit events, checkpoints, limits, and overlap protection.

This subprocess boundary is intentionally simpler than an in-process Rust plugin ABI. Adapters can use any language or SDK, fail without crashing `cr`, and evolve independently. They are still trusted local programs: they inherit your environment except for `CR_ENCRYPTION_ACTIVE_KEY` and `CR_ENCRYPTION_KEYS`, and can access the filesystem, network, and external services with your operating-system permissions. The keyring is needed by CR's storage boundary, never by the plaintext adapter protocol.

## A Notion meeting-notes adapter

For example, save this as `scripts/notion_page.py` inside the database. It uses Notion's Markdown endpoint, which can return a meeting page and optionally its transcript directly as Markdown:

```python
#!/usr/bin/env python3
import json
import os
import urllib.parse
import urllib.request

page_id = os.environ["NOTION_PAGE_ID"]
url = "https://api.notion.com/v1/pages/" + urllib.parse.quote(page_id) + "/markdown?include_transcript=true"
request = urllib.request.Request(url, headers={
    "Authorization": "Bearer " + os.environ["NOTION_API_KEY"],
    "Notion-Version": "2026-03-11",
})

with urllib.request.urlopen(request) as response:
    page = json.load(response)

if page["truncated"] or page["unknown_block_ids"]:
    raise RuntimeError("Notion returned incomplete page content")

print(json.dumps({
    "type": "upsert",
    "collection": "meeting_notes",
    "id": page["id"],
    "front_matter": {
        "source": "notion",
        "notion_page_id": page["id"],
    },
    "markdown": page["markdown"],
}))
print(json.dumps({
    "type": "checkpoint",
    "state": {"last_page_id": page["id"]},
}))
```

Keep credentials out of the sync definition. Export them in your shell, inject them through your scheduler or secret manager, and then register the command:

```sh
export NOTION_API_KEY='secret_...'
export NOTION_PAGE_ID='00000000-0000-0000-0000-000000000000'

cr sync create notion-meeting \
  --actor 'notion-sync@example.com' \
  --timeout-seconds 120 \
  -- python3 scripts/notion_page.py

cr sync show notion-meeting
cr sync run notion-meeting --json
cr sync state notion-meeting
```

No `cr save` follows a successful run. The upsert is already schema-validated and recorded with `source: sync`, the configured actor, and a message containing the sync name and unique run ID. An identical second run reports the record as unchanged and creates no duplicate audit event.

For Gmail, use the same shape: list message IDs, fetch each message with `users.messages.get`, decode the MIME content, and emit one `upsert` per stable Gmail message ID. A final checkpoint can store the last Gmail `historyId` for the next incremental run. An importer should only emit `delete` when it has an explicit source-side deletion signal; absence from one paginated response is not proof of deletion.

## JSON Lines protocol

Stdout is reserved for protocol messages. Send diagnostics and progress to stderr. Blank stdout lines are ignored. The version 1 messages are:

```json
{"type":"upsert","collection":"emails","id":"message-123","front_matter":{"from":"ada@example.com","labels":["inbox"]},"markdown":"Message body\n"}
{"type":"delete","collection":"emails","id":"message-456"}
{"type":"checkpoint","state":{"history_id":"98765"}}
```

- `upsert` creates the record or completely replaces its front matter and Markdown. It is unchanged when the parsed front matter and exact Markdown body already match.
- `delete` is idempotent: deleting a missing record counts as unchanged.
- `checkpoint` is optional, must be the final message, and is stored only after all preceding record operations succeed. For an encrypted interrupted stream the run ledger retains only its presence and digest; recovery obtains the value from the authenticated stream.
- A run cannot target the same `collection/id` twice. Every message and every upsert schema is preflighted before the first mutation.
- Output defaults to 16 MiB and 10,000 messages; the command defaults to a 300-second timeout. `sync create` can lower or raise these within the built-in safety bounds.

The adapter runs from the database root with stdin closed and receives:

```text
CR_DATABASE_ROOT
CR_SYNC_NAME
CR_SYNC_RUN_ID
CR_SYNC_PROTOCOL=cr-jsonl-v1
CR_SYNC_STATE_PATH
CR_SYNC_HAS_STATE=true|false
```

`CR_SYNC_STATE_PATH` is a read-only-by-convention temporary snapshot containing the previous JSON checkpoint or `null`. Read it to choose an incremental cursor, then emit the next checkpoint; do not modify `.cr/sync/state` yourself.

Checkpoint files under `.cr/sync/state/` are ordinary operational state, not
schema-marked record values, and are not encrypted by record-value encryption.
Adapter stderr likewise goes directly to the caller's terminal or job log. Do
not put credentials or other secrets in checkpoints or stderr; use a secret
manager or the adapter's protected environment instead.

The command is stored as a program plus an exact argument array, not as a shell command string. Shell expansion, pipes, and redirects only happen when you explicitly register a shell such as `sh scripts/import.sh`. Relative executables containing a path separator are resolved from the database root, and other relative arguments are interpreted from that root.

## Failure, direct writes, and external effects

The database must pass `audit verify` before an adapter starts and again after it exits. During the second verification, `cr` holds the audit lock and captures every stream target as absent or at its exact record version at that same audit head. Every later replacement, deletion, creation, and idempotent no-op conditionally requires both that target state and the audit sequence produced by the preceding sync operation. An ordinary CLI or API write anywhere in the database therefore stops the remaining stream rather than letting stale adapter output overwrite it; the sequence guard also catches an edit that restores byte-identical target contents, which necessarily has the same public record hash. A timeout, nonzero exit, invalid JSON, output-limit violation, duplicate target, schema error, or dirty database prevents all emitted operations and checkpoint changes. Only one run of a named sync can execute at once.

Do not have an unattended adapter write `records/` directly. If it does, the second verification rejects its protocol output and leaves the direct file edit visible in `cr status`; a person can review it with the normal selective `cr save` flow. This is what keeps sync automation from silently accepting unrelated manual edits or tampering.

Record operations are preflighted together but committed as sequential audited single-record mutations, not one all-or-nothing multi-record transaction. A durable-write failure midway through application therefore still leaves earlier operations committed. What it can no longer do is leave that fact unrecorded.

Adapter stdout is captured in bounded memory, not a temporary file, so a hard
crash during fetch cannot orphan a plaintext protocol stream under `.cr/`.
Before the first mutation `cr` writes a run ledger containing that head-bound
target-version snapshot, and the exact operation stream beside it, under
`.cr/sync/runs/`, and removes both only once the checkpoint agrees with the
committed work. A stream that contains an upsert for an encrypted collection is
stored as one authenticated ciphertext blob (ledger version 3) bound to the
database context, sync name, and run ID; recovery therefore requires the
keyring. Its ledger stores checkpoint presence and domain-separated digests,
not the before or after checkpoint JSON, so neither logical record operations
nor the stream's checkpoint appear in plaintext under `.cr/sync/runs/`.
Unprotected streams retain the plaintext version-2 format. Recovery
also accepts version-1 ledgers written by earlier builds: it reconstructs their
missing target snapshot by replaying the immutable audit prefix to the head
recorded in the ledger. An interrupted run is then a durable fact rather than something to infer:

```sh
cr sync recover notion-meeting --check          # report an interrupted run, change nothing
cr sync recover notion-meeting --check --json
cr sync recover notion-meeting                  # complete it
```

`cr sync run` refuses to start while a ledger is present, so a stale checkpoint can never be silently replayed from the beginning. `cr sync recover` completes the interrupted run by replaying its recorded stream. That is roll-forward, never rollback: the audit chain is append-only and nothing already committed is ever unwound. It is sound because the protocol stream is idempotent — a target appears at most once, an upsert carries the whole record, and deleting a missing record is a no-op — so the replay commits only the operations the interrupted run never reached and appends no event for the rest. The events it commits carry the original run's ID, so the audit log shows one run rather than two.

Legacy v1/v2 interrupted runs recorded their operation stream and checkpoint as plaintext. They remain recoverable when all of their upsert targets are still unprotected, including when unrelated collections use encryption. If any target collection now has an encrypted field or body policy, recovery fails before applying another operation. `cr` does not silently migrate or replay that plaintext stream under the newer storage policy. New runs also read existing upsert targets against the verified audit snapshot before staging the adapter stream, so moving or removing an encryption marker cannot leave the adapter's plaintext output in the recovery directory.

Recovery refuses, rather than guessing, when a record the run still has to write changed after the run stopped, or when the recorded stream no longer matches its ledger. It recognizes committed progress only when an event has both `source: sync` and the run's message, then verifies that the event's target, action, and resulting record hash match the recorded stream. It captures that history and the current audit sequence under one lock and checks the sequence again inside every remaining mutation lock, so a writer racing after the scan — including an edit-and-restore ABA — is refused. An unrelated record changed before that recovery snapshot is reported by `--check` but does not block completion. If the original failure is still present, recovery fails the same way and leaves the ledger intact, so the run stays completable once the cause is fixed.

An adapter may also perform external effects, such as creating a calendar event or sending a message. `cr` cannot roll those effects back if a later record operation fails. Use the remote service's idempotency keys, design the adapter to retry safely, and emit the checkpoint only for work that can be resumed.

## Run on a schedule

`cr` deliberately does not keep a background daemon running. Use the platform scheduler you already operate—cron, a systemd timer, macOS `launchd`, a container scheduler, or CI—to run:

```sh
cd /absolute/path/to/my-database
/absolute/path/to/cr sync recover notion-meeting
/absolute/path/to/cr sync run notion-meeting
```

`cr sync recover` succeeds and prints `Sync NAME has no interrupted run` when there is nothing to complete, so an unattended job can run it unconditionally before each fetch. Leave it out and a run interrupted by a reboot or an OOM kill will make every later run exit nonzero until somebody looks — which is the intended failure mode, not a silent one.

Schedulers often start with a small environment and a different working directory. Use absolute paths and inject credentials through the scheduler's protected environment or a secret manager, never into `.cr/syncs/*.yaml`. Capture stdout/stderr in your normal job logs and alert on the nonzero exit status.

List configured adapters at any time:

```sh
cr sync list
cr sync list --json
```
