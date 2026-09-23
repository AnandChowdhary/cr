# Audit history and integrity

Every successful `create`, `update`, `link`, `delete`, direct `save`, and changed sync upsert/delete writes an attributed event.

![The global audit log filtered to one CRM deal, with a field-level change expanded](screenshots/audit-log.jpg)

## View history

Show recent events for the entire database:

```sh
cr audit log
cr audit log --limit 100 --json
```

With RBAC enabled, owners see the complete global stream. Other principals see
only events for records whose audit history they may currently read, plus their
own user-policy history; visibility is applied before `--limit`. This makes an
editor's `audit log` useful without granting database-wide access management.

Show history for one record:

```sh
cr audit log candidates alex-smith --limit 20
```

## Verify the journal

Verify the journal and all current records:

```sh
cr audit verify
```

Verification does more than check the event hash chain. It replays every
record's change sets, checks each `before_hash`, and requires every replayed
post-state to reproduce that event's exact `after_hash`. Version 3 audit events
carry a versioned exact-Markdown `after_snapshot` for every state in which the
record exists. This keeps YAML comments, quoting, key order, and line endings
honest without making verification depend on a serializer's current output.
Old version 1 and 2 events remain readable: when their lost representation
details matter at a record's current head, the matching materialized record is
used as the exact witness. Payload versions may increase but never decrease
within a journal. Every new mutation performs the same replay before it writes,
so an inconsistent older event refuses the write at the guilty sequence with
`audit_integrity_failed`.

Print the current audit checkpoint:

```sh
cr audit head --json
```

The audit journal is tamper-evident, not magically tamper-proof if an attacker can rewrite both the database and its entire local history. Store important checkpoints outside the database—for example in a signed Git commit or trusted remote service—and verify them later:

```sh
cr audit verify --expected-head 'sha256:YOUR_SAVED_HASH'
```

## Anchor the head in Git

Every audit event but the newest is pinned by the hash recorded in the event
after it. The newest one is pinned by nothing. Replay now catches a rewritten
result whose change set no longer reproduces `after_hash`, but it cannot derive
an event's actor, timestamp, message, or attribution from record state. Those
fields can still be rewritten and re-hashed without an external checkpoint.
The fix for that remaining boundary has always been to keep a copy of the head
hash somewhere the forger cannot reach — and the reason it did not help is that
saving one by hand is a step nobody performs.

`cr` now keeps that copy for you, in `.cr-audit-head.json` at the root of the database:

```json
{
  "version": 1,
  "sequence": 42,
  "hash": "sha256:9f2c…",
  "timestamp": "2026-03-04T11:22:33Z"
}
```

Every command that records an audit event rewrites it, and `cr audit verify` checks it with no arguments. Inspect or repair it directly:

```sh
cr audit anchor           # show the recorded anchor
cr audit anchor --json
cr audit anchor --write   # (re)write it to the current head
```

**Commit it, or it is worth nothing.** This file sits at the database root, so
anybody who can rewrite `.cr/audit/` can rewrite it in the same pass — alter
non-state metadata, recompute the hash, update the anchor, and verification goes
quiet again. Its protection comes entirely from the copy in your **Git
history**: a pushed, distributed history is a second place to write that a
local process cannot reach. So keep the database in version control and commit
the anchor alongside the records it attests:

```sh
git add records .cr-audit-head.json
git commit -m 'Move alex-smith to offer'
```

Nothing in `cr` writes a `.gitignore`, and the anchor must never be excluded by one.

When you review a commit, the anchor tells you two useful things. The hash should change in exactly the commits that also change records or `.cr/audit/`, and the sequence should only ever go **up**. An anchor that moved on its own, went backwards, or jumped is worth stopping on.

If `cr audit verify` reports a mismatch, it means the journal on disk is not the journal your anchor attests to. Compare the anchor in your working copy against the last one in `git log -p -- .cr-audit-head.json`, and against what a colleague or your server has. Whichever side moved without a commit to explain it is the side to distrust.

A **behind** notice is different, and says so:

```text
Verified 12 audit events and 4 records; head sha256:6b1a…
notice: the audit anchor is behind at sequence 9 of 12; the journal still agrees with it, so this is a lagging anchor rather than altered history
```

That is not tampering. The journal still contains exactly the event the anchor names, at the sequence it names — it has simply grown past it, which is what a crash between writing the event and writing the anchor leaves behind. Events after the anchored sequence are unpinned until you catch up, so run `cr audit anchor --write` and commit. `cr check` reports the same thing as a warning, and reports a real mismatch as an error.

A database created before this feature has no anchor at all. It keeps working and says so; adopt it with one command and a commit:

```sh
cr audit anchor --write && git add .cr-audit-head.json
```

## Baseline existing records

For records that existed before audit logging was introduced, establish their starting state once:

```sh
cr --actor 'migration@example.com' audit baseline
```

## What the journal retains

Audit events retain historical field values and deleted record bodies, and now
also any recorded intent text. Every version 3 event with a present record
retains the complete exact post-state in `after_snapshot`, not only the changed
fields. Everything written to the journal is permanent: removing it would break
verification for that event and every event after it. Protect `.cr/audit/` at
least as carefully as `records/`, particularly for personal CRM and recruiting
data, and treat
`--intent-request` and `--intent-rationale` as a bounded attribution channel
rather than a place to paste a transcript.

## Check the whole database

`cr status` tells you what has changed since the last save. `cr check` tells you whether the database is *coherent* — and, unlike every other integrity command, it reports everything it finds instead of stopping at the first problem:

```sh
cr check
# error   dangling_link           record deals/acme-renewal has a relation 'company' pointing at companies/acme, which does not exist
# error   schema_violation        record deals/globex-expansion does not match the schema for collection 'deals': "stage" is a required property
# warning record_content_mismatch record companies/globex does not match its latest audited state; 'cr status' reports it as modified and 'cr save' records the change
# Checked 2 collections: 4 records on disk, 4 audited records.
# 2 errors, 1 warning.
```

It reports:

- **dangling links** — a relation pointing at a record that no longer exists;
- **malformed relation values** — a `relations` entry that is not a `{ collection, id }` reference at all;
- **schema failures** — records that no longer satisfy their collection's JSON Schema, which is what happens whenever a schema changes after its records were written, plus schema files that are themselves unusable;
- **invalid record names** — files and directories that cannot be a record ID or a collection. Every other command refuses such a database outright, so this is the one finding `check` exists to be able to report: it names the offending filename and keeps scanning the records around it;
- **unreadable records** — Markdown that cannot be parsed, and anything behind a symbolic link;
- **audit reconciliation problems** — records with no audit history, audited records whose file has gone, files whose content does not match the audited state, a journal whose chain cannot be replayed, and a stored change set that does not match the approval recorded beside it;
- **interrupted sync runs** — a `cr sync run` that stopped partway, leaving part of an import applied and its checkpoint behind;
- **audit anchor problems** — a `.cr-audit-head.json` that does not agree with the journal (an error), one that lags behind it (a warning), and a journal with events that nothing anchors at all (a warning).

Every finding names a record as `collection/id`, or a sync by name. A file that cannot be a record is named by its filename inside its collection, because that is the only way to say which file to remove. None of them ever prints a filesystem path.

The interrupted-sync finding is worth calling out, because nothing else surfaces it. The records a stopped run did commit agree with the journal, so `cr status` reports `Clean` and `cr audit verify` passes; without `cr check` you would only find out by running `cr sync recover <name> --check` on a sync you already suspected, or by being refused the next time you ran it. `check` reports it as a warning and tells you the command to inspect it with — it never recovers anything itself.

### `check` versus `status`

They answer different questions, and `check` does not repeat `status`'s answer.

- `cr status` is the working tree: *what would `cr save` record next?* Every line it prints is a normal, resolvable direct edit.
- `cr check` is integrity: *is this database coherent?* When a divergence from the journal is one `cr save` can reconcile, `check` reports it as a **warning** and points you back at `status`. When the same record also fails to parse or fails its schema, `save` will refuse it, so `check` raises it to an **error** — that record is stuck, and `check` is the only command that says why.

Everything else `check` reports — dangling links, malformed relations, schema drift, invalid names, journal damage — is invisible to `status`.

### Exit status, scope, and output

```sh
cr check                              # whole database
cr check --collection deals           # one collection; links, journal and syncs are still checked
cr check --json                       # the complete report, including the summary
cr check --fail-on warning            # unsaved direct edits fail too
cr check --fail-on never              # report without ever failing
```

| Exit | Meaning |
| ---- | ------- |
| `0`  | Ran successfully; nothing reached the failure threshold. |
| `2`  | Ran successfully; found problems at or above the threshold. |
| `1`  | Could not run at all — no database, an unknown `--collection`, unreadable configuration. |

That split is the point in CI and cron: a typo in a scheduled job must never look like a clean bill of health. The default threshold is `error`, so an ordinary unsaved edit does not fail the build.

`check` never writes. It cannot repair anything, and there is no `--fix`: a dangling link might want the relation removed, the target restored, or a delete policy applied, and only you know which.

It reads and parses every record in scope and replays the journal, so it costs about what `cr search` over the whole database costs, and it holds the write lock while it runs. Use `--collection` on a large database.
