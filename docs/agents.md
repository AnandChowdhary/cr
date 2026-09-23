# Agents and automation

`--actor` is the responsible human, always. When an AI coding agent or another
program runs `cr` on that human's behalf, three optional objects are recorded
beside it: **who acted**, **under what approval**, and **why**.

```sh
cr update deals acme-renewal --set status=closed-won \
  --agent claude-code --agent-model claude-opus-4-5 --agent-session "$CLAUDE_CODE_SESSION_ID" \
  --authorization delegated --grant acceptEdits \
  --intent-request 'they messaged that they want to buy — mark this deal closed-won' \
  --intent-rationale 'Set status to closed-won. Value left unchanged because no figures were given.'
```

That event records `actor` as the human, `agent` as the software, `authorization`
as the approval it acted under, and `intent` as both the instruction and the
agent's own account of what it did:

```json
{
  "actor": "Anand Chowdhary <anand@example.com>",
  "source": "cli",
  "agent": {
    "id": "claude-code",
    "model": "claude-opus-4-5",
    "session": "6d1baa69-f114-490c-ae19-4be99c2bd744",
    "detected_from": "flag"
  },
  "authorization": { "mode": "delegated", "grant": "acceptEdits" },
  "intent": {
    "request": { "author": "human", "text": "they messaged that they want to buy — mark this deal closed-won" },
    "rationale": { "author": "agent", "text": "Set status to closed-won. Value left unchanged because no figures were given." }
  },
  "action": "update"
}
```

A human at the keyboard records none of this, and the resulting event is
byte-for-byte what earlier versions of `cr` wrote.

## What is asserted, and what that means

**Everything in the agent channel is a claim the calling process makes about itself.** `cr` runs
as you, with your environment and your files, so it has no way to prove that an
agent is what it says it is, that you really asked, or that a recorded rationale
is honest or complete. Agent, approval, and intent fields are attribution: they
do not affect authentication, and they never affect what an operation is allowed
to do. `CR_AGENT=none` suppresses detection entirely and produces an event
indistinguishable from a human's — that is a property of a local-first tool, not
a gap to be closed later.

What it does buy is legibility in the honest case, which is nearly every case,
and a conventional slot: once the fields exist and tools fill them, *their
absence becomes information*.

`agent.detected_from` records how `cr` came to believe an agent was involved.
**None of its values means "verified".**

| Value | Meaning |
| --- | --- |
| `environment` | A documented agent variable was present: `CLAUDECODE` or `CURSOR_AGENT`. |
| `flag` | Declared with `--agent` or the `CR_AGENT` environment variable. |
| `header` | Declared with the `X-CR-Agent` request header. |
| `config` | Declared in a stored sync definition. |

An explicit declaration always outranks a sniffed environment. `cr` records only
what it actually observed: `CLAUDECODE=1` with no session ID records an
identifier and nothing else. `agent.model` is never detected, because no agent
publishes it — declare it or leave it absent.

## The approval mode

`--authorization` answers the question an auditor actually asks: did a person see
*this* change before it happened?

| Mode | Meaning |
| --- | --- |
| `direct` | A human ran the command. No agent involved. |
| `interactive` | A human was present and approved this specific invocation. |
| `delegated` | A human instructed the task; this write was covered by a standing grant. |
| `autonomous` | No human in the session: scheduled, headless, or unattended. |
| `unknown` | The approval path could not be determined. |

`--grant` stores the raw vendor string verbatim beside the normalized mode, so
`acceptEdits` survives even though only `delegated` is queryable.

## Both halves of the intent

`--intent-request` is the instruction and is attributed to the human.
`--intent-rationale` is the agent's account of what this particular write was
discharging and is attributed to the agent. Both are stored because they answer
different questions, and the gap between them is where an agent's misreadings
show up. `author: "human"` means *this text is attributed to the human*, not
*`cr` watched them type it* — the agent still chose what to quote.

Each is capped at 4,096 characters, with 8,192 characters total per event. Going
over is an error, not a silent truncation.

`-m/--message` also now works on `create`, `update`, `link`, and `delete`, not
only `save`. It keeps its existing meaning: a short note about the change.

## Keep a read-modify-write from overwriting a newer record

Every single-record read has a `version`: `sha256:` plus SHA-256 over the bytes
`cr:record:v1\0` followed by the exact stored Markdown bytes, including front
matter formatting and body text. The domain prefix prevents a record version
from being confused with an audit event or change-set digest. `cr get --json`
prints it. Pass that value back when a CLI mutation was calculated from a prior read:

```sh
version=$(cr get deals acme-renewal --json | jq -r .version)
cr update deals acme-renewal --set status=won \
  --expected-record-hash "$version"
```

`update`, `link`, and `delete` accept `--expected-record-hash`. A competing
write makes the command fail with the typed `precondition_failed` code; a
malformed hash is `validation_failed`. The comparison is made after acquiring
the same audit lock that guards the write, so another process cannot change the
record between checking the version and committing it.

REST record reads return the same value in the JSON `version` field and as a
strong `ETag`, including exact-document reads. Send that ETag as `If-Match` on a
conditional `PATCH`, `DELETE`, or link request. `PUT` replaces the complete
front matter and Markdown document and therefore requires `If-Match`; omitting
it returns `428 precondition_required`, while a stale or weak validator returns
`412 precondition_failed`. Atomic `PATCH` remains safe and unconditional when
the header is omitted: its merge is calculated from the current record while
the lock is held, rather than from a client-supplied whole document.

The server-rendered editor and delete form carry the record version in a hidden
field automatically. Leaving an old form open can no longer overwrite or
delete a record changed in another tab; the stale submission returns 412 and
creates no audit event.

## Retry one mutation without doing it twice

`create`, `update`, `link`, and `delete` accept `--idempotency-key`. Generate a
fresh random key for one logical operation and keep it unchanged across retries:

```sh
key=$(openssl rand -hex 16)
cr create deals acme-renewal --set status=open --idempotency-key "$key"
# Safe after a timeout: prints the same result and appends no second event.
cr create deals acme-renewal --set status=open --idempotency-key "$key"
```

Add `--json` to any supported CLI mutation to receive the original structured
record result on both the first success and every exact replay. For delete,
that JSON is the full pre-delete record retained by the event.

Keys contain 16–128 visible ASCII bytes; use at least 128 bits of randomness.
They are scoped by the effective principal, canonical operation, and target
record. The request digest also covers the payload, record precondition, API or
CLI source, audit message, attribution, and impersonating operator. Reusing a
key in that scope with different semantics fails as
`idempotency_conflict` (`409` over HTTP). JSON object member order is not a
semantic difference. YAML input is encoded with explicit scalar, sequence,
mapping, and tag types before hashing, so keys such as `true` and `"true"`
remain different and non-string keys never pass through JSON's object-key
coercion. Reusing the same key on another record is independent.

Only a committed success consumes a key. Preview, validation, authorization,
and write failures do not. A replay still runs current authorization before it
returns the old result, so revoking access also revokes replay access. Delete
retries return the original deleted record even though its file is now absent.

The audit event is the idempotency store. It contains a domain-separated hash
of the key—never the raw key—an HMAC-SHA-256 of the canonical plaintext request
keyed by that raw key, and the exact operation result, including its original
relative path and exact Markdown. The stored
path is checked against the event's collection and ID, so changing `data_dir`
later does not alter a replayed response or open an arbitrary-path channel.
Those fields pass through the same pending-mutation journal and audit lock as
the record write. A concurrent duplicate waits and replays; a crash
after the record write is recovered into the event before the retry is looked
up; a lost success response is therefore safe to retry. `audit verify` binds
the stored result back to the event's semantic state, exact bytes, and record
version.

REST uses the same contract through `Idempotency-Key` on record `POST`, `PATCH`,
`PUT`, `DELETE`, and link `POST` requests. Keep the same `If-Match` and
attribution headers on a retry. `save`, sync application, managed `cr user` and
`cr access` lifecycle commands, and server-rendered form posts are not in this
single-record v1 contract; `user ensure` remains declaratively idempotent on its
own terms.

## Approve a change set before it is written

Actor and agent attribution are asserted. The preview digest is a separate
value `cr` can check against the change it is about to record.

`--preview` computes the change set a mutation would record and prints a digest
over it, without writing anything — no record change, no audit event, no pending
mutation, and the lock released on the way out:

```sh
$ cr update deals acme-renewal --set status=closed-won --set stage=closed --preview
update deals/acme-renewal
replace /attributes/stage "negotiation" -> "closed"
replace /attributes/status "open" -> "closed-won"
digest sha256:47d8473f1c3fa8c044954674c2a97cb0eb9667eeaad7b80d691535c08277c78d
```

Read it, then pass the digest back to perform the write:

```sh
cr update deals acme-renewal --set status=closed-won --set stage=closed \
  --authorization interactive --approved-by 'Anand Chowdhary <anand@example.com>' \
  --approved-changes sha256:47d8473f1c3fa8c044954674c2a97cb0eb9667eeaad7b80d691535c08277c78d
```

`cr` recomputes the digest from the change set it is about to record and refuses
the write if they differ:

```
$ cr update deals acme-renewal --set status=lost \
    --authorization interactive --approved-changes sha256:47d8473f…
error: record deals/acme-renewal does not match the approved change set:
sha256:47d8473f… was approved, but this change set is sha256:149d63eb…
```

The digest is stored in `authorization.approved_changes`, and `cr audit verify`
recomputes it from the event's own `changes`:

```
$ cr audit verify
error: audit event 2 for record deals/acme-renewal records an approved change set
that is not the one it applied: sha256:47d8473f… was approved, but its changes
hash to sha256:b92149ba…
```

That is a different finding from a broken chain, and it has its own error and its
own HTTP code (`409 approval_mismatch`), because "the change that was applied is
not the change that was approved" and "the journal was tampered with" call for
different responses.

`--preview --json` prints the same thing as a JSON object with `changes`,
`before_hash`, `after_hash`, and `digest`, which is the form a wrapper reads.

Over HTTP, `preview` is a query parameter because it decides whether the request
writes, and the digest is a header because it is a precondition on one:

```sh
curl -X PATCH 'http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal?preview=true' \
  -H 'Content-Type: application/json' -d '{"front_matter":{"status":"closed-won"}}'

curl -X PATCH 'http://127.0.0.1:3000/api/v1/collections/deals/records/acme-renewal' \
  -H 'Content-Type: application/json' \
  -H 'X-CR-Authorization: interactive' \
  -H 'X-CR-Approved-Changes: sha256:…' \
  -d '{"front_matter":{"status":"closed-won"}}'
```

`--preview` works on `create`, `update`, `link`, `delete`, and `save`, and
`preview=true` on `POST`/`PUT`/`PATCH`/`DELETE` records, `POST` links, and `POST
/api/v1/save`. `cr delete --preview` does not need `--yes`, because it deletes
nothing.

### What the digest proves, and what it does not

**It proves**: the change set recorded in the event is the one the digest
commits to. Nothing else in the event, and nothing about the record's other
fields, is covered — the digest is over `changes` and only `changes`.

**It does not prove that a human saw the preview.** An agent can compute a
digest and pass it to itself. What the digest gives an auditor is a value they
can compare against an approval recorded somewhere else — a ticket, a message, a
commit — and it is worth exactly as much as that independent record.

**It does not prove the journal is honest.** Anyone who can rewrite the chain can
rewrite the digest with it. `audit verify` catches a change set that was altered
without updating the approval beside it; it is a consistency check inside one
event, not a second signature over it.

**It is not enforced when it is absent.** A mutation with no
`--approved-changes` is written unchecked, exactly as before. Its absence is
information, not a failure.

**The preview-to-apply gap is real, and closing it is what the digest is for.**
State does change in between. If it changes in a way that alters the change set —
including a change to the `before` value of any field being written — the digest
no longer matches and the write is refused. If it changes some *other* field, the
change set is unaffected and the write proceeds: you approved a change, not a
resulting document. The separate `before_hash` guard is not enough on its own for
this, because a competing `cr update` moves the record *and* the audited state
together and so passes it; the digest is what actually notices.

**One digest approves one record.** `cr save --preview` prints a digest per
record, and `--approved-changes` on `save` requires exactly one
`COLLECTION/ID` — approving a multi-record save needs a per-record mapping and
waits on the bulk-mutation design in `TODO.md`.

`sync` runs carry no approved digest. An adapter has no human in the loop by
construction, so a digest there would only be a machine approving itself.

## Find what an agent did

```sh
cr audit log --by-agent claude-code
cr audit log --by-session 6d1baa69-f114-490c-ae19-4be99c2bd744
```

Both match the acting agent or any delegate in its `via` chain, so a sub-agent's
writes are still findable under the agent that spawned it. The same filters exist
at `GET /api/v1/audit/log?agent=…&session=…` and on the `/audit` page.
The older `--agent` and `--session` spellings remain aliases for compatibility.

Preview what would be recorded without writing anything:

```sh
cr identity --json --agent claude-code --authorization delegated
```

## Structured and chained agents

`--agent`, `--authorization`, and `--intent` each also accept a JSON object, which
is how a wrapper supplies everything at once, and how a sub-agent records the
chain behind it:

```sh
export CR_AGENT='{"id":"claude-code-subagent","session":"child",
                  "via":[{"id":"claude-code","session":"parent"}]}'
```

`via` is ordered nearest actor first. Delegates are informational only.

`CR_AGENT`, `CR_AUTHORIZATION`, and `CR_INTENT` apply to every command, so an
agent harness can set them once for a whole session.

An explicitly empty `--agent-session`, `--agent-turn`, or corresponding JSON
value means that correlation key is absent. This lets host-level bookkeeping
clear a session inherited through `CR_AGENT` instead of failing or attaching a
write to the wrong conversation.

## Compatibility

These fields are optional and are omitted entirely when absent, so the audit
format version does not change. A journal written before they existed verifies
to exactly the same head hash, and an older `cr` still verifies a journal that
contains them — it simply does not display them. That last point matters in a
shared repository: an older binary shows an agent-written event with no sign that
anything was omitted.

The same holds for the *values* of `detected_from`, `mode`, and `author`. If a
later `cr` adds one, this one reads it, prints it verbatim, and rewrites it
unchanged, so the event keeps its hash and the journal keeps verifying. `cr`
still refuses to *record* a value it does not know, so an approval mode in a
journal always means what this table says it means.

Intent text is stored inline and is therefore **permanent**, like every other
value in the journal.
