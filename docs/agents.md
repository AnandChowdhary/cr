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
| `hook` | Supplied by a harness hook through `CR_HOOK_AGENT` and `CR_HOOK_AUTHORIZATION`. See [Let Claude Code fill in the attribution](#let-claude-code-fill-in-the-attribution). |
| `flag` | Declared with `--agent` or the `CR_AGENT` environment variable. |
| `header` | Declared with the `X-CR-Agent` request header. |
| `config` | Declared in a stored sync definition. |

An explicit declaration always outranks a sniffed environment or a hook. `cr`
records only what it actually observed: `CLAUDECODE=1` with no session ID
records an identifier and nothing else. `agent.model` is never detected: no
agent publishes it where `cr` can see it, and the one place Claude Code reports
it, a session-start hook, goes stale as soon as `/model` switches. Declare it or
leave it absent.

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

## Let Claude Code fill in the attribution

Everything above depends on the agent passing flags, and the approval mode it
passes is its own account of its own permissions. Claude Code already tells
`cr` something unprompted: it sets `CLAUDECODE=1` and `CLAUDE_CODE_SESSION_ID`
for every command it runs, which `cr` records with `detected_from:
environment`. The two things an auditor most wants are not in the environment:
which prompt a write was answering, and which permission mode it ran under.
Claude Code hands both to a `PreToolUse` hook, on stdin, before every tool call.

[`examples/hooks/claude-code-attribution.sh`](../examples/hooks/claude-code-attribution.sh)
is that hook, a POSIX shell script that needs only `jq`. Install it for every
session:

```sh
mkdir -p ~/.claude/hooks
cp examples/hooks/claude-code-attribution.sh ~/.claude/hooks/
chmod +x ~/.claude/hooks/claude-code-attribution.sh
```

Then merge [`examples/hooks/claude-code-settings.json`](../examples/hooks/claude-code-settings.json)
into `~/.claude/settings.json`, or into a project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "if": "Bash(cr *)",
            "command": "\"$HOME/.claude/hooks/claude-code-attribution.sh\"",
            "timeout": 10
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"$HOME/.claude/hooks/claude-code-attribution.sh\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The `PreToolUse` entry does the work. `matcher` limits it to the Bash tool, and
`if`, in Claude Code's permission-rule syntax, to calls with a `cr` subcommand,
so no other command pays for a process. The script checks for `cr` again,
because Claude Code runs a filtered hook anyway when it cannot parse a command.
The `SessionStart` entry is a fallback, described [below](#the-session-start-fallback).

### What a hook can and cannot do

**A `PreToolUse` hook cannot set an environment variable for the command it
precedes.** It runs as a separate process, and Claude Code offers
`CLAUDE_ENV_FILE`, the file whose exports reach later Bash commands, only to
`SessionStart`, `Setup`, `CwdChanged`, and `FileChanged` hooks. None of those
runs for an individual tool call, so none can describe one. What a
`PreToolUse` hook can do is return `hookSpecificOutput.updatedInput`, which
replaces the tool's input before it runs. So the script hands the input back
with one line in front of the command. Given this on stdin:

```json
{
  "session_id": "6d1baa69-f114-490c-ae19-4be99c2bd744",
  "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
  "transcript_path": "/home/ada/.claude/projects/-home-ada-crm/6d1baa69-f114-490c-ae19-4be99c2bd744.jsonl",
  "cwd": "/home/ada/crm",
  "permission_mode": "acceptEdits",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "cr update deals acme-renewal --set status=closed-won",
    "description": "Mark the Acme renewal closed-won",
    "timeout": 120000,
    "run_in_background": false
  },
  "tool_use_id": "toolu_01ABC123"
}
```

it prints (wrapped here for reading):

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","updatedInput":{
  "command":"export CR_HOOK_AGENT='{\"id\":\"claude-code\",\"session\":\"6d1baa69-f114-490c-ae19-4be99c2bd744\",\"turn\":\"550e8400-e29b-41d4-a716-446655440000\"}' CR_HOOK_AUTHORIZATION='{\"mode\":\"unknown\",\"grant\":\"acceptEdits\"}'\ncr update deals acme-renewal --set status=closed-won",
  "description":"Mark the Acme renewal closed-won","timeout":120000,"run_in_background":false}}}
```

so the command Claude Code runs is:

```sh
export CR_HOOK_AGENT='{"id":"claude-code","session":"6d1baa69-f114-490c-ae19-4be99c2bd744","turn":"550e8400-e29b-41d4-a716-446655440000"}' CR_HOOK_AUTHORIZATION='{"mode":"unknown","grant":"acceptEdits"}'
cr update deals acme-renewal --set status=closed-won
```

An `export` on its own line reaches every command in the call: `cd crm && cr
update …`, a pipeline, a `cr` inside `$(…)`. Bash tool variables do not carry
over to the next call, so nothing leaks into a later one. Values are
single-quoted JSON, so nothing in a session ID is ever run; a value `cr` would
reject as an identifier is dropped rather than allowed to fail the write.
`updatedInput` replaces the whole input, so `description`, `timeout`, and
`run_in_background` are copied through. `transcript_path` is not recorded: a
path into a store `cr` does not own is not traceability (see
[architecture](architecture.md#agent-attribution)).

The hook makes no permission decision and never blocks. Without `jq`, for any
other command, or on input it cannot read, it prints nothing and exits 0, and
Claude Code runs the command as written.

### What gets recorded

```json
"agent": {
  "id": "claude-code",
  "session": "6d1baa69-f114-490c-ae19-4be99c2bd744",
  "turn": "550e8400-e29b-41d4-a716-446655440000",
  "detected_from": "hook"
},
"authorization": { "mode": "unknown", "grant": "acceptEdits" }
```

`turn` is Claude Code's `prompt_id`, the user prompt the write was answering.
`grant` is `permission_mode`, verbatim. The mode is mapped conservatively:

| `permission_mode` | Recorded mode | Why |
| --- | --- | --- |
| `default` (Manual) | `unknown` | A `cr` command either prompts or matches an allow rule, and the hook runs before that check, so it cannot tell `interactive` from `delegated`. |
| `acceptEdits` | `unknown` | The same. This mode approves file edits and a handful of filesystem commands on its own, not `cr`. |
| `plan` | `unknown` | The same. A command runs after a prompt, an allow rule, or a classifier review. |
| `auto` | `delegated` | A classifier, not a person, approves each call, under the grant the human gave by choosing the mode. |
| `dontAsk` | `delegated` | Only calls an allow rule already covers can run; nothing is ever asked. |
| `bypassPermissions` | `delegated` | Nothing is asked. |
| absent, or a mode added later | `unknown` | Nothing to go on. A new mode is still kept as the grant. |

Two modes are never produced. `interactive` says a person approved *this* call,
which a hook that runs before the permission check cannot know; recording it for
`default` would be false whenever an allow rule such as `Bash(cr *)` let the
call through unseen. `autonomous` says nobody was there, which a permission mode
does not say: a `bypassPermissions` session can have a person watching every
line, and a `default` session can be a headless `claude -p`. Where the mapping
errs, it errs towards less human involvement than there was (an `ask` rule can
still prompt in `auto` mode), never more.

### Why a separate channel, and what `hook` means

`CR_HOOK_AGENT` and `CR_HOOK_AUTHORIZATION` accept the same compact or JSON
forms as `CR_AGENT` and `CR_AUTHORIZATION`, with the same validation. They are a
separate pair rather than the hook exporting `CR_AGENT`, for two reasons:

- **Honest evidence.** A `CR_AGENT` the hook set would be recorded as `flag`,
  exactly like one the model typed, and the journal could not show the one
  difference the hook exists to make.
- **Precedence.** The hook's layer sits above environment probing and below
  every declaration. A user's own `CR_AGENT`, including `CR_AGENT=none`, still
  wins. A hook that exported `CR_AGENT` would instead silently override it.

`hook` covers the agent and the approval together, and they stay together.
Declaring an agent with `CR_AGENT`, `--agent`, or `X-CR-Agent`, `none`
included, replaces the hook's whole layer, as if the hook had not run: the grant
described the session it came from, not the agent now declared. Declaring any
detail of either on top (`--authorization`, `--grant`, `--approved-by`,
`--approved-changes`, `--agent-model`, `CR_AUTHORIZATION`, and so on) keeps the
rest but records `flag` (or `header`), because the event would otherwise credit
the hook with a value the calling process chose. An agent still labelled `hook`
therefore means its authorization, if there is one, came from the hook as well.
Intent does not count: no hook supplies it, and every intent is authored by
somebody.

`hook` names the channel, not its author, like every other value in the evidence
table. A process that sets `CR_HOOK_AGENT` itself is recorded as `hook`. What
the label buys is that the model now has to do that on purpose, where before its
own description of its grant was the only one there was.

### Limits

- **Permission rules see the rewritten command.** Claude Code checks its rules
  against the input a hook returns and treats each line as its own subcommand.
  An allow rule such as `Bash(cr *)` covers the `cr` line but not the `export`
  line, so a call that used to run silently can now ask in Manual, `acceptEdits`,
  and `plan` modes, and is refused in `dontAsk` mode. Do not paper over it with
  a rule like `Bash(export CR_HOOK_AGENT=*)`: the wildcard would equally approve
  `export CR_HOOK_AGENT=x PATH=/tmp/evil:$PATH` in front of an allowed `cr`.
  Where the extra line is unacceptable, install only the `SessionStart` entry.
- **One rewriter per tool.** When several `PreToolUse` hooks return
  `updatedInput`, the last to finish wins. Do not combine this hook with another
  that rewrites Bash commands.
- **`if` matches `cr` by name.** A binary run by path, such as
  `./target/release/cr`, or from inside a script is not rewritten. The
  `SessionStart` entry still ties it to the session.
- **Sub-agents are recorded as the session they belong to.** The payload's
  `agent_id` and `agent_type` are not recorded; `via` could carry them only by
  inventing an identity for the sub-agent.
- **A server inherits it.** `cr serve` started through the Bash tool attributes
  every write it serves to the session and the mode it started under, as
  `CLAUDECODE` already would. Start servers yourself.
- **Bash only.** The PowerShell tool is not covered.

### The session-start fallback

`SessionStart` is one of the events whose hooks may export variables to later
Bash commands, by appending to `CLAUDE_ENV_FILE`, which Claude Code runs ahead
of each command. It runs when a session starts, not for each call, so as a
`SessionStart` hook the script appends the agent and the session and nothing
else:

```sh
export CR_HOOK_AGENT='{"id":"claude-code","session":"6d1baa69-f114-490c-ae19-4be99c2bd744"}'
```

It prints nothing, because Claude reads a session-start hook's output as
conversation. Every later command carries the variable and its text is never
touched. Beside the `PreToolUse` entry, it covers the `cr` invocations that
filter misses; where both apply, the `PreToolUse` line runs later and wins. On
its own it records the session with no turn and no approval: a grant read at
session start would be wrong as soon as the mode changed. The model Claude Code
reports at session start is left out for the same reason.

## Commit as the agent, on the human's behalf

The journal keeps the responsible human (`actor`) apart from the software that
acted (`agent`). A Git history can say the same thing with no new mechanism,
because every commit already carries two identities:

| In the commit | Holds | Corresponds to |
| --- | --- | --- |
| Author | The human | `actor`. `cr` falls back to the same Git author identity. |
| Committer | The agent | `agent` |
| `Co-authored-by:` trailer | The agent, for hosts that display only authors | |
| `Cr-Audit-Head:` trailer | `cr audit head` at commit time | The journal event the commit was made at |

Keep `user.name` and `user.email` as they are: they stay the author, and they
stay `cr`'s actor. Claude Code already adds a `Co-Authored-By:` trailer naming
the model (its `attribution.commit` setting). To make it the committer too, set
the committer identity in Claude Code's own `settings.json`, whose `env` reaches
the commands Claude Code runs and not your own shell:

```json
{
  "env": {
    "GIT_COMMITTER_NAME": "Claude Code",
    "GIT_COMMITTER_EMAIL": "noreply@anthropic.com"
  }
}
```

Set only the committer. `GIT_AUTHOR_NAME` in the same place would make the
agent the author and, because `cr` reads the Git author, the journal's actor.
If you sign commits, a host that matches the signing key against the committer
will stop marking them verified.

[`examples/hooks/commit-msg`](../examples/hooks/commit-msg) adds the trailer. Install
it in any repository whose commits should name the head, and point it at the
database unless that is the repository root:

```sh
cp examples/hooks/commit-msg .git/hooks/commit-msg
chmod +x .git/hooks/commit-msg
git config cr.database path/to/database
```

A commit made in a Claude Code session then reads, in `git log --format=fuller`:

```text
Author:     Ada Lovelace <ada@example.com>
Commit:     Claude Code <noreply@anthropic.com>

    Close the Acme renewal

    Co-Authored-By: Claude <noreply@anthropic.com>
    Cr-Audit-Head: 42 sha256:9f2c…
```

The trailer is [the audit anchor](audit.md#anchor-the-head-in-git) carried in the
commit object instead of a file in its tree. That matters when the commit is
not in the database's repository, such as code changed in the same session as
the records, and it shows in `git log` without a checkout. It names an event by
sequence and hash, so `cr audit log --json` must still show that sequence with
that hash; at a checkout of a commit whose tree includes the journal,
`cr audit verify --expected-head` with the hash checks it directly.

It is a `commit-msg` hook rather than `prepare-commit-msg` because it runs on
the finished message: the head is read as late as possible, and the trailer
lands after the text instead of in the empty editor template above where the
subject will go. Amending replaces the trailer. Without `cr`, without a
database, or with an empty journal, it leaves the message alone, and it never
stops a commit. `git commit --no-verify` skips it. Like everything else on this
page, the trailer is asserted: it is worth what the history holding it is worth,
which is why a pushed, and ideally signed, history is where it belongs.

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
journal always means what this table says it means. `detected_from: hook` is
the first value added this way: a `cr` from before it verifies and displays a
hook-attributed event, and appends after it, without change.

Intent text is stored inline and is therefore **permanent**, like every other
value in the journal.
