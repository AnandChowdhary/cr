# cr

`cr` is a local, file-based database whose records are ordinary Markdown files with YAML front matter. Collections and fields are not compiled into the CLI, so the same database engine can represent a CRM, ATS, project tracker, knowledge base, or another data model.

## Quick start

```sh
cargo build
cargo install --path .

cr init ./my-database
cd ./my-database

cr create companies acme --set 'name=Acme Corp' --set 'industry=Manufacturing'
cr create candidates jane-doe \
  --set 'name=Jane Doe' \
  --set 'stage=screening' \
  --set 'contact.email=jane@example.com' \
  --body $'# Jane Doe\n\nCandidate notes go here.\n'

cr update candidates jane-doe --set 'stage=interview'
cr link candidates jane-doe company companies acme
cr get candidates jane-doe --json
cr list candidates --where 'stage=interview' --json
cr audit verify
```

Commands automatically search the current directory and its parents for `.cr/config.yaml`. Use `--database PATH` to target a database explicitly.

## Storage format

Each record is stored at `records/<collection>/<id>.md`:

```markdown
---
name: Jane Doe
stage: interview
contact:
  email: jane@example.com
relations:
  company:
  - collection: companies
    id: acme
---
# Jane Doe

Candidate notes go here.
```

Identity comes from the path, leaving every front matter key available to the data model. Values passed to `--set` and `--where` are parsed as YAML, so booleans, numbers, lists, objects, and nulls retain their types. Quote shell arguments that contain spaces or YAML punctuation.

`get` returns the Markdown file by default. Use `--json` for a machine-readable record envelope, or `--field contact.email` for one value.

## Audit journal

Every successful `create`, `update`, `link`, and `delete` mutation writes an attributed event to a tamper-evident audit journal. Pass `--actor NAME`, set `CR_ACTOR`, or let `cr` use the operating-system username.

```sh
cr --actor alice update candidates jane-doe --set 'stage=interview'

cr audit log candidates jane-doe --limit 10
cr audit log --json
cr audit verify
cr audit head --json

cr --actor admin delete candidates jane-doe --yes
```

An event records a global sequence, UTC timestamp, actor, action, record identity, field-level before/after changes, exact before/after file hashes, the previous event hash, and its own SHA-256 hash. Create and baseline events retain the full resulting record; delete events retain the full previous record as an auditable tombstone.

The journal is stored as bounded JSON Lines segments under `.cr/audit/segments/`. Defaults are configured in `.cr/config.yaml`:

```yaml
audit:
  segment_max_events: 256
  segment_max_bytes: 8388608
```

A segment rotates when either bound would be crossed. A single event larger than the byte limit receives its own segment. Only the active bounded segment is rewritten when an event is appended.

`audit verify` streams the chain and checks sequence continuity, every event digest, cross-segment links, and current record contents. Direct filesystem changes and untracked Markdown records therefore fail verification. For records created before auditing was enabled, run `cr --actor migration audit baseline` once.

The local hash chain is tamper-evident, not absolutely tamper-proof against someone who can rewrite the database and its complete history. Save the output of `cr audit head --json` outside the database—such as a signed Git commit, remote service, or trusted timestamp—and later pass the saved hash to `cr audit verify --expected-head HASH`. That external checkpoint detects tail deletion and full-chain rewrites.

Audit events intentionally retain historical values, including deleted Markdown and potentially sensitive CRM or ATS data. Protect and retain `.cr/audit` according to the same or stricter policy as the records themselves.

## Optional schemas

The database is schemaless by default. To validate a collection, add a standard JSON Schema at `.cr/schemas/<collection>.json`. Create, update, and link operations validate before replacing the record or extending the audit journal.

For example, `.cr/schemas/candidates.json` can constrain an ATS stage:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name", "stage"],
  "properties": {
    "name": { "type": "string" },
    "stage": {
      "enum": ["screening", "interview", "offer", "hired", "rejected"]
    }
  },
  "additionalProperties": true
}
```

Schemas validate front matter only; the record ID, collection, path, and Markdown body are exposed separately by `get --json`.

## Development

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

See [`docs/architecture.md`](docs/architecture.md) for the design boundaries and planned extension points.
