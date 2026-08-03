# cr

`cr` is a local database stored as ordinary Markdown files with YAML front matter.

You choose the collections and fields. The same CLI can therefore be used as a CRM, an applicant tracking system (ATS), a project tracker, a knowledge base, or another small custom database.

Every change made through the CLI is recorded in a tamper-evident audit journal. You can also edit Markdown files directly, review those edits with `cr status`, and record them with `cr save`.

## Install the CLI

You need a current Rust toolchain. From this repository, run:

```sh
cargo install --path .
```

Confirm that the command is available:

```sh
cr --help
```

During development, you can use `cargo run --` instead of the installed `cr` command. For example, `cargo run -- --help`.

## Create your first database

Initialize a new database and enter its directory:

```sh
cr init ./my-database
cd ./my-database
```

The new directory contains:

```text
my-database/
├── .cr/
│   ├── config.yaml
│   ├── audit/
│   └── schemas/
└── records/
```

- `records/` contains your Markdown records.
- `.cr/audit/` contains the audit journal.
- `.cr/schemas/` can contain optional validation rules.
- `.cr/config.yaml` contains database settings.

Commands search the current directory and its parents for a database. If you are elsewhere, pass its path explicitly:

```sh
cr --database ./my-database list companies
```

## Set your identity

Audit events include the identity responsible for the change. The easiest persistent setup is:

```sh
export CR_NAME='Jane Doe'
export CR_EMAIL='jane@example.com'
```

Check the identity that will be recorded:

```sh
cr identity
# Jane Doe <jane@example.com>
```

For one command, override it with `--actor`:

```sh
cr --actor 'admin@example.com' delete companies old-company --yes
```

Identity is resolved from `--actor`, `CR_ACTOR`, `CR_NAME` and `CR_EMAIL`, Git author environment variables, Git `user.name` and `user.email`, `EMAIL`, and finally the operating-system username.

This provides attribution, not cryptographically authenticated identity. For stronger assurance, store signed audit checkpoints outside the database.

## How records work

A record is identified by its collection and ID:

```text
companies/acme
```

It is stored at:

```text
records/companies/acme.md
```

A record contains structured fields in YAML front matter and free-form notes in the Markdown body:

```markdown
---
name: Acme Corporation
industry: Manufacturing
active: true
tags:
- enterprise
- renewal
---
# Acme Corporation

Account notes go here.
```

Values passed to `--set` and `--where` are parsed as YAML. Strings, numbers, booleans, lists, objects, and `null` retain their types. Quote arguments containing spaces or YAML punctuation.

## Everyday commands

Create a record:

```sh
cr create companies acme \
  --set 'name=Acme Corporation' \
  --set 'industry=Manufacturing' \
  --set 'active=true' \
  --set 'tags=[enterprise, renewal]' \
  --body 'Account notes go here.'
```

Fetch the Markdown file:

```sh
cr get companies acme
```

Fetch the record as JSON:

```sh
cr get companies acme --json
```

Fetch one field, including a nested field:

```sh
cr get companies acme --field industry
cr get contacts jane-doe --field contact.email
```

List a collection:

```sh
cr list companies
cr list companies --json
```

Filter using typed equality. Multiple filters are combined with AND:

```sh
cr list companies --where 'active=true'
cr list deals --where 'stage=proposal' --where 'value=25000' --json
```

Update fields or replace the Markdown body:

```sh
cr update companies acme --set 'industry=Industrial automation'
cr update companies acme --set 'active=false' --body 'Account is currently paused.'
```

Add a named relation from one record to another:

```sh
cr link contacts jane-doe company companies acme
```

The arguments are:

```text
cr link SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
```

Delete a record. Deletion requires confirmation and retains an audited tombstone:

```sh
cr delete companies acme --yes
```

## CRM example

A simple CRM can use three collections:

- `companies` for accounts;
- `contacts` for people;
- `deals` for sales opportunities.

### 1. Create a company

```sh
cr create companies acme \
  --set 'name=Acme Corporation' \
  --set 'domain=acme.example' \
  --set 'industry=Manufacturing' \
  --set 'status=customer' \
  --set 'owner.email=sales@example.com' \
  --body 'Strategic account. Renewal is due in December.'
```

### 2. Create a contact and connect them to the company

```sh
cr create contacts jane-doe \
  --set 'name=Jane Doe' \
  --set 'title=VP of Operations' \
  --set 'contact.email=jane@acme.example' \
  --set 'contact.phone=+1-555-0100' \
  --set 'active=true' \
  --body 'Jane is the main buying contact.'

cr link contacts jane-doe company companies acme
```

### 3. Create a deal and add its relationships

```sh
cr create deals acme-renewal-2027 \
  --set 'name=Acme 2027 renewal' \
  --set 'stage=qualification' \
  --set 'value=25000' \
  --set 'currency=USD' \
  --set 'expected_close=2027-12-15' \
  --body 'Confirm seat count before preparing the proposal.'

cr link deals acme-renewal-2027 company companies acme
cr link deals acme-renewal-2027 primary_contact contacts jane-doe
```

### 4. Work with the pipeline

```sh
cr list deals --where 'stage=qualification'
cr update deals acme-renewal-2027 --set 'stage=proposal'
cr get deals acme-renewal-2027 --json
cr audit log deals acme-renewal-2027 --limit 10
```

### 5. Close or remove the deal

Mark it won while retaining the record:

```sh
cr update deals acme-renewal-2027 \
  --set 'stage=won' \
  --set 'closed_at=2027-11-30'
```

Or delete a test or duplicate deal:

```sh
cr delete deals duplicate-deal --yes
```

## ATS example

An ATS can use three collections:

- `candidates` for people;
- `roles` for job openings;
- `applications` for a candidate's progress through one role.

Keeping stage on an application is useful because one candidate can apply for multiple roles.

### 1. Create a role

```sh
cr create roles senior-rust-engineer \
  --set 'title=Senior Rust Engineer' \
  --set 'department=Engineering' \
  --set 'location=Remote - Europe' \
  --set 'status=open' \
  --set 'headcount=1' \
  --body 'Looking for production Rust and distributed systems experience.'
```

### 2. Create a candidate

```sh
cr create candidates alex-smith \
  --set 'name=Alex Smith' \
  --set 'contact.email=alex@example.com' \
  --set 'location=Amsterdam' \
  --set 'skills=[Rust, PostgreSQL, distributed systems]' \
  --set 'source=referral' \
  --body 'Strong infrastructure background. Referred by Sam.'
```

### 3. Create an application and connect it

```sh
cr create applications alex-smith-senior-rust \
  --set 'stage=applied' \
  --set 'applied_at=2026-08-03' \
  --set 'owner.email=recruiter@example.com' \
  --body 'Resume received. Schedule the recruiter screen.'

cr link applications alex-smith-senior-rust candidate candidates alex-smith
cr link applications alex-smith-senior-rust role roles senior-rust-engineer
```

### 4. Move the application through the hiring process

```sh
cr update applications alex-smith-senior-rust --set 'stage=recruiter_screen'
cr update applications alex-smith-senior-rust --set 'stage=technical_interview'
cr list applications --where 'stage=technical_interview' --json
cr get applications alex-smith-senior-rust --json
```

Record an offer or rejection:

```sh
cr update applications alex-smith-senior-rust \
  --set 'stage=offer' \
  --set 'offer.sent_at=2026-09-15'
```

Or:

```sh
cr update applications alex-smith-senior-rust \
  --set 'stage=rejected' \
  --set 'rejection.reason=Role requires a different time zone'
```

Review the complete history:

```sh
cr audit log applications alex-smith-senior-rust --limit 20 --json
```

## Edit records directly

You do not have to use `cr update`. Open any record under `records/` in a text editor and change its front matter or Markdown body.

After editing, inspect the working tree:

```sh
cr status
# M candidates/alex-smith
# A candidates/new-candidate
# D candidates/removed-candidate
```

- `M` means modified.
- `A` means added directly on disk.
- `D` means deleted directly on disk.

Reads use the current Markdown files, so `get` and `list` can show an unsaved direct edit. Audit verification and further CLI mutations will reject the divergence until you review and save it.

Record one or more reviewed changes:

```sh
cr save candidates/alex-smith --message 'Add interview notes'
cr save candidates/new-candidate candidates/removed-candidate \
  --message 'Review recruiting file changes'
```

Record everything currently shown by `status`:

```sh
cr save --all --message 'Import reviewed editor changes'
```

Use JSON when integrating with scripts:

```sh
cr status --json
cr save candidates/alex-smith --message 'Reviewed' --json
```

`save` parses and schema-validates every selected file before recording any event. Formatting-only changes are recorded because the exact file bytes changed, even when the fields and body have the same meaning.

Do not run `cr save --all` automatically from a watcher or scheduled task. An explicit save is the point where you acknowledge that the filesystem changes are legitimate rather than tampering.

## Audit history

Every successful `create`, `update`, `link`, `delete`, and direct `save` writes an attributed event.

Show recent events for the entire database:

```sh
cr audit log
cr audit log --limit 100 --json
```

Show history for one record:

```sh
cr audit log candidates alex-smith --limit 20
```

Verify the journal and all current records:

```sh
cr audit verify
```

Print the current audit checkpoint:

```sh
cr audit head --json
```

The audit journal is tamper-evident, not magically tamper-proof if an attacker can rewrite both the database and its entire local history. Store important checkpoints outside the database—for example in a signed Git commit or trusted remote service—and verify them later:

```sh
cr audit verify --expected-head 'sha256:YOUR_SAVED_HASH'
```

For records that existed before audit logging was introduced, establish their starting state once:

```sh
cr --actor 'migration@example.com' audit baseline
```

Audit events retain historical field values and deleted record bodies. Protect `.cr/audit/` at least as carefully as `records/`, particularly for personal CRM and recruiting data.

## Add validation with JSON Schema

The database is schemaless by default. Add `.cr/schemas/<collection>.json` when a collection needs required fields or controlled values.

For example, `.cr/schemas/applications.json` can restrict ATS stages:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["stage"],
  "properties": {
    "stage": {
      "enum": [
        "applied",
        "recruiter_screen",
        "technical_interview",
        "offer",
        "hired",
        "rejected",
        "withdrawn"
      ]
    }
  },
  "additionalProperties": true
}
```

Schemas validate front matter. The record ID, collection, path, and Markdown body remain separate. Creates, updates, links, and direct `save` operations validate before extending the audit journal.

## Useful command summary

```text
cr init PATH
cr identity

cr create COLLECTION ID [--set KEY=YAML]... [--body TEXT]
cr get COLLECTION ID [--json | --field KEY]
cr list COLLECTION [--where KEY=YAML]... [--json]
cr update COLLECTION ID [--set KEY=YAML]... [--body TEXT]
cr link SOURCE_COLLECTION SOURCE_ID RELATION TARGET_COLLECTION TARGET_ID
cr delete COLLECTION ID --yes

cr status [--json]
cr save COLLECTION/ID... [--message TEXT] [--json]
cr save --all [--message TEXT] [--json]

cr audit log [COLLECTION] [ID] [--limit N] [--json]
cr audit verify [--expected-head HASH]
cr audit head [--json]
cr audit baseline
```

Run `cr COMMAND --help` for complete command-specific help.

## Troubleshooting

### No database found

Run commands inside the database directory, or pass its root explicitly:

```sh
cr --database /path/to/my-database list companies
```

### Audit verification fails after editing Markdown

Review and record the direct change:

```sh
cr status
cr save collection/id --message 'Explain the change'
cr audit verify
```

### A record has no audit history

For a one-time migration of existing records, use:

```sh
cr audit baseline
```

For a newly added Markdown record, prefer `cr status` followed by a selective `cr save collection/id`.

### A schema rejects a change

The file or proposed CLI update does not satisfy `.cr/schemas/<collection>.json`. Fix the fields and retry. Failed validation does not append an audit event.

## Backups and sensitive data

Back up the whole database directory, not only `records/`. The `.cr/audit/` directory is necessary to verify history and reconcile direct edits.

CRM and ATS records often contain personal or confidential information. Apply appropriate filesystem permissions, disk encryption, backup retention, and access controls.

## Development

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

See [`docs/architecture.md`](docs/architecture.md) for the storage protocol, integrity boundaries, and planned extension points.
