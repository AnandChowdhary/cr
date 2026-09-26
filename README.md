<div align="center">
  <h1>cr</h1>
  <p><strong>A local-first database made from Markdown.</strong></p>
  <p>Typed front matter · audited changes · CLI · REST API · server-rendered views</p>
  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#see-it-in-action">Screenshots</a> ·
    <a href="#documentation">Documentation</a> ·
    <a href="docs/http-api.md">HTTP API</a> ·
    <a href="TODO.md">Roadmap</a>
  </p>
</div>

![The cr database home showing automatic and saved CRM views](docs/screenshots/database-views.jpg)

`cr` turns a folder of ordinary Markdown files with YAML front matter into a queryable database. Choose any collections and fields, then use the same project as a CRM, applicant tracking system, project tracker, knowledge base, or another custom data tool.

> Your editor can edit it. Git can diff it. `cr` can validate, query, audit, sync, and serve it.

| Own the source | Model what you need |
| --- | --- |
| Each record is a readable Markdown file by default. Direct edits are first-class; collections that need confidentiality can opt specific values into encrypted storage. | Collections and typed YAML fields are arbitrary, with optional JSON Schema validation and relationships. |
| **Query everywhere** | **Trust the history** |
| Filter, compare, sort, search, and page through the same data from the CLI, REST API, tables, or Kanban boards. | Every accepted create, update, link, move, direct edit, sync, and delete extends a tamper-evident audit chain. |

## See it in action

<table>
  <tr>
    <td width="50%">
      <img src="docs/screenshots/high-value-deals.jpg" alt="A filtered table of high-value CRM deals">
      <br><sub><strong>Saved tables</strong> — searchable, filterable, sortable, and editable.</sub>
    </td>
    <td width="50%">
      <img src="docs/screenshots/sales-pipeline.jpg" alt="A sales pipeline rendered as a Kanban board">
      <br><sub><strong>Kanban pipelines</strong> — moving a card updates and audits its grouping property.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="docs/screenshots/record-audit-history.jpg" alt="A schema-driven record form beside the record's newest audit events">
      <br><sub><strong>Record history</strong> — schema-driven forms beside actor, source, timestamp, and field-level changes.</sub>
    </td>
    <td width="50%">
      <img src="docs/screenshots/audit-log.jpg" alt="The global audit log filtered to one CRM deal, with a field-level change expanded">
      <br><sub><strong>Global audit log</strong> — filtered, paginated, and independently verifiable.</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="docs/screenshots/users.jpg" alt="The read-only users page listing each principal with its kind, status, and grants">
      <br><sub><strong>Access control</strong> — opt-in users, roles, and private or shared records.</sub>
    </td>
    <td width="50%">
      <img src="docs/screenshots/file-browser.jpg" alt="The owner-only file browser listing the database root, with its README previewed below">
      <br><sub><strong>File browser</strong> — an owner-only view of the files around the database, with in-place editing and confirmed deletes.</sub>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <img src="docs/screenshots/cli-session.jpg" alt="A terminal session that lists open deals, previews an update, edits a record file directly, and saves it">
      <br><sub><strong>The CLI</strong> — query, preview a change before writing it, or edit a file in any editor and record it with <code>cr save</code>.</sub>
    </td>
  </tr>
</table>

## How it works

A record is a Markdown file at `records/<collection>/<id>.md`. Structured fields
live in its YAML front matter, and free-form notes in its body:

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

- **Change it however you like.** `cr create` and `cr update`, the REST API,
  and the browser forms make the same validated, audited write. Edit the file
  in your editor instead, and `cr status` shows the change until `cr save`
  records it.
- **Every change is on the record.** Each accepted write appends an event to a
  hash-chained journal: who made it, from where, and—when an agent acted for
  someone—which agent, under what approval, and why. `cr audit verify` replays
  the whole chain.
- **Structure is opt-in.** A collection is schemaless until you give it a JSON
  Schema. The same schema can encrypt chosen fields at rest, generate the web
  forms, and describe the collection in the generated OpenAPI document.
- **So is access control.** Users, roles, and private or shared records are
  stored in the database, and the CLI, the API, and the web UI apply the same
  decision.

## Quick start

Download the archive for your platform from the
[latest release](https://github.com/AnandChowdhary/cr/releases/latest) and put
`cr` on your `PATH`, or build it with a current Rust toolchain:

```sh
cargo install --git https://github.com/AnandChowdhary/cr --locked
```

[Installation](docs/installation.md) lists every platform, shows how to verify
a download's checksum and build provenance, and includes an update script.

The repository includes a complete CRM with companies, contacts, deals,
relationships, schemas, audit history, saved tables, and a Kanban pipeline:

```sh
git clone https://github.com/AnandChowdhary/cr.git && cd cr
cr --database examples/crm audit verify
cr --database examples/crm serve
```

Open [http://127.0.0.1:3000/](http://127.0.0.1:3000/) for the database home,
`/deals` for open deals, `/pipeline` for Kanban, or `/audit` for the journal.

Or start a database of your own:

```sh
cr init ./my-database && cd ./my-database
export CR_NAME='Jane Doe' CR_EMAIL='jane@example.com'

cr create companies acme --set 'name=Acme Corporation' --set 'active=true'
cr list companies --where 'active=true'
cr audit log
cr serve
```

[Getting started](docs/getting-started.md) goes through the same steps in more
detail.

## Documentation

**Start here**

- [Installation](docs/installation.md) — supported platforms, verified downloads, building from source, and updating.
- [Getting started](docs/getting-started.md) — create a database, set your identity, and learn what a record is.
- [Working with records](docs/working-with-records.md) — create, read, update, link, delete, filter, and search records, and edit the files directly.
- [Examples](docs/examples.md) — a CRM and an applicant tracking system, step by step.

**Model and protect your data**

- [Schemas](docs/schemas.md) — optional JSON Schema validation for each collection.
- [Encryption](docs/encryption.md) — encrypt chosen fields and bodies at rest.
- [Access control](docs/access-control.md) — users, roles, and private or shared records.
- [Audit history and integrity](docs/audit.md) — the journal, anchoring it in Git, and `cr check`.

**Automate and integrate**

- [Agents and automation](docs/agents.md) — record which agent acted and why, approve a change set before it is written, and retry writes safely.
- [Sync adapters](docs/sync.md) — import data from any program that prints JSON Lines.
- [Web UI](docs/web-ui.md) — `cr serve`, tables, Kanban boards, forms, and the file browser.
- [REST API](docs/http-api.md) — authentication, CRUD, filtering, audit endpoints, and OpenAPI.

**Reference**

- [Command reference](docs/cli-reference.md) — every command and option at a glance.
- [Troubleshooting](docs/troubleshooting.md) — common errors, and what to back up.

For the design, see [architecture](docs/architecture.md) and
[releasing](docs/releasing.md). Planned work—including nested Boolean
expressions, projections, relationship traversal, and indexes—is tracked in
[`TODO.md`](TODO.md).

## Development

`cr` requires Rust 1.89 or newer, declared as `rust-version` in `Cargo.toml`.

Continuous integration runs these exact commands on Linux, so running them locally reproduces the pipeline:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --all-targets
cargo test --locked
```

During development, use `cargo run --` instead of the installed command—for example, `cargo run -- --help`.

See [`docs/architecture.md`](docs/architecture.md) for the storage protocol and integrity boundaries. [`TODO.md`](TODO.md) is the canonical list of shortcuts, technical debt, and planned capabilities; update it in the same commit as future feature work. User-facing behavior is documented in the guides under [`docs/`](docs/); update the guide a change affects in the same commit.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md) rather than in a public issue.

## License

Released under the [MIT License](LICENSE).
