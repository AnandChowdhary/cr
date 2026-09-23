# cr documentation

The [README](../README.md) is the overview. These guides cover everything
`cr` does today; planned work is tracked in [`TODO.md`](../TODO.md).

**Start here**

- [Installation](installation.md) — supported platforms, verified downloads, building from source, and updating.
- [Getting started](getting-started.md) — create a database, set your identity, and learn what a record is.
- [Working with records](working-with-records.md) — create, read, update, link, delete, filter, and search records, and edit the files directly.
- [Examples](examples.md) — a CRM and an applicant tracking system, step by step.

**Model and protect your data**

- [Schemas](schemas.md) — optional JSON Schema validation for each collection.
- [Encryption](encryption.md) — encrypt chosen fields and bodies at rest.
- [Access control](access-control.md) — users, roles, and private or shared records.
- [Audit history and integrity](audit.md) — the journal, anchoring it in Git, and `cr check`.

**Automate and integrate**

- [Agents and automation](agents.md) — record which agent acted and why, approve a change set before it is written, and retry writes safely.
- [Sync adapters](sync.md) — import data from any program that prints JSON Lines.
- [Web UI](web-ui.md) — `cr serve`, tables, Kanban boards, forms, and the file browser.
- [REST API](http-api.md) — authentication, CRUD, filtering, audit endpoints, and OpenAPI.

**Reference**

- [Command reference](cli-reference.md) — every command and option at a glance.
- [Troubleshooting](troubleshooting.md) — common errors, and what to back up.

**Design and maintenance**

- [Architecture](architecture.md) — the storage protocol, audit chain, and integrity boundaries.
- [Releasing](releasing.md) — how a merge to `main` becomes a release.
