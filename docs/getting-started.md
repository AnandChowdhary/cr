# Getting started

This guide creates a database, sets the identity recorded with every change,
and explains how records are stored. [Install `cr`](installation.md) first.

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
│   ├── audit/
│   ├── encryption.json
│   ├── schemas/
│   ├── sync/
│   ├── syncs/
│   └── views/
└── records/
```

- `records/` contains your Markdown records.
- `.cr/audit/` contains the audit journal.
- `.cr/encryption.json` is a portable, non-secret database identity used to
  bind protected ciphertext to this database. Keep it with every clone and
  backup.
- `.cr/schemas/` can contain optional validation rules.
- `.cr/syncs/` contains versioned external sync definitions; `.cr/sync/` holds their checkpoints and locks.
- `.cr/views/` contains optional saved web views.
- `.cr/` identifies the database root.
- `.cr/config.yaml` is optional and contains only overrides from the defaults.

Without a config file, `cr` uses format version 1, stores records under `records/`, and rotates audit segments after 256 events or 8 MiB. Add only the settings you want to change; omitted fields retain their defaults:

```yaml
data_dir: content/data
audit:
  segment_max_events: 500
```

`data_dir` must be a relative path inside the database, and every directory `cr`
opens beneath the root must be a real directory rather than a symbolic link.
That includes `records/`, each collection directory, `.cr/`, and everything
under it. A link anywhere in the chain is refused with an error naming the
record, collection, or view involved; the database itself may still be reached
through a linked path, because the root is resolved once before any of this
applies.

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

### What counts as a record

A collection directory may hold anything you like: a `README`, an image, a
subdirectory of attachments. `cr` treats a file as a record only if its name
ends in `.md`, and the rest of the name has to be a usable record ID — not
empty, not `.` or `..`, and free of path separators. Files that are not
Markdown are ignored everywhere, silently and permanently.

A `.md` file whose name *cannot* be an ID is a different case, and every
command refuses it rather than guessing:

```console
$ cr list deals
error: collection 'deals' contains a Markdown file named '..md' whose name cannot be a record ID
```

`list`, `search`, `status`, `save`, `audit verify`, `audit baseline`, `sync
run`, the REST API, and the web views all stop with that one sentence, which
names the collection and the file but never where the database lives. One such
file therefore blocks writes to the whole database until you remove or rename
it — deliberately, so that `cr` never disagrees with itself about which files
are records.

The exception is [`cr check`](audit.md#check-the-whole-database), which reports the
same problem as an `invalid_record_name` finding and keeps scanning. It is the
command to reach for when everything else refuses.

## Next steps

- [Working with records](working-with-records.md) covers creating, reading,
  filtering, searching, and editing records.
- [Examples](examples.md) builds a small CRM and an applicant tracking system
  step by step.
- [Schemas](schemas.md) add validation to a collection.
- [Web UI](web-ui.md) serves the database as tables, Kanban boards, and forms.
