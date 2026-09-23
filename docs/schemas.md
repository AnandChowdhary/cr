# Add validation with JSON Schema

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

Schemas validate front matter. The record ID, collection, path, and Markdown body remain separate. Creates, updates, links, direct `save` operations, and sync upserts validate before extending the audit journal.

## Manage schemas from the command line

You can write the file by hand, but `cr schema` checks a schema against the
records already in the collection before it takes effect:

```sh
cr collections                                  # every collection, its title, and its schema features
cr schema show applications                     # print the installed schema
cr schema check applications applications.json  # which existing records would it reject?
cr schema set applications applications.json    # install it
cr schema remove applications                   # back to schemaless
```

`check` prints one line per violation, naming the record and field, and exits
`2` when any record fails the proposed schema; nothing is written. `set` runs
the same judgement under the audit lock and refuses the schema if an existing
record fails it, listing them. Fix those records first, or pass
`--allow-violations` to install it anyway: `cr check` then reports each one,
and each is refused on its next write until it is fixed. Both read `-` as
standard input and accept `--json`.

A schema set this way cannot change which values are
[encrypted](encryption.md) or whether records are
[creator-owned](access-control.md), because those change what is stored rather
than what is accepted; `cr schema encrypt` and `cr access policy set` are the
commands for them. For the same reason `remove` refuses a schema that declares
either. The reserved `users` collection keeps its built-in schema.

Only a database owner can check, set, or remove a schema when access control
is enabled. Schema files are configuration rather than records, so these
changes are not recorded in the audit journal; commit `.cr/schemas/` to Git to
keep their history.

## What else a schema controls

The same file drives more than validation:

- [encryption at rest](encryption.md) for the fields and bodies it marks;
- the typed [record forms](web-ui.md#use-schema-driven-record-forms) and their
  field order in the web UI;
- a collection's [name and icon](web-ui.md#name-collections-and-give-them-icons);
- the lanes of a [Kanban pipeline](web-ui.md#create-a-kanban-pipeline), which
  follow an `enum`'s declared order;
- the collection's component in the
  [generated OpenAPI document](http-api.md#generated-openapi).

A schema that changes after its records were written can leave some of them
invalid. [`cr check`](audit.md#check-the-whole-database) reports each one.
