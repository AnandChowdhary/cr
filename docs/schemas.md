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
