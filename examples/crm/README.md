# Sample CRM

This is a ready-to-use `cr` database with sample companies, contacts, deals, relationships, schemas, audit history, an open-deals table, and a Kanban pipeline.

From the repository root, start it with:

```sh
cr --database examples/crm serve
```

Then open:

- `http://127.0.0.1:3000/` for the database home page;
- `http://127.0.0.1:3000/deals` for the saved open-deals pipeline;
- `http://127.0.0.1:3000/pipeline` for every deal grouped by stage on a Kanban board;
- `http://127.0.0.1:3000/companies` for all companies;
- `http://127.0.0.1:3000/contacts` for all contacts;
- `http://127.0.0.1:3000/audit` for the complete audit timeline;
- `http://127.0.0.1:3000/openapi.json` for the generated API contract.

The HTML forms are live: creating, editing, deleting, or moving a Kanban card changes the Markdown files in this directory and appends to its audit journal. Record pages derive typed inputs, select controls, descriptions, and validation hints from the CRM schemas. Drag a card between stage lanes, or use its accessible move selector and button.

List and Kanban pages also derive their filter controls from the schema. Add multiple conditions such as `stage is negotiation` and `currency is USD`; both must match, and select fields only offer their declared values.

Useful CLI queries:

```sh
cr --database examples/crm list deals --where 'status=open' --json
cr --database examples/crm list deals --where 'stage=negotiation' --json
cr --database examples/crm search 'Acme' --ignore-case --json
cr --database examples/crm audit verify
```
