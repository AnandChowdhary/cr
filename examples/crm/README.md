# Sample CRM

This is a ready-to-use `cr` database with sample companies, contacts, deals, relationships, schemas, audit history, and an open-deals view.

From the repository root, start it with:

```sh
cr --database examples/crm serve
```

Then open:

- `http://127.0.0.1:3000/` for the database home page;
- `http://127.0.0.1:3000/deals` for the saved open-deals pipeline;
- `http://127.0.0.1:3000/companies` for all companies;
- `http://127.0.0.1:3000/contacts` for all contacts;
- `http://127.0.0.1:3000/audit` for the complete audit timeline;
- `http://127.0.0.1:3000/openapi.json` for the generated API contract.

The HTML forms are live: creating, editing, or deleting a record changes the Markdown files in this directory and appends to its audit journal.

Useful CLI queries:

```sh
cr --database examples/crm list deals --where 'status=open' --json
cr --database examples/crm list deals --where 'stage=negotiation' --json
cr --database examples/crm search 'Acme' --ignore-case --json
cr --database examples/crm audit verify
```
