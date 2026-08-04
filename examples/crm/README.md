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
- `http://127.0.0.1:3000/high-value-deals` for open deals worth at least 50,000, ordered by value;
- `http://127.0.0.1:3000/companies` for all companies;
- `http://127.0.0.1:3000/contacts` for all contacts;
- `http://127.0.0.1:3000/audit` for the complete audit timeline;
- `http://127.0.0.1:3000/openapi.json` for the generated API contract.

The HTML forms are live: creating, editing, deleting, or moving a Kanban card changes the Markdown files in this directory and appends to its audit journal. Record pages derive typed inputs, select controls, descriptions, and validation hints from the CRM schemas. Drag a card between stage lanes, or use its accessible move selector and button.

List and Kanban pages keep search in the header. Open **Filter** for the schema-derived query controls, then add conditions such as `stage is negotiation`, `value is at least 50000`, or `tags contains renewal` and choose whether all or any conditions must match. Each field only offers compatible operators, and select values only offer their declared choices.

Use the Sorting controls to order deals by value, close date, owner, or any other schema field. Table column headings toggle direction directly; Kanban sorts cards within each stage lane. The saved pipeline opens with its persisted `value` descending default, which the current URL can override or clear.

Open **Columns** to show only the fields you need. The same control chooses table columns and Kanban card details, and the selection stays in the URL through sorting and pagination.

The `high-value-deals` route demonstrates a reusable typed saved query. Its YAML combines `status=open` with `value>=50000`; browser filters remain additive and cannot escape that scope.

Use **Save as view** on any table or Kanban page to turn the currently applied filters, visible columns, and sorting into another named route. Choose **Kanban** and a grouping field such as `stage` to create another board entirely in the browser. The form preserves **all** versus **any** matching and creates a new file under `.cr/views/`; search text remains in the shareable URL rather than being persisted.

Useful CLI queries:

```sh
cr --database examples/crm list deals --where 'status=open' --sort value --desc --json
cr --database examples/crm list deals --where 'stage=negotiation' --sort value --desc --json
cr --database examples/crm list deals --where-expr 'value>=50000' --where-expr 'stage!=won' --json
cr --database examples/crm search 'Acme' --ignore-case --json
cr --database examples/crm audit verify
```
