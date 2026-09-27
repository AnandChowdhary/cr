# Examples

- [`crm`](crm/) is a ready-to-run sales CRM with companies, contacts, deals, relationships, schemas, audit history, and saved web views.
- [`hooks`](hooks/) holds a Claude Code hook that records which session, prompt, and permission mode a `cr` write ran under, and a Git `commit-msg` hook that adds the audit head to each commit. [Agents and automation](../docs/agents.md#let-claude-code-fill-in-the-attribution) explains both.

Run the CRM from the repository root:

```sh
cr --database examples/crm serve
```

Then open `http://127.0.0.1:3000/`.
