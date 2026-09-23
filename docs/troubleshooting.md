# Troubleshooting

## No database found

Run commands inside the database directory, or pass its root explicitly:

```sh
cr --database /path/to/my-database list companies
```

## Audit verification reports an anchor mismatch

`cr` is telling you that the journal on disk is not the journal `.cr-audit-head.json` attests to. The chain itself is intact — that would be a different message — so either the journal was rewritten or the anchor was. Do not run `cr audit anchor --write`; it refuses in this state on purpose, because rewriting the anchor would destroy the evidence.

Find out which side moved, using the history the anchor exists for:

```sh
git log -p -- .cr-audit-head.json
cr audit log --limit 20
```

If the anchor in your last commit matches the journal, something rewrote the file locally. If it matches the file and not the journal, something rewrote the journal. Restore from the version-controlled copy you trust, and treat the database as suspect until you know which.

A **behind** notice is not this. See [Anchor the head in Git](audit.md#anchor-the-head-in-git): it means the anchor lags a journal that still agrees with it, and `cr audit anchor --write` is the right response.

## Audit verification fails after editing Markdown

Review and record the direct change:

```sh
cr status
cr save collection/id --message 'Explain the change'
cr audit verify
```

## Something is wrong and you do not know what

Run `cr check`. It reports every problem it can find in one pass instead of failing on the first one, and its warnings tell you which of them `cr save` would resolve on its own.

## A record has no audit history

For a one-time migration of existing records, use:

```sh
cr audit baseline
```

For a newly added Markdown record, prefer `cr status` followed by a selective `cr save collection/id`.

## A schema rejects a change

The file or proposed CLI update does not satisfy `.cr/schemas/<collection>.json`. Fix the fields and retry. Failed validation does not append an audit event.

## A sync fails after changing files directly

The adapter bypassed the JSONL protocol or another process edited a record during its run. Inspect the changes before doing anything else:

```sh
cr status
cr save collection/id --message 'Reviewed direct adapter change'
```

Prefer changing the adapter to emit `upsert` or `delete` messages so future runs are validated and audited automatically.

## Backups and sensitive data

Back up the whole database directory, not only `records/`. The `.cr/audit/` directory is necessary to verify history and reconcile direct edits, `.cr/encryption.json` is necessary to decrypt protected data, and `.cr/syncs/` plus `.cr/sync/state/` are needed to resume configured incremental imports. Include `.cr-audit-head.json`, and prefer a backup that keeps history—a Git remote rather than a mirror of the current directory—because a backup taken after a tamper is a copy of the tamper, while a history is a record of when it appeared.

CRM and ATS records often contain personal or confidential information. Apply appropriate filesystem permissions, disk encryption, backup retention, and access controls.
