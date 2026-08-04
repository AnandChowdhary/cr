# Architecture

## Research conclusions

YAML front matter is a well-established convention: a metadata mapping appears first in a Markdown file between `---` delimiters, and custom fields can contain typed values such as strings, booleans, numbers, arrays, and maps. Jekyll documents the delimiter and custom-variable convention, while Hugo explicitly describes front matter as metadata that can establish relationships with other content.

Markdown data tools suggest two distinct layers. Dataview treats files as the durable source and builds a queryable metadata index over them. Front Matter CMS adds optional content types and field constraints. `cr` follows the same separation: correctness cannot depend on an index, and stronger modeling is opt-in.

JSON Schema is the optional constraint language because it can describe arbitrary object shapes without coupling models to Rust types. The Rust `jsonschema` validator supports Draft 2020-12 and reusable validators. YAML values are converted to their JSON representation before validation.

Updates use a temporary file in the target directory, flush it, and persist it over the destination. Keeping the temporary file beside the record avoids cross-filesystem rename behavior and ensures readers see either the previous complete file or the next complete file.

For audit integrity, OWASP recommends a chronological, independently verifiable trail with enough context to reconstruct transactions and built-in tamper detection. Signed Syslog similarly calls for message integrity, sequencing, replay resistance, and missing-message detection. Certificate Transparency demonstrates how hashes and externally observed heads make append-only violations detectable. `cr` uses a simpler linear SHA-256 chain because local history is read sequentially; an externally stored head hash provides the independent observation point.

The mutation protocol follows write-ahead logging principles: durable intent precedes the record change, and recovery determines whether to commit or discard that intent by hashing the resulting record. Rust's standard file locks serialize writers across processes. The audit payload's exact stored JSON bytes are the hash input, so verification does not depend on parsing and reserializing arbitrary YAML-derived values.

Git's working-tree model separates detecting differences from explicitly selecting changes to record. `cr` applies the same boundary without adopting Git as a storage dependency: the audit journal is the recorded state, Markdown files are the working tree, `status` compares them, and `save` accepts reviewed paths. Git's author environment variables and repository `user.email` configuration also provide a familiar identity fallback.

The HTML layer follows the web platform directly. Native forms submit mutations with `POST`, successful writes use `303 See Other` to return to an idempotent `GET`, and Maud escapes dynamic text while producing server-rendered markup. Tailwind's Play CDN supplies the requested no-build styling, with its documented development-only limitation recorded as technical debt.

External syncs use a subprocess protocol rather than an in-process Rust extension ABI. Singer demonstrates the durable, language-neutral pattern: a connector streams one JSON object per stdout line, sends logs to stderr, uses process status for success or failure, and retains state for incremental runs. Rust's `Command` keeps the executable and argument vector separate and gives `cr` explicit control over the working directory, environment, and standard streams. This lets Bash, Python, or a compiled Rust adapter share one versioned contract without loading untrusted code into the `cr` process.

Secrets remain deployment configuration and are inherited from the invoking shell or scheduler; sync YAML never contains an environment map. Recurrence is delegated to cron, systemd timers, `launchd`, container schedulers, or CI rather than introducing another long-running service. Notion now exposes complete page content and meeting transcripts through a Markdown endpoint, while Gmail exposes stable message resources suitable for Markdown conversion, so both fit the same adapter boundary.

Research sources:

- [Jekyll front matter](https://jekyllrb.com/docs/front-matter/)
- [Hugo front matter](https://gohugo.io/content-management/front-matter/)
- [Dataview indexing and querying](https://blacksmithgu.github.io/obsidian-dataview/)
- [Front Matter CMS content types](https://frontmatter.codes/docs/content-creation/content-types)
- [Rust JSON Schema validation](https://docs.rs/jsonschema/latest/jsonschema/)
- [Rust `tempfile` persistence](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [RFC 5848: Signed Syslog Messages](https://www.rfc-editor.org/info/rfc5848/)
- [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/info/rfc6962/)
- [SQLite write-ahead logging](https://www.sqlite.org/wal.html)
- [Rust file locking](https://doc.rust-lang.org/std/fs/struct.File.html#method.lock)
- [Git status and working-tree states](https://git-scm.com/docs/git-status)
- [Git user identity](https://git-scm.com/docs/user-manual#telling-git-your-name)
- [Axum server and router](https://docs.rs/axum/latest/axum/fn.serve.html)
- [Axum repeated query parameters](https://docs.rs/axum/latest/axum/extract/struct.Query.html)
- [OpenAPI Specification 3.1](https://spec.openapis.org/oas/v3.1.1.html)
- [MDN HTML forms](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/form)
- [MDN 303 See Other](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/303)
- [Maud templates and escaping](https://docs.rs/maud/latest/maud/)
- [Tailwind Play CDN](https://tailwindcss.com/docs/installation/play-cdn)
- [Singer specification](https://github.com/singer-io/getting-started/blob/master/docs/SPEC.md)
- [Rust subprocess `Command`](https://doc.rust-lang.org/std/process/struct.Command.html)
- [POSIX `crontab`](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/crontab.html)
- [The Twelve-Factor App: Config](https://www.12factor.net/config)
- [Notion Markdown content API](https://developers.notion.com/guides/data-apis/working-with-markdown-content)
- [Gmail `users.messages.get`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)

## Version 1 layout

```text
database-root/
├── .cr/
│   ├── config.yaml
│   ├── audit/
│   │   ├── lock
│   │   └── segments/
│   │       ├── 00000000000000000001.jsonl
│   │       └── 00000000000000000257.jsonl
│   ├── schemas/
│   │   └── candidates.json
│   ├── views/
│   │   └── interviews.yaml
│   ├── syncs/
│   │   └── notion-meetings.yaml
│   └── sync/
│       ├── locks/
│       │   └── notion-meetings.lock
│       └── state/
│           └── notion-meetings.json
└── records/
    ├── candidates/
    │   └── jane-doe.md
    └── companies/
        └── acme.md
```

- `.cr/config.yaml` versions the storage format and chooses the records directory.
- A collection is a directory; a record ID is its Markdown filename without `.md`.
- Front matter contains arbitrary model attributes.
- The Markdown body is opaque user content and is preserved by metadata-only updates.
- Relations live under `relations.<name>` as lists of `{ collection, id }` references. `cr link` verifies the target exists and is idempotent.
- A collection schema is optional and validates only its front matter.
- A saved view is an optional versioned query/display definition. Collections also receive automatic views without a file.
- A saved sync is an optional versioned command definition. Its mutable JSON checkpoint and advisory lock are stored separately from configuration.

## Audit protocol

Each stored line is a small JSON wrapper containing a SHA-256 hash and an exact JSON payload. The payload contains:

- format version, global sequence, UTC timestamp, actor, source, optional message, and action;
- collection and record ID;
- JSON Pointer-like field changes with distinguishable absent and `null` values;
- SHA-256 hashes of the complete record bytes before and after the mutation;
- the previous event hash, chaining events across segment files.

Create and baseline events store the complete after-state. Delete events store the complete before-state. Updates and links recursively diff objects while treating arrays and scalar values as replaceable units. Version 2 changes use explicit `add`, `remove`, and `replace` operations, so an absent value remains distinguishable from a present `null`. The reader accepts and safely converts version 1 change objects while retaining their original hashed bytes.

Verification replays these operations independently for each record. Every event's `before_hash` must equal that record's prior audited hash, every change's before-value must equal the replayed semantic state, and record presence must agree with `after_hash`. This replay makes the prior document available even after somebody directly edits or deletes its Markdown file.

Segments rotate on configurable event-count and byte-size bounds. Appending atomically rewrites only the active bounded segment; verification and history reads stream segments and never require the complete journal in memory. `audit log` reads newest segments backward until its requested limit is satisfied.

Writers acquire `.cr/audit/lock`. Before changing a record, the CLI verifies the existing chain and confirms that the record's exact bytes match its last audited hash. It then writes and flushes `.cr/audit/pending.json`, atomically changes or deletes the record, commits the event to a segment, and removes the pending file. Startup recovery handles the two possible atomic record states:

- previous hash: the mutation did not land, so intent is discarded;
- next hash: the mutation landed, so the audit event is committed.

Any third state stops recovery for manual investigation. This protocol covers one-record mutations; it is not a multi-record transaction system.

### Direct-edit reconciliation

`status` verifies and replays the audit chain without requiring current files to match it, scans the records tree, and compares exact file hashes across the union of audited and current record identities. It reports added, modified, and deleted records in deterministic order. Malformed Markdown is still visible as a changed path because status does not need to parse working files.

`save` requires selected `collection/id` references or an explicit `--all`. Under the audit lock it:

1. verifies and replays the current chain;
2. calculates the working-tree changes;
3. reconstructs the prior documents from replayed events;
4. reads, parses, and schema-validates every selected current document before appending anything;
5. rechecks each current file hash and appends a `source: filesystem` event.

The record already contains the proposed state, so this path does not use the pending mutation file: an atomic event append either accepts that hash or leaves the record dirty. An editor that races with save can cause a selected hash check to fail; if it changes a file immediately after acceptance, the next `status` reports another modification. Multiple selected records are preflighted together but committed as sequential single-record events, not as one atomic transaction.

Automatic filesystem watchers are intentionally not trusted to append events. Automatically accepting every observed change would erase the distinction between a reviewed edit and tampering. A future UI may watch only to refresh status and request approval.

Structured sync adapters are the unattended alternative. They propose typed operations over stdout; they do not receive permission from `cr` to accept arbitrary working-tree changes. A direct record write by an adapter makes the post-process verification fail and remains a normal dirty file for human review.

Reconciliation observes net record-content state, not every low-level filesystem operation. Byte-for-byte reverted edits and metadata-only changes are outside this journal; deployments that need every write attempt require operating-system audit facilities in addition to `cr`.

`audit verify` validates the chain and reconciles every latest record hash, including deleted-record absence and manually added untracked files. `audit baseline` explicitly introduces legacy records into the chain. It cannot silently baseline a record that already has history.

## Sync extension protocol

`.cr/syncs/<name>.yaml` stores format version 1, an exact command argument array, timeout, output-byte limit, message-count limit, and optional audit actor. Sync names are single path components. The configuration is intentionally data rather than executable shell text; `sh -c` or a script file must be explicit when shell interpretation is wanted.

`cr sync run` takes a nonblocking per-sync lock, then verifies that records and audit history are clean. It starts the adapter in the database root with stdin closed, stdout redirected to a bounded temporary file, stderr inherited for job logs, and a random run ID. A previous checkpoint is copied into a temporary JSON input so the adapter cannot mutate the committed cursor in place. On POSIX, the adapter receives its own process group so timeouts and output violations terminate descendants as well as the immediate child.

The `cr-jsonl-v1` stream has three internally tagged messages:

- `upsert` contains `collection`, `id`, a complete `front_matter` mapping, and complete `markdown` body;
- `delete` contains `collection` and `id`;
- an optional final `checkpoint` contains any JSON value.

The complete bounded output is parsed before application. Unknown fields, malformed JSON, unsupported paths, duplicate record targets, messages after a checkpoint, excessive output, and excessive message counts fail the run. Every upsert is schema-validated before the first mutation, and the database is verified a second time to detect direct or concurrent record edits during the external command.

Application uses the same `Database` mutation methods as the CLI and HTTP server with `source: sync` and `message: sync:<name> run:<random-id>`. A separate application lock serializes the post-process verification and application phases across different sync names. The audit head must still equal the head observed before the command started, preventing a clean concurrent CLI or API commit from being overwritten by stale adapter output. Exact upsert matches and missing deletes are counted as unchanged without creating audit noise. The checkpoint must also match its initial value and is atomically replaced only after record operations succeed. A nonzero adapter exit or any preflight failure applies neither records nor state.

This is not yet a multi-record transaction. After preflight, individual record changes use the existing one-record write-ahead audit protocol; a durable failure during the application loop can commit a prefix while leaving the checkpoint unchanged. Retrying is safe for deterministic upserts and deletes. Remote side effects occur outside the database transaction entirely and must use provider idempotency controls.

Adapters are trusted local executables, not a sandbox. They inherit the caller's environment—including secrets—and operating-system access to files, processes, network services, and external APIs. Limits constrain runtime, protocol output, and message count, but not CPU, memory, network traffic, stderr volume, or platform-specific child behavior. The scheduler and service account remain part of the deployment security boundary.

### Threat boundary

The hash chain detects modified payloads, missing or reordered middle events, segment gaps, internally inconsistent record changes, and current-record divergence. It cannot by itself prove that the final events were not removed or that an attacker with full write access did not rewrite the entire chain. `audit head` exists so the sequence and head hash can be signed, timestamped, committed, or uploaded outside the database; `audit verify --expected-head` checks such a checkpoint. Stronger deployments can later automate Ed25519-signed checkpoints or remote transparency-log anchoring without changing event files.

Actor values are assertions supplied by the process, not authenticated principals. Resolution prefers the explicit CLI override and `CR_*` environment, then Git author environment/configuration, then common email and OS-user fallbacks. Signed events or trusted operating-system identity integration would be required to authenticate them.

The journal contains historical values and deletion tombstones. Encryption, redaction rules, retention, and access control are deployment concerns and must be designed before storing regulated or highly sensitive data.

## Query and indexing strategy

Version 1 scans and parses one collection for every `list`; `search` scans either one selected collection or all collection directories in deterministic order. This keeps behavior easy to inspect and makes valid manual edits immediately visible. An index can be added later as disposable derived state keyed by file path, modification time, size, and content hash. The CLI must always be able to rebuild it from Markdown.

Filters support typed equality and dotted field paths. Search is literal and case-sensitive by default, with explicit case-insensitive and Rust-regex modes. It can target the exact Markdown document, parsed front matter, one dotted field, the body, or the database-relative path. Rust's regex engine provides linear-time matching and avoids executing shell commands or user-supplied programs.

CLI list and search results are intentionally compact: plain output contains relative Markdown paths, while JSON contains `{ path, front_matter }` objects. Record bodies remain available through `get`, avoiding unexpectedly large multi-record responses.

A future expression layer can add numeric and date comparisons, membership, boolean OR/NOT, ordering, projections, aggregation, backlinks, and pagination without changing the file format.

## HTTP transport and OpenAPI

`cr serve` is a transport over `Database`, not a subprocess adapter around the CLI binary. CLI and HTTP handlers therefore reach the same validation, locking, write-ahead audit, atomic file replacement, search, and reconciliation code. The database instance carries an audit source: command-line mutations use `cli`, REST mutations use `api`, accepted direct edits retain `filesystem`, and adapter mutations use `sync`.

Axum runs synchronous filesystem operations through its blocking worker pool so scans and durable writes do not block asynchronous socket workers. The database-wide audit lock remains the concurrency boundary. A PATCH deep-merges front matter and removes explicit dotted paths while holding that lock, so concurrent patches cannot overwrite fields merely because both began from an older HTTP read.

The REST API uses generic collection and record routes. List, search, status, and audit-log endpoints support bounded `limit`/`offset` windows. Record scans can report an exact total. Audit history intentionally reads only `offset + limit + 1` recent matching events, so its total is unknown while `has_more` remains exact; this preserves the segmented journal's bounded-read design.

The OpenAPI 3.1 document is produced on demand at `/openapi.json`. OpenAPI 3.1 uses the Draft 2020-12 JSON Schema model, allowing collection schemas to be embedded without translating them into Rust types. The document includes generic transport schemas plus one live component per `.cr/schemas/<collection>.json`; `x-cr-collection-schemas` preserves the mapping when collection names are not safe or unique component identifiers.

The server binds to loopback by default. `CR_API_TOKEN` enables bearer authentication for HTML views, the OpenAPI document, and all `/api/v1` routes; `/health` remains public. `X-CR-Actor` is an audit attribution override with the same assertion-only trust boundary as CLI actor values. The server does not implement TLS, user accounts, authorization policies, or rate limiting; network deployments must supply those controls at a trusted reverse proxy or service boundary.

## Views and server-rendered HTML

`.cr/views/<name>.yaml` stores a format version, title, target collection, typed equality filters, visible dotted columns, layout, optional Kanban grouping field, and default page size. These files contain no record data. A saved view overrides the automatic view with the same route name; otherwise each discovered collection is available at `/<collection>`. View names reserve their single-segment root routes, while `/health`, `/audit`, `/openapi.json`, and `/api` remain server-owned.

The root page, tables, search/filter controls, pagination, record forms, embedded record history, and global `/audit` timeline are rendered with Maud on the server. Dynamic schema metadata, title, front matter, ID, historical values, actor, message, and error text are HTML-escaped. Before/after previews are character-bounded in HTML while the authoritative complete events remain available through the CLI and JSON API. Tailwind's browser CDN supplies styling without a frontend build or JavaScript framework. Because the CDN is explicitly intended for development, a production/offline deployment should replace it with compiled and pinned CSS.

Record pages read the newest bounded events with the same collection/ID audit filter as `cr audit log`. The global audit route uses `offset + limit + 1` reads and unknown-total pagination, preserving the segmented journal's bounded newest-first behavior instead of loading all history into memory. It is read-only and protected by the same optional bearer middleware as every other HTML route.

View reads call the same `list` and `search` methods as the CLI and REST API. Create, update, and delete forms call `Database` directly with `source: api`; they never shell out to the CLI. The edit form replaces the complete submitted front matter and Markdown atomically, then validates and records the normal update audit event. Like any whole-document editor without `If-Match`, an old open form can overwrite a newer edit, which is covered by the existing conditional-write roadmap item.

When a collection schema exposes top-level `properties`, record forms derive typed controls from `type`, `format`, `enum`, array item enums, required fields, descriptions, length constraints, and numeric bounds. The optional non-validating `x-cr-ui.order` extension gives data models explicit field ordering; unlisted fields follow with required fields first. Submitted structured fields are decoded by the server into typed YAML; clients cannot introduce undeclared structured fields or override a declared property through the additional-attributes mapping. The complete reconstructed mapping still passes through authoritative JSON Schema validation before an atomic create or replacement. Complex declared values use a scoped YAML control, schema-permitted undeclared values use a separate advanced mapping, and collections without usable properties retain the complete raw-YAML editor. The legacy raw form payload remains accepted for compatibility, but generated pages use the structured contract.

Kanban is a presentation mode over the same saved-view query. Its lanes use the grouping field's JSON Schema `enum` order when available, so empty pipeline stages remain visible in the model's declared order; observed values not declared by the schema follow deterministically, and records without the field appear as unassigned. Cards show the view's configured columns. A move POST sets the grouping field—or removes it for the unassigned lane—through the normal `Database::update` or `Database::patch` path, preserving validation, atomic replacement, actor/source attribution, and field-level audit diffs. Native forms provide the accessible interaction; a small same-origin JavaScript enhancement translates drag-and-drop into the same CSRF-protected form POST. Boards group only the bounded current result page and retain normal pagination.

Mutating forms include a cryptographically random token generated when the server starts. Same-origin protections keep another website from reading it, and every form POST verifies it before touching the database. Successful writes return `303 See Other` to a view `GET`, preventing refresh from replaying the mutation. Validation errors return escaped HTML and do not change the record or audit head.

`CR_API_TOKEN` protects view routes with the same bearer middleware as REST and OpenAPI. It does not create cookies or a browser login, so direct browser navigation is most useful for the default loopback-only configuration; authenticated browser deployments currently need a trusted proxy capable of adding the header. The HTML routes are deliberately not part of the machine-facing OpenAPI contract.

## Integrity boundaries

- Collection names and IDs are single path components, preventing path traversal.
- Markdown record paths must be regular files. Single-record CRUD, status, save, and audit verification reject symlinks and other special file types rather than trusting them by content hash; ordinary collection listings continue to ignore non-file entries.
- Creation never overwrites an existing record.
- Updates and links validate the complete next front matter before atomically replacing a file and committing its audit event.
- Links validate that their target exists and matches its latest audited content hash. Manual deletion can still produce a dangling reference after the link is created; a future `cr check` command should scan links and delete policies.
- A database-wide filesystem lock serializes audited mutations, and a pending-operation journal recovers single-record crash windows. There are no multi-record transactions.
- Per-sync filesystem locks reject overlapping runs of one adapter. Different syncs may fetch concurrently, but a separate application lock plus the initial audit-head comparison rejects stale output if another sync or ordinary mutation committed first. The audit lock still serializes individual record mutations during a run.
- YAML comments and hand-chosen front matter formatting are not preserved after a CLI mutation; the Markdown body is preserved exactly. A syntax-preserving YAML editor could replace serialization later without changing the command model.

## Roadmap

[`TODO.md`](../TODO.md) is the canonical roadmap and technical-debt register. It includes query expressions, projections, relationship traversal, indexes, schema migrations, HTTP hardening, audit improvements, and test work. Keeping the roadmap in one file avoids drift between implementation documentation and future plans.
