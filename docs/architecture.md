# Architecture

## Research conclusions

YAML front matter is a well-established convention: a metadata mapping appears first in a Markdown file between `---` delimiters, and custom fields can contain typed values such as strings, booleans, numbers, arrays, and maps. Jekyll documents the delimiter and custom-variable convention, while Hugo explicitly describes front matter as metadata that can establish relationships with other content.

Markdown data tools suggest two distinct layers. Dataview treats files as the durable source and builds a queryable metadata index over them. Front Matter CMS adds optional content types and field constraints. `cr` follows the same separation: correctness cannot depend on an index, and stronger modeling is opt-in.

JSON Schema is the optional constraint language because it can describe arbitrary object shapes without coupling models to Rust types. The Rust `jsonschema` validator supports Draft 2020-12 and reusable validators. YAML values are converted to their JSON representation before validation.

Updates use a temporary file in the target directory, flush it, and persist it over the destination. Keeping the temporary file beside the record avoids cross-filesystem rename behavior and ensures readers see either the previous complete file or the next complete file.

For audit integrity, OWASP recommends a chronological, independently verifiable trail with enough context to reconstruct transactions and built-in tamper detection. Signed Syslog similarly calls for message integrity, sequencing, replay resistance, and missing-message detection. Certificate Transparency demonstrates how hashes and externally observed heads make append-only violations detectable. `cr` uses a simpler linear SHA-256 chain because local history is read sequentially; an externally stored head hash provides the independent observation point.

The mutation protocol follows write-ahead logging principles: durable intent precedes the record change, and recovery determines whether to commit or discard that intent by hashing the resulting record. Rust's standard file locks serialize writers across processes. The audit payload's exact stored JSON bytes are the hash input, so verification does not depend on parsing and reserializing arbitrary YAML-derived values.

Git's working-tree model separates detecting differences from explicitly selecting changes to record. `cr` applies the same boundary without adopting Git as a storage dependency: the audit journal is the recorded state, Markdown files are the working tree, `status` compares them, and `save` accepts reviewed paths. Git's author environment variables and repository `user.email` configuration also provide a familiar identity fallback.

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
│   └── schemas/
│       └── candidates.json
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

Reconciliation observes net record-content state, not every low-level filesystem operation. Byte-for-byte reverted edits and metadata-only changes are outside this journal; deployments that need every write attempt require operating-system audit facilities in addition to `cr`.

`audit verify` validates the chain and reconciles every latest record hash, including deleted-record absence and manually added untracked files. `audit baseline` explicitly introduces legacy records into the chain. It cannot silently baseline a record that already has history.

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

`cr serve` is a transport over `Database`, not a subprocess adapter around the CLI binary. CLI and HTTP handlers therefore reach the same validation, locking, write-ahead audit, atomic file replacement, search, and reconciliation code. The database instance carries an audit source: command-line mutations use `cli`, REST mutations use `api`, and accepted direct edits retain `filesystem`.

Axum runs synchronous filesystem operations through its blocking worker pool so scans and durable writes do not block asynchronous socket workers. The database-wide audit lock remains the concurrency boundary. A PATCH deep-merges front matter and removes explicit dotted paths while holding that lock, so concurrent patches cannot overwrite fields merely because both began from an older HTTP read.

The REST API uses generic collection and record routes. List, search, status, and audit-log endpoints support bounded `limit`/`offset` windows. Record scans can report an exact total. Audit history intentionally reads only `offset + limit + 1` recent matching events, so its total is unknown while `has_more` remains exact; this preserves the segmented journal's bounded-read design.

The OpenAPI 3.1 document is produced on demand at `/openapi.json`. OpenAPI 3.1 uses the Draft 2020-12 JSON Schema model, allowing collection schemas to be embedded without translating them into Rust types. The document includes generic transport schemas plus one live component per `.cr/schemas/<collection>.json`; `x-cr-collection-schemas` preserves the mapping when collection names are not safe or unique component identifiers.

The server binds to loopback by default. `CR_API_TOKEN` enables bearer authentication for the OpenAPI document and all `/api/v1` routes; `/health` remains public. `X-CR-Actor` is an audit attribution override with the same assertion-only trust boundary as CLI actor values. The server does not implement TLS, user accounts, authorization policies, or rate limiting; network deployments must supply those controls at a trusted reverse proxy or service boundary.

## Integrity boundaries

- Collection names and IDs are single path components, preventing path traversal.
- Markdown record paths must be regular files. Single-record CRUD, status, save, and audit verification reject symlinks and other special file types rather than trusting them by content hash; ordinary collection listings continue to ignore non-file entries.
- Creation never overwrites an existing record.
- Updates and links validate the complete next front matter before atomically replacing a file and committing its audit event.
- Links validate that their target exists and matches its latest audited content hash. Manual deletion can still produce a dangling reference after the link is created; a future `cr check` command should scan links and delete policies.
- A database-wide filesystem lock serializes audited mutations, and a pending-operation journal recovers single-record crash windows. There are no multi-record transactions.
- YAML comments and hand-chosen front matter formatting are not preserved after a CLI mutation; the Markdown body is preserved exactly. A syntax-preserving YAML editor could replace serialization later without changing the command model.

## Roadmap

[`TODO.md`](../TODO.md) is the canonical roadmap and technical-debt register. It includes query expressions, projections, relationship traversal, indexes, schema migrations, HTTP hardening, audit improvements, and test work. Keeping the roadmap in one file avoids drift between implementation documentation and future plans.
