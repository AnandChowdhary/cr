# TODO

This is the canonical backlog for `cr`. It records both desired capabilities and shortcuts or technical debt in the current implementation.

## Maintenance rule

- Update this file in the same commit that completes, changes, or supersedes an item.
- Add newly discovered shortcuts here instead of leaving them only in code comments or conversation history.
- Check an item only when its acceptance notes are satisfied and covered by appropriate tests.
- Keep `README.md` focused on current behavior and `docs/architecture.md` focused on design. Future work belongs here.

Priorities:

- **P0** — correctness or security boundary;
- **P1** — important product capability;
- **P2** — scalability, operations, or maintainability;
- **P3** — useful polish.

## Current shortcuts and technical debt

- [ ] **P0 — Replace string-based HTTP error classification with typed domain errors.**
  `server.rs` currently maps `anyhow` messages to HTTP status codes using text matching. Introduce stable error variants shared by CLI and HTTP, preserve error chains for logs, and test every public status/code mapping.

- [ ] **P0 — Redact internal error details in HTTP 500 responses.**
  Unexpected errors can currently expose filesystem paths and internal context. Return a request ID and safe public message while retaining complete diagnostics in server logs.

- [ ] **P0 — Harden every parent path against symlink escapes.**
  Final record files and explicitly listed collection directories are checked, but a replaced `data_dir` or an intermediate configured directory could still be a symlink. Resolve or open path components safely beneath the database root for every read and mutation.

- [ ] **P0 — Add authenticated actor identity for stronger audit attribution.**
  CLI actors, `X-CR-Actor`, and bearer tokens are assertions, not authenticated people. Define a trusted identity integration or signed-request mode and distinguish authenticated principals from display attribution in audit events.

- [ ] **P1 — Generate OpenAPI route metadata from the router contract.**
  HTTP routes and the static portion of `openapi_paths()` are maintained separately. Adopt route metadata or a derive/build-time mechanism that makes drift impossible, then validate the generated document with an independent OpenAPI validator.

- [ ] **P1 — Express collection-specific request and response schemas without a vendor extension.**
  Live collection schemas are embedded correctly, but generic `{collection}` routes use an open front matter schema and `x-cr-collection-schemas` supplies the exact mapping. Evaluate generated literal collection paths, discriminators, or another interoperable OpenAPI representation.

- [ ] **P1 — Add conditional writes and optimistic concurrency.**
  Database locking prevents torn writes and atomic PATCH avoids stale read/merge races, but HTTP has no `ETag`/`If-Match` contract and CLI has no expected-record-hash option. Reject stale whole-body replacements explicitly.

- [ ] **P1 — Replace offset-heavy scans with cursors where needed.**
  List and search calculate exact totals by scanning all matching records. Audit pagination reads `offset + limit + 1` matching events. Add stable cursors that do not become progressively more expensive.

- [ ] **P2 — Avoid reparsing and rescanning unchanged files.**
  Every list and search reads current Markdown directly for correctness. Add a disposable, rebuildable index keyed by path, size, modification time, and content hash; never make the index the source of truth.

- [ ] **P2 — Define PATCH semantics for arrays and whole-object replacement.**
  Object patches deep-merge and array values replace the complete array. Add explicit operations if element-level array changes or forced object replacement are needed, while keeping JSON `null` distinct from deletion.

- [ ] **P2 — Define behavior for YAML that cannot be represented in JSON.**
  The file parser can accept YAML mappings with non-string keys, while JSON API responses cannot. Either constrain front matter to JSON-compatible YAML everywhere or provide a documented alternate representation.

- [ ] **P2 — Make health checks reflect database readiness.**
  `/health` currently proves that the HTTP process is running. Add a separate readiness check that verifies the database root, configuration, audit recovery state, and optionally the latest chain head without performing a full expensive verification.

- [ ] **P2 — Handle service shutdown signals consistently.**
  Graceful shutdown currently waits for Ctrl-C. Add Unix `SIGTERM` handling, document shutdown behavior, and test that in-flight mutations either complete safely or recover on restart.

- [ ] **P2 — Add structured server observability.**
  Add request IDs, structured access logs, latency/error metrics, and safe audit-operation fields without logging bearer tokens or sensitive record contents.

- [ ] **P3 — Add opt-in CORS configuration.**
  The API intentionally sends no permissive CORS headers. Add an explicit origin allowlist for browser clients without weakening the local-only default.

- [ ] **P1 — Add browser sessions for token-protected views.**
  `CR_API_TOKEN` protects HTML routes with a bearer header, which ordinary address-bar navigation and native forms cannot attach. Add an explicit login/session design with secure cookie rotation, logout, CSRF binding, expiry, and brute-force controls, or document a supported identity-aware proxy contract.

- [ ] **P1 — Replace Tailwind Play CDN with compiled, pinned CSS.**
  The server-rendered UI currently follows the requested CDN-only setup, but Tailwind documents the Play CDN as development-only. Bundle a reproducible stylesheet for production, offline use, tighter content security policy, and immunity to CDN changes.

- [ ] **P2 — Add configuration history for schemas, views, and syncs.**
  View definitions, collection schemas, sync definitions, and mutable sync checkpoints are Git-friendly files but are not record audit events. Define configuration and operational-state history without confusing either with record history or exposing adapter secrets.

- [ ] **P1 — Add sync sandboxing and complete resource controls.**
  Sync adapters are trusted local executables that inherit the caller's environment, filesystem, and network access. Add opt-in environment allowlists, stderr bounds, CPU/memory/process limits, and a defensible sandbox profile. POSIX timeouts terminate the adapter process group; define and test equivalent descendant termination on Windows.

- [ ] **P2 — Add scheduler helpers and durable run history.**
  Version 1 delegates recurrence and job logs to cron, systemd, `launchd`, containers, or CI. Add optional platform-specific schedule install/remove/status helpers and a bounded run ledger with start/end time, exit result, counts, checkpoint hash, and safe diagnostics—without turning `cr serve` into an implicit scheduler.

- [ ] **P2 — Stream large sync output through bounded preflight storage.**
  Sync stdout is bounded on disk but then read and parsed into memory before application. Preserve all-before-first-mutation validation while supporting larger imports through a validated spool/index or another bounded two-pass design.

- [ ] **P2 — Preserve submitted form values on validation errors.**
  HTML mutations correctly remain atomic and audit-neutral on failure, but the generic error page requires navigating back and may lose unsaved browser input. Re-render the form with escaped submitted values and field-level schema diagnostics.

- [ ] **P2 — Define large-board Kanban loading and ordering.**
  Kanban lanes group the current bounded result page so the server never loads an unbounded collection. Define cursor-based incremental loading or an explicit board-size policy for pipelines larger than the configured page limit, plus optional card sorting within lanes.

## Query and result capabilities

- [x] **P1 — Comparison expressions.**
  Support typed numeric, string, and date comparisons such as `value > 10000`, `score >= 80`, and `expected_close < 2027-12-31`.

- [ ] **P1 — Boolean expressions.**
  Add an expression grammar with `AND`, `OR`, `NOT`, parentheses, clear precedence, useful parse errors, and identical CLI/HTTP semantics.

- [ ] **P1 — Membership, containment, and existence operators.**
  Support `in`, `not in`, array/string `contains`, field existence, and explicit distinctions among missing, `null`, empty string, and empty collection.

- [ ] **P1 — Sorting.**
  Single-field sorting now works across CLI, REST, and HTML for dotted fields, path, collection, or ID with stable missing-value and mixed-type rules before pagination. Add ordered multi-field keys and define a URL/CLI syntax that preserves deterministic ties.

- [ ] **P1 — Field projections.**
  Add `--select` and an HTTP equivalent so callers can request only selected front matter fields, identity/path fields, or optionally Markdown.

- [ ] **P1 — Counts and aggregation.**
  Add count, distinct values, grouping, and basic numeric aggregation without requiring record bodies in the response.

- [ ] **P2 — Additional streaming output formats.**
  Add JSON Lines and CSV where the projection is tabular. Large results should stream rather than building the complete response in memory.

- [x] **P2 — Saved and reusable filtered queries.**
  Versioned `.cr/views/*.yaml` definitions provide named collection queries, typed equality filters, shared comparison/containment/empty expressions, dotted columns, default ordering, and page sizes to CLI discovery and server-rendered routes.

- [ ] **P2 — Query planner and disposable indexes.**
  Use equality/range indexes when available, fall back to authoritative Markdown scans, and include explain/debug output for performance work.

## Relationships

- [ ] **P1 — Add `unlink` and its REST equivalent.**
  Removal must be idempotent, schema-validated, atomic, and represented clearly in the audit diff.

- [ ] **P1 — Backlink queries.**
  Find every record that references a given `collection/id`, with filtering and pagination.

- [ ] **P1 — Relationship traversal and expansion.**
  Traverse named relations with explicit depth limits, cycle detection, missing-target reporting, projections, and compact versus expanded output.

- [ ] **P1 — Whole-database integrity checks.**
  Add `cr check` and an HTTP endpoint for dangling links, malformed relation values, schema failures, invalid record names, and audit reconciliation problems.

- [ ] **P1 — Delete policies.**
  Support configurable restrict, cascade, nullify, and allow-dangling behavior. Multi-record policies require a transaction design before implementation.

- [ ] **P2 — Relationship constraints in models.**
  Declare permitted target collections, required cardinality, uniqueness, and inverse relation expectations.

## Data modeling and file workflows

- [ ] **P1 — Add CLI field removal for parity with HTTP PATCH.**
  Provide `cr update --unset dotted.field` using the same atomic mutation path and audit semantics as REST `remove`.

- [ ] **P1 — First-class collection and schema commands.**
  List models, inspect schemas, validate proposed schema changes, and create/update schemas without manually editing `.cr/schemas`.

- [ ] **P1 — Schema migrations.**
  Plan, preview, apply, and audit versioned record migrations with safe restart behavior and explicit handling of partial failures.

- [ ] **P2 — Defaults, computed fields, and lifecycle hooks.**
  Define which values are stored versus derived, when hooks run, and how deterministic results are audited.

- [ ] **P2 — Uniqueness and secondary indexes.**
  Enforce unique fields such as email or external ID without making a derived index the only durable evidence.

- [ ] **P2 — Record and collection rename support.**
  Update inbound relations safely, represent renames in audit history, and recover interrupted multi-file operations.

- [ ] **P2 — Preserve YAML comments and deliberate formatting.**
  CLI/API metadata mutations currently reserialize front matter. Evaluate a syntax-preserving YAML editor while retaining semantic validation and deterministic audit diffs.

- [ ] **P2 — Watch mode for status refresh.**
  Detect external edits and refresh status or subscribed clients, but never auto-accept changes into the audit journal.

- [ ] **P3 — Status ignore patterns and rename detection.**
  Add reviewed ignore rules for editor artifacts and distinguish a likely rename from independent delete/create operations.

## HTTP and integrations

- [ ] **P1 — Bulk mutation endpoints and multi-record transactions.**
  Define atomicity, validation, audit grouping, crash recovery, maximum batch sizes, and partial-failure behavior before exposing bulk create/update/delete. Sync runs currently preflight their complete bounded stream but commit sequential single-record mutations, so a durable application failure can leave a committed prefix and unchanged checkpoint.

- [ ] **P1 — Define sync ownership, pruning, and remote-effect idempotency.**
  Version 1 only deletes records when an adapter emits an explicit target. Add optional source ownership metadata and safe prune previews without treating absence from a partial page as deletion. Define retry/idempotency guidance or primitives for adapters that also perform irreversible remote effects.

- [ ] **P1 — Idempotency keys for retried mutations.**
  Safely replay POST/PATCH requests after client timeouts without duplicating audit events.

- [ ] **P1 — Authorization policies.**
  Add collection-, operation-, and possibly field-level permissions independently from actor attribution and bearer-token authentication.

- [ ] **P2 — Schema management API.**
  Expose model discovery and controlled schema changes with validation and appropriate audit or configuration history.

- [ ] **P2 — OpenAPI export and documentation UI.**
  Add a command that writes a deterministic `openapi.json` file and optionally serve a bundled documentation UI without external CDNs.

- [ ] **P2 — Generated client compatibility tests.**
  Generate at least one typed client from OpenAPI and run CRUD/query/audit contract tests against a real server.

- [ ] **P2 — Event subscriptions.**
  Consider Server-Sent Events or webhooks for committed audit events with replay cursors, delivery authentication, and backpressure.

## Audit, security, and operations

- [ ] **P1 — Signed or remotely anchored audit checkpoints.**
  Automate Ed25519 signing, trusted timestamping, or remote transparency-log publication and verification.

- [ ] **P1 — Audit retention, redaction, and encryption policy.**
  Define how regulated or deleted personal data is protected while preserving useful integrity guarantees.

- [ ] **P2 — Backup and restore commands.**
  Capture records, configuration, schemas, audit segments, and external checkpoint metadata; verify a restored database before activation.

- [ ] **P2 — Repair and recovery tooling.**
  Add read-only diagnosis and explicit repair flows for interrupted operations, corrupted active segments, and record/audit divergence. Never silently rewrite evidence.

- [ ] **P2 — Operating-system audit integration guidance.**
  Document and optionally integrate controls for deployments that must observe every write attempt rather than only accepted net file state.

## Test and quality backlog

- [ ] **P1 — Property and fuzz tests.**
  Fuzz front matter parsing/rendering, field paths, query expressions, audit replay, HTTP request decoding, and generated OpenAPI documents.

- [ ] **P1 — Crash/fault injection.**
  Exercise failures at every durable-write boundary, including server termination during mutation, segment rotation, direct-edit save, and future multi-record work.

- [ ] **P2 — Larger scale and performance baselines.**
  Measure list, search, audit pagination, startup, and OpenAPI generation across realistic record counts and body sizes before designing indexes.

- [ ] **P2 — Independent OpenAPI validation.**
  Validate the complete generated document, not only local `$ref` resolution, and test schema changes that use `$id`, local references, and supported external references.

- [ ] **P2 — Cross-platform filesystem coverage.**
  Run Windows and Linux CI in addition to macOS-oriented development, including locks, atomic replacement, permissions, Unicode, and symlink/junction behavior.

- [ ] **P2 — HTTP security regression tests.**
  Cover header smuggling boundaries, oversized/slow bodies, path encoding, token handling, accidental secret logging, and denial-of-service limits.

## Completed foundations

- [x] Arbitrary Markdown/YAML collections and records with typed front matter.
- [x] Audited create, read, update, link, and delete operations.
- [x] Optional per-collection Draft 2020-12 JSON Schema validation.
- [x] Tamper-evident segmented audit journal with recovery and external head verification.
- [x] First-class direct Markdown edits through `status` and reviewed `save`.
- [x] Typed equality filters, dotted field paths, and compact list results.
- [x] Literal/regex search across paths, front matter, fields, bodies, and collections.
- [x] REST API covering current database, search, direct-edit, relation, and audit operations.
- [x] Bounded HTTP pagination, bearer-token option, request actor attribution, and structured errors.
- [x] Live OpenAPI 3.1 collection-schema components.
- [x] Automatic collection tables and saved server-rendered HTML views with CSRF-protected audited forms.
- [x] Per-record and global server-rendered audit history with filtering, pagination, attribution, and expandable field diffs.
- [x] Saved Kanban views with schema-ordered lanes, drag-and-drop plus accessible move forms, schema validation, CSRF protection, and normal audit events.
- [x] Schema-driven create and edit forms with typed scalar controls, enum and multi-enum selection, complex-value YAML fallback, additional attributes, and escaped schema metadata.
- [x] Schema-aware multi-condition filter builder with typed comparison, containment, and empty-value operators; constrained controls; AND/OR composition; saved-view scoping; URL persistence; bounded decoding; and progressive row management.
- [x] Shared single-field sorting across CLI, REST, OpenAPI, tables, and Kanban with accessible table-header toggles, typed YAML ordering, missing-last rules, deterministic ties, and pre-pagination application.
- [x] Persisted saved-view default ordering with CLI/YAML configuration, legacy defaults, URL overrides, explicit clearing, and Kanban lane application.
- [x] Persisted typed saved-view expressions with CLI/YAML configuration, immutable AND scoping, legacy defaults, and visible query chips.
- [x] In-page Save as view with CSRF protection, atomic no-clobber creation, preserved all/any filter groups, inherited immutable scopes, effective sorting, redirects, and conflict/error coverage.
- [x] URL-persisted visible-column selection for tables and Kanban cards, including pagination/sort preservation, validation, and Save as view persistence.
- [x] Browser-created Kanban views with layout selection, schema/data-derived grouping fields, inherited pipeline settings, and server-side validation.
- [x] Compact view header with always-available search and an on-demand filter, column, and sorting panel with active-condition count.
- [x] Optional `.cr/config.yaml` overrides with `.cr/` discovery and safe built-in storage/audit defaults.
- [x] Versioned subprocess sync adapters with JSONL upsert/delete/checkpoint messages, clean-state verification, limits, overlap locks, checkpointing, and `source: sync` audit provenance.
- [x] Unit, CLI, concurrency, direct-edit, in-process HTTP, and real TCP server tests.
