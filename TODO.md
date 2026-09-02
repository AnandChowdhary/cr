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

- [x] **P0 — Replace string-based HTTP error classification with typed domain errors.**
  A shared `DomainError` classification travels inside the `anyhow` chain, so the CLI still prints complete chains while `server.rs` selects each status and code by typed downcast instead of message text. Every public status/code mapping is covered by unit and HTTP tests.

- [x] **P0 — Redact internal error details in HTTP responses.**
  Every request carries a correlation ID returned as `X-Request-Id` and in the error envelope. Unexpected failures return a fixed generic message; expected client errors keep actionable wording that names records, views, and fields rather than filesystem paths or operating-system errors. JSON and HTML responses share the rules, and the complete chain reaches the server log under the request ID.

- [x] **P0 — Close production identity workflow gaps.**
  Owner delegation is first-class in the CLI and the local server, records both the effective principal and operator, and verifies the audited operator before revealing or trusting the target policy. The reserved user schema now has an open application-owned `profile` namespace while CR keeps identity, status, kind, and grants validated; bootstrap supports service owners; user definitions have atomic ensure/update and exact audited restore operations; global audit history is permission-filtered before its limit and always includes a principal's own policy history; blank agent session/turn values mean absence; audit attribution filters have unambiguous `--by-*` names with compatibility aliases; and `--json-errors` gives daemons stable error envelopes. Domain and CLI tests cover the boundaries, including concurrent ensure and direct-edit recovery.

- [x] **P0 — Harden every parent path against symlink escapes.**
  Every database-relative path is walked component by component from a descriptor for the resolved root, with `openat` and `O_NOFOLLOW`, and the target is opened, replaced, linked, renamed, or unlinked through its verified parent's descriptor. That covers `data_dir` and its intermediate directories, collection directories, record files, `.cr/`, and the audit, schema, view, and sync trees, on reads as well as mutations. Refusals are classified `DomainError::Conflict` and name the record, collection, or view rather than a path. `tests/symlink_escape.rs` constructs each escape and asserts nothing outside the root is read or written; nine of its eleven tests fail against the previous implementation, two of them by disclosing file contents from outside the database.

- [ ] **P0 — Add authenticated actor identity for stronger audit attribution.**
  CLI actors, `X-CR-Actor`, and bearer tokens are assertions, not authenticated people. Define a trusted identity integration or signed-request mode and distinguish authenticated principals from display attribution in audit events.
  Partially addressed and deliberately left open. Optional `agent`, `authorization`, and `intent` objects make delegated attribution expressible, and RBAC now normalizes the local actor to a stable principal, rejects a different `--actor` once access is enabled, evaluates that principal's fixed-schema `users` record, and stores the effective principal and policy hash in each allowed mutation's `access` object. That closes identity *consistency* inside one CLI process, not authentication: the process still controls `CR_ACTOR` and the backing files. `cr serve` now offers a loopback-only owner perspective console whose cookie selects an explicitly impersonated user; this is an administrative policy preview, and records the operator as `access.impersonated_by`, but deliberately is not a login system. The remaining work is a managed boundary: bind tokens, operating-system peer credentials, or signed requests to principals while the daemon owns the database directory, then make the CLI a client of that boundary.

- [x] **P1 — Verify a previewed change set against what was applied.**
  `--preview` on `create`, `update`, `link`, `delete`, and `save`, and `preview=true` on the equivalent REST routes, compute a change set and its digest without writing a record, an audit event, or a pending mutation, and without holding the audit lock afterwards. `--approved-changes sha256:…` and `X-CR-Approved-Changes` record the digest in `authorization.approved_changes` and bind the write to it: `cr` recomputes the digest from the change set it is about to record and refuses the mutation on a mismatch, and `audit verify` recomputes it from the stored `changes` and fails with `DomainError::ApprovalMismatch` / `409 approval_mismatch`, distinct from every other conflict so an auditor can tell an unapproved change from a corrupt chain. The canonical form is the exact byte range `changes` occupies inside the serialized payload, read with `RawValue`, so preview, apply, and verify share one definition and none of them depends on reserializing parsed values. `tests/fixtures/mismatched-approval` is a committed journal whose chain verifies and whose approval does not.
  Honest scope, because the field name invites more than it delivers: the digest commits to the change set and to nothing else — not to the rest of the event, not to the record's untouched fields, and not to a human having seen the preview, which an agent can assert by computing the digest itself. Its value to an auditor is as something to compare against an approval recorded elsewhere. The `before_hash` guard does *not* combine with it to give "the human approved exactly this": a competing `cr update` moves the record and the audited state together and passes that guard, and it is the digest, not `before_hash`, that notices. Approving a multi-record `save` is refused rather than checked against one of several change sets; that needs a per-record mapping and waits on the bulk-mutation entry above.

- [x] **P2 — Make attribution enum growth safe.**
  `AgentEvidence`, `AuthorizationMode`, and `IntentAuthor` each carry an `Other(String)` variant that preserves an unrecognized label verbatim and serializes it back unchanged, so an event naming a value a later `cr` invented still verifies here under its stored hash, byte for byte. Reading is permissive and writing is strict: every caller-supplied value is checked against the labels the build knows, so `Other` is reachable from stored bytes and from nothing else and `cr` never records an approval mode it cannot interpret. `tests/fixtures/future-journal` is a committed chain naming `attestation`, `escalated`, and `operator`; before this change `audit verify` refused the whole journal on it, including the events carrying no attribution at all.
  `AuditAction` and `AuditSource` are deliberately left closed. They are core payload semantics rather than metadata, and the v1 to v2 bump exists precisely because changing what `changes` means has to make an unprepared reader stop. If `AuditSource` ever needs a value that is not a channel change, revisit that judgment rather than adding one quietly.

- [ ] **P3 — Populate attribution from agent harnesses instead of flags.**
  Agent, authorization, and intent are currently supplied by flags, `CR_*` variables, or `X-CR-*` headers, so an agent has to remember to pass them and the model self-reports its own grant. A Claude Code `PreToolUse` hook receives `session_id`, `prompt_id`, and `permission_mode` on stdin and could export `CR_AGENT` and `CR_AUTHORIZATION` without the model's involvement, which is a materially better source for exactly the two fields environment probing cannot reach. Separately, document a Git convention — human as author, agent as committer, `Co-authored-by:`, and a `Cr-Audit-Head:` trailer — so the commit history stops having the same defect the journal just lost.

- [ ] **P1 — Generate OpenAPI route metadata from the router contract.**
  HTTP routes and the static portion of `openapi_paths()` are maintained separately. Adopt route metadata or a derive/build-time mechanism that makes drift impossible, then validate the generated document with an independent OpenAPI validator.

- [ ] **P1 — Express collection-specific request and response schemas without a vendor extension.**
  Live collection schemas are embedded correctly, but generic `{collection}` routes use an open front matter schema and `x-cr-collection-schemas` supplies the exact mapping. Evaluate generated literal collection paths, discriminators, or another interoperable OpenAPI representation.

- [x] **P1 — Add conditional writes and optimistic concurrency.**
  The version of a record is `sha256:` plus SHA-256 over `b"cr:record:v1\0" || exact_stored_markdown_bytes`; retaining that domain prefix preserves the hashes already stored in audit history. Domain and JSON records expose it; REST single-record and exact-document reads return the quoted form as a strong `ETag`. `If-Match` is optional for atomic `PATCH`, delete, and link mutations, while whole-document `PUT` requires it (`428 precondition_required` when absent); stale or weak validators fail as typed `412 precondition_failed` responses. Server-rendered edit and delete forms carry the version automatically. CLI `update`, `link`, and `delete` accept `--expected-record-hash`, and `cr get --json` supplies the value. Every comparison occurs after acquiring the audit lock and before preparing or committing the audit event, so a failed condition writes neither record nor history and cannot race the mutation. Sync captures every target version under that lock at the pre-application audit head, persists the snapshot for recovery, and combines conditional target writes with an audit-sequence precondition advanced by its own events. That extra generation guard rejects intervening writers even when an edit restores byte-identical contents; recovery captures history under the same lock, trusts only source-marked run events whose action and resulting hash match the stream, and reconstructs the target snapshot for legacy version-1 ledgers from their recorded audit prefix. Preview and approved-change digests remain orthogonal: a conditional preview checks the version, and an approved apply still verifies its canonical change set.

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
  Request IDs and a structured error log line now exist. Add structured access logs for successful requests, latency/error metrics, a real logging framework with levels instead of `eprintln!`, and safe audit-operation fields without logging bearer tokens or sensitive record contents.

- [ ] **P2 — Close the two remaining check-then-use windows in path resolution.**
  Directory listings are read from the resolved path rather than the verified descriptor, and the sync working directory is verified before adapter output is staged in it with `tempfile`. Neither is exploitable by a planted link—every listed name is reopened through the safe walk before it is read—but both are races rather than descriptor-relative operations. Use `fdopendir` for listings and stage sync output through the verified descriptor. The non-Unix fallback checks components with `symlink_metadata` and has no descriptor guarantee at all; decide whether Windows is supported before relying on it.

- [ ] **P3 — Add opt-in CORS configuration.**
  The API intentionally sends no permissive CORS headers. Add an explicit origin allowlist for browser clients without weakening the local-only default.

- [ ] **P1 — Add browser sessions for token-protected views.**
  `CR_API_TOKEN` protects HTML routes with a bearer header, which ordinary address-bar navigation and native forms cannot attach. Add an explicit login/session design with secure cookie rotation, logout, CSRF binding, expiry, and brute-force controls, or document a supported identity-aware proxy contract.

- [ ] **P1 — Replace Tailwind Play CDN with compiled, pinned CSS.**
  The server-rendered UI currently follows the requested CDN-only setup, but Tailwind documents the Play CDN as development-only. Bundle a reproducible stylesheet for production, offline use, tighter content security policy, and immunity to CDN changes.

- [ ] **P2 — Add configuration history for schemas, views, and syncs.**
  View definitions, collection schemas, sync definitions, and mutable sync checkpoints are Git-friendly files but are not record audit events. Define configuration and operational-state history without confusing either with record history or exposing adapter secrets.

- [ ] **P1 — Add sync sandboxing and complete resource controls.**
  Sync adapters are trusted local executables that inherit the caller's environment, filesystem, and network access. A relative sync program is still resolved with `canonicalize` under the root, so a linked program can point outside it; that is consistent with allowing absolute programs, but a sandbox design should decide it explicitly. Add opt-in environment allowlists, stderr bounds, CPU/memory/process limits, and a defensible sandbox profile. POSIX timeouts terminate the adapter process group; define and test equivalent descendant termination on Windows.

- [ ] **P2 — Add scheduler helpers and durable run history.**
  Version 1 delegates recurrence and job logs to cron, systemd, `launchd`, containers, or CI. Add optional platform-specific schedule install/remove/status helpers and a bounded run ledger with start/end time, exit result, counts, checkpoint hash, and safe diagnostics—without turning `cr serve` into an implicit scheduler.

- [ ] **P2 — Stream large sync output through bounded preflight storage.**
  Sync stdout is bounded on disk but then read and parsed into memory before application. Preserve all-before-first-mutation validation while supporting larger imports through a validated spool/index or another bounded two-pass design.

- [ ] **P2 — Preserve submitted form values on validation errors.**
  HTML mutations correctly remain atomic and audit-neutral on failure, but the generic error page requires navigating back and may lose unsaved browser input. Re-render the form with escaped submitted values and field-level schema diagnostics.

- [ ] **P2 — Define large-board Kanban loading and ordering.**
  Kanban lanes group the current bounded result page so the server never loads an unbounded collection. Define cursor-based incremental loading or an explicit board-size policy for pipelines larger than the configured page limit, plus optional card sorting within lanes.

- [ ] **P1 — Classify the remaining CLI-only failures.**
  `sync.rs`, `Database::init`, and `Database::discover` still return unclassified failures because only the CLI reaches them. They would surface as `500`/`internal_error` if a future route exposed them; give them typed classifications when that happens or as a routine cleanup.

- [ ] **P2 — Enforce response redaction structurally rather than by construction.**
  Safe public messages are guaranteed by writing them at the failure site and covered by tests that reject the database root and operating-system text. Nothing in the type system prevents a future caller from putting a path into `ApiError::message`. Consider a newtype for public messages, or a final scrub against the database root before a response is written.

- [ ] **P3 — Reach or remove the unreachable `invalid_location` error.**
  `see_other` and the create-record `Location` header return `400`/`invalid_location` when a header value cannot be built. Percent-encoding makes that unreachable today, so the mapping has no test. Either construct the header infallibly or find a case that exercises it.

- [x] **P2 — Move the crate to edition 2024.**
  `edition = "2024"`, with `rust-version` left at 1.89: edition 2024 needs 1.85 and the let-chains it enables need 1.88, so neither sets the floor. `cargo fix --edition` found nothing to change, and neither did any migration lint named individually (`if_let_rescope`, `tail_expr_drop_order`, `impl_trait_overcaptures`, `static_mut_refs`, `unsafe_attr_outside_unsafe`, `missing_unsafe_on_extern`, `keyword_idents_2024`, `rust_2024_prelude_collisions`, and the rest of `rust_2024_compatibility`), across lib, binary, and every integration test. The tree had nothing for them to catch: no `unsafe fn`, no `extern` block, no `static mut`, no `gen` identifier, no `macro_rules!` taking an `expr` fragment, and the one RPIT signature (`database::update_with`) already writes the `+ 'a` bound that edition 2024 would otherwise change the meaning of.
  The two silent traps do not apply either. Every audit and sync lock is a named `File` local (`let _lock = audit.lock()?`), never a temporary in an `if let` scrutinee, so `if let` rescoping cannot shorten one; and no tail expression builds a temporary with a significant `Drop` beside such a local, so tail-expression drop order cannot reorder one.
  What the migration did cost is real but mechanical: rustfmt's 2024 style edition reordered imports and rewrapped call chains across 30 files, adding a trailing `;` to six `return Err(...)` match arms, and let-chain stabilisation made `clippy::collapsible_if` fire on seven nested `if let`s, which are now `&&` chains. Comparing the non-whitespace character multiset of every touched file before and after shows exactly those two changes and nothing else.

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

- [x] **P1 — Whole-database integrity checks.**
  `cr check` and `GET /api/v1/check` report twelve finding kinds without stopping at the first one: dangling links, malformed relation values, schema violations, unusable collection schemas, invalid record and collection names, records that cannot be read or parsed, the three audit reconciliation states (no history, audited file missing, content divergence), a journal that cannot be replayed, a stored change set that does not match its approval, and a sync run that stopped partway. Findings name records by `collection/id` and never by path, and `src/check.rs` holds the logic so `database.rs`, `main.rs`, and `server.rs` only gained seams. Exit status is 0 for clean, 2 for "ran and found problems", and 1 for "could not run"; `--fail-on error|warning|never` moves the threshold and `--collection` bounds the expensive phase. `check` is strictly read-only, proven by a byte-level before/after snapshot over the whole database in `tests/check_cli.rs` and `tests/check_http.rs`.
  Three deliberate boundaries. `cr status` keeps the working-tree view, so a divergence `cr save` could reconcile is reported at `warning` and points back at `status`; the same divergence becomes an `error` when the record also fails to parse or validate, because then `save` refuses it and nothing but `check` explains why. The interrupted-sync-run finding is a durability report rather than an integrity one — the run ledger is not hash-chained, the committed prefix genuinely agrees with the journal, and `check` does not take the per-sync lock so it cannot tell an abandoned run from one in flight — so it is a `warning` that names the sync and points at `cr sync recover <name> --check`. And `check` never repairs, including never completing a sync run it just reported; see the `--fix` entry below.

- [ ] **P2 — Decide whether `cr check --fix` should exist.**
  `check` is deliberately read-only: the findings it reports have genuinely different right answers (a dangling link may want the relation removed, the target restored, or a delete policy applied), and a command that both diagnoses and mutates cannot be run unattended from cron. If a repair mode is ever added it must be a separate verb rather than a flag on `check`, must require naming what to repair, must write ordinary audited events rather than editing the journal, and must not be able to resolve a finding by deleting data. The `unlink`, delete-policy, and relationship-constraint entries above are prerequisites for most of what a fix would want to do.

- [ ] **P2 — Give `check` an incremental or bounded mode.**
  `check` reads and parses every in-scope record and replays the journal twice — once for record state and once for the approval digests — so it is O(records + 2·events) with no index, exactly like `list` and `search`. It also holds the audit lock for the whole scan, as `status` does, so a check over a large database blocks writers for its duration. `--collection` is the only bound today. The disposable-index entry above would fix the record half; a cached replay to a known-good head would fix the journal half.

- [x] **P1 — Report a Markdown filename that cannot be a record ID instead of failing every command.**
  Resolved as a hard error everywhere, from one definition. `database::collection_entry` and `database::collection_directory_name` decide what a record and a collection are, and the four paths that walk the records tree — `Database::list` (so `search` and every view), `Database::record_files` (so `status`, `save`, `audit baseline`, and `sync run`), `AuditLog::verify_records`, and `cr check`'s index — all call them, so there is no second definition left to drift. Three of the four were wrong in three different ways before: `list` never checked the stem and returned `records/deals/..md` as a record with exit 0, `record_files` refused the whole database with `id must be a non-empty path component`, and `verify_records` never checked it either and reported a record called `deals/.` as unaudited. `list` is stricter as a result; that is a user-visible behaviour change, documented in `README.md` and `docs/architecture.md`.
  The refusal is `DomainError::Conflict` — the stored state is unusable, not the request — so HTTP answers `409 conflict` rather than a `422` blaming a caller who asked for nothing unusual or an unclassified `500`. It reads `collection 'deals' contains a Markdown file named '..md' whose name cannot be a record ID`: a bare filename inside a named collection, which is enough to act on and is not a filesystem path, so the no-path-leakage invariant holds and `tests/check_cli.rs` now asserts the precise form of it rather than banning the substring `.md`. Non-UTF-8 record filenames and unusable collection-directory and schema-file names were classified the same way; they had been unclassified `anyhow` context, so they reached HTTP as `500`.
  `cr check` keeps reporting `invalid_record_name` and scanning past it, now with the same sentence, and `tests/check_cli.rs` proves it still enumerates a database that `list`, `status`, and `audit verify` all refuse.
  One deliberate narrowing: `check` no longer reports a non-UTF-8 filename that is not a `.md` file. Nothing treats such a file as a record, so the finding was not actionable, and the alternative was to make every other command refuse it.
  Two enumerations of the same shape are deliberately untouched. `SyncStore::syncs` and `Views::all` refuse an unusable `.yaml` stem with a message that names no file, exactly as `record_files` used to; they are separate namespaces, they wedge only their own commands, and folding them in would have changed sync and view behaviour that nobody has reported a problem with. Worth doing when either is next touched.
  Also left as it is, and worth a decision on its own: `list` silently skips a `.md` entry that is a symlink or a directory, while `record_files` and `AuditLog::verify_records` refuse it with `is stored behind a symbolic link` and `cr check` reports it. That is the same class of split as this entry, in the *kind* dimension rather than the *name* dimension, and `tests/cli_features.rs` currently pins the skipping behaviour.

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
  Define atomicity, validation, audit grouping, crash recovery, maximum batch sizes, and partial-failure behavior before exposing bulk create/update/delete. Deliberately still open: nothing here is a multi-record transaction.
  The sync half of it is closed to the strongest property available without one. Sync runs still preflight their bounded stream and commit sequential single-record mutations, so a durable application failure still commits a prefix — but it can no longer do so silently. A run ledger and the run's exact validated stream become durable under `.cr/sync/runs/` before the first mutation and are removed only once the checkpoint agrees with the committed work, so an interrupted run is a fact on disk rather than an inference. `cr sync run` refuses to start over one, and `cr sync recover <name>` completes it by replaying the recorded stream forward — sound because the protocol stream is idempotent by construction — under the interrupted run's own ID; `--check` reports it while reading committed progress back out of the audit chain rather than keeping a second copy. Rollback is not attempted and is not wanted: the journal is append-only, and appending inverse mutations would trade a true history for a longer one that gains nothing over finishing the run. Per-record checkpoint advancement is impossible by protocol, because the adapter emits one opaque cursor at the end.
  What remains for this entry: genuine all-or-nothing application across several records, which needs a staging-and-publish design for record files plus an audit protocol that can commit a group of events as one unit; bulk create/update/delete over HTTP and the CLI built on that; and per-record approval mapping so `--approved-changes` can cover a multi-record `save`. Recovery of a run whose original failure persists remains a truthful stuck state that needs a person, and a replay can re-drive an adapter's remote side effects, which is the neighbouring "remote-effect idempotency" entry.

- [ ] **P1 — Define sync ownership, pruning, and remote-effect idempotency.**
  Version 1 only deletes records when an adapter emits an explicit target. Add optional source ownership metadata and safe prune previews without treating absence from a partial page as deletion. Define retry/idempotency guidance or primitives for adapters that also perform irreversible remote effects.

- [x] **P1 — Idempotency keys for retried mutations.**
  CLI create/update/link/delete and REST record POST/PATCH/PUT/DELETE/link POST accept bounded, high-entropy retry keys. The raw key is never persisted: a principal/operation/record-scoped key hash, lossless typed-YAML request hash, and original result are committed inside the same audit event and pending-mutation protocol as the write. Exact retries re-run current authorization and return that result without another event; the stored safe relative path and exact Markdown keep the response unchanged across `data_dir` changes; mismatched reuse is typed `idempotency_conflict`; concurrent callers serialize under the audit lock; pending recovery closes both response-loss crash windows; previews and failures consume nothing. The scoped identity occurs at most once regardless of request hash, enforced by replay, lookup, preparation, append, and recovery as typed `audit_integrity_failed`, while a pending copy of its already-committed event remains an honest cleanup case. Verification binds the stored result back to the replayed event state, exact bytes, before/after version, collection, and ID, including delete tombstones. V1 is honestly single-record: multi-record save and sync, managed user/access lifecycle commands, and HTML form posts remain outside this contract until they have command/group result semantics; `user ensure` remains independently declarative.

- [x] **P1 — Authorization policies.**
  The reserved fixed-schema `users` collection is the principal registry and policy store. Each audited user record carries direct `viewer`, `editor`, `access_manager`, or `owner` grants at database, collection, or record scope. Grants inherit down the resource tree, the most specific role wins except that ownership is never narrowed, and every `Database` record read and mutation evaluates the current principal. List/search omit unreadable records; scoped history requires audit-read access; database-wide integrity operations require ownership; editors cannot delete; access managers cannot mint ownership or other access managers; and the last database owner cannot be removed. Generic partial mutations expose one narrow field-level rule for `users`: editors may update `profile.*`, active principals may update their own name and profile by default, and email/kind/status/access remain on managed paths. Owner-only user deletion records a full-state tombstone, supports complete-chain `--if-unused` checks, keeps historical actor references verifiable, and blocks ID reuse unless `--reuse-deleted-id` is explicit. Direct grants to an absent user record are inert. Mixed-field requests authorize at the strongest required level before writing. Every policy change is ordinary record history, and allowed data events store the principal, action, resource, role, grant scope, decision basis, and exact user-record hash behind the decision. CLI commands enforce the resolved local principal, while `cr serve` provides a loopback-only owner console that can explicitly impersonate each user and records the owner behind allowed impersonated mutations. Both remain local guardrails until the authenticated-principal item above supplies a non-bypassable backing-store boundary.

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

- [x] **P1 — Detect a forged newest record result without an external checkpoint.**
  `audit verify` now replays every record's change sets and requires each semantic post-state to reproduce that event's exact `after_hash`; the formerly ignored forged-head test is enabled. Version 3 events add a versioned exact-Markdown `after_snapshot` to every present post-state. Replay parses the witness back to the same semantic state before hashing its exact bytes, so YAML spelling is evidence rather than something a renderer guesses. Actions are bound to their presence transitions, and baseline is valid only as a record's first event.
  Version 1 and 2 events remain compatible without making a false byte-equivalence claim. A non-reproducible legacy event records a representation gap; a later strongly verified transition clears it. When the gap remains at a record head, only the materialized file with the exact stored hash can serve as its witness, and its parsed document must equal semantic replay. This covers old baselines, managed-user mapping order, and direct `save` events. Payload versions can increase but cannot decrease mid-journal; proving that the first event or the complete history was not rewritten from v3 to v2 still requires the signed or remote checkpoint above.
  Replay is also mutation admission: `prepare`, reconciled saves, sync recovery, and pending-mutation recovery all refuse an already inconsistent journal before creating a pending write or appending an innocent event. The failure is `DomainError::AuditIntegrity` / `409 audit_integrity_failed`, names the guilty sequence, and publishes no path or value. What remains is deliberately the signed/remote-checkpoint entry above: replay cannot derive actor, timestamp, message, authorization, intent, or attribution from record state, and an attacker who rewrites the newest event into an internally consistent different state can update its `after_hash`, the record, event hash, and local anchor together. `tests/audit_corruption.rs::a_forged_head_actor_still_needs_an_external_checkpoint` keeps that boundary executable.

- [x] **P1 — Anchor the audit head to a file the version control system carries.**
  `.cr-audit-head.json` sits at the database root, outside `.cr/`, and records `{version, sequence, hash, timestamp}` for the newest audit event — every field derived from the journal, the timestamp being the anchored event's own rather than the time of writing, so the file is a pure function of the chain and two databases holding the same journal hold byte-identical anchors. It is rewritten inside `AuditLog::append`, which is the single funnel for `create`, `update`, `link`, `delete`, `save`, `sync`, `audit baseline`, and pending-mutation recovery, so no path that advances the chain can leave it behind. `cr audit verify` checks it by default, `cr check` reports it, and `cr audit anchor [--write]` inspects and repairs it.
  Honest scope, because the location invites more than it delivers: a file at the database root is writable by anybody who can write `.cr/`, so on its own the anchor stops nothing — the forger re-hashes the event and rewrites the anchor in one pass. **The protection comes entirely from committing the anchor to Git**, where a pushed, distributed history is a second write boundary a local filesystem write cannot reach. What ships here is that the Git-based practice becomes automatic, ergonomic, and checked by default instead of a manual `audit head` nobody ran. `cr` writes no `.gitignore` and nothing in the repository excludes the file; `tests/audit_anchor.rs::the_anchor_is_tracked_by_git_and_excluded_by_nothing` checks that against real Git.
  Stale is separated from tampered by *position*, not by comparing head hashes. The anchor names a sequence as well as a hash, and the journal is append-only, so the event at that sequence is fixed forever: recomputing the anchor the journal implies at exactly that sequence gives "the journal is shorter than the anchor claims", "the journal has a different event there", and "the journal has the same event there and more after it" as three separable answers. Only the first two fail, as `DomainError::AnchorMismatch` / `409 anchor_mismatch`, distinct from a corrupt chain. A new variant rather than a `Conflict` for the same reason `ApprovalMismatch` is one: the *status* follows the established precedent for unusable stored state — 409, exactly as `paths::refuse_entry` and the record-name refusals map — but the machine-readable code has to separate "the chain is damaged" from "the chain is intact and is not the one your anchor attests to", because those two send an auditor to different places. The third is a pass with a notice, which is what a crash between the segment write and the anchor write legitimately leaves. A lagging anchor is a real reduction — the events past its sequence are pinned by nothing again — and `check` reports it at warning severity rather than hiding it.
  Left open on purpose: an absent anchor passes with a notice rather than failing, so deleting the file downgrades a database to the pre-anchor situation silently as far as the exit status goes, and only the notice, the `audit_anchor_missing` finding, and the Git deletion say so. `cr status` still reports `Clean` on a database whose head was forged, because `status` is the working-tree view and reads no anchor. And the anchor is not signed, which is the separate P1 entry above.

- [ ] **P1 — Audit retention, redaction, and encryption policy.**
  Define how regulated or deleted personal data is protected while preserving useful integrity guarantees.

- [ ] **P2 — Backup and restore commands.**
  Capture records, configuration, schemas, audit segments, and external checkpoint metadata; verify a restored database before activation.

- [ ] **P2 — Repair and recovery tooling.**
  Add read-only diagnosis and explicit repair flows for interrupted operations, corrupted active segments, and record/audit divergence. Never silently rewrite evidence.
  `cr sync recover --check` and `cr sync recover` are the first pair of this shape, scoped to one interrupted sync run. Generalizing means surfacing an interrupted run in whatever whole-database diagnosis command lands, so an operator who does not already suspect a wedged sync still finds it, and doing the same for the other interrupted operations listed above.
  The read-only half of that is now done for syncs: `cr check` reports an `interrupted_sync_run` finding for every sync with a ledger on disk, naming the sync and pointing at `cr sync recover <name> --check`, so an operator finds a wedged sync without suspecting it first. It stays a `warning` and never recovers. What remains is the other interrupted operations — a pending single-record mutation left by a crash, which `Database::discover` recovers silently before any command can report it, and a corrupted active segment, which today makes the whole chain unreplayable and so appears only as `audit_chain_broken` with no indication of which segment or how much of the journal is still good.
  Add sweeping orphaned staging files to the same command. `paths::write_new` and `paths::write_replace` publish atomically by writing `.cr-tmp-<random>` beside the destination and then linking or renaming it, and the unlink that tidies up runs in the process, so a process killed in between leaves the staging file in the collection or segment directory. It is litter rather than corruption — the name carries neither a `.md` nor a `.jsonl` extension, so listings, `status`, and `audit verify` all skip it, which `tests/audit_fault_injection.rs::staging_files_orphaned_by_a_crash_are_ignored_by_every_reader` pins — but nothing removes it and it accumulates one file per hard kill. A sweep must only remove entries matching the prefix that no live process holds; deleting on a name match alone would race a concurrent writer.

- [ ] **P2 — Operating-system audit integration guidance.**
  Document and optionally integrate controls for deployments that must observe every write attempt rather than only accepted net file state.

## Test and quality backlog

- [ ] **P1 — Property and fuzz tests.**
  Fuzz front matter parsing/rendering, field paths, query expressions, audit replay, HTTP request decoding, and generated OpenAPI documents.
  Audit replay is done. `tests/audit_properties.rs` drives seeded sequences of create/update/link/save/delete against the library and asserts after every step that the chain verifies, that sequence numbers stay dense and monotonic across constant segment rotation, and that a copied database reproduces the same head. It also sweeps *every* byte of a segment and of a record with two bit patterns each and requires every one of them to be detected. The hash re-derivation lives in `tests/common/chain.rs` and is written from the format documentation rather than reusing `src/audit.rs`, so a green run means the stored bytes match the specification rather than that `cr` agrees with itself.
  Deliberately no property-testing dependency: the generation needed here is a weighted choice among five operations over a five-record namespace, shrinking buys little against a fixed seed set, and `Cargo.lock` churn costs an MSRV check. The generator is SplitMix64 with a pinned reproduction vector, so a failure is replayable from its seed on any platform.
  What remains is everything that is not the audit chain: front matter parsing and rendering, field paths, query expressions, HTTP request decoding, and the generated OpenAPI document. Those are separable and none of them needs the crash harness.

- [ ] **P1 — Crash/fault injection.**
  Exercise failures at every durable-write boundary, including server termination during mutation, segment rotation, direct-edit save, and future multi-record work.
  The single-record audit write-ahead protocol is done. `tests/audit_fault_injection.rs` enumerates the four points in a mutation — pending written, record replaced, event appended, pending cleared — and proves each one recovers to the correct atomic state, for create, update, delete, and the degenerate case where the before-state and after-state are identical. Every state that is none of those four produces a named refusal that is asserted by wording: a record matching neither state, a committed event whose record was rolled back, a pending file that cannot extend the head, and one older than the committed head. `tests/audit_corruption.rs` does the same for torn and tampered state: truncated tails, a tear terminated by a newline, flipped bytes in a payload and in a stored hash, empty segments, re-hashed forgeries, unsupported versions, reordered/removed/duplicated events, segment gaps, misnamed segments, and eight malformed shapes of `pending.json`.
  The interruption is produced by blocking the name the next segment will take, so a real `cr` process writes its real pending file and its real record and then fails to append. That is deterministic and needs no hook in production code; the cost is that no test kills a process *inside* the mutation window, because there is no rendezvous that would make the kill point deterministic without such a hook. `tests/concurrency.rs` does kill a real `cr` process outright, via a sync adapter that signals its own parent, and covers writers racing recovery and writers contending for the audit lock.
  What remains: terminating the HTTP server mid-request (the durable states are the same ones, but the shutdown path is not covered), the sync run ledger under `.cr/sync/runs/`, which is a separate durability mechanism and is not hash-chained, and multi-record work when it exists.

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
- [x] Bounded HTTP pagination, bearer-token option, request actor attribution, and typed, redacted, request-correlated errors.
- [x] Optional agent, authorization, and intent attribution recorded beside the responsible human, with documented-variable detection, explicit precedence, an escape hatch, bounded asserted values, `--agent`/`--session` history filters across CLI, REST, and HTML, tolerant reading of attribution values a later `cr` may add, and no audit format version bump.
- [x] Previewed change sets with a digest over their canonical stored bytes, recorded as `authorization.approved_changes`, enforced at write time and recomputed by `audit verify` under its own named failure.
- [x] Exact-byte record versions with REST ETags, locked `If-Match` and CLI expected-hash preconditions, required guards for whole-document web replacements, and stale browser-form protection.
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
- [x] Opt-in record RBAC through a fixed-schema, audited `users` collection with editor-writable profile fields, self-service names and profiles, human/service principals, atomic ensure/update/restore/delete workflows, guarded ID-reuse tombstones, database/collection/record inheritance, viewer/editor/access-manager/owner roles, current-principal CLI enforcement, filtered discovery and audit history, verified owner delegation, non-impersonable `--actor`, last-owner protection, and per-mutation access-decision evidence.
- [x] Loopback-only owner RBAC perspective console with a live user switcher, cookie-scoped HTML and REST impersonation, permission-aware controls and Kanban movement, owner-attributed impersonation evidence, and no-store responses.
- [x] Versioned subprocess sync adapters with JSONL upsert/delete/checkpoint messages, clean-state verification, limits, overlap locks, checkpointing, and `source: sync` audit provenance.
- [x] Unit, CLI, concurrency, direct-edit, in-process HTTP, and real TCP server tests.
