# SQLite audit storage implementation plan

Status: implemented and validated on 2026-10-14. Scope: audit storage only.

## Objective and compatibility

Keep editable Markdown records, bundle assets, schemas, views, sync definitions,
encryption keys/context, CLI syntax, REST responses, HTML routes, and `cr serve`.
Move audit events and their operational indexes to `.cr/audit.sqlite`. Every
accepted historical event keeps its exact payload bytes, sequence, hash, actor,
attribution, snapshots, retry result, and encryption representation. Record
versions, approval digests, and signed checkpoint identities remain unchanged.

The existing JSONL reader remains available for format-1 databases and migration.
New databases use format 2 with SQLite audit storage. Existing databases upgrade
once with `cr audit migrate`; migration is explicit because it changes the
durable format and makes older binaries unable to open the database. Normal
commands keep their syntax and results on both formats. Format 2 is a fail-closed
compatibility fence, not an audit-payload version change.

## Findings driving the design

The production investigation measured ordinary operations at 0.12–0.25 seconds,
keyed CLI updates at 11.1 seconds, history reads at 10.9 seconds, and recovery at
18.4–18.9 seconds on a copy of a roughly 209 MB journal. A fresh CLI process
rebuilds its in-memory retry/history index by replaying the entire journal.
Periodic verification and interrupted-write recovery also replay history while
holding the exclusive writer lock. Every command acquires that lock at startup.
Deadlines can repeatedly interrupt recovery and prevent progress.

The acceptance criterion is that a normal single-record mutation, retry lookup,
history page, and interrupted single-record recovery do not replay unrelated
history or load/serialize every audited record. Full verification remains linear.
Whole-collection queries and direct-edit status still inspect their input files.

## Durable SQLite model

Use bundled SQLite through `rusqlite` so installation requires no database
service or system SQLite development package. Use WAL, FULL synchronous writes,
foreign keys, a bounded busy timeout, explicit schema/application versions, and
transactions. Open existing databases without CREATE; a missing/corrupt/unknown
audit database is an error, never permission to initialize an empty history.

Tables:

- `events`: sequence primary key, exact payload bytes, event hash, collection,
  record ID, and exact historical encryption transitions. Index
  collection/record/sequence; a separate `agent_values` membership table indexes
  acting and delegated agent/session identifiers. Actor/source/action/time remain
  in the authoritative exact payload.
- `record_states`: collection/ID primary key, latest audited document/hash,
  tombstone, protected-storage ownership, legacy representation gap, bundle
  state, created/updated activity, and the event sequence backing that state.
  Store only ciphertext representations for protected data.
- `idempotency`: unique effective principal/operation/collection/ID/key hash,
  request hash and original event sequence. Original response and historical
  bundle versions are recovered from the indexed event, never current files.
- `principals`: first external participation per effective or impersonating
  principal, supporting indexed identity reuse checks.
- `protected_events`: event sequences whose historical transitions own
  ciphertext, supporting indexed lazy encryption-context safety checks.
- `head`: singleton sequence/hash/payload version, advanced with each append.
- `pending`: singleton exact pending mutation; bundle contents continue to use
  safely staged files because their size and filesystem publication matter.

The append transaction inserts the immutable event, validates uniqueness and
sequence, updates only its record state/activity and retry identity, advances
the head. Pending intent is cleared after external checkpoint publication.
Derived state can be checked by
independent full replay, but is not rebuilt for ordinary operations.

## Write and recovery protocol

SQLite cannot atomically replace an external Markdown file. Retain one writer
coordination lock across the existing operation boundary:

1. Read current principal/schema/record state and expected version; authorize,
   validate, encrypt, calculate changes, and prepare exact event bytes.
2. Persist pending intent before changing record bytes. Stage bundle contents
   durably before publishing them.
3. Atomically replace/create/delete the record, or apply the staged bundle plan.
4. In one SQLite transaction append the event and advance affected indexes/head.
   Publish existing anchor/signature files with established continuity rules,
   then clear pending intent. If publication fails, recovery recognizes the
   exact committed pending event, restores its derived checkpoint, and clears
   intent without appending twice.
5. Remove unused staged contents and release writer coordination.

Recovery reads the pending row, current head, and affected indexed state. The
existing before/after/neither and bundle partial-state rules remain authoritative.
Recovery either discards an unapplied intent, finishes a published mutation once,
recognizes its already committed event, or refuses conflicting file/history
state. It never replays unrelated history. Retrying after a lost response uses
the unique durable operation identity and original result.

Remove unconditional startup writer locking for healthy SQLite databases.
Check pending state first, then acquire writer coordination and recheck before
recovery. Single-file reads retain atomic replacement semantics; bundle readers
retain existing concurrent snapshot semantics and can observe a mixture of
files during an in-flight multi-file write. Operations requiring filesystem
consistency retain writer coordination. Healthy ordinary record readers do not
queue behind integrity maintenance.
Keep lock ordering consistent: writer coordination precedes SQLite write
transactions; do not hold a read transaction while waiting for that lock.

## Reads, verification, and trust

- Retry lookup uses its full scoped unique index and verifies the matching
  event/result before returning it under current authorization.
- History queries seek by sequence and indexed record scope, then apply current
  visibility before counting the requested page. Historical encryption
  transitions come from the same committed event transaction.
- Single-record policy/ownership/tombstone checks use one record-state lookup.
  Bulk readers obtain one consistent state view for their actual scope.
- Head, activity, live invalidations, and signing lookups use indexed metadata.
- Explicit `audit verify`, `check`, and `--verify-audit` independently stream
  every exact event and reuse the existing semantic replay rules. They compare
  operational projections with reconstructed state and check materialized files,
  anchors, approvals, and trusted signatures as appropriate.
- SQLite normal writes validate the affected transition and new event against
  committed current state. They do not schedule an entire historical replay
  every 64 writes. The legacy verification cadence remains supported for
  format 1; format 2 documents explicit/scheduled independent verification.

This makes the trust boundary explicit: normal operations trust transactionally
maintained audit state; full verification independently checks historical
integrity. A writable SQLite file is not an external trust anchor. Retain signed
checkpoints and externally retained heads. SQLite corruption and unsupported
schemas fail closed. Do not claim immediate detection of every historical
rewrite on each ordinary read.

## One-time migration

`cr audit migrate` runs as the database owner when access control is enabled.
It is safe to repeat: a format-2 database with verified projections and anchor
continuity reports already migrated; unsaved Markdown edits remain untouched.

1. Acquire existing writer coordination, reread config, and resolve any legacy
   pending mutation with the legacy recovery rules before taking the source
   snapshot. Reject unknown/corrupt input and unsupported payload versions.
   For configless legacy databases, first persist a format-1 config so a failed
   import still has an explicit source selector alongside the SQLite artifact.
2. Independently replay legacy segments in sequence order, retaining exact
   payload bytes and hashes. Validate snapshots, changes, retry identities,
   legacy representation witnesses, and existing anchor/signature continuity.
   Preserve unsaved direct edits as unsaved edits; migration must not accept,
   discard, or normalize them. Missing witnesses needed by legacy events fail.
3. Atomically publish a small initialized SQLite schema at `.cr/audit.sqlite`,
   still unselected while config is format 1. Schema construction uses a separate
   disposable `.cr/audit.sqlite.init` file, checkpointed and closed before safe
   publication. Import the history and indexes in one transaction. No records,
   schemas, views, keys, ciphertext, or external checkpoints are rewritten.
   A retry validates every existing imported payload against the source before
   appending a missing suffix, allowing legacy writes after an interrupted cutover.
4. Check SQLite integrity, event count, terminal sequence/hash, independent
   semantic replay, and every maintained projection. Import is checkpointed
   before config publication. This avoids copying or renaming a live database
   and its WAL after a large import.
5. Atomically write format-2 config only after the complete SQLite file is
   durable. Preserve every unrelated setting. Re-read config after obtaining
   writer coordination so an old waiting process cannot append legacy history
   after cutover. Updated binaries refuse a stale backend selection.
6. Retain original segments as a migration backup. They are no longer writable
   active history. Do not silently fall back to them if SQLite disappears.
   Interrupted migration before config cutover leaves the legacy source usable;
   restart discards interrupted schema staging and resumes a matching imported
   prefix safely. After cutover, SQLite is authoritative. Missing configuration
   alongside SQLite is refused rather than interpreted as configless format 1.

Old binaries must be stopped before migration: an already-running old process
cannot be made to honor a format fence it never rereads. Document this operator
requirement. Rollback requires the pre-migration backup and config together;
restoring old segments after new SQLite writes would lose accepted history.

## Backups, portability, and filesystem safety

SQLite is binary and replaces the human-readable active JSONL journal. Keep
Markdown and existing external checkpoint files Git-friendly. Document a
consistent SQLite backup (backup API or stopped writers/checkpointed database),
the WAL/SHM sidecars while active, and backing up record files with the matching
audit head. Never instruct users to copy only an active main database file.
Legacy segments remain inspectable migration evidence. A future export command
can emit exact JSONL; it is not a second concurrently written journal.

Refuse unsafe preexisting SQLite main/sidecar files with SQLite NOFOLLOW plus
preflight checks beneath the real `.cr` directory. SQLite's VFS opens full
paths; retaining the checked parent descriptor does not make those opens
descriptor-relative. Unlike CR's ordinary Unix file primitives, this does not
close a race against a hostile local process concurrently replacing an ancestor
directory. Keep database directory ownership trusted for the connection lifetime.
Refuse unsupported file kinds and malformed identifiers, and redact private
payloads, paths, and secrets from HTTP refusals.

## Delivery sequence

1. Add the storage module, schema/version checks, indexed reads, independent
   event replay, and unit tests for transactional append and corruption.
2. Route audit operations through SQLite while retaining the legacy reader and
   writer for compatibility and migration. Remove full-state hot-path work.
3. Integrate pending recovery, bundle staging, anchors/signing, current-state
   lookup, authorization, encryption history, live updates, and startup locking.
4. Add migration command, durable publication, version fence, interruption and
   repeat-run handling; make newly initialized databases use SQLite.
5. Adapt storage-specific tests while running existing domain/CLI/HTTP tests on
   SQLite; retain explicit legacy fixtures and migration coverage.
6. Update architecture, audit, backup/troubleshooting, CLI, release compatibility,
   and roadmap documentation with the actual final behavior.

Operational limits: writers remain serialized while publishing Markdown and
checkpoints. Explicit verification, check, sync snapshot verification, and
migration still do linear integrity work and retain filesystem coordination.
WAL requires a local filesystem with reliable locks/shared memory. This change
removes history-dependent ordinary mutation/retry/recovery costs; it does not
turn record scans into SQL queries or promise a fixed production latency.

## Verification and completion gates

- Preserve exact imported event bytes, hashes, sequence, head, record versions,
  signatures, encrypted storage, scoped retries, and dirty working-tree state.
- Exercise create/update/link/unlink/delete, direct save/status, schema/policy
  changes, user lifecycles, bundles, sync recovery, CLI/API errors, ETags,
  attribution, previews/approvals, and history visibility.
- Inject failures before/after intent, file publication, event commit, derived
  checkpoints, and migration cutover. Kill/restart real subprocesses where
  useful; verify no lost/duplicate events or self-sustaining recovery loop.
- Test simultaneous readers/writers, duplicate keys, stale preconditions,
  pending recovery races, and legacy processes queued across migration.
- Corrupt payload/hash/state/index/head data, test unsupported SQLite versions,
  missing database, unsafe paths/sidecars, and interrupted migration artifacts.
- Measure separate CLI invocations with increasing history, keyed and unkeyed
  writes, record/global history pages, recovery, and mixed CLI/server load.
  Record replay/row counts as deterministic complexity assertions; wall-clock
  benchmarks supplement them. No unmeasured production latency promises.
- Run formatting, strict clippy, all-target build, complete tests, and diff
  checks. Report any remaining failures or limitations without marking the
  implementation complete until required behavior is achieved.

## Delivery evidence

- Complete suite: **928 passed, 0 failed, 1 pre-existing ignored test** across
  78 test targets. Existing domain, CLI, HTTP, HTML, encryption, signing, sync,
  and bundle coverage uses SQLite by default; explicit storage/forgery fixtures
  continue to exercise legacy JSONL.
- Twenty SQLite integration tests cover new defaults, exact historical payload
  migration, configless legacy input, preserved dirty files/settings, owner
  authorization, retry results, encrypted/bundle data, trusted signatures,
  rollback/resume, stale handles, indexed corruption, unsafe preexisting paths,
  missing configuration/storage, concurrency, and pending recovery boundaries.
- Deterministic complexity checks assert zero historical replays through 130
  updates plus fresh-handle mutation/read/history/activity operations. Independent
  full verification still replays and checks every maintained projection.
- A real subprocess was killed while importing a 100,003-event journal, after
  SQLite had written over 3 MB of uncommitted WAL. The import rolled back to
  zero events, config remained format 1, and the source remained readable.
  Retrying migration and independent verification preserved all 100,003 events.
- Release-build measurements at 1,000/10,000/100,000 synthetic events show
  ordinary SQLite update/history costs remaining roughly flat. At 100,000
  events (166.49 MB JSONL), a fresh keyed update dropped from 1,112.13 to
  9.93 ms and a 20-event record history page from 1,151.30 to 7.77 ms.
  SQLite interrupted-write recovery took 10.06 ms. These are warm-cache VM
  samples, not production or tail-latency guarantees.
- On that SQLite fixture, 14 HTTP writes, 14 CLI writes, and 28 HTTP reads
  completed together in 0.216 seconds with 12 client workers, all successful.
  The head advanced exactly 28 events and full verification passed afterward.
  [Performance notes](serve-performance.md#sqlite-audit-measurements-2026-10-14)
  give methodology, timing tables, and artifact locations.
- `cargo fmt --all --check`, strict all-target clippy, all-target build, and
  `git diff --check` pass. `cargo +1.89.0 check --locked --all-targets` passes
  at the declared minimum Rust version. A locked release build also passed.

## Rollout

1. Install the updated binary and stop every existing CR process using the
   database, including schedulers and older servers. Take a consistent complete
   backup while stopped.
2. Run `cr --database /path/to/database audit migrate` as its owner, with any
   encryption/signing configuration normally required by that database.
3. Run `cr --database /path/to/database audit verify`, supplying the established
   trusted signing key or expected head when applicable. Unsaved direct edits
   remain unsaved and can make record verification report drift.
4. Restart normal CLI/API/serve workloads with the updated binary. Schedule
   explicit full verification outside latency-sensitive writes. Keep the
   pre-migration backup and retained source segments until rollout is accepted.

The implementation is ready for review. No production database was migrated.
