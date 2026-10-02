# Serve scalability review and fixes

Research and implementation date: 2026-10-02. The web app prioritizes quick navigation and bounded output. External edits may take up to five seconds to appear in list results and counts. Permissions, authentication, record details, schema validation, mutation preconditions, and saves continue to read current authoritative data.

## What changed

| Finding | Implemented fix | Remaining cost or trade-off |
| --- | --- | --- |
| Repeated users-directory, principal, and schema reads inside a collection scan | Batch shared policy reads per operation; check each record's permissions with that current policy. | Record-owned ACLs still require fresh entry reads. |
| Every navigation rereads and parses the complete collection | A bounded, serve-only source cache shares parsed records, with per-collection single-flight fills and immediate invalidation after local writes. | Cold fills, filtering, exact counts, and ordering remain linear in collection size. |
| Kanban output grows with cards × lanes because every card carries every move option | Replace inline selectors with a native searchable move page; assign cards to lanes through a map; cap a board at 50 lanes and 200 cards. | Large boards open in sections. Lane loading narrows to one lane; search/filtering reaches records beyond its card limit. |
| Grouped counts rescan every record for every distinct value | Assign records to groups once using YAML equality/hash; preserve group order and metric semantics. | Metrics still visit their contributing records and group sorting costs O(groups × log groups). |
| A record form scans all readable collections for relations before opening | Load the relations panel when revealed, with a native link fallback. Bound suggestions at 500; use a reverse index when the complete source snapshot is available. | A cold, incomplete, or oversized relation index falls back to a current scan. Large actual link sets can still produce large panels. |
| Each live subscriber evaluates the whole database and every reset refetches an unchanged page | Browser subscriptions scope to their visible collection. Page and reset carry the same opaque generation; refresh only when it differs. Reconcile source edits as well as audited changes. | Each active subscriber checks current permissions and its collection once a second; these checks are intentionally not permission-cached. |
| Private collection discovery repeatedly tests records even when a broader grant suffices | Short-circuit legitimate broader discovery and record grants; batch discovery policy; memoize models within one read operation. | Discovering a private collection without broader access may still inspect its records. |
| Bundle lists and ACL checks hash every supporting asset | Read the entry for permission checks and web metadata queries. Hydrate exact whole-bundle versions only for records on a JSON list's returned page. | Details, file operations, saves, and hydrated JSON list versions still hash current supporting files. Asset-only edits do not change entry-only view metadata. |
| Every search renders/reparses canonical Markdown, even for field/body/path queries | Render only document searches; reuse canonical text by cached source version, with the existing fidelity checks. | Regex, literal substring, and canonical-text matching semantics stay unchanged; no token/FTS approximation. |
| Complex sort values and history keys are recomputed inside every comparison | Prepare YAML/history/dotted-field sort keys once per row. Move view sorting, column discovery, pagination, rendering, and blocking request identity work to blocking workers. | Ordered query results are not persisted; a query still sorts its candidates. |
| Results fragments build unused navigation, registry, and pin context; large menus overload the DOM | Skip unused shell work for results fragments. Bound/search All views and users at 100 rows, sidebar menus at 100 entries, and directory output at 200 entries. Preview at most 101 registry users for the owner picker, with free-text selection for any principal. Cache parsed view definitions by exact current contents. | Definitions and searchable registry/directory metadata still need enumeration for exact visibility, search, or order. |
| Safe filesystem reads repeatedly reopen every parent component | Reuse a verified collection-directory descriptor for each Markdown fill, retaining no-follow and regular-file checks. | Files within a cold collection fill remain sequential. Independent collection requests can run concurrently. |
| Deep history pages materialize/decrypt the whole skipped prefix, and repeat current ACL checks for the same record | Skip offsets before projecting results; memoize current history visibility per operation; add `before_sequence` cursor lookup over the verified history index. | An offset still visits the skipped visible events. A sequence cursor avoids that prefix; initial history index establishment needs a full verified replay. |
| Idempotency lookup replays the audit journal while holding the write lock | Index fully scoped retry identities in verified in-memory history; recheck current journal segments and the original matching event. Preserve historical bundle hashes without retaining supporting-file text. | One verified replay establishes the index after a saved walk; current authorization, corruption checks, and periodic full verification remain. |
| Writes synchronously serialize/fsync the disposable whole-state checkpoint under the lock | Serve advances its shared walk after each commit and serializes its checkpoint once after draining on graceful shutdown. The CLI keeps its per-append checkpoint behavior. | A crash or forced shutdown can leave an older disposable checkpoint and require more verified replay on restart. Authoritative pending files and audit commits remain durable. |
| JSON Schema validators and encryption key/context setup repeat per record | Cache compiled validators by exact schema contents; reuse a short-lived encryption context and zeroizing keyring within a protected collection scan. | Protected collections and users bypass the persistent source cache. Keys and decrypted records are not retained between requests. |

Sources: [database scans, policy, source cache, relations, and schema validation](../src/database.rs), [audit indexes and checkpointing](../src/audit.rs), [web handlers and bounded output](../src/server.rs), [live subscriptions](../src/server/live.rs), [aggregation](../src/aggregate.rs), [sorting](../src/sort.rs), [safe reads](../src/paths.rs), [encryption](../src/encryption.rs).

## Freshness and resource contract

The source cache expires **four seconds from the beginning of its directory scan**, leaving a second for the live/count polling cadence within the agreed five-second presentation budget. Expired snapshots reread exact contents, independently of mtimes: direct edits with restored timestamps, rename, create, delete, and directory replacement cannot remain cached indefinitely. There is no filesystem watcher dependency or persistent record index to migrate. Navigation also checks expiry, so the cache works without JavaScript; automatic visible-page refresh requires JavaScript.

Writes through the serving database invalidate snapshots immediately after audit append. Mutation responses also invalidate after filesystem-editor writes. Separate CLI processes and direct editor changes follow the external-edit window. Configuration changes invalidate the cache; current schema, grant, user suspension, record-owned access, encryption policy/context, and keys are checked independently of cached display data. A stale list version can legitimately yield a `412` on save and cannot overwrite a newer external edit.

The source cache retains at most 64 collection variants, 16 MiB of accounted source/parsed/search data per collection, and 128 MiB in total, with least-recently-used eviction. Full and entry-only bundle sources use separate cache keys. Accounting includes raw bytes, parsed body/YAML, IDs, references, and canonical search text; these limits are cache accounting bounds rather than process RSS bounds. Requests, the verified audit walk, temporary fill allocations, and evicted snapshots still in use also consume memory. Oversized collections stay correct by rereading uncached records. Reverse-link candidates are used only when the snapshot is complete, preventing an incomplete private scan from hiding newly granted sources.

At most eight disposable reads/render tasks run concurrently. Abandoned collection scans check a cancellation flag; mutations always finish their durable protocol. A collection lock coalesces simultaneous fills. Compiled-validator and parsed-view caches cap both entry count and input size; definitions over 64 KiB are used without retention. This avoids an unbounded collection of cached large definitions.

Browser refreshes pause while the tab is hidden, a user is editing, or controls have focus. The five-second window describes source reconciliation under normal responsive operation, not a promise that a busy machine or a deliberately paused browser will render within five wall-clock seconds. All views revalidates counted fragments with a private ETag after fresh permission checks; unchanged results return `304`. Collection live generations are keyed by the server secret and perspective, expose no hidden IDs or global audit sequence, and close the page/subscription race without an unnecessary second list fetch. Unscoped API subscribers retain the existing audited-change feed.

## Measurements

Tests use normal Cargo release builds on this workspace's Amazon Linux x86_64 VM (16 CPUs, about 32 GiB RAM), localhost full-response-body reads, and warm filesystem cache. Read timings are medians of four warm requests after an initial request. These small samples are not p95 results or production capacity estimates. Browser measurements use headless Chrome without CPU throttling.

The main read fixture has 10,000 ordinary records across 21 collections, including 5,000 in `items`, 201 registered users, and roughly 2,050 audit events. Most records have three scalar attributes and about 420 bytes of notes; many are direct files without audit history. Separate fixtures cover 1,000 small/large bodies, 1,000 private records, 200 bundles with 1 MiB assets, 500 saved views, and 5,000 Kanban grouping values.

Before policy batching, a 5,000-record web list cost 986 ms and All views counts 2.15 seconds in the initial paired experiment; batching reduced them to 231 ms and 395 ms. Those samples predate the source-cache/output changes and should not be compared as a matched run with the table below.

The final paired comparison below uses the binary with policy batching and
idempotency indexing already applied as its **before** baseline, so it isolates
the remaining source-cache, output, and checkpoint fixes.

| Workload | Before | After |
| --- | ---: | ---: |
| 5,000-record table, one returned row | 154 ms | 40 ms |
| Same table, 200 returned rows | 131 ms | 37 ms |
| Search over the 5,000-record collection | 164 ms | 45 ms |
| Table results fragment | 163 ms | 26 ms |
| Record form in a 250-record collection | 236 ms | 7 ms |
| No-backlinks lookup across all collections | 214 ms | 8 ms |
| Group 5,000 records by 5,000 distinct values | 2,439 ms | 20 ms |
| 200 bundles with 1 MiB assets, one table row | 197 ms | 2 ms |
| Bundle collection's All views counts | 199 ms | 1 ms |
| 500 saved views, counted home page | 64 ms / 390 KB | 21 ms / 81 KB |
| 1,000 records with roughly 69 KiB bodies, one row | 99 ms | 83 ms |
| Large-body collection's home counts | 96 ms | 81 ms |
| 1,000 private records, one row with current ACL checks | 59 ms | 60 ms |
| Private collection's home counts | 56 ms | 31 ms |
| Reader's discovery of 1,000 hidden private records | 160 ms | 25 ms |
| 14 concurrent updates, without keys | 1.01 s | 0.25 s |
| 14 concurrent updates, with distinct keys | 1.02 s | 0.27 s |

The earlier 5,000-lane board probe returned **2.52 GB in 12.17 seconds**.
The final binary returns **67 KB in 32 ms**, with fifty cards/lanes and native
paging; the enormous old response was not repeated in this final paired run.
The grouping experiment returns the same 123,928 JSON bytes in both binaries.
The private-record row stays roughly unchanged because permission I/O remains
current. Large bodies exceed the per-collection cache budget, so gains there
are deliberately modest.

Headless Chrome confirms an unchanged table opens one document and one scoped
EventSource, with no reset-driven second list fetch. The 500-view home page's
settled DOM shrank from 8,594 nodes in the earlier browser probe to 1,777; the
final count poll subsequently returns `304` when unchanged. These are sampled
browser checks; occasional long tasks still occur, rather than a guarantee of
zero main-thread work.

The write fixture is fully verified: **50,218 events, 10,201 records, 234,410,789 journal bytes**. Most added events carry a roughly 4 KiB body snapshot. Each trial copies the same fixture, warms verified history, then sends 14 concurrent PATCH requests. New keys are distinct. Startup/index establishment is excluded and reported separately by the probe; all requests must succeed. No reduced audit verification cadence is used.

Before idempotency indexing, the keyed batch took **26.80 seconds**, versus **1.46 seconds** without keys. Indexing alone reduced keyed writes to **1.60 seconds**, near the plain batch's **1.53 seconds**, in the earlier paired experiment. The final checkpoint change additionally removes whole-state serialization from each serving write, while advancing the in-memory walk immediately to prevent a whole-map copy on the next admission. The final paired batches above completed all fourteen requests successfully in both binaries; startup/history warm-up took about 1.6–1.8 seconds.

## Validation and remaining choices

Regression coverage checks current grants/suspension/ACL/schema changes, protected-record handling, immediate local invalidation, exact-content expiry and ID changes, concurrent single-flight fills, cancellation, indexed backlinks, stale-save refusal, historical idempotency results, retries racing later edits, journal tampering/forgery, recovery and checkpoint resumption, YAML sort/group equivalence, scoped hidden-change isolation, reconnect generations, native move controls, bounded boards, paged/searchable views, deferred relations, and permission-aware ETag revalidation. The existing signal/shutdown and crash-recovery tests also exercise the durable write path.

Cold collection reads and current private-record ACL checks still scale with records. The verified journal still checks sealed-segment metadata and current-segment bytes; a periodic full walk (64 appended events by default), explicit verification, and the first history replay remain linear in history. These are intentional integrity constraints. Static assets already use content-addressed browser caching and relation traversal already has depth/record budgets; OpenAPI was inexpensive at the tested schema count.

Further sorted-ID/query indexes, cold-fill parallelism, persistent SQLite metadata, or body projections should follow measurements at larger datasets and concurrent live-reader load. They add memory/invalidation or storage contracts, and are not needed to remove the measured quadratic output, repeated parsing, asset hashing, and per-write checkpoint costs. Track cold/rebuild time, p95/p99 under browsing plus writes, permission I/O, cache pressure, freshness lag, and browser long tasks on smaller machines as well as this VM.

Synthetic probes and raw results are saved in ignored `.context/` workspace artifacts: `deep_scale_probe.py`, `deep_case_probe.py`, `deep_browser_probe.mjs`, `idempotency_write_benchmark.py`, the `final-*.jsonl` and `all-*.jsonl` results, and verification logs. They operate on synthetic databases and are not shipped with the repository.

The completed change passes **906 tests**, `cargo clippy --locked --all-targets -- -D warnings`, `cargo fmt --all --check`, `git diff --check`, JavaScript syntax checking, and the regenerated Tailwind stylesheet check. Release probes use `cargo build --release --locked`.
