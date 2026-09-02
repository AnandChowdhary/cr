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
├── .cr-audit-head.json    # the audit anchor, committed to version control
├── .cr/
│   ├── config.yaml        # optional overrides
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
│       ├── runs/
│       │   ├── notion-meetings.json
│       │   └── notion-meetings.jsonl
│       └── state/
│           └── notion-meetings.json
└── records/
    ├── candidates/
    │   └── jane-doe.md
    └── companies/
        └── acme.md
```

- `.cr-audit-head.json` is the audit anchor: the newest event's sequence, hash, and timestamp, kept outside `.cr/` so that an ordinary `git add .` picks it up. It is derived state — deleting it loses a guarantee, never data.
- `.cr/` is the database marker. An absent `.cr/config.yaml` uses format version 1, `records/`, 256 events per audit segment, and an 8 MiB segment limit. A present config can override any subset while unknown, malformed, unsafe, or unsupported settings remain errors.
- A collection is a directory; a record ID is its Markdown filename without `.md`. See [What a record is](#what-a-record-is) for what happens when a filename cannot be one.
- Front matter contains arbitrary model attributes.
- The Markdown body is opaque user content and is preserved by metadata-only updates.
- Relations live under `relations.<name>` as lists of `{ collection, id }` references. `cr link` verifies the target exists and is idempotent.
- A collection schema is optional and validates only its front matter.
- A saved view is an optional versioned query/display definition. Collections also receive automatic views without a file.
- A saved sync is an optional versioned command definition. Its mutable JSON checkpoint and advisory lock are stored separately from configuration, as is the ledger of a run that has started applying records and not yet finished.

### What a record is

The records tree is enumerated from four places: `Database::list` (and so `search` and every view), `Database::record_files` (and so `status`, `save`, `audit baseline`, and `sync run`), `AuditLog::verify_records`, and `cr check`'s index. A filename that is a record to one of them and not to another is a database that disagrees with itself, so all four call `database::collection_entry` and `database::collection_directory_name` and there is no second definition to drift from.

The definition: a directory under `records/` is a collection if its name is a usable path component; a file inside one is a record if its name ends in `.md` and the rest is a usable path component. A usable component is non-empty, is neither `.` nor `..`, and contains no `/`, `\`, or NUL — the same rule `cr create` applies to an ID a caller types, so a record that can be enumerated is exactly a record that could have been created.

Anything that is not a `.md` file is ignored, and always was. A `.md` file whose name cannot be an ID is an error, everywhere, rather than being skipped. That is a deliberate trade: one such file blocks every write path in the database until it is removed. Skipping it instead would mean `cr save` silently not saving a file the user can see, and `audit verify` passing over a record it never examined, which is a worse failure for a tool whose value is that the journal accounts for every record.

What makes the trade payable is the refusal itself. It is a `DomainError::Conflict` — the stored state is unusable, not the request, so a `GET /api/v1/collections/deals/records` that asked for nothing unusual gets `409 conflict` rather than a `422` blaming the caller or an unclassified `500` hiding the reason. And it names both facts needed to fix it:

```text
collection 'deals' contains a Markdown file named '..md' whose name cannot be a record ID
```

A bare filename inside a named collection is not a filesystem path, so this stays inside the no-path-leakage invariant while still being enough to act on. `cr check` reports the identical sentence as an `invalid_record_name` finding and carries on scanning, so the database remains diagnosable at exactly the moment nothing else will touch it.

Two enumerations of the same shape are deliberately not part of this: saved views and sync definitions name themselves from `.cr/views/` and `.cr/syncs/` and validate independently, because they are separate namespaces with their own labels.

### Path resolution

The root is resolved once, when a database is opened or discovered, so a user may keep the database behind a symbolic link. Everything below it is treated as hostile input: an editor, a sync adapter, a synchronized checkout, or another local process can create entries there, and none of them may cause `cr` to touch anything outside the root.

A database-relative path is therefore never handed to the operating system as one string. `src/paths.rs` walks it component by component from a descriptor for the root, opening each component with `openat` and `O_NOFOLLOW`, and then opens, replaces, links, renames, or unlinks the final entry through the descriptor of its verified parent. Only plain components are accepted, so `.`, `..`, an absolute path, and a NUL byte are refused before any syscall. Files are opened `O_NONBLOCK` and checked to be regular, so a named pipe cannot stall a read and a device cannot be mistaken for Markdown. Atomic publication uses `linkat` for a create that must not clobber and `renameat` for a replacement that preserves the destination's permissions, both relative to that same descriptor, followed by an `fsync` of the directory.

This makes the check and the operation the same act rather than two racing ones. A symbolic link planted before the walk is refused whatever it points at, including one pointing back inside the database, and a link swapped in after the walk cannot redirect a descriptor that is already open. Two smaller windows remain and are accepted deliberately for a local-first single-user tool. Directory *listings* are read from the resolved path rather than the descriptor, which is harmless because a listing is never trusted on its own: every name it yields is reopened through the same walk before it is read. And the sync working directory is verified before the adapter's output is staged in it with `tempfile`, which is a check-then-use window rather than a descriptor-relative write. Platforms without `openat` fall back to checking each component with `symlink_metadata`, which refuses the same planted links without closing the race.

Refusals are classified `DomainError::Conflict`, so they reach a caller as `409` with wording that names the record, collection, view, or configuration directory involved. The resolved location stays underneath the classification in the `anyhow` chain, where the CLI and the server log can use it and a response cannot.

## Audit protocol

Each stored line is a small JSON wrapper containing a SHA-256 hash and an exact JSON payload. The payload contains:

- format version, global sequence, UTC timestamp, actor, source, optional agent/authorization/intent attribution, optional message, and action;
- collection and record ID;
- JSON Pointer-like field changes with distinguishable absent and `null` values;
- SHA-256 hashes of the complete record bytes before and after the mutation;
- the previous event hash, chaining events across segment files.

Create and baseline events store the complete after-state. Delete events store the complete before-state. Updates and links recursively diff objects while treating arrays and scalar values as replaceable units. Version 2 changes use explicit `add`, `remove`, and `replace` operations, so an absent value remains distinguishable from a present `null`. The reader accepts and safely converts version 1 change objects while retaining their original hashed bytes.

Verification replays these operations independently for each record. Every event's `before_hash` must equal that record's prior audited hash, every change's before-value must equal the replayed semantic state, and record presence must agree with `after_hash`. This replay makes the prior document available even after somebody directly edits or deletes its Markdown file.

### The audit anchor

The newest event is the one weak point of a hash chain: every other event is pinned by the `previous_hash` of the event after it, and the last one has no successor. `audit head` and `audit verify --expected-head` have always been the mitigation, and their weakness was never cryptographic — it was that using them is a manual step, so nobody did.

`.cr-audit-head.json` at the database root makes that step automatic. It holds `{version, sequence, hash, timestamp}` for the newest event, one field per line, in a stable order, newline-terminated, so a commit diff shows the head hash moving and a reviewer can reason about it. Every field is derived from the journal, and the timestamp is the anchored *event's* timestamp rather than the moment of writing, so the file is a pure function of the chain: `cr` can recompute what it should contain, and two databases holding the same journal hold byte-identical anchors.

**What this buys, stated plainly.** A file at the database root is writable by anybody who can write `.cr/`. On its own it stops nothing: an attacker forges the head event, recomputes its hash, and rewrites the anchor in the same pass, and verification goes quiet again. `tests/audit_corruption.rs::a_forged_head_event_is_accepted_by_verification_and_caught_only_by_a_checkpoint` performs exactly that pair of writes and still passes. The protection comes entirely from **committing the anchor to Git**: a pushed, distributed history is a second write boundary that a local filesystem write cannot reach, and a reviewer who sees the head hash change in a diff that contains no records — or sees it change to a value nobody's working copy produced — is looking at the tamper. The feature being shipped is ergonomics and a default-on check, not a new cryptographic guarantee.

**When it is written.** Inside the single `append` that every chain-advancing path funnels through — `create`, `update`, `link`, `delete`, `save`, `sync`, `audit baseline`, and pending-mutation recovery — immediately after the event is durable. Writing it *before* the append would let the anchor lead the journal, which is indistinguishable from events having been removed. Writing it after means a crash in between leaves the anchor exactly one event behind, which is a state the design has to handle rather than avoid.

**Stale versus tampered.** This is the design's main risk, and it is resolved by anchoring a *position* rather than only a hash. Because the journal is append-only and hash-linked, the event at a given sequence is fixed for all time. So `verify` does not ask "does the anchor equal the head?"; it recomputes the anchor the journal implies at the anchor's own sequence and gets three separable answers:

| Journal at the anchored sequence | Meaning | Result |
| --- | --- | --- |
| does not reach it | events were removed, or the anchor was rolled forward | `DomainError::AnchorMismatch` |
| holds a different event | history at or before that point was rewritten | `DomainError::AnchorMismatch` |
| holds the same event, and more after it | the anchor merely lags | pass, with a notice naming both sequences |

Lagging can never produce either failure, and neither failure can be produced by lagging. A lag is still a real reduction — the events past the anchored sequence are pinned by nothing again, exactly as before the anchor existed — so `verify` prints it, `check` reports `audit_anchor_behind` at warning severity, and `cr audit anchor --write` repairs it without needing a mutation. That command refuses while the anchor disagrees with the journal, so `cr` is never the tool that launders a forgery into a fresh attestation.

`AnchorMismatch` is its own classification, `409 anchor_mismatch` over HTTP, for the same reason `ApprovalMismatch` is: an auditor told "the chain is corrupt" when the chain is intact and the *anchor* disagrees will go looking in the wrong place.

**Absent, unreadable, and overridden.** An absent anchor passes with a notice rather than failing, so databases that predate the file keep working and adoption is `cr audit anchor --write` plus a commit; `check` reports `audit_anchor_missing` at warning severity. An anchor that cannot be parsed, or that names a format version this build does not know, is a refusal rather than an "absent" — treating a scribble as a missing file would let one stray byte silently turn the default check off. An explicit `--expected-head` wins over the file and says so, because the flag arrives from outside the database while the file sits inside the blast radius of anybody who can edit the journal.

### Agent attribution

`actor` is the responsible human and keeps that meaning in every event ever written. When software acts on that human's behalf, three optional objects are recorded beside it rather than replacing it: `agent` (which software, at which version and model, in which session and turn, with a `via` delegation chain for sub-agents), `authorization` (a normalized `mode` plus the raw vendor `grant` and any separately-known approver and time), and `intent` (the human's `request` and the agent's `rationale`, each tagged with an `author`). The polarity — human primary, agent qualifier — follows every system designed specifically for agents acting for humans, and is forced here anyway: reassigning a field's meaning partway through an append-only log is the one thing such a log must never do.

Both halves of the intent are stored because they answer different questions. The request is evidence about the human and the rationale is evidence about the agent; a misinterpretation is invisible if only the rationale is kept, because the summary is written by the party whose interpretation is in question, and a misattribution is invisible if only the request is kept, because one instruction typically causes many writes. Each event is self-contained: the text lives in the event rather than behind a session pointer, because a session identifier is a foreign key into a store with a different owner and a shorter lifetime, and a pointer to a deleted transcript looks like traceability without being it. The session and turn identifiers are kept as well, as secondary correlation keys that cost nothing when the transcript is gone.

`agent.detected_from` records how `cr` came to believe an agent was involved — `environment` for a documented variable, `flag` for `--agent` or `CR_AGENT`, `header` for `X-CR-Agent`, `config` for a sync definition — and **none of its values means verified**. Detection probes only variables their vendors document for this purpose (`CLAUDECODE`, `CURSOR_AGENT`) and records only what it observed; an explicit declaration always outranks a sniffed environment, and enriching an observed agent with declared details downgrades its evidence to the declaring source rather than overstating what was seen. Callers can supply the fields but never `detected_from` itself: the stored types accept unknown fields so a newer writer cannot break an older reader, while the separate input types reject them.

Adding these fields does not change `AUDIT_VERSION`. Every one is `Option` with `skip_serializing_if`, so an event with no attribution serializes to exactly the bytes it did before, and verification hashes stored bytes rather than a reserialization, so existing chains verify to identical head hashes. A bump would have been the harmful choice: `parse_line` rejects any version outside the supported range, so one newer event would make an older `cr` hard-fail an entire chain, and a metadata addition must never be able to make `audit verify` fail. The cost, accepted deliberately, is that an older binary silently omits these fields when it displays an event. For the same reason the payload must never gain a non-optional field, a `HashMap`, or a `#[serde(flatten)]`.

The same argument applies to the *values* of `agent.detected_from`, `authorization.mode`, and `intent.<part>.author`, so all three read tolerantly. A label this build does not know deserializes into an `Other` variant that preserves the original string verbatim and serializes it back unchanged, so an event naming a value a later `cr` invented still verifies here, under its stored hash, byte for byte. A closed enum would have failed the payload and therefore the whole journal, including its unrelated events; a tolerant reader that normalized the unknown label to a default would have succeeded on read and silently changed the bytes the hash covers, which is worse. Reading is permissive and writing is strict: every caller-supplied value is checked against the labels this build knows, so `Other` is reachable from stored bytes and from nothing else, and `cr` never records an approval mode it cannot interpret. `action` and `source` deliberately stay closed — they are core payload semantics covered by the format version, and the v1 to v2 bump exists precisely because changing what `changes` means has to make an unprepared reader stop.

### The previewed-change digest

Every mutating operation can compute its change set without writing it. `--preview` on the command line and `preview=true` in the query string stop after the change set is known: no record write, no audit event, no pending-mutation file, and the audit lock released on the way out. Preview deliberately does not run pending-mutation recovery either, because recovery appends an event; an interrupted mutation therefore makes a preview fail on the audited-state check rather than quietly predicting the wrong result.

The preview prints a digest, and passing it back as `--approved-changes` or `X-CR-Approved-Changes` records it in `authorization.approved_changes` and binds the write to it. `cr` recomputes the digest from the change set it is about to record and refuses the mutation if they differ; `audit verify` recomputes it from the event's stored `changes` and fails if they differ there. Both failures are `DomainError::ApprovalMismatch`, with their own message and their own `approval_mismatch` HTTP code, because "the change that was applied is not the change that was approved" and "the journal is corrupt" call for different responses and a shared conflict code would bury the distinction.

**The canonical form is the exact byte range the `changes` array occupies inside the serialized payload,** read back out with `RawValue`. This is the same discipline the event hash follows — hash what is stored, never what a later parse happens to produce — and it means the change-set digest covers a substring of the bytes the event hash already commits to. Preview, apply, and verify all reach it through one function. Two things would break its stability, and both are ruled out by that choice rather than argued away: re-serializing the parsed `changes` would make the digest depend on how `serde_json` renders numbers that this build did not itself write, and any writer that formats the journal differently from `cr`'s compact output would produce different bytes for the same logical change set. `cr` is the only writer, and it always writes compact.

The digest is over `changes` and only `changes`. It commits to what was applied, not to who saw it, not to the rest of the event, and not to the record's untouched fields. An agent can compute a digest and hand it to itself; what the value gives an auditor is something to compare against an approval recorded elsewhere. It is also not a second signature over the journal — anyone able to rewrite the chain can rewrite the digest with it — so `audit verify`'s branch catches a change set altered without updating the approval beside it, which is a consistency check inside one event.

That check is the part of the preview-to-apply gap the digest actually closes. State does change in between, and the existing `before_hash` guard does not close it: a competing `cr update` moves the record and the audited state together, so the guard still passes. The digest notices, because a change to any `before` value being written changes the change set. A change to some *other* field does not, and the write proceeds — an approval is over a change, not over a resulting document. `audit verify` only recomputes approvals; reading history must not fail on a mismatch, because an auditor who has just been told a change set does not match its approval needs `audit log` to still show them the event.

One digest approves one record. `cr save --preview` prints a digest per record, and an approved digest on `save` requires exactly one named record rather than being checked against one of several independent change sets; multi-record approval needs a per-record mapping and waits on the bulk-mutation design. Sync runs carry no approved digest, because an adapter has no human in the loop by construction.

`audit log` filters by `--by-agent` and `--by-session` (`--agent` and
`--session` remain compatibility aliases), matching the acting agent or any
delegate in its chain over CLI, REST, and the HTML timeline. An explicitly
blank session or turn is normalized to absence, including when it clears a
value inherited from `CR_AGENT`; host bookkeeping that belongs to no
conversation therefore does not need a synthetic session. Recording a delegate
that cannot be queried answers none of the questions the record exists for.

Segments rotate on configurable event-count and byte-size bounds. Appending atomically rewrites only the active bounded segment; verification and history reads stream segments and never require the complete journal in memory. `audit log` reads newest segments backward until its requested limit is satisfied.

Writers acquire `.cr/audit/lock`. Before changing a record, the CLI verifies the existing hash chain and confirms that the record's exact bytes match its last audited hash. That is the chain and not the full `audit verify`: a write replays sequence continuity and event hashes but not the per-record change sets, so a journal whose replay is already inconsistent keeps accepting writes and surfaces the inconsistency on the next `audit verify` rather than at the mutation. It then writes and flushes `.cr/audit/pending.json`, atomically changes or deletes the record, commits the event to a segment, and removes the pending file. Startup recovery handles the two possible atomic record states:

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

### Record authorization and the users collection

RBAC is absent by default, preserving the behavior of every database created
before it existed. `cr access init` enables it by creating the current
principal at `records/users/<principal>.md` with database ownership. The
presence of at least one Markdown user record is the feature switch; an empty
directory is deliberately not enough, so a bootstrap interrupted before the
record write leaves the database open and retryable.

`users` is a reserved collection with a built-in JSON Schema. A user record
contains `name`, optional `email`, `kind`, `status`, an application-owned open
`profile` mapping, and direct `access` grants. Keeping extensibility below one
namespace preserves the closed policy schema: future CR-owned fields cannot
collide with arbitrary application keys, and applications can choose whether a
principal record also serves as their person record. A person who can never act
still has no reason to be placed in this policy collection.
Each grant pairs one of `viewer`, `editor`, `access_manager`, or `owner` with a
resource string: `database`, `collection:<name>`, or
`record:<collection>/<id>`. Database grants inherit through the resource tree,
collection grants inherit to their records, and the most specific matching
grant replaces broader roles. Ownership is the exception: an owner grant on an
ancestor continues to authorize descendants, so a narrower viewer grant cannot
silently strip an owner's recovery authority.

The users collection is the policy store as well as the principal registry.
That makes a policy version an ordinary audited user-record version rather than
a second configuration history. Generic create, full replacement, save, and
delete mutations cannot target `users`. Partial update and patch are deliberately
field-aware: an ordinary `editor` decision may change only `profile.*`; an
active principal may change its own `name` and `profile.*` without a stored
grant; and changing another user's name or any user's email, kind, or status
requires an owner. Access remains on the dedicated grant/revoke path. Requests
that mix fields use the strongest required authorization before anything is
written, so an editor cannot smuggle a managed-field change beside a profile
change. Resource-only access checks cannot predict this field-aware boundary;
the concrete mutation records the decision actually used. `cr user` and
`cr access` preserve the fixed schema, prevent an access
manager from minting ownership or another access manager, and prevent removal
of the final active database owner. Bootstrap accepts an explicit human or
service kind. User add/ensure/update/delete operations apply lifecycle and
identity changes inside the same audit lock as the write; update cannot change
access grants, and ensure is a create-or-exact-match operation rather than a
read-then-create race. An owner-only restore reconstructs the exact latest
audited user bytes after a direct edit, without appending a fictional policy
change. Each allowed data mutation stores an
optional access decision beside the event: principal, display identity,
action, target resource, effective role, grant scope, decision basis, and the
exact hash of the user record evaluated. Stored grants omit the default `grant`
basis for format compatibility; the built-in own-record rule writes
`self_service`. Legacy and bootstrap events omit the object and retain their
original bytes.

User deletion is a specialized owner-only use of the same audited delete
protocol as every other record. Authorization, current-policy checks, final
active-owner protection, the optional unused-history scan, event preparation,
and removal all occur under the audit lock. The delete event's absent latest
document is the durable tombstone; its changes and `before_hash` retain the
prior user and all outgoing grants. `--if-unused` walks the complete verified
chain rather than a bounded history page. It treats the effective access
principal, a canonicalized legacy actor, and an explicit impersonating owner as
participation, excluding only events for that identity's own `users/ID` record.

Add and ensure distinguish a never-seen ID from a tombstone. Reuse defaults to
refusal and requires the owner-only `--reuse-deleted-id` acknowledgement, after
which an ordinary create event starts a fresh active definition with no direct
grants. Ordinary records retain their existing create-after-delete behavior.
Direct grants to an absent `record:users/ID` are removed from authorization
evaluation in memory, without mutating the grant holder in a second non-atomic
event. Such a grant can become applicable after explicit ID reuse, which is why
operators replacing a real identity should revoke incoming grants first or use
a new ID. Audit actors and access decisions are historical values rather than
foreign keys: replay and verification never require a referenced principal to
remain live. For the same reason, the own-history shortcut now requires a
current, active, audited user policy; a deleted principal cannot reclaim its old
ID merely to read the tombstone.

Authorization happens inside `Database`. Mutations evaluate under the audit
lock before preparing the event; list and search filter records by `read`; a
specific history read requires `read_audit`; and database-wide status, check,
head, anchor, verification, and baseline operations require ownership. A global
history read is different: owners receive every event, while other principals
receive only events for records they may currently audit plus their own user
history. Filtering happens before the requested limit. The
principal is the normalized policy identity derived from the actor (an email
inside `Name <email>` when present), so actor and principal remain one
user-facing identity. Once RBAC is enabled, an explicit actor with a different
principal is rejected.

This is an honest local boundary, not authenticated multi-user isolation. The
process still supplies its actor environment and anyone with backing-file
access can bypass CR. The global `--as PRINCIPAL` option gives a trusted owner
process an explicit delegation path for a single CLI command. It calls the
same verified delegation boundary as the server: the audit chain is replayed
once, the launching policy is checked and authorized before the target is even
looked up, and both materialized policy files must match that replay.
Permissions are evaluated for the selected registered user, while an allowed event's access decision
stores the launching owner under `impersonated_by`. `cr serve` exposes that
boundary through its loopback-only owner perspective console: a CSRF-protected
switcher stores one selected principal in an HTTP-only, same-site session
cookie, and every HTML and REST request clones the owner's database handle and
impersonates that selection before it reaches `Database`. `--as` cannot launch
the long-lived server, so its original operator can never be lost at that
boundary. Non-bypassable
multi-user enforcement still requires a managed daemon or server that owns the
Markdown directory and authenticates each client.

`audit verify` validates the chain and reconciles every latest record hash, including deleted-record absence and manually added untracked files. `audit baseline` explicitly introduces legacy records into the chain. It cannot silently baseline a record that already has history.

## Whole-database integrity checks

`cr check` and `GET /api/v1/check` answer one question — is this database coherent? — and answer it exhaustively. Every other integrity-adjacent operation stops at the first problem, because each of them guards a write: `audit verify` returns one classified failure, and a mutation refuses rather than describes. That is wrong for a command an operator runs *because* something is already broken, so `check` collects findings instead of propagating them. A database with a damaged journal is still fully inspectable for dangling links and schema drift, and a record that cannot be parsed does not hide the record after it.

A finding carries a severity, a kind, the `collection` and `id` it concerns, the dotted `field` where one applies, and a `target` for a relation. It never carries a filesystem path — the same invariant the `DomainError` messages hold, and one that matters more here because a check report is the output most likely to be pasted somewhere public. Failures raised inside the scan are therefore not forwarded verbatim: only a `DomainError`'s own authored message reaches a finding, and a chain failure, whose text names segment files, is replaced by a fixed sentence that points at `audit verify` for the detail.

The twelve kinds are `dangling_link`, `malformed_relation`, `schema_violation`, `unusable_schema`, `invalid_record_name`, `unreadable_record`, `unaudited_record`, `missing_record`, `record_content_mismatch`, `audit_chain_broken`, `approval_mismatch`, and `interrupted_sync_run`. Relation references tolerate extra keys beside `collection` and `id`, because an annotated reference is still a reference and a check that fires on a working database is worse than no check.

`interrupted_sync_run` is the one finding that is about durability rather than integrity, and it is separated from the audit-reconciliation kinds for that reason. A sync run writes a ledger under `.cr/sync/runs/` before its first mutation and removes it once the checkpoint agrees with the committed work, so a ledger on disk means a run stopped in the middle. Nothing else surfaces that: the records the run did commit agree with the journal, so `status` reports clean and `audit verify` passes, and the only other ways to find it are `cr sync recover <name> --check` or being refused by the next run. `check` reads the ledger through the same safe path walk as everything else, names the sync and never the file, and points at `cr sync recover <name> --check` rather than recovering anything itself. The ledger is deliberately not hash-chained, so a missing or damaged one is not evidence of tampering and is never reported as an integrity failure.

It is a `warning` for two reasons. The committed prefix is sound, so the database's integrity is intact and a supported remedy exists. And `check` deliberately does not take the per-sync lock, so it cannot distinguish an abandoned run from one that is running at this moment; failing a build because an import happened to be in flight would be wrong. `--fail-on warning` is there for deployments that want it to fail anyway.

Sync findings and journal findings are database-wide, so `--collection` does not suppress them; it bounds the per-record phase only.

The scan has three phases. A cheap directory index lists collections and record filenames and is always whole-database, so a relation pointing into another collection can still be resolved under `--collection`. The expensive phase — read, hash, parse, and schema-validate — is bounded by scope, and compiles one validator per collection rather than one per record, which also means an unusable schema is reported once instead of once per record. The reconciliation phase replays the journal and compares it with the index. `check` takes the audit lock for the whole scan, exactly as `status` does, so a mutation landing halfway through cannot manufacture a finding; it deliberately does *not* run pending-mutation recovery, because recovery appends an event and a read-only command may not write. An interrupted mutation is visible instead as an ordinary reconciliation finding.

### `check` versus `status`

`status` is the working-tree view. It answers *what would `cr save` record next?*, and every row it prints is an expected, resolvable direct edit. `check` reports the same three physical conditions — a record with no audit history, an audited record whose file is gone, and a file whose bytes do not match the audited state — because a whole-database integrity report that omitted them would be misleading. It reports them at `warning` and points back at `status`, **provided `cr save` could actually reconcile them**. When the same record also fails to parse, fails its schema, or cannot be named, `save` refuses it, the divergence is permanent until a human intervenes, and the finding is escalated to `error`. That is the boundary: `status` enumerates the working set, and `check` says whether the working set is reconcilable and whether the journal underneath it is sound. Everything else `check` reports — dangling links, malformed relation values, schema drift, unusable schemas, invalid names, chain damage, approval mismatches — is invisible to `status` entirely.

`check` is also a superset of what `audit verify` refuses, with one exception. Chain damage, approval mismatches, records missing from the journal, and records diverging from their audited state all appear as findings rather than as a single early failure. `--expected-head` has no `check` equivalent: anchoring the head against an externally stored checkpoint is a deliberate act with an argument, not a scan.

### Exit status and severity

A check command belongs in CI and cron, where "the database has a dangling link" and "the check could not run" call for completely different responses. `cr check` therefore exits 0 when nothing reached the failure threshold, **2** when something did, and 1 only when it could not run at all — a missing database, an unusable `--collection`, an unreadable configuration. Collapsing findings into 1 would make a typo in a scheduled job look like a clean bill of health. `--fail-on error` is the default, `--fail-on warning` makes unsaved direct edits fail too, and `--fail-on never` reports without ever failing.

There are two severities rather than four. The only decision a caller makes from a severity is whether to fail, and further gradations would be judgements `cr` is not entitled to make about somebody else's data.

The HTTP route always answers `200` on a successful run, including when it found problems: the findings are the resource, and a broken database is not a transport error. Findings paginate with the same `limit`/`offset` contract as `status`, and the `summary` object sits beside the page rather than inside it, so a caller reading page three can still tell a clean database from a broken one.

### Read-only, and why there is no repair mode

`check` writes nothing: no record, no audit event, no configuration file, no index. This is proven by a byte-level before-and-after snapshot of every file beneath the root, taken across a plain run, a JSON run, and a scoped run on a database that has problems to report. There is deliberately no `--fix`. The findings have genuinely different right answers — a dangling link may want the relation removed, the target restored, or a delete policy applied — and a command that both diagnoses and mutates cannot be run unattended. `TODO.md` records the conditions a future repair verb would have to meet.

`check` is O(records + events) with no index to lean on, like `list` and `search`, and it holds the audit lock for the duration. `--collection` is the only bound today; `TODO.md` carries both the index and the bounded-replay follow-ups.

## Sync extension protocol

`.cr/syncs/<name>.yaml` stores format version 1, an exact command argument array, timeout, output-byte limit, message-count limit, and optional audit actor. Sync names are single path components. The configuration is intentionally data rather than executable shell text; `sh -c` or a script file must be explicit when shell interpretation is wanted.

`cr sync run` takes a nonblocking per-sync lock, then verifies that records and audit history are clean. It starts the adapter in the database root with stdin closed, stdout redirected to a bounded temporary file, stderr inherited for job logs, and a random run ID. A previous checkpoint is copied into a temporary JSON input so the adapter cannot mutate the committed cursor in place. On POSIX, the adapter receives its own process group so timeouts and output violations terminate descendants as well as the immediate child.

The `cr-jsonl-v1` stream has three internally tagged messages:

- `upsert` contains `collection`, `id`, a complete `front_matter` mapping, and complete `markdown` body;
- `delete` contains `collection` and `id`;
- an optional final `checkpoint` contains any JSON value.

The complete bounded output is parsed before application. Unknown fields, malformed JSON, unsupported paths, duplicate record targets, messages after a checkpoint, excessive output, and excessive message counts fail the run. Every upsert is schema-validated before the first mutation, and the database is verified a second time to detect direct or concurrent record edits during the external command.

Application uses the same `Database` mutation methods as the CLI and HTTP server with `source: sync` and `message: sync:<name> run:<random-id>`. A separate application lock serializes the post-process verification and application phases across different sync names. Under the audit lock, the audit head must still equal the head observed before the command started and every stream target is captured as either absent or its exact record version. That single snapshot closes the gap between checking the head and reading targets. Existing upserts and deletes then use conditional replace/delete against those captured versions; creates remain atomic absent-to-present writes, and idempotent upserts or missing deletes assert their captured state under the same audit lock without creating noise. Each condition also requires the complete audit sequence expected after the preceding sync event, and the sequence comparison occurs under that same mutation lock. Thus any audited writer landing after the snapshot stops the remaining stream, including a target edit that later restores byte-identical contents and therefore restores the same content-based ETag. The checkpoint must also match its initial value and is atomically replaced only after record operations succeed. A nonzero adapter exit or any preflight failure applies neither records nor state.

### Interrupted runs

This is not a multi-record transaction, and it deliberately does not pretend to be one. After preflight, individual record changes use the existing one-record write-ahead audit protocol, so a durable failure during the application loop still commits a prefix. The property the design does hold is narrower and honest: **a run cannot leave committed work and the recorded checkpoint disagreeing without that being durably recorded, reportable, and completable.**

Rollback is not available and is not attempted. The journal is append-only, so unwinding a prefix would mean deleting events, and forward-only compensation — appending inverse mutations — would replace one true history with a longer, more confusing one for no gain over simply finishing the run. Advancing the checkpoint per record is not available either: the protocol's checkpoint is a single opaque adapter value emitted once at the end, and `cr` cannot invent an intermediate cursor an adapter never described.

What is available is making the run itself durable. After preflight and the locked head-and-target snapshot, and before the first mutation, `cr` writes `.cr/sync/runs/<name>.jsonl` — the adapter's exact validated stream — and then `.cr/sync/runs/<name>.json`, a version-2 ledger naming the run, its start time, its operation count, a domain-separated digest of that stream, the audit head it started from, every target's present/absent version at that head, and the checkpoints it began with and owes. The stream is written first, so a ledger on disk always has its operations beside it. Both are removed only after the checkpoint has been committed, ledger first, so an interruption while tidying up can only leave a stream that claims nothing about committed work and is discarded by the next run. A version-1 ledger from an earlier build remains recoverable: because it recorded the audit sequence and head but not target versions, recovery replays that immutable chain prefix and selects the stream targets from the reconstructed state rather than adopting current bytes.

A ledger on disk is therefore the single fact that separates "a run finished" from "a run stopped somewhere in the middle". `cr sync run` refuses to start while one is present, which is what stops a stale checkpoint from being silently replayed. `cr sync recover <name>` completes the run by replaying the recorded stream, which is sound rather than merely convenient: `cr-jsonl-v1` guarantees each target appears at most once, an upsert carries the complete record, and deleting a missing record is a no-op, so a replay commits exactly the operations the interrupted run never reached and appends no event for the rest. The events it appends carry the interrupted run's own ID, so the journal shows one run rather than two.

Progress is never counted into the ledger as the run proceeds. `cr sync recover --check` reads it back out of the audit chain by counting events after the ledger's recorded head that carry both `source: sync` and this run's message, so an ordinary CLI or API event cannot become run progress by copying the message. Before replay, recovery also checks that every purported run event names a stream target, uses the create/update action and exact resulting hash promised by an upsert or the delete action and absent result promised by a delete. The same pass identifies records changed after the run stopped by anything other than that run: recovery refuses if any of them is a record the run still has to write, and proceeds if they are unrelated. For targets already committed by the interrupted run, recovery advances the ledger's expected version only to that validated event's audited `after_hash`; every remaining operation still compares against the original head-bound target version. Recovery captures the events and current audit sequence under one lock, then requires that generation inside each mutation lock, advancing it only after its own commits. A foreign writer racing after the scan is therefore caught even if it restores the target's original bytes. Recovery also refuses when the recorded stream no longer matches the digest in its ledger, when the chain was rewritten beneath it, or when the checkpoint moved for some other reason.

Two limits remain. If the original failure is still present, recovery reproduces it and leaves the ledger in place; that is a truthful stuck state, not a repaired one, and it needs a person. And remote side effects an adapter performed occur outside the database entirely, so a replay can re-drive them: an adapter that also writes to a remote service must use that service's idempotency controls.

Adapters are trusted local executables, not a sandbox. They inherit the caller's environment—including secrets—and operating-system access to files, processes, network services, and external APIs. Limits constrain runtime, protocol output, and message count, but not CPU, memory, network traffic, stderr volume, or platform-specific child behavior. The scheduler and service account remain part of the deployment security boundary.

### Threat boundary

The hash chain detects modified payloads, missing or reordered middle events, segment gaps, internally inconsistent record changes, and current-record divergence. It cannot by itself prove that the final events were not removed or that an attacker with full write access did not rewrite the entire chain. The *newest* event is the specific weak point, and for the same reason: every other event is pinned by the `previous_hash` of the event after it, and that one has no successor. Two things still constrain it — the replay checks each change's `before` value against the state it reconstructed, and record reconciliation pins `after_hash` to the file on disk — but the rest of it, including `actor`, `timestamp`, `message`, attribution, and the `after` value of every change, can be rewritten and re-hashed without `audit verify` objecting. Verification also does not cross-check the replayed document against `after_hash`, only its presence. `audit head` exists so the sequence and head hash can be signed, timestamped, committed, or uploaded outside the database; `audit verify --expected-head` checks such a checkpoint, and `.cr-audit-head.json` maintains one automatically so that `audit verify` performs the check by default. That anchor moves the practice from "remember to do this" to "already done", and it moves nothing else: it lives at the database root, so the same write access that rewrites the journal rewrites it, and its value depends entirely on the copy in a pushed Git history rather than on the copy on disk. Stronger deployments can later automate Ed25519-signed checkpoints or remote transparency-log anchoring without changing event files.

Actor values are assertions supplied by the process, not authenticated principals. Resolution prefers the explicit CLI override and `CR_*` environment, then Git author environment/configuration, then common email and OS-user fallbacks. In an RBAC-enabled local database the normalized actor is also the policy principal and a later `--actor` cannot change it, but the original environment remains process-controlled; signed requests, trusted operating-system identity integration, or a managed service boundary would be required to authenticate it.

Agent, authorization, and intent are assertions on exactly the same footing, and the schema says so rather than implying otherwise through field names. `cr` is an ordinary local process with no attestation authority, so it cannot establish that an agent is what it claims, that the human actually asked, or that a rationale is honest or complete; `CR_AGENT=none` suppresses detection and produces an event indistinguishable from a human's. None of it may ever gate an authorization decision, and the delegation chain is informational only. What the design does achieve is a conventional, cheap, structured slot, so that in the ordinary honest case the record stops making a false statement, and in every case the absence of attribution becomes information rather than silence. The one locally checkable property is the previewed-change digest below; everything else in this section is a claim.

The journal contains historical values and deletion tombstones, and intent text adds volume to that permanence rather than a new class of risk. Text is bounded per field and per event, and exceeding the bound is an explicit error rather than a truncation. An intent part can alternatively carry a digest and reference instead of inline text, so a deployment that must be able to delete intent later can adopt content-addressed storage without a schema change.

The journal contains historical values and deletion tombstones. Encryption, redaction rules, retention, and non-bypassable backing-store isolation remain deployment concerns and must be designed before storing regulated or highly sensitive data.

## Query and indexing strategy

Version 1 scans and parses one collection for every `list`; `search` scans either one selected collection or all collection directories in deterministic order. This keeps behavior easy to inspect and makes valid manual edits immediately visible. An index can be added later as disposable derived state keyed by file path, modification time, size, and content hash. The CLI must always be able to rebuild it from Markdown.

Exact filters support typed equality and dotted field paths. A shared `FilterExpression` layer adds numeric and ISO string/date ordering, string and array containment, prefixes/suffixes, and explicit empty checks to CLI `--where-expr`, REST `where_expr`, and HTML views. CLI and REST repeat expressions with AND; the view builder additionally supports a bounded all/any group inside the mandatory saved-view scope. Search is literal and case-sensitive by default, with explicit case-insensitive and Rust-regex modes. It can target the exact Markdown document, parsed front matter, one dotted field, the body, or the database-relative path. Rust's regex engine provides linear-time matching and avoids executing shell commands or user-supplied programs.

CLI list and search results are intentionally compact: plain output contains relative Markdown paths, while JSON contains `{ path, front_matter }` objects. Record bodies remain available through `get`, avoiding unexpectedly large multi-record responses. A shared sorter operates on the filtered result before output or HTTP pagination. It accepts one dotted front matter field or `$id`, `$collection`, and `$path`; values use the same typed YAML ordering as HTML views, missing values remain last in either direction, and collection plus record ID provide deterministic ascending ties. CLI `--sort`/`--desc`, REST `sort`/`direction`, and HTML view sorting all call this shared layer.

A future expression grammar can add nested Boolean groups, `NOT`, membership sets, multi-field ordering, projections, aggregation, backlinks, and cursor pagination without changing the file format.

## HTTP transport and OpenAPI

`cr serve` is a transport over `Database`, not a subprocess adapter around the CLI binary. CLI and HTTP handlers therefore reach the same validation, locking, write-ahead audit, atomic file replacement, search, and reconciliation code. The database instance carries an audit source: command-line mutations use `cli`, REST mutations use `api`, accepted direct edits retain `filesystem`, and adapter mutations use `sync`.

Axum runs synchronous filesystem operations through its blocking worker pool so scans and durable writes do not block asynchronous socket workers. The database-wide audit lock remains the concurrency boundary. A PATCH deep-merges front matter and removes explicit dotted paths while holding that lock, so concurrent patches cannot overwrite fields merely because both began from an older HTTP read.

The authoritative version of a record is `sha256:` plus SHA-256 over
`b"cr:record:v1\0" || exact_stored_markdown_bytes`. The explicit domain keeps
record hashes distinct from event and change-set digests and is retained for
compatibility with the `before_hash` and `after_hash` values already in audit
history. `Record.version`, REST JSON, and CLI `get --json` expose the unquoted
value; REST single-record and exact-document responses carry its quoted form
as a strong `ETag`. A `RecordPrecondition` reaches the mutation
primitive rather than being checked in a handler: `run_update`, `run_link`, and
`run_delete` acquire the audit lock, authorize, read the current bytes, compare
their hash, and only then calculate and prepare the event. Thus a concurrent
writer cannot enter between comparison and commit, and a failed condition
creates no pending mutation or audit entry. HTTP supports strong `If-Match`
lists and `*`; weak validators never match. Atomic PATCH, delete, and link
requests use the condition when supplied. Whole-document PUT requires one and
answers 428 when it is absent. A false condition, including a target that no
longer exists, is the typed `PreconditionFailed` domain error and maps to 412
`precondition_failed`; the CLI exposes the same code through
`--json-errors`. CLI `update`, `link`, and `delete` construct the same condition
from `--expected-record-hash`.

The REST API uses generic collection and record routes. List, search, status, and audit-log endpoints support bounded `limit`/`offset` windows. Record scans can report an exact total. Audit history intentionally reads only `offset + limit + 1` recent matching events, so its total is unknown while `has_more` remains exact; this preserves the segmented journal's bounded-read design.

The OpenAPI 3.1 document is produced on demand at `/openapi.json`. OpenAPI 3.1 uses the Draft 2020-12 JSON Schema model, allowing collection schemas to be embedded without translating them into Rust types. The document includes generic transport schemas plus one live component per `.cr/schemas/<collection>.json`; `x-cr-collection-schemas` preserves the mapping when collection names are not safe or unique component identifiers.

Failures carry a typed `DomainError` classification attached to the `anyhow`
chain rather than being recovered from message text. The domain layer names the
meanings a caller can act on—not found, already exists, forbidden, conflicting
durable or audited state, a failed record precondition, invalid input, approval
mismatch, and anchor
mismatch—and writes the caller-facing wording at the point of failure, so it
names records, views, collections, and fields instead of paths. The HTTP layer
maps each classification to one status and code and treats an unclassified
failure as `500`/`internal_error`. By default the CLI keeps printing the
complete chain; global `--json-errors` instead emits the same stable domain code
and authored message in a JSON envelope, uses `usage_error` for command-line
parsing failures, and reserves `internal_error` for unclassified failures.
Transport-level problems the domain layer never sees—authentication, routing,
body decoding, and body limits—keep their own codes.

Every request receives a correlation ID, returned as `X-Request-Id` and inside the error envelope. Before a response is rendered, the server writes the complete chain to standard error under that ID together with the method, path, status, and code; unexpected failures replace their message with a fixed generic one. Expected client errors keep their actionable wording. This holds the line that internal detail is a server-side artifact: the log is authoritative for diagnosis and the response is authoritative for what a caller may know.

The server binds to loopback by default. `CR_API_TOKEN` enables bearer authentication for HTML views, the OpenAPI document, and all `/api/v1` routes; `/health` remains public. `X-CR-Actor` is an audit attribution override with the same assertion-only trust boundary as CLI actor values, and `X-CR-Agent`, `X-CR-Authorization`, and `X-CR-Intent` extend that boundary unchanged to the three attribution objects. Each accepts the same compact or JSON form as its command-line option and is recorded as `detected_from: header`; because HTTP header values are visible ASCII, non-ASCII intent text must arrive as JSON escapes, and a header that is not decodable is refused with a message that names the header and nothing internal. `GET /api/v1/identity` returns the effective actor, principal, optional impersonating owner, and attribution a request would record, which is how a client checks its wiring without writing anything.

For RBAC, router construction proves the launching principal is a database
owner against its audited policy and rejects a non-loopback bind before opening
a listener. Every selected perspective is also checked against the same
verified delegation boundary before a request uses it. The single
bearer token is not treated as a principal registry. Instead, the local owner
console enumerates the live fixed-schema user records and switches perspective
through a CSRF-protected POST. The resulting HTTP-only, same-site cookie is a
selection, not an authentication credential: any client admitted to this
local console is intentionally allowed to choose any user. Responses vary on
the cookie and are marked `no-store`. The server still does not implement TLS,
per-token users, or rate limiting; real network deployments must supply an
authenticated principal boundary rather than exposing this console.

## Views and server-rendered HTML

`.cr/views/<name>.yaml` stores a format version, title, target collection, typed equality `filters`, richer shared `where_expr` predicates, bounded structured `filter_groups`, visible dotted columns, layout, optional Kanban grouping field, optional default sort field and direction, and default page size. Equality and `where_expr` predicates are an immutable AND scope. Every structured group preserves its own all/any mode, and groups are ANDed with that base and with the browser's current ad hoc group, so a URL cannot broaden the configured view. These files contain no record data. A saved view overrides the automatic view with the same route name; otherwise each discovered collection is available at `/<collection>`. Saved and automatic views whose collections the effective principal cannot discover are omitted. View names reserve their single-segment root routes, while `/health`, `/audit`, `/openapi.json`, `/perspective`, `/users`, and `/api` remain server-owned. Absent query sorting inherits the saved default; an explicitly empty `sort_field` clears it for that URL, while any chosen field overrides it. Legacy view files deserialize with no expression predicates or groups, no default sort, and ascending direction.

The HTML query panel can replace the definition's default visible fields with a validated subset drawn from the saved columns, schema, and current records. `columns=custom` distinguishes an intentional projection and repeated `column` parameters preserve its order through table-header sorting and pagination. The same subset drives table cells and Kanban card details.

The HTML `Save as view` POST copies the source view's immutable scopes and presentation settings, appends the currently applied browser group without flattening its Boolean mode, and persists the effective columns and sort. Its layout control can retain a table or create a Kanban view with a required grouping field drawn from the available schema/data fields; omitted layout inputs inherit the source for compatibility. It uses the same CSRF token and atomic no-clobber file creation as other local forms. Search text is not persisted in this version and stays in the shareable query URL. Creating a view changes configuration rather than record data, so it does not append a record audit event; configuration history remains an explicit backlog item.

The root page, tables, search/filter controls, pagination, record forms, embedded record history, and global `/audit` timeline are rendered with Maud on the server. Every HTML handler also loads the effective principal's discoverable views and passes them to one workspace shell. Desktop pages render those collections and saved views in a persistent sidebar beside utility links and the RBAC perspective selector; mobile pages render the same routes as a sticky, horizontally scrollable strip. Active-route state is computed on the server, so navigation remains correct without client application state. Under RBAC, the same policy evaluator determines both sidebar visibility and collection and record visibility, plus whether new-record, save-view, edit, delete, and per-card Kanban movement controls render. A readable but non-editable record is rendered through a disabled fieldset with an explicit read-only label. Dynamic schema metadata, title, front matter, ID, historical values, actor, message, and error text are HTML-escaped. Before/after previews are character-bounded in HTML while the authoritative complete events remain available through the CLI and JSON API. Tailwind's browser CDN supplies styling without a frontend build or JavaScript framework. Because the CDN is explicitly intended for development, a production/offline deployment should replace it with compiled and pinned CSS.

Density is structural rather than cosmetic. Page chrome uses short breadcrumbs,
compact headings, 32-pixel controls, tighter table and audit rows, and the full
workspace width. Wide record pages place recent activity in a sticky secondary
column beside the schema form; narrower pages return it to document flow.
Kanban card properties render as label/value rows, lanes and cards use smaller
fixed widths and gaps, and native move forms live in a disclosure while drag and
drop remains the progressive enhancement. All controls and history remain in
the HTML and keyboard-accessible when scripts are unavailable.

View filter forms submit a `filter_match=all|any` mode and repeated `filter_field`, `filter_operator`, and `filter_value` triples. The server requires one-to-one fields/values/operators, caps each request at 20 conditions, parses typed YAML values in the shared filter-expression layer, and combines the ad hoc conditions with AND or OR before paginating. Operators cover typed equality, numeric and ISO string ordering, string/array containment, prefixes/suffixes, and explicit empty checks. Missing fields count as empty but do not satisfy negative operators. Saved-view filters are a separate required AND scope, so OR matching cannot broaden a record set beyond the saved view. Generated controls offer only schema-compatible operators and enum, boolean, number, multi-select, or string-format value inputs; a small progressive script swaps those controls when a field or operator changes, but URLs and server behavior do not depend on JavaScript. Pagination preserves the match mode and every triple in order; legacy URLs without operators default to equality.

View sorting calls the same shared record sorter as CLI and REST and is applied to the complete filtered result before offset pagination. YAML numbers compare numerically, strings lexicographically, sequences element-by-element, and heterogeneous values by a stable type rank. Missing fields remain last regardless of direction; collection and record ID provide an ascending deterministic tie-break. The query panel exposes schema-derived sort fields for tables and Kanban, while table headers generate accessible direction-toggling links. Pagination preserves `sort_field` and `sort_direction`.

Record pages read the newest bounded events with the same collection/ID audit filter as `cr audit log`. The global audit route uses `offset + limit + 1` reads and unknown-total pagination, preserving the segmented journal's bounded newest-first behavior instead of loading all history into memory. It is read-only and protected by the same optional bearer middleware as every other HTML route.

View reads call the same `list` and `search` methods as the CLI and REST API. Create, update, and delete forms call `Database` directly with `source: api`; they never shell out to the CLI. The edit form replaces the complete submitted front matter and Markdown atomically, then validates and records the normal update audit event. Generated edit and delete forms embed the exact record version they rendered; submission passes it to the same locked `RecordPrecondition` path as HTTP `If-Match`, so an old open form returns 412 instead of overwriting or deleting newer state.

When a collection schema exposes top-level `properties`, record forms derive typed controls from `type`, `format`, `enum`, array item enums, required fields, descriptions, length constraints, and numeric bounds. The optional non-validating `x-cr-ui.order` extension gives data models explicit field ordering; unlisted fields follow with required fields first. Submitted structured fields are decoded by the server into typed YAML; clients cannot introduce undeclared structured fields or override a declared property through the additional-attributes mapping. The complete reconstructed mapping still passes through authoritative JSON Schema validation before an atomic create or replacement. Complex declared values use a scoped YAML control, schema-permitted undeclared values use a separate advanced mapping, and collections without usable properties retain the complete raw-YAML editor. The legacy raw form payload remains accepted for compatibility, but generated pages use the structured contract.

Kanban is a presentation mode over the same saved-view query. Its lanes use the grouping field's JSON Schema `enum` order when available, so empty pipeline stages remain visible in the model's declared order; observed values not declared by the schema follow deterministically, and records without the field appear as unassigned. Cards show the view's configured columns. A move POST sets the grouping field—or removes it for the unassigned lane—through the normal `Database::update` or `Database::patch` path, preserving validation, atomic replacement, actor/source attribution, and field-level audit diffs. Native forms provide the accessible interaction; a small same-origin JavaScript enhancement translates drag-and-drop into the same CSRF-protected form POST. Boards group only the bounded current result page and retain normal pagination.

Mutating forms include a cryptographically random token generated when the server starts. Same-origin protections keep another website from reading it, and every form POST verifies it before touching the database. Successful writes return `303 See Other` to a view `GET`, preventing refresh from replaying the mutation. Validation errors return escaped HTML and do not change the record or audit head.

`CR_API_TOKEN` protects view routes with the same bearer middleware as REST and OpenAPI. It does not create cookies or a browser login, so direct browser navigation is most useful for the default loopback-only configuration; authenticated browser deployments currently need a trusted proxy capable of adding the header. The HTML routes are deliberately not part of the machine-facing OpenAPI contract.

## Integrity boundaries

- Collection names and IDs are single path components, preventing path traversal. `data_dir` must be a relative path of plain components.
- Actor, agent, authorization, and intent values are asserted by the caller and bounded in length. Agent, authorization, and intent remain evidence only. In local RBAC mode the normalized actor is also the principal used by policy; the owner perspective console explicitly replaces both with the selected user and attaches the operator as `access.impersonated_by`. The documented process-controlled trust limitation remains explicit.
- No directory between the root and a target may be a symbolic link. That covers `data_dir`, its intermediate directories, each collection directory, `.cr/`, and the audit, schema, view, and sync directories beneath it. A configured directory replaced by a link is refused rather than followed.
- Markdown record paths must be regular files. Single-record CRUD, status, save, and audit verification reject symlinks and other special file types rather than trusting them by content hash; ordinary collection, schema, view, and sync listings continue to ignore non-file entries, and every name they do yield is reopened safely before it is read.
- Creation never overwrites an existing record.
- Updates and links validate the complete next front matter before atomically replacing a file and committing its audit event.
- Links validate that their target exists and matches its latest audited content hash. Manual deletion can still produce a dangling reference after the link is created; `cr check` reports every such reference, and delete policies remain future work.
- The audit anchor at the database root is maintained by every path that appends an event and checked by `audit verify` by default. It is not a second custodian of the head: it is as writable as the journal, and it is worth something only once it is committed and pushed. A lagging anchor is reported as lagging and never as tampering, and an absent one is a notice rather than a failure, so neither can be mistaken for the other.
- A database-wide filesystem lock serializes audited mutations, and a pending-operation journal recovers single-record crash windows. There are no multi-record transactions.
- Per-sync filesystem locks reject overlapping runs of one adapter. Different syncs may fetch concurrently, but a separate application lock plus the initial audit-head comparison rejects stale output if another sync or ordinary mutation committed first. During application, each operation also requires the audit generation produced by the preceding sync operation, so an ordinary audited writer interleaving with a stream stops its remaining operations. The audit lock still serializes each comparison and record mutation.
- A run that stops partway through leaves a durable ledger under `.cr/sync/runs/`, so committed work and a lagging checkpoint can never disagree unnoticed. The next run refuses until the interrupted one is completed by `cr sync recover`, which replays the recorded stream forward and never deletes an audit event.
- YAML comments and hand-chosen front matter formatting are not preserved after a CLI mutation; the Markdown body is preserved exactly. A syntax-preserving YAML editor could replace serialization later without changing the command model.

## Roadmap

[`TODO.md`](../TODO.md) is the canonical roadmap and technical-debt register. It includes query expressions, projections, relationship traversal, indexes, schema migrations, HTTP hardening, audit improvements, and test work. Keeping the roadmap in one file avoids drift between implementation documentation and future plans.
