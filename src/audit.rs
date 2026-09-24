use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    ffi::OsStr,
    fmt,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(test)]
use std::cell::Cell;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    access::{AccessDecision, USERS_COLLECTION, principal_id},
    attribution::{Attribution, AuditAgent, AuditAuthorization, AuditIntent},
    database::{
        CollectionEntry, RECORDS_LABEL, collection_directory_name, collection_entry, record_label,
        validate_component,
    },
    encryption::{EncryptionStorageMetadata, audit_document_encryption_metadata},
    error::{
        DomainError, anchor_mismatch, approval_mismatch, audit_integrity, conflict,
        idempotency_conflict, invalid, is_already_exists,
    },
    frontmatter::Document,
    paths::{self, EntryKind},
};

/// Exact manifest ownership immediately before and after one verified event.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct AuditEncryptionTransition {
    pub before: Option<EncryptionStorageMetadata>,
    pub after: Option<EncryptionStorageMetadata>,
}

impl AuditEncryptionTransition {
    pub fn metadata(&self) -> impl Iterator<Item = &EncryptionStorageMetadata> {
        self.before.iter().chain(self.after.iter())
    }

    fn is_empty(&self) -> bool {
        self.before.is_none() && self.after.is_none()
    }
}

/// Recent entries and the exact historical storage meaning established while
/// replaying the same verified chain that selected them.
pub(crate) struct AuditHistory {
    pub entries: Vec<AuditEntry>,
    pub encryption_transitions: HashMap<u64, AuditEncryptionTransition>,
}

#[cfg(test)]
thread_local! {
    static VERIFY_CHAIN_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_verify_chain_calls() {
    VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn verify_chain_calls() -> usize {
    VERIFY_CHAIN_CALLS.with(Cell::get)
}

/// Where the tamper-evident journal lives beneath the database root.
const SEGMENT_DIRECTORY: &str = ".cr/audit/segments";
const PENDING_PATH: &str = ".cr/audit/pending.json";
const LOCK_PATH: &str = ".cr/audit/lock";
const SEGMENT_DIRECTORY_LABEL: &str = "the audit segment directory";
const SEGMENT_LABEL: &str = "an audit segment";
const PENDING_LABEL: &str = "the pending audit mutation";
const LOCK_LABEL: &str = "the audit lock";

/// Where the head anchor lives: at the database *root*, deliberately outside
/// `.cr/`, so that an ordinary `git add .` picks it up and a reviewer sees it
/// change in the same commit as the records it attests.
///
/// The name is prefixed so it sorts next to `.cr/`, says what it holds rather
/// than what feature produced it, and carries `.json` so editors, Git, and code
/// review render it. Nothing about the location makes it harder to rewrite than
/// the journal itself; see the module note on [`AuditAnchor`] for what it is
/// actually worth.
const ANCHOR_PATH: &str = ".cr-audit-head.json";
const ANCHOR_LABEL: &str = "the audit anchor";
/// Format version of the anchor file, independent of [`AUDIT_VERSION`].
///
/// The anchor is derived state with its own shape, so it versions on its own
/// and a change here never touches an audit payload or a stored hash.
const ANCHOR_VERSION: u32 = 1;

const AUDIT_VERSION: u32 = 3;
const MIN_AUDIT_VERSION: u32 = 1;
const SNAPSHOT_VERSION: u32 = 1;
const EVENT_HASH_DOMAIN: &[u8] = b"cr:audit:event:v1\0";
const RECORD_HASH_DOMAIN: &[u8] = b"cr:record:v1\0";
/// Domain separator for the previewed-change digest.
///
/// Distinct from the event and record domains so a change-set digest can never
/// be mistaken for, or substituted with, either of the other two hashes.
const CHANGE_SET_HASH_DOMAIN: &[u8] = b"cr:audit:changes:v1\0";

/// Where the verified walk a write leaves behind lives: beneath `.cr/cache/`,
/// which holds nothing but derived state and keeps itself out of Git, because
/// the file is rewritten on every append and describes one machine's files.
/// See [`JournalCache`] for what it is trusted with.
const JOURNAL_CACHE_PATH: &str = ".cr/cache/verified-journal.json";
const JOURNAL_CACHE_LABEL: &str = "the verified journal cache";
const CACHE_IGNORE_PATH: &str = ".cr/cache/.gitignore";
const CACHE_IGNORE_LABEL: &str = "the cache's Git ignore file";
/// Format version of the saved walk. It also names the `cr` release that
/// wrote it, and any other release ignores it, because what a walk derives is
/// only as good as the replay rules that derived it.
const JOURNAL_CACHE_VERSION: u32 = 1;
const JOURNAL_CACHE_HASH_DOMAIN: &[u8] = b"cr:audit:journal-cache:v1\0";
const VERIFIED_PREFIX_HASH_DOMAIN: &[u8] = b"cr:audit:verified-prefix:v1\0";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Baseline,
    Create,
    Update,
    Link,
    Delete,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Baseline => "baseline",
            Self::Create => "create",
            Self::Update => "update",
            Self::Link => "link",
            Self::Delete => "delete",
        };
        formatter.write_str(value)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    pub collection: String,
    pub id: String,
}

/// Exact stored Markdown for an event whose semantic document does not render
/// back to the same bytes.
///
/// Most records need no witness: replaying `changes` and rendering the audit
/// JSON result reproduces `after_hash`. A baseline, direct filesystem save, or
/// deliberately ordered managed record can introduce comments, quoting, key
/// order, line endings, and other YAML representation the semantic document
/// cannot retain. In that case this versioned witness supplies the exact UTF-8
/// bytes, while replay still proves that parsing those bytes yields the
/// semantic state in `changes`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecordSnapshot {
    pub version: u32,
    pub markdown: String,
}

impl AuditRecord {
    pub fn reference(&self) -> String {
        format!("{}/{}", self.collection, self.id)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum AuditChange {
    Add {
        path: String,
        after: Value,
    },
    Remove {
        path: String,
        before: Value,
    },
    Replace {
        path: String,
        before: Value,
        after: Value,
    },
}

impl AuditChange {
    pub fn path(&self) -> &str {
        match self {
            Self::Add { path, .. } | Self::Remove { path, .. } | Self::Replace { path, .. } => path,
        }
    }
}

impl<'de> Deserialize<'de> for AuditChange {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut fields = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        let path = take_string::<D::Error>(&mut fields, "path")?;
        let operation = fields.remove("operation");
        let change = match operation {
            Some(Value::String(operation)) if operation == "add" => Self::Add {
                path,
                after: take_value::<D::Error>(&mut fields, "after")?,
            },
            Some(Value::String(operation)) if operation == "remove" => Self::Remove {
                path,
                before: take_value::<D::Error>(&mut fields, "before")?,
            },
            Some(Value::String(operation)) if operation == "replace" => Self::Replace {
                path,
                before: take_value::<D::Error>(&mut fields, "before")?,
                after: take_value::<D::Error>(&mut fields, "after")?,
            },
            Some(Value::String(operation)) => {
                return Err(D::Error::custom(format!(
                    "unsupported audit change operation '{operation}'"
                )));
            }
            Some(_) => return Err(D::Error::custom("audit change operation must be a string")),
            None => match (fields.remove("before"), fields.remove("after")) {
                (None, Some(after)) => Self::Add { path, after },
                (Some(before), None) => Self::Remove { path, before },
                (Some(before), Some(after)) => Self::Replace {
                    path,
                    before,
                    after,
                },
                (None, None) => {
                    return Err(D::Error::custom(
                        "legacy audit change must contain before or after",
                    ));
                }
            },
        };
        if !fields.is_empty() {
            return Err(D::Error::custom(format!(
                "unknown audit change fields: {}",
                fields.keys().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        Ok(change)
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSource {
    #[default]
    Cli,
    Api,
    Filesystem,
    Sync,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuditPayload {
    pub version: u32,
    pub sequence: u64,
    pub timestamp: String,
    pub actor: String,
    #[serde(default)]
    pub source: AuditSource,
    /// The software that carried the change out on the actor's behalf.
    ///
    /// Absent for a human at the keyboard, which is why it and its two
    /// siblings are `Option` with `skip_serializing_if`: an event with no
    /// attribution serializes to exactly the bytes it did before these fields
    /// existed, so no audit version bump is needed and every existing journal
    /// keeps verifying. See `src/attribution.rs` for the byte-stability rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AuditAgent>,
    /// How much of a human decision stood behind the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization: Option<AuditAuthorization>,
    /// What was asked, and what the agent thought it was doing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<AuditIntent>,
    /// The authenticated principal and effective role that permitted this
    /// mutation. Absent for legacy and access-control-disabled databases.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Retry identity committed atomically with this event.
    ///
    /// The caller's key is never stored: `key_hash` is domain-separated, and
    /// the principal, operation, and record fields make its scope explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<AuditIdempotency>,
    pub action: AuditAction,
    pub record: AuditRecord,
    pub changes: Vec<AuditChange>,
    /// Exact post-mutation representation for every present version-3 state.
    ///
    /// Version 1 and 2 predate this witness. Version 3 retains it unconditionally
    /// rather than making durable verification depend on a serializer's current
    /// idea of canonical Markdown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_snapshot: Option<AuditRecordSnapshot>,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub previous_hash: Option<String>,
}

/// Durable replay data for a successfully committed single-record mutation.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditIdempotency {
    pub principal: String,
    pub operation: String,
    pub key_hash: String,
    pub request_hash: String,
    pub result: AuditIdempotencyResult,
}

/// Original single-record domain result returned to a retrying caller.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditIdempotencyResult {
    pub path: PathBuf,
    pub version: String,
    pub markdown: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuditEntry {
    /// Hash of the exact stored payload. User-facing history may project
    /// protected `changes` to plaintext, so reserializing this returned value
    /// is not a way to recompute the hash; verification reads stored bytes.
    pub hash: String,
    #[serde(flatten)]
    pub payload: AuditPayload,
}

/// When a record first entered the journal and when it last changed.
///
/// Derived, not stored: the journal is the only place this exists, so it is
/// recomputed from a verified chain rather than cached in front matter that a
/// direct edit could contradict. Sequence numbers accompany the timestamps
/// because they are the exact total order. Two events can share a formatted
/// instant, and RFC 3339 fractional seconds do not sort lexicographically, so
/// ordering by sequence is both cheaper and correct.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RecordActivity {
    pub created_at: String,
    pub created_sequence: u64,
    pub updated_at: String,
    pub updated_sequence: u64,
}

/// Which audit events a history read should return.
///
/// The agent and session predicates exist because "show me everything this
/// agent did" is the first question anyone asks of delegated attribution, and
/// recording the delegate without being able to query it answers none of it.
/// Both match the acting agent or any delegate in its `via` chain.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditFilter<'a> {
    /// Only events for this collection.
    pub collection: Option<&'a str>,
    /// Only events for this record ID within `collection`.
    pub id: Option<&'a str>,
    /// Only events whose agent chain contains this agent identifier.
    pub agent: Option<&'a str>,
    /// Only events whose agent chain contains this session identifier.
    pub session: Option<&'a str>,
}

impl<'a> AuditFilter<'a> {
    /// Every event, unfiltered.
    pub fn all() -> Self {
        Self::default()
    }

    /// Every event for one record.
    pub fn record(collection: &'a str, id: &'a str) -> Self {
        Self {
            collection: Some(collection),
            id: Some(id),
            ..Self::default()
        }
    }

    /// True when `payload` satisfies every configured predicate.
    fn matches(&self, payload: &AuditPayload) -> bool {
        if self
            .collection
            .is_some_and(|value| payload.record.collection != value)
            || self.id.is_some_and(|value| payload.record.id != value)
        {
            return false;
        }
        if let Some(agent) = self.agent
            && !payload
                .agent
                .as_ref()
                .is_some_and(|value| value.declares_id(agent))
        {
            return false;
        }
        if let Some(session) = self.session
            && !payload
                .agent
                .as_ref()
                .is_some_and(|value| value.declares_session(session))
        {
            return false;
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditHead {
    pub sequence: u64,
    pub hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditVerification {
    pub entries: u64,
    pub records_checked: usize,
    pub head: AuditHead,
    /// How the anchor stored at the database root relates to that head.
    pub anchor: AnchorStatus,
}

/// The audit head written to a file at the database root for Git to carry.
///
/// # What this is, honestly
///
/// Every audit event but the newest is pinned by the `previous_hash` of the
/// event after it. The newest is pinned by nothing, so its `actor`,
/// `timestamp`, `message`, attribution, and every change's `after` value can be
/// rewritten and re-hashed, after which the chain is internally perfect. The
/// only thing that has ever caught that is a copy of the head hash kept where
/// the forger cannot reach it, compared back with `audit verify --expected-head`.
///
/// This file is *not* such a place. It sits at the database root, writable by
/// anybody who can write `.cr/`, so an attacker forges the event, recomputes
/// the hash, and rewrites this file in the same pass. On its own it stops
/// nothing.
///
/// Its entire value is that it makes the *Git*-based version of that practice
/// automatic. The second write boundary is a pushed, distributed history, which
/// a local filesystem write cannot reach; committing this file alongside the
/// records it attests puts the head hash there on every mutation, without
/// anybody remembering to run `audit head` and paste the result somewhere. The
/// feature being shipped is the ergonomics and the default-on check, not a new
/// cryptographic guarantee.
///
/// # Why it is fully derived
///
/// Every field is a function of the journal: the sequence, that event's stored
/// hash, and that event's own timestamp — never "now". So `cr` can recompute
/// the file the journal implies and compare, two databases with the same
/// journal produce byte-identical anchors, and the file has no state of its own
/// that could drift.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAnchor {
    /// Format version of this file, not of the audit payload.
    pub version: u32,
    /// The audit sequence this anchor attests to.
    pub sequence: u64,
    /// The stored hash of the event at `sequence`.
    pub hash: String,
    /// That event's timestamp, so a reviewer reading a diff can date it.
    pub timestamp: String,
}

impl AuditAnchor {
    /// The anchor an event at `sequence` implies.
    fn at(sequence: u64, hash: &str, timestamp: &str) -> Self {
        Self {
            version: ANCHOR_VERSION,
            sequence,
            hash: hash.to_owned(),
            timestamp: timestamp.to_owned(),
        }
    }

    /// The anchor an already-stored event implies.
    fn of(entry: &AuditEntry) -> Self {
        Self::at(
            entry.payload.sequence,
            &entry.hash,
            &entry.payload.timestamp,
        )
    }

    /// The exact bytes this anchor is stored as: stable field order, two-space
    /// indentation, one field per line, newline-terminated. Chosen so a commit
    /// diff shows the head hash moving on its own line and nothing else.
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut bytes =
            serde_json::to_vec_pretty(self).context("could not serialize the audit anchor")?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}

/// How the stored anchor relates to the journal it sits beside.
///
/// The distinction that matters is [`Self::Behind`] versus the
/// [`DomainError::AnchorMismatch`] that is returned instead of a status. An
/// anchor may legitimately lag — a crash between appending the event and
/// rewriting the anchor leaves exactly that state — and a lagging anchor must
/// never be reported as, or confused with, a rewritten journal. Because the
/// chain is append-only and hash-linked, the two are separable *exactly*: a
/// lagging anchor's hash is still present in the journal at its own sequence,
/// and a rewritten journal's is not.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AnchorStatus {
    /// The journal holds no events, so there is nothing to anchor yet.
    Empty,
    /// The journal has a head and no anchor attests to it.
    Absent,
    /// The anchor attests to the current head.
    Matched { sequence: u64 },
    /// The anchor attests to an earlier event the journal still agrees with.
    ///
    /// Not a failure. It is a reduced guarantee, and it says so: events after
    /// `sequence` are anchored by nothing, which is the pre-anchor situation
    /// for that tail alone.
    Behind { sequence: u64, head: u64 },
    /// A checkpoint was supplied explicitly, so the stored file was not read.
    Overridden,
}

impl AnchorStatus {
    /// A sentence worth printing beside a successful verification, or `None`
    /// when the anchor has nothing to say.
    pub fn notice(&self) -> Option<String> {
        match self {
            Self::Empty | Self::Matched { .. } => None,
            Self::Absent => Some(
                "notice: no audit anchor is recorded, so the newest event is pinned by nothing; run 'cr audit anchor --write' and commit the result"
                    .to_owned(),
            ),
            Self::Behind { sequence, head } => Some(format!(
                "notice: the audit anchor is behind at sequence {sequence} of {head}; the journal still agrees with it, so this is a lagging anchor rather than altered history"
            )),
            Self::Overridden => Some(
                "notice: an expected head was supplied, so the recorded audit anchor was not consulted"
                    .to_owned(),
            ),
        }
    }
}

/// Everything `cr audit anchor` reports.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnchorReport {
    /// The anchor stored at the database root, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor: Option<AuditAnchor>,
    /// The head the anchor was judged against.
    pub head: AuditHead,
    pub status: AnchorStatus,
}

/// A change set computed without writing it, and the digest that commits to it.
///
/// The digest is over the exact bytes the `changes` array will occupy in the
/// audit payload. Passing it back as `--approved-changes` binds the write to
/// this change set: `cr` refuses to apply anything whose change set hashes
/// differently, and `audit verify` recomputes it from the stored event.
///
/// What the digest does not carry: any evidence that a human ever looked at
/// this. It commits to a change set, and to nothing about who saw it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ChangePreview {
    /// Always `true`. Present so a client cannot mistake this for a write that
    /// happened, if a proxy dropped the preview parameter on the way in.
    pub preview: bool,
    pub action: AuditAction,
    pub record: AuditRecord,
    /// The change set exactly as the audit event would record it.
    pub changes: Vec<AuditChange>,
    /// The record's current audited state, or absent when it does not exist.
    pub before_hash: Option<String>,
    /// The state the mutation would produce, or absent for a deletion.
    pub after_hash: Option<String>,
    /// `sha256:` over the canonical bytes of `changes`. Pass to
    /// `--approved-changes` or `X-CR-Approved-Changes`.
    pub digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct PendingMutation {
    target: PathBuf,
    before_hash: Option<String>,
    after_hash: Option<String>,
    hash: String,
    payload: String,
}

pub(crate) struct PreparedEntry {
    hash: String,
    payload: String,
    parsed: AuditPayload,
    /// Digest of this event's change set, computed from the bytes above.
    change_digest: String,
}

impl PreparedEntry {
    /// Describe this event as a preview, discarding it rather than writing it.
    pub fn into_preview(self) -> ChangePreview {
        ChangePreview {
            preview: true,
            action: self.parsed.action,
            record: self.parsed.record,
            changes: self.parsed.changes,
            before_hash: self.parsed.before_hash,
            after_hash: self.parsed.after_hash,
            digest: self.change_digest,
        }
    }
}

struct StoredEntry {
    entry: AuditEntry,
    payload: String,
}

#[derive(Deserialize)]
struct StoredLine {
    hash: String,
    payload: Box<RawValue>,
}

#[derive(Clone)]
struct ChainState {
    entries: u64,
    head_hash: Option<String>,
    idempotency_identities: HashSet<IdempotencyIdentity>,
}

/// The checks a walk of the chain applies, as state that can stop at any line
/// boundary and resume from it.
///
/// [`AuditLog::verify_chain`] runs one from the first segment to the last.
/// [`JournalCache`] keeps one between walks and feeds it only the lines
/// appended since, so an event verified late is held to exactly the rules an
/// event verified by a fresh walk is: there is one implementation of them.
#[derive(Deserialize, Serialize)]
struct ChainWalk {
    expected_sequence: u64,
    previous_hash: Option<String>,
    previous_version: Option<u32>,
    idempotency_identities: HashSet<IdempotencyIdentity>,
}

impl ChainWalk {
    fn new() -> Self {
        Self {
            expected_sequence: 1,
            previous_hash: None,
            previous_version: None,
            idempotency_identities: HashSet::new(),
        }
    }

    /// Refuse a segment whose name does not start where the chain so far ends.
    fn begin_segment(&self, path: &Path) -> Result<()> {
        if segment_start(path)? != self.expected_sequence {
            bail!("audit segment sequence gap at {}", self.expected_sequence);
        }
        Ok(())
    }

    /// Verify each line of `contents` — a segment from a line boundary to its
    /// end — hand every entry to `visitor`, and return how many there were.
    fn lines<F>(&mut self, path: &Path, contents: &[u8], visitor: &mut F) -> Result<usize>
    where
        F: FnMut(&AuditEntry, &str) -> Result<()>,
    {
        let mut entries = 0;
        let mut rest = contents;
        while !rest.is_empty() {
            let Some(end) = rest.iter().position(|byte| *byte == b'\n') else {
                bail!("audit segment {} has a truncated tail", path.display());
            };
            self.line(path, &rest[..end], visitor)?;
            rest = &rest[end + 1..];
            entries += 1;
        }
        Ok(entries)
    }

    fn line<F>(&mut self, path: &Path, line: &[u8], visitor: &mut F) -> Result<()>
    where
        F: FnMut(&AuditEntry, &str) -> Result<()>,
    {
        let stored = parse_line(line)
            .with_context(|| format!("invalid audit event in {}", path.display()))?;
        if stored.entry.payload.sequence != self.expected_sequence {
            bail!("audit sequence gap at {}", self.expected_sequence);
        }
        if stored.entry.payload.previous_hash != self.previous_hash {
            bail!(
                "audit hash chain is broken at sequence {}",
                self.expected_sequence
            );
        }
        if let Some(previous_version) = self.previous_version {
            verify_version_progress(
                previous_version,
                stored.entry.payload.version,
                self.expected_sequence,
            )?;
        }
        register_idempotency_identity(&mut self.idempotency_identities, &stored.entry.payload)?;
        visitor(&stored.entry, &stored.payload)?;
        self.previous_version = Some(stored.entry.payload.version);
        self.previous_hash = Some(stored.entry.hash);
        self.expected_sequence += 1;
        Ok(())
    }

    fn finish(self) -> ChainState {
        ChainState {
            entries: self.expected_sequence - 1,
            head_hash: self.previous_hash,
            idempotency_identities: self.idempotency_identities,
        }
    }

    /// [`Self::finish`] for a walk that goes on.
    fn state(&self) -> ChainState {
        ChainState {
            entries: self.expected_sequence - 1,
            head_hash: self.previous_hash.clone(),
            idempotency_identities: self.idempotency_identities.clone(),
        }
    }
}

/// When each record was created and last changed, by collection and then ID.
pub(crate) type CollectionsActivity = BTreeMap<String, BTreeMap<String, RecordActivity>>;

/// Where a command that needs audited state starts verifying the journal.
///
/// Neither choice changes what is verified — sequence continuity, the hash
/// chain, version progress, idempotency identities, and the replay of every
/// change set — only how much of that one command does itself. `cr audit
/// verify` and `cr check` ignore it and always verify everything.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum JournalVerification {
    /// Resume from the verified walk the last write saved, while it still
    /// describes the segments on disk, and verify only the events appended
    /// since. `JournalCache` in `src/audit.rs` states what that trusts.
    #[default]
    Resume,
    /// Verify every event from the first, whatever walk was saved.
    Full,
}

/// A verified walk of the journal, kept so that the next reader verifies only
/// what has been appended since.
///
/// Without one, every read that needs audited state — reading or listing a
/// plaintext collection, a record's created and updated times, switching the
/// RBAC perspective — replays and re-hashes every event ever recorded, so each
/// read costs more the longer the database has existed. `cr serve` keeps one
/// for as long as it runs, and so does a CLI command, so `--as` and the read it
/// delegates share one walk.
///
/// What it trusts in place of re-hashing:
///
/// * The newest segment is compared with what was verified, and only the lines
///   after that prefix are verified. Appends rewrite that file, so this is
///   where tampering is most likely to land, and it is detected exactly as a
///   fresh walk would detect it.
/// * An older segment is not read again while its identity is what it was
///   when it was verified: the same path, device and inode, length,
///   modification time and change time. A write, truncation, or replacement
///   changes at least one of those, and the change time cannot be set back by
///   `touch` or any other ordinary interface. A change sends the next reader
///   back to the first segment.
///
/// That is a real trade and a deliberate one. A same-length rewrite of a
/// sealed segment that also restores its change time goes unnoticed while the
/// walk is trusted. Restoring it takes resetting the system clock or writing
/// the block device directly, and anyone who can do either can also replace
/// the binary. The one other way is timing: a filesystem that stamps times
/// from a coarse clock gives a rewrite landing in the same tick as the
/// segment's last legitimate write the same change time, a window of a few
/// milliseconds after a segment is sealed.
///
/// # On disk
///
/// With `save`, every append leaves the walk on disk ([`JOURNAL_CACHE_PATH`]),
/// and with `resume` an empty cache starts from that saved walk rather than
/// from the first event, so a short-lived CLI command costs what a server
/// request does. The file holds the newest segment's verified prefix as a
/// length and digest rather than the bytes, and a digest of its own body so a
/// torn or damaged file is ignored rather than believed.
///
/// That extends the trade above by one file. The saved walk is derived state
/// and as writable as the journal, so whoever can rewrite `.cr/` can write one
/// that claims any replayed state for segments that have not changed. What
/// bounds it:
///
/// * A walk is only ever saved if it began at the first event in the saving
///   process, which every append makes anyway, so one saved walk is never
///   built on another and the next write replaces a forged one with a
///   verified one.
/// * A saved walk that is unreadable, from another release of `cr`, or no
///   longer matches the segments on disk is ignored, and so is one whose
///   continuation fails: the walk starts again from the first event and its
///   result, success or failure, is the answer. A saved walk can make a
///   command skip work, never fail.
/// * Nothing that decides whether the journal is intact uses it: `cr audit
///   verify`, `cr check`, and their API routes walk the whole chain every
///   time. Neither does any write: `append` verifies the whole chain before it
///   extends it, so a mutation never builds on a journal only the cache
///   believed. [`JournalVerification::Full`] (`--verify-audit`) makes any
///   other command do the same.
#[derive(Default)]
pub(crate) struct JournalCache {
    verified: Mutex<Option<VerifiedJournal>>,
    /// Start an empty cache from the walk saved on disk.
    resume: bool,
    /// Save the walk on disk after every append.
    save: bool,
}

impl fmt::Debug for JournalCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JournalCache")
            .field("resume", &self.resume)
            .field("save", &self.save)
            .finish_non_exhaustive()
    }
}

impl JournalCache {
    /// A cache that saves its walk after every append, and starts from the
    /// saved walk when `verification` allows it.
    pub(crate) fn persistent(verification: JournalVerification) -> Self {
        Self {
            verified: Mutex::default(),
            resume: verification == JournalVerification::Resume,
            save: true,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<VerifiedJournal>> {
        match self.verified.lock() {
            Ok(verified) => verified,
            // A reader panicked part-way through extending it, so what is
            // there may be half an update. Start again from nothing.
            Err(poisoned) => {
                let mut verified = poisoned.into_inner();
                *verified = None;
                self.verified.clear_poison();
                verified
            }
        }
    }
}

/// What a walk of the journal established, and where it stopped.
struct VerifiedJournal {
    walk: ChainWalk,
    states: Arc<AuditedRecordStates>,
    activity: Arc<CollectionsActivity>,
    /// Every segment before the newest, as it was when it was verified.
    sealed: Vec<(PathBuf, SegmentStamp)>,
    /// The newest segment and exactly the part of it that was verified.
    tail: Option<(PathBuf, VerifiedPrefix)>,
    /// Whether this process verified every event itself rather than resuming
    /// from a saved walk. Only such a walk is saved.
    walked: bool,
}

impl VerifiedJournal {
    fn new() -> Self {
        Self {
            walk: ChainWalk::new(),
            states: Arc::default(),
            activity: Arc::default(),
            sealed: Vec::new(),
            tail: None,
            walked: true,
        }
    }

    fn snapshot(&self) -> JournalSnapshot {
        JournalSnapshot {
            states: Arc::clone(&self.states),
            activity: Arc::clone(&self.activity),
        }
    }

    /// Verify one segment's `contents` from the line boundary `from`, or from
    /// its first line for a segment no walk has seen.
    fn verify(&mut self, path: &Path, contents: &[u8], from: Option<usize>) -> Result<()> {
        // Copies the maps only when a reader still holds the previous
        // snapshot, which is what lets a snapshot be read without a lock.
        let states = Arc::make_mut(&mut self.states);
        let activity = Arc::make_mut(&mut self.activity);
        let mut visitor = |entry: &AuditEntry, _: &str| {
            track_activity(activity, entry);
            replay_entry(states, entry)
        };
        match from {
            Some(from) => {
                self.walk.lines(path, &contents[from..], &mut visitor)?;
            }
            None => {
                self.walk.begin_segment(path)?;
                if self.walk.lines(path, contents, &mut visitor)? == 0 {
                    bail!("audit segment {} is empty", path.display());
                }
            }
        }
        Ok(())
    }

    /// Verify the part of each segment not yet verified, in order, and make
    /// the last of them the tail.
    fn append(&mut self, segments: Vec<UnverifiedSegment>) -> Result<()> {
        if segments
            .iter()
            .all(|segment| segment.verified == Some(segment.contents.len()))
        {
            return Ok(());
        }
        let last = segments.len() - 1;
        self.tail = None;
        for (index, segment) in segments.into_iter().enumerate() {
            if segment.verified != Some(segment.contents.len()) {
                self.verify(&segment.path, &segment.contents, segment.verified)?;
            }
            if index == last {
                self.tail = Some((segment.path, VerifiedPrefix::Bytes(segment.contents)));
            } else {
                self.sealed.push((segment.path, segment.stamp));
            }
        }
        Ok(())
    }

    /// This walk as a file: the body, and a digest of it that a reader checks
    /// before believing any of it.
    fn serialize(&self) -> Result<Vec<u8>> {
        let mut records = self.states.iter().collect::<Vec<_>>();
        records.sort_by(|left, right| left.0.cmp(right.0));
        let body = serde_json::to_string(&StoredJournalRef {
            walk: &self.walk,
            records,
            activity: &self.activity,
            sealed: &self.sealed,
            tail: self.tail.as_ref().map(|(path, prefix)| StoredTail {
                path: path.clone(),
                length: prefix.len(),
                digest: prefix.digest(),
            }),
        })
        .context("could not serialize the verified journal cache")?;
        let digest = digest(JOURNAL_CACHE_HASH_DOMAIN, body.as_bytes());
        let body = RawValue::from_string(body)
            .context("could not serialize the verified journal cache")?;
        let mut serialized = serde_json::to_vec(&StoredJournalCacheRef {
            version: JOURNAL_CACHE_VERSION,
            cr: env!("CARGO_PKG_VERSION"),
            digest: &digest,
            journal: &body,
        })
        .context("could not serialize the verified journal cache")?;
        serialized.push(b'\n');
        Ok(serialized)
    }

    /// A walk resumed from a saved one, or `None` for anything that is not
    /// exactly a walk this release saved.
    fn deserialize(serialized: &[u8]) -> Option<Self> {
        let stored = serde_json::from_slice::<StoredJournalCache>(serialized).ok()?;
        if stored.version != JOURNAL_CACHE_VERSION
            || stored.cr != env!("CARGO_PKG_VERSION")
            || digest(JOURNAL_CACHE_HASH_DOMAIN, stored.journal.get().as_bytes()) != stored.digest
        {
            return None;
        }
        let journal = serde_json::from_str::<StoredJournal>(stored.journal.get()).ok()?;
        let records = journal.records.len();
        let states = journal.records.into_iter().collect::<AuditedRecordStates>();
        if states.len() != records || journal.walk.expected_sequence == 0 {
            return None;
        }
        Some(Self {
            walk: journal.walk,
            states: Arc::new(states),
            activity: Arc::new(journal.activity),
            sealed: journal.sealed,
            tail: journal.tail.map(|tail| {
                (
                    tail.path,
                    VerifiedPrefix::Digest {
                        length: tail.length,
                        digest: tail.digest,
                    },
                )
            }),
            walked: false,
        })
    }
}

/// The part of the newest segment a walk has verified.
enum VerifiedPrefix {
    /// The bytes themselves, as this process verified them.
    Bytes(Vec<u8>),
    /// Their length and digest, as a saved walk recorded them.
    Digest { length: usize, digest: String },
}

impl VerifiedPrefix {
    fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::Digest { length, .. } => *length,
        }
    }

    fn digest(&self) -> String {
        match self {
            Self::Bytes(bytes) => digest(VERIFIED_PREFIX_HASH_DOMAIN, bytes),
            Self::Digest { digest, .. } => digest.clone(),
        }
    }

    /// Whether `contents` still begins with exactly the verified bytes.
    fn begins(&self, contents: &[u8]) -> bool {
        match self {
            Self::Bytes(bytes) => contents.starts_with(bytes),
            Self::Digest {
                length,
                digest: expected,
            } => contents
                .get(..*length)
                .is_some_and(|prefix| digest(VERIFIED_PREFIX_HASH_DOMAIN, prefix) == *expected),
        }
    }
}

/// The on-disk form of a saved walk. The journal is kept as the exact bytes
/// its digest covers.
#[derive(Serialize)]
struct StoredJournalCacheRef<'a> {
    version: u32,
    cr: &'a str,
    digest: &'a str,
    journal: &'a RawValue,
}

#[derive(Deserialize)]
struct StoredJournalCache {
    version: u32,
    cr: String,
    digest: String,
    journal: Box<RawValue>,
}

#[derive(Serialize)]
struct StoredJournalRef<'a> {
    walk: &'a ChainWalk,
    records: Vec<(&'a (String, String), &'a AuditedRecordState)>,
    activity: &'a CollectionsActivity,
    sealed: &'a [(PathBuf, SegmentStamp)],
    tail: Option<StoredTail>,
}

#[derive(Deserialize)]
struct StoredJournal {
    walk: ChainWalk,
    records: Vec<((String, String), AuditedRecordState)>,
    activity: CollectionsActivity,
    sealed: Vec<(PathBuf, SegmentStamp)>,
    tail: Option<StoredTail>,
}

#[derive(Deserialize, Serialize)]
struct StoredTail {
    path: PathBuf,
    length: usize,
    digest: String,
}

/// One segment read from disk, with how much of it is already verified.
struct UnverifiedSegment {
    path: PathBuf,
    stamp: SegmentStamp,
    contents: Vec<u8>,
    /// The length of the prefix a previous walk verified, or `None` for a
    /// segment no walk has seen.
    verified: Option<usize>,
}

/// The shared result of a cached walk.
struct JournalSnapshot {
    states: Arc<AuditedRecordStates>,
    activity: Arc<CollectionsActivity>,
}

/// What rewriting a sealed segment cannot leave as it was.
///
/// On Unix the change time carries the weight: every write, truncation, or
/// permission change sets it to the current time, and unlike the modification
/// time no ordinary interface sets it back. A segment replaced rather than
/// rewritten has a different inode. Elsewhere only the length and
/// modification time are available, which is a weaker promise.
#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SegmentStamp {
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed: (i64, i64),
}

impl SegmentStamp {
    fn of(file: &File) -> Result<Self> {
        let metadata = file
            .metadata()
            .with_context(|| format!("could not inspect {SEGMENT_LABEL}"))?;
        Ok(Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
struct IdempotencyIdentity {
    principal: String,
    operation: String,
    collection: String,
    id: String,
    key_hash: String,
}

pub(crate) struct AuditLog<'a> {
    root: &'a Path,
    records_dir: &'a Path,
    segment_max_events: usize,
    segment_max_bytes: u64,
    actor: &'a str,
    attribution: &'a Attribution,
    journal: Option<&'a JournalCache>,
}

pub(crate) struct AuditMutation<'a> {
    pub action: AuditAction,
    pub collection: &'a str,
    pub id: &'a str,
    pub before_document: Option<&'a Document>,
    pub after_document: Option<&'a Document>,
    pub before_bytes: Option<&'a [u8]>,
    pub after_bytes: Option<&'a [u8]>,
    pub source: AuditSource,
    pub message: Option<&'a str>,
    pub access: Option<&'a AccessDecision>,
    pub idempotency: Option<&'a AuditIdempotency>,
}

pub(crate) struct ReconciledMutation<'a> {
    pub action: AuditAction,
    pub collection: &'a str,
    pub id: &'a str,
    pub before_document: Option<&'a Document>,
    pub after_document: Option<&'a Document>,
    pub before_hash: Option<&'a str>,
    pub after_bytes: Option<&'a [u8]>,
    pub had_history: bool,
    pub message: Option<&'a str>,
    pub access: Option<&'a AccessDecision>,
}

struct PayloadMutation<'a> {
    action: AuditAction,
    collection: &'a str,
    id: &'a str,
    before_document: Option<&'a Document>,
    after_document: Option<&'a Document>,
    before_hash: Option<String>,
    after_hash: Option<String>,
    after_bytes: Option<&'a [u8]>,
    chain: ChainState,
    source: AuditSource,
    message: Option<&'a str>,
    access: Option<&'a AccessDecision>,
    idempotency: Option<&'a AuditIdempotency>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct AuditedRecordState {
    pub hash: Option<String>,
    pub document: Option<Value>,
    /// Whether the terminal audited lifecycle owns protected storage.
    ///
    /// Present states derive this from their authenticated manifest. A
    /// tombstone inherits the deleted state's ownership so copying a stripped
    /// ciphertext file back into place cannot make it ordinary. A later
    /// audited create starts a new lifecycle and derives ownership afresh.
    pub protected_storage_owned: bool,
    /// The newest event could not prove its exact representation because it
    /// predates v3. When the materialized file still matches its hash, replay
    /// uses that file as the missing witness and checks its semantics too.
    legacy_representation_gap: Option<u64>,
}

pub(crate) type AuditedRecordStates = HashMap<(String, String), AuditedRecordState>;
pub(crate) type VerifiedRecordHashes = HashMap<(String, String), Option<String>>;

/// One fully verified journal generation retained across a locked bulk
/// reconciliation. The chain cursor advances only through entries this same
/// snapshot validates and appends, so callers do not need to replay all prior
/// events between independent records in one `save` operation.
pub(crate) struct ReconciliationSnapshot {
    pub states: AuditedRecordStates,
    chain: ChainState,
}

impl ReconciliationSnapshot {
    pub fn sequence(&self) -> u64 {
        self.chain.entries
    }
}

impl<'a> AuditLog<'a> {
    pub fn new(
        root: &'a Path,
        records_dir: &'a Path,
        segment_max_events: usize,
        segment_max_bytes: u64,
        actor: &'a str,
        attribution: &'a Attribution,
    ) -> Self {
        Self {
            root,
            records_dir,
            segment_max_events,
            segment_max_bytes,
            actor,
            attribution,
            journal: None,
        }
    }

    /// Answer [`Self::record_states`], [`Self::record_activity`] and
    /// [`Self::collections_activity`] from `journal` rather than a fresh walk.
    pub(crate) fn with_journal_cache(mut self, journal: Option<&'a JournalCache>) -> Self {
        self.journal = journal;
        self
    }

    pub fn ensure_layout(&self) -> Result<()> {
        paths::create_directory_all(
            self.root,
            Path::new(SEGMENT_DIRECTORY),
            SEGMENT_DIRECTORY_LABEL,
        )
        .map(|_| ())
    }

    pub fn lock(&self) -> Result<File> {
        self.ensure_layout()?;
        let lock = paths::open_lock_file(self.root, Path::new(LOCK_PATH), LOCK_LABEL)?;
        lock.lock().context("could not lock the audit journal")?;
        Ok(lock)
    }

    pub fn prepare(&self, mutation: AuditMutation<'_>) -> Result<PreparedEntry> {
        let before_hash = mutation.before_bytes.map(record_hash);
        let (audited_state, chain) = self.record_state(mutation.collection, mutation.id)?;
        if mutation.action == AuditAction::Baseline {
            if audited_state.is_some() {
                return Err(conflict(format!(
                    "record {}/{} already has audit history",
                    mutation.collection, mutation.id
                )));
            }
            if mutation.before_bytes.is_some() || mutation.after_bytes.is_none() {
                bail!("a baseline event must capture an existing record as new audit state");
            }
        } else {
            let (collection, id) = (mutation.collection, mutation.id);
            match audited_state {
                None if before_hash.is_none() => {}
                Some(expected) if expected == before_hash => {}
                None => return Err(missing_audit_history(collection, id, "mutating")),
                Some(_) => return Err(stale_audit_state(collection, id)),
            }
        }

        self.prepare_payload(PayloadMutation {
            action: mutation.action,
            collection: mutation.collection,
            id: mutation.id,
            before_document: mutation.before_document,
            after_document: mutation.after_document,
            before_hash,
            after_hash: mutation.after_bytes.map(record_hash),
            after_bytes: mutation.after_bytes,
            chain,
            source: mutation.source,
            message: mutation.message,
            access: mutation.access,
            idempotency: mutation.idempotency,
        })
    }

    /// Capture one verified generation for a locked multi-record filesystem
    /// reconciliation.
    pub(crate) fn reconciliation_snapshot(&self) -> Result<ReconciliationSnapshot> {
        let (states, chain) = self.states(false)?;
        self.verify_legacy_representation_heads(&states)?;
        Ok(ReconciliationSnapshot { states, chain })
    }

    /// Prepare one filesystem event against a caller-retained verified
    /// generation instead of replaying the journal again for this record.
    pub(crate) fn prepare_reconciled_in(
        &self,
        mutation: ReconciledMutation<'_>,
        snapshot: &ReconciliationSnapshot,
    ) -> Result<PreparedEntry> {
        let audited_state = snapshot
            .states
            .get(&(mutation.collection.to_owned(), mutation.id.to_owned()))
            .map(|state| state.hash.clone());
        self.prepare_reconciled_from_state(mutation, audited_state, snapshot.chain.clone())
    }

    fn prepare_reconciled_from_state(
        &self,
        mutation: ReconciledMutation<'_>,
        audited_state: Option<Option<String>>,
        chain: ChainState,
    ) -> Result<PreparedEntry> {
        let before_hash = mutation.before_hash.map(str::to_owned);
        let expected_state = mutation.had_history.then_some(before_hash.clone());
        if audited_state != expected_state {
            return Err(conflict(format!(
                "record {}/{} changed since status was calculated",
                mutation.collection, mutation.id
            )));
        }
        self.prepare_payload(PayloadMutation {
            action: mutation.action,
            collection: mutation.collection,
            id: mutation.id,
            before_document: mutation.before_document,
            after_document: mutation.after_document,
            before_hash,
            after_hash: mutation.after_bytes.map(record_hash),
            after_bytes: mutation.after_bytes,
            chain,
            source: AuditSource::Filesystem,
            message: mutation.message,
            access: mutation.access,
            idempotency: None,
        })
    }

    fn prepare_payload(&self, mutation: PayloadMutation<'_>) -> Result<PreparedEntry> {
        let ChainState {
            entries,
            head_hash: previous_hash,
            mut idempotency_identities,
        } = mutation.chain;
        let sequence = entries + 1;
        let before = mutation.before_document.map(document_value).transpose()?;
        let after = mutation.after_document.map(document_value).transpose()?;
        let after_snapshot = exact_snapshot(mutation.after_document, mutation.after_bytes)?;
        let payload = AuditPayload {
            version: AUDIT_VERSION,
            sequence,
            timestamp: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .context("could not format audit timestamp")?,
            actor: self.actor.to_owned(),
            source: mutation.source,
            agent: self.attribution.agent.clone(),
            authorization: self.attribution.authorization.clone(),
            intent: self.attribution.intent.clone(),
            access: mutation.access.cloned(),
            message: mutation.message.map(str::to_owned),
            idempotency: mutation.idempotency.cloned(),
            action: mutation.action,
            record: AuditRecord {
                collection: mutation.collection.to_owned(),
                id: mutation.id.to_owned(),
            },
            changes: diff_documents(before.as_ref(), after.as_ref()),
            after_snapshot,
            before_hash: mutation.before_hash,
            after_hash: mutation.after_hash,
            previous_hash,
        };
        register_idempotency_identity(&mut idempotency_identities, &payload)?;
        let serialized =
            serde_json::to_string(&payload).context("could not serialize audit event")?;
        let change_digest = change_set_hash(&serialized)?;
        if let Some(approved) = payload
            .authorization
            .as_ref()
            .and_then(|authorization| authorization.approved_changes.as_deref())
            && approved != change_digest
        {
            return Err(approval_mismatch(format!(
                "record {}/{} does not match the approved change set: {approved} was approved, but this change set is {change_digest}",
                payload.record.collection, payload.record.id
            )));
        }
        let hash = event_hash(serialized.as_bytes());

        Ok(PreparedEntry {
            hash,
            payload: serialized,
            parsed: payload,
            change_digest,
        })
    }

    pub fn assert_current(&self, collection: &str, id: &str, contents: &[u8]) -> Result<()> {
        let states = self.record_states()?;
        Self::assert_current_in(&states, collection, id, contents)
    }

    /// Compare one materialized record with an already replayed journal state.
    pub(crate) fn assert_current_in(
        states: &AuditedRecordStates,
        collection: &str,
        id: &str,
        contents: &[u8],
    ) -> Result<()> {
        let actual = Some(record_hash(contents));
        match states.get(&(collection.to_owned(), id.to_owned())) {
            Some(state) if state.hash == actual => Ok(()),
            None => Err(missing_audit_history(collection, id, "using")),
            Some(_) => Err(stale_audit_state(collection, id)),
        }
    }

    pub fn commit<F>(&self, entry: PreparedEntry, target: &Path, apply: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        let target = target.to_path_buf();
        validate_relative_target(&target)?;
        let expected_target = self
            .records_dir
            .join(&entry.parsed.record.collection)
            .join(format!("{}.md", entry.parsed.record.id));
        if target != expected_target {
            bail!("audit target does not match its record identity");
        }
        let pending = PendingMutation {
            target,
            before_hash: entry.parsed.before_hash.clone(),
            after_hash: entry.parsed.after_hash.clone(),
            hash: entry.hash.clone(),
            payload: entry.payload.clone(),
        };
        let pending_bytes = serde_json::to_vec_pretty(&pending)
            .context("could not serialize pending audit mutation")?;
        paths::write_new(
            self.root,
            Path::new(PENDING_PATH),
            &pending_bytes,
            PENDING_LABEL,
        )?;

        let result = apply();
        let current_hash = self.record_file_hash(
            &pending.target,
            &entry.parsed.record.collection,
            &entry.parsed.record.id,
        )?;

        if current_hash == pending.after_hash {
            self.append(&entry)?;
            self.clear_pending()?;
            return result;
        }

        if result.is_err() {
            self.clear_pending()?;
            return result;
        }

        bail!(
            "record mutation completed without producing the audited state; pending recovery was retained"
        )
    }

    /// Accept one event while advancing the verified generation held by a
    /// locked bulk save. Direct filesystem tampering is still checked against
    /// the exact prepared hash, and the on-disk tail must still match the
    /// retained chain cursor before the append is published.
    pub(crate) fn accept_reconciled_in(
        &self,
        entry: PreparedEntry,
        target: &Path,
        snapshot: &mut ReconciliationSnapshot,
    ) -> Result<AuditEntry> {
        let result = self.validate_accepted_entry(&entry, target)?;
        self.append_in_snapshot(&entry, snapshot)?;
        Ok(result)
    }

    fn validate_accepted_entry(&self, entry: &PreparedEntry, target: &Path) -> Result<AuditEntry> {
        let target = target.to_path_buf();
        validate_relative_target(&target)?;
        let expected_target = self
            .records_dir
            .join(&entry.parsed.record.collection)
            .join(format!("{}.md", entry.parsed.record.id));
        if target != expected_target {
            bail!("audit target does not match its record identity");
        }
        let current_hash = self.record_file_hash(
            &target,
            &entry.parsed.record.collection,
            &entry.parsed.record.id,
        )?;
        if current_hash != entry.parsed.after_hash {
            return Err(conflict(format!(
                "record {}/{} changed while it was being saved",
                entry.parsed.record.collection, entry.parsed.record.id
            )));
        }
        let result = AuditEntry {
            hash: entry.hash.clone(),
            payload: entry.parsed.clone(),
        };
        Ok(result)
    }

    pub fn recover_pending(&self) -> Result<()> {
        let Some(serialized) =
            paths::read_optional(self.root, Path::new(PENDING_PATH), PENDING_LABEL)?
        else {
            return Ok(());
        };

        let pending: PendingMutation =
            serde_json::from_slice(&serialized).context("the pending audit mutation is invalid")?;
        validate_relative_target(&pending.target)?;
        let payload: AuditPayload =
            serde_json::from_str(&pending.payload).context("pending audit payload is invalid")?;
        if !(MIN_AUDIT_VERSION..=AUDIT_VERSION).contains(&payload.version) {
            bail!("unsupported audit event version {}", payload.version);
        }
        if event_hash(pending.payload.as_bytes()) != pending.hash {
            bail!("pending audit mutation hash does not match its payload");
        }
        if payload.before_hash != pending.before_hash || payload.after_hash != pending.after_hash {
            bail!("pending audit mutation state hashes are inconsistent");
        }
        validate_component(&payload.record.collection, "collection")?;
        validate_component(&payload.record.id, "id")?;
        let expected_target = self
            .records_dir
            .join(&payload.record.collection)
            .join(format!("{}.md", payload.record.id));
        if pending.target != expected_target {
            bail!("pending audit mutation target does not match its record identity");
        }

        let current_hash = self.record_file_hash(
            &pending.target,
            &payload.record.collection,
            &payload.record.id,
        )?;
        // Recovery is a write path too. Refuse to append or bless a pending
        // event on top of a journal whose change sets no longer reproduce the
        // states they claim, and name the guilty committed sequence first.
        let (mut states, mut chain) = self.states(false)?;
        self.verify_legacy_representation_heads(&states)?;
        let head = self.load_head()?;

        if let Some(head) = head.as_ref() {
            if head.entry.payload.sequence == payload.sequence && head.entry.hash == pending.hash {
                if current_hash != pending.after_hash {
                    bail!(
                        "audit event was committed but the record does not match its audited state"
                    );
                }
                self.clear_pending()?;
                return Ok(());
            }
            if head.entry.payload.sequence >= payload.sequence {
                bail!("pending audit mutation conflicts with committed audit history");
            }
        }

        if current_hash == pending.after_hash {
            let expected_sequence = head
                .as_ref()
                .map_or(1, |head| head.entry.payload.sequence + 1);
            let expected_previous = head.as_ref().map(|head| head.entry.hash.as_str());
            if payload.sequence != expected_sequence
                || payload.previous_hash.as_deref() != expected_previous
            {
                bail!("audit event does not extend the current chain head");
            }
            register_idempotency_identity(&mut chain.idempotency_identities, &payload)?;
            replay_entry(
                &mut states,
                &AuditEntry {
                    hash: pending.hash.clone(),
                    payload: payload.clone(),
                },
            )?;
            let change_digest = change_set_hash(&pending.payload)?;
            self.append(&PreparedEntry {
                hash: pending.hash,
                payload: pending.payload,
                parsed: payload,
                change_digest,
            })?;
            self.clear_pending()?;
            return Ok(());
        }

        if current_hash == pending.before_hash {
            self.clear_pending()?;
            return Ok(());
        }

        bail!("pending audit mutation cannot be recovered because the record matches neither state")
    }

    pub fn recent(&self, limit: usize, filter: AuditFilter<'_>) -> Result<Vec<AuditEntry>> {
        self.recent_where(limit, filter, |_| Ok(true))
    }

    /// Select recent history while reconstructing its exact encryption
    /// metadata in the same forward verification and semantic replay.
    pub(crate) fn recent_history(
        &self,
        limit: usize,
        filter: AuditFilter<'_>,
    ) -> Result<AuditHistory> {
        self.recent_history_where(limit, filter, |_| Ok(true))
    }

    /// Find the committed result for one fully scoped retry identity.
    ///
    /// Callers hold the audit lock. `verify_chain` both validates every event
    /// and makes the journal itself authoritative; no disposable side index
    /// can cause a replay or conflict by itself.
    pub(crate) fn idempotency_result(
        &self,
        principal: &str,
        operation: &str,
        collection: &str,
        id: &str,
        key_hash: &str,
        request_hash: &str,
    ) -> Result<Option<AuditIdempotencyResult>> {
        let mut result = None;
        let mut latest = AuditedRecordStates::new();
        self.verify_chain(|entry, _| {
            replay_entry(&mut latest, entry)?;
            let Some(stored) = entry.payload.idempotency.as_ref() else {
                return Ok(());
            };
            if stored.principal != principal
                || stored.operation != operation
                || stored.key_hash != key_hash
                || entry.payload.record.collection != collection
                || entry.payload.record.id != id
            {
                return Ok(());
            }
            if stored.request_hash != request_hash {
                return Err(idempotency_conflict(format!(
                    "idempotency key was already used for a different {operation} request on record {collection}/{id}"
                )));
            }
            result = Some(stored.result.clone());
            Ok(())
        })?;
        Ok(result)
    }

    /// Return recent events that satisfy both the caller's filter and a
    /// visibility predicate.
    ///
    /// Applying `visible` while walking newest-first is important for callers
    /// that enforce record-level access: `limit` must count visible events,
    /// rather than truncating the journal before inaccessible events are
    /// removed.
    pub(crate) fn recent_where(
        &self,
        limit: usize,
        filter: AuditFilter<'_>,
        mut visible: impl FnMut(&AuditEntry) -> Result<bool>,
    ) -> Result<Vec<AuditEntry>> {
        self.verify_chain(|_, _| Ok(()))?;
        let mut result = Vec::new();
        let paths = self.segment_paths()?;

        for path in paths.into_iter().rev() {
            let mut entries = self.read_segment(&path)?;
            entries.reverse();
            for stored in entries {
                if !filter.matches(&stored.entry.payload) {
                    continue;
                }
                if !visible(&stored.entry)? {
                    continue;
                }
                result.push(stored.entry);
                if result.len() == limit {
                    return Ok(result);
                }
            }
        }

        Ok(result)
    }

    /// The history equivalent of [`Self::recent_where`], with manifest
    /// transitions produced by the same verified replay rather than a second
    /// full journal scan.
    ///
    /// Entries are encountered oldest-first because semantic replay is
    /// forward-only. A bounded deque retains the newest visible matches and is
    /// reversed at the end, preserving the public newest-first order and the
    /// rule that inaccessible entries do not consume `limit`.
    pub(crate) fn recent_history_where(
        &self,
        limit: usize,
        filter: AuditFilter<'_>,
        mut visible: impl FnMut(&AuditEntry) -> Result<bool>,
    ) -> Result<AuditHistory> {
        let mut entries = VecDeque::new();
        let mut encryption_transitions = HashMap::new();
        self.replay_encryption_chain(|entry, _, transition| {
            if !transition.is_empty() {
                encryption_transitions.insert(entry.payload.sequence, transition);
            }
            if !filter.matches(&entry.payload) || !visible(entry)? {
                return Ok(());
            }
            // `recent_where` historically treats zero as unbounded. Public
            // CLI and HTTP limits are positive, but preserve the domain API's
            // established behavior here.
            if limit > 0 && entries.len() == limit {
                entries.pop_front();
            }
            entries.push_back(entry.clone());
            Ok(())
        })?;
        Ok(AuditHistory {
            entries: entries.into_iter().rev().collect(),
            encryption_transitions,
        })
    }

    pub fn head(&self) -> Result<AuditHead> {
        let state = self.verify_chain(|_, _| Ok(()))?;
        Ok(AuditHead {
            sequence: state.entries,
            hash: state.head_hash,
        })
    }

    /// Replay the complete verified chain and retain each event's exact
    /// historical manifest policy. Replay also checks v3 snapshots,
    /// idempotency results, and scoped retry uniqueness before this metadata is
    /// trusted by logical history projection or lazy context creation.
    pub(crate) fn encryption_storage_transitions(
        &self,
    ) -> Result<HashMap<u64, AuditEncryptionTransition>> {
        let mut transitions = HashMap::new();
        self.replay_encryption_chain(|entry, _, transition| {
            if !transition.is_empty() {
                transitions.insert(entry.payload.sequence, transition);
            }
            Ok(())
        })?;
        Ok(transitions)
    }

    /// Whether verified history contains any manifest-owned ciphertext. Used
    /// before lazily creating a context for a database initialized by an older
    /// CR version, including when the encrypted record was later deleted.
    pub(crate) fn contains_protected_storage(&self) -> Result<bool> {
        Ok(self
            .encryption_storage_transitions()?
            .values()
            .any(|transition| {
                transition
                    .before
                    .as_ref()
                    .is_some_and(|state| state.has_envelopes)
                    || transition
                        .after
                        .as_ref()
                        .is_some_and(|state| state.has_envelopes)
            }))
    }

    /// Replay the chain, reconcile it with the records, and check the head.
    ///
    /// The head is checked against `expected_head` when the caller supplied
    /// one, and otherwise against the anchor recorded at the database root.
    /// An explicit checkpoint wins deliberately: it arrives from outside the
    /// database, while the anchor file sits inside the blast radius of anyone
    /// who can edit the journal, so a caller holding an out-of-band value must
    /// not have their answer decided by an in-band file. `cr check` reports the
    /// anchor either way.
    ///
    /// Ordering matters. The chain is replayed first, so a damaged journal is
    /// reported as a damaged journal and never as an anchor problem.
    pub fn verify(&self, expected_head: Option<&str>) -> Result<AuditVerification> {
        self.verify_with_record_hashes(expected_head)
            .map(|(verification, _)| verification)
    }

    /// Verify and retain the replayed record hashes from that exact head.
    ///
    /// Sync uses this while holding the audit lock so every target condition
    /// comes from the same state as the head comparison. The public verifier
    /// keeps its existing response shape and discards this internal map.
    pub(crate) fn verify_with_record_hashes(
        &self,
        expected_head: Option<&str>,
    ) -> Result<(AuditVerification, VerifiedRecordHashes)> {
        let (verification, latest) = self.verify_with_record_states(expected_head)?;
        let latest_hashes = latest
            .iter()
            .map(|(record, state)| (record.clone(), state.hash.clone()))
            .collect::<HashMap<_, _>>();
        Ok((verification, latest_hashes))
    }

    /// Verify and retain complete replayed record state from the exact same
    /// journal generation. Sync staging needs both hashes and authenticated
    /// encryption ownership for logical reads; returning the replay avoids a
    /// second full pass for every existing target.
    pub(crate) fn verify_with_record_states(
        &self,
        expected_head: Option<&str>,
    ) -> Result<(AuditVerification, AuditedRecordStates)> {
        let (latest, state) = self.states(true)?;
        self.verify_legacy_representation_heads(&latest)?;

        let anchor = match expected_head {
            Some(expected) => {
                if state.head_hash.as_deref() != Some(expected) {
                    return Err(conflict(format!(
                        "audit head does not match expected checkpoint (actual: {})",
                        state.head_hash.as_deref().unwrap_or("none")
                    )));
                }
                AnchorStatus::Overridden
            }
            None => self.anchor_status(self.load_anchor()?.as_ref(), &state)?,
        };

        let latest_hashes = latest
            .iter()
            .map(|(record, state)| (record.clone(), state.hash.clone()))
            .collect::<HashMap<_, _>>();
        self.verify_records(&latest_hashes)?;
        Ok((
            AuditVerification {
                entries: state.entries,
                records_checked: latest.len(),
                head: AuditHead {
                    sequence: state.entries,
                    hash: state.head_hash,
                },
                anchor,
            },
            latest,
        ))
    }

    /// Reconstruct record hashes at one historical chain head.
    ///
    /// Version-1 sync ledgers recorded the head but not their target hashes.
    /// Replaying the immutable prefix lets recovery upgrade those ledgers
    /// safely instead of adopting whatever record bytes happen to exist now.
    pub(crate) fn record_hashes_at(
        &self,
        sequence: u64,
        expected_head: Option<&str>,
    ) -> Result<VerifiedRecordHashes> {
        let mut latest = AuditedRecordStates::new();
        let mut hashes = VerifiedRecordHashes::new();
        let mut head_at_sequence = None;
        let chain = self.verify_chain(|entry, _| {
            replay_entry(&mut latest, entry)?;
            if entry.payload.sequence == sequence {
                hashes = latest
                    .iter()
                    .map(|(record, state)| (record.clone(), state.hash.clone()))
                    .collect();
            }
            if entry.payload.sequence == sequence {
                head_at_sequence = Some(entry.hash.clone());
            }
            Ok(())
        })?;
        if chain.entries < sequence
            || head_at_sequence.as_deref() != expected_head
            || (sequence == 0 && expected_head.is_some())
        {
            return Err(conflict(
                "sync run ledger does not match the audit head it recorded",
            ));
        }
        self.verify_legacy_representation_heads(&latest)?;
        Ok(hashes)
    }

    /// Read the anchor and judge it against a freshly replayed chain.
    ///
    /// Fails with [`DomainError::AnchorMismatch`] when the two disagree, so a
    /// read-only inspection of a tampered database is a failure rather than a
    /// report. Replays the chain itself, which costs one extra pass over the
    /// journal; `check` and `verify` are already O(events).
    pub fn anchor_report(&self) -> Result<AnchorReport> {
        let state = self.verify_chain(|_, _| Ok(()))?;
        let stored = self.load_anchor()?;
        let status = self.anchor_status(stored.as_ref(), &state)?;
        Ok(AnchorReport {
            anchor: stored,
            head: AuditHead {
                sequence: state.entries,
                hash: state.head_hash,
            },
            status,
        })
    }

    /// Write the anchor the current head implies.
    ///
    /// Refuses when the stored anchor already disagrees with the journal. `cr`
    /// must never be the tool that launders a forgery into a fresh attestation:
    /// an attacker with write access can of course overwrite the file directly,
    /// but they will not be handed a command that does it for them and reports
    /// success. Adopting the anchor on an existing database, and repairing one
    /// left behind by a crash, both go through here.
    pub fn write_anchor(&self) -> Result<AuditAnchor> {
        let state = self.verify_chain(|_, _| Ok(()))?;
        self.anchor_status(self.load_anchor()?.as_ref(), &state)?;
        let Some(anchor) = self.anchor_at(state.entries)? else {
            return Err(conflict("there are no audit events to anchor"));
        };
        self.store_anchor(&anchor)?;
        Ok(anchor)
    }

    /// Judge `stored` against a chain that has already been replayed.
    ///
    /// The whole stale-versus-tampered question is decided here, and it is
    /// decided by *position* rather than by comparing head hashes. An anchor
    /// names a sequence as well as a hash, and the journal is append-only, so
    /// the event at that sequence is fixed for all time. Recomputing the anchor
    /// the journal implies at exactly that sequence gives three separable
    /// answers instead of one "does not match":
    ///
    /// - the journal is shorter than the anchor claims — events were removed,
    ///   or the anchor was rolled forward past them;
    /// - the journal has a different event there — history at or before the
    ///   anchored point was rewritten;
    /// - the journal has the same event there and more events after it — the
    ///   anchor merely lags, which is what a crash between appending the event
    ///   and rewriting the anchor leaves behind.
    ///
    /// Only the first two are failures, and neither can be produced by lagging.
    fn anchor_status(
        &self,
        stored: Option<&AuditAnchor>,
        state: &ChainState,
    ) -> Result<AnchorStatus> {
        let Some(stored) = stored else {
            return Ok(if state.entries == 0 {
                AnchorStatus::Empty
            } else {
                AnchorStatus::Absent
            });
        };
        if stored.sequence == 0 {
            return Err(anchor_mismatch(
                "the audit anchor does not name an audit event",
            ));
        }
        let Some(derived) = self.anchor_at(stored.sequence)? else {
            return Err(anchor_mismatch(format!(
                "the audit anchor attests to sequence {} but the journal ends at sequence {}",
                stored.sequence, state.entries
            )));
        };
        if derived.hash != stored.hash {
            return Err(anchor_mismatch(format!(
                "the audit event at sequence {} does not match the audit anchor (anchored {}, actual {})",
                stored.sequence, stored.hash, derived.hash
            )));
        }
        if derived != *stored {
            return Err(anchor_mismatch(format!(
                "the audit anchor does not describe the audit event at sequence {} it names",
                stored.sequence
            )));
        }
        Ok(if stored.sequence == state.entries {
            AnchorStatus::Matched {
                sequence: stored.sequence,
            }
        } else {
            AnchorStatus::Behind {
                sequence: stored.sequence,
                head: state.entries,
            }
        })
    }

    /// The anchor the stored journal implies at `sequence`, or `None` when the
    /// journal does not reach that far.
    ///
    /// Reads only the one segment that can hold it, rather than walking the
    /// chain again. Callers run this after a full replay has already checked
    /// sequence continuity, so the segment that starts at or before `sequence`
    /// is the only one that can contain it.
    fn anchor_at(&self, sequence: u64) -> Result<Option<AuditAnchor>> {
        if sequence == 0 {
            return Ok(None);
        }
        let mut chosen = None;
        for path in self.segment_paths()? {
            if segment_start(&path)? > sequence {
                break;
            }
            chosen = Some(path);
        }
        let Some(path) = chosen else {
            return Ok(None);
        };
        Ok(self
            .read_segment(&path)?
            .iter()
            .find(|stored| stored.entry.payload.sequence == sequence)
            .map(|stored| AuditAnchor::of(&stored.entry)))
    }

    /// Read the anchor file, classifying anything unreadable as a mismatch.
    ///
    /// A file that cannot be interpreted is not the same as no file: somebody
    /// or something wrote it. Reporting it as absent would let a single
    /// scribble silently downgrade verification, so it fails instead.
    fn load_anchor(&self) -> Result<Option<AuditAnchor>> {
        let Some(bytes) = paths::read_optional(self.root, Path::new(ANCHOR_PATH), ANCHOR_LABEL)?
        else {
            return Ok(None);
        };
        let value: Value = serde_json::from_slice(&bytes).map_err(unreadable_anchor)?;
        match value.get("version").and_then(Value::as_u64) {
            Some(version) if version == u64::from(ANCHOR_VERSION) => {}
            Some(version) => {
                return Err(anchor_mismatch(format!(
                    "the audit anchor records checkpoint format version {version}, and this build understands version {ANCHOR_VERSION}"
                )));
            }
            None => {
                return Err(unreadable_anchor(serde::de::Error::missing_field(
                    "version",
                )));
            }
        }
        serde_json::from_value(value)
            .map(Some)
            .map_err(unreadable_anchor)
    }

    /// Publish `anchor` at the database root, creating or replacing it.
    fn store_anchor(&self, anchor: &AuditAnchor) -> Result<()> {
        let relative = Path::new(ANCHOR_PATH);
        let bytes = anchor.serialize()?;
        match paths::entry_kind(self.root, relative, ANCHOR_LABEL)? {
            Some(EntryKind::File) => {
                paths::write_replace(self.root, relative, &bytes, ANCHOR_LABEL)
            }
            Some(kind) => Err(paths::refuse_entry(ANCHOR_LABEL, kind)),
            None => paths::write_new(self.root, relative, &bytes, ANCHOR_LABEL),
        }
    }

    pub fn record_states(&self) -> Result<Arc<AuditedRecordStates>> {
        let states = match self.journal {
            Some(journal) => self.cached_journal(journal)?.states,
            None => Arc::new(self.states(false)?.0),
        };
        // Not cached: this reads record files, which change without the
        // journal changing.
        self.verify_legacy_representation_heads(&states)?;
        Ok(states)
    }

    /// When each record in one collection was created and last changed.
    ///
    /// A deletion ends a record's lifecycle, so a later create with the same ID
    /// starts a new `created_at` rather than inheriting the tombstoned one.
    /// Records with no audit history at all are simply absent from the map;
    /// the caller decides how to present an unaudited file.
    pub(crate) fn record_activity(
        &self,
        collection: &str,
    ) -> Result<BTreeMap<String, RecordActivity>> {
        Ok(self
            .collections_activity(|name| name == collection)?
            .remove(collection)
            .unwrap_or_default())
    }

    /// [`Self::record_activity`] for every collection `include` accepts, keyed
    /// by collection, from one walk of the chain rather than one per
    /// collection.
    pub(crate) fn collections_activity(
        &self,
        include: impl Fn(&str) -> bool,
    ) -> Result<CollectionsActivity> {
        if let Some(journal) = self.journal {
            return Ok(self
                .cached_journal(journal)?
                .activity
                .iter()
                .filter(|(collection, _)| include(collection))
                .map(|(collection, activity)| (collection.clone(), activity.clone()))
                .collect());
        }
        let mut collections = CollectionsActivity::new();
        self.verify_chain(|entry, _| {
            if include(&entry.payload.record.collection) {
                track_activity(&mut collections, entry);
            }
            Ok(())
        })?;
        Ok(collections)
    }

    /// The verified journal as `journal` holds it, brought up to date first.
    ///
    /// An empty cache that may resume starts from the walk saved on disk.
    /// Anything the cache cannot vouch for is walked afresh, and a walk that
    /// fails leaves nothing cached, so the next reader starts from the first
    /// segment and meets the same failure rather than a stale success.
    fn cached_journal(&self, journal: &JournalCache) -> Result<JournalSnapshot> {
        let mut verified = journal.lock();
        let paths = self.segment_paths()?;
        if verified.is_none() && journal.resume {
            *verified = self.load_journal_cache();
        }
        if let Some(cached) = verified.as_mut() {
            match self.extend_journal(cached, &paths) {
                Ok(true) => return Ok(cached.snapshot()),
                Ok(false) => {}
                // A saved walk only ever saves work. Whatever went wrong
                // continuing one, a walk from the first event decides.
                Err(_) if !cached.walked => {}
                Err(error) => {
                    *verified = None;
                    return Err(error);
                }
            }
        }
        *verified = None;
        let walked = self.walk_journal(&paths)?;
        let snapshot = walked.snapshot();
        *verified = Some(walked);
        Ok(snapshot)
    }

    /// Replay the whole journal from its first event, trusting nothing a cache
    /// holds, and leave the walk in `journal` for the readers after it.
    ///
    /// This is the walk a write makes before it extends the chain, so every
    /// walk [`Self::save_journal_cache`] saves descends from one.
    fn walk_into(&self, journal: &JournalCache) -> Result<(AuditedRecordStates, ChainState)> {
        let walked = self
            .segment_paths()
            .and_then(|paths| self.walk_journal(&paths));
        let mut verified = journal.lock();
        match walked {
            Ok(walked) => {
                let result = ((*walked.states).clone(), walked.walk.state());
                *verified = Some(walked);
                Ok(result)
            }
            Err(error) => {
                *verified = None;
                Err(error)
            }
        }
    }

    /// Verify every segment from the first, keeping what a later
    /// [`Self::extend_journal`] needs to resume where this stopped.
    ///
    /// Segments are read one at a time, and only the newest is kept.
    fn walk_journal(&self, paths: &[PathBuf]) -> Result<VerifiedJournal> {
        #[cfg(test)]
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut journal = VerifiedJournal::new();
        for (index, path) in paths.iter().enumerate() {
            let (stamp, contents) = self.read_stamped_segment(path)?;
            journal.verify(path, &contents, None)?;
            if index + 1 == paths.len() {
                journal.tail = Some((path.clone(), VerifiedPrefix::Bytes(contents)));
            } else {
                journal.sealed.push((path.clone(), stamp));
            }
        }
        Ok(journal)
    }

    /// Leave the journal this process has verified on disk, so that the next
    /// command resumes from it instead of from the first event.
    ///
    /// Called after an append, while the audit lock is still held, which is
    /// what keeps two saves from overlapping. Only a walk this process began
    /// at the first event is saved; see [`JournalCache`]. Failing to save one
    /// costs the next reader time and nothing else, so nothing here can fail
    /// the write that has already been committed.
    pub(crate) fn save_journal_cache(&self) {
        let Some(journal) = self.journal.filter(|journal| journal.save) else {
            return;
        };
        let mut verified = journal.lock();
        let Some(cached) = verified.as_mut().filter(|cached| cached.walked) else {
            return;
        };
        let extended = self
            .segment_paths()
            .and_then(|paths| self.extend_journal(cached, &paths));
        match extended {
            Ok(true) => {}
            Ok(false) => return,
            Err(_) => {
                *verified = None;
                return;
            }
        }
        if let Ok(serialized) = cached.serialize() {
            drop(verified);
            let _ = self.store_journal_cache(&serialized);
        }
    }

    /// The walk saved on disk, to resume, or `None` when there is no usable
    /// one. Whether it still describes the segments is for
    /// [`Self::extend_journal`] to judge.
    fn load_journal_cache(&self) -> Option<VerifiedJournal> {
        let serialized = paths::read_optional(
            self.root,
            Path::new(JOURNAL_CACHE_PATH),
            JOURNAL_CACHE_LABEL,
        )
        .ok()??;
        VerifiedJournal::deserialize(&serialized)
    }

    fn store_journal_cache(&self, serialized: &[u8]) -> Result<()> {
        let relative = Path::new(JOURNAL_CACHE_PATH);
        match paths::entry_kind(self.root, relative, JOURNAL_CACHE_LABEL)? {
            Some(EntryKind::File) => {
                paths::write_replace(self.root, relative, serialized, JOURNAL_CACHE_LABEL)
            }
            Some(kind) => Err(paths::refuse_entry(JOURNAL_CACHE_LABEL, kind)),
            None => {
                // Everything under `.cr/cache/` is derived from files that
                // are committed, and rewritten on every append. Keep it out of
                // a `git add .` from the start.
                let ignore = Path::new(CACHE_IGNORE_PATH);
                if let Err(error) = paths::write_new(self.root, ignore, b"*\n", CACHE_IGNORE_LABEL)
                    && !is_already_exists(&error)
                {
                    return Err(error);
                }
                paths::write_new(self.root, relative, serialized, JOURNAL_CACHE_LABEL)
            }
        }
    }

    /// Bring `journal` up to date with the segments now on disk, verifying
    /// only the events it has not seen.
    ///
    /// `Ok(false)` means something it had already verified is no longer what
    /// it verified, which only a walk from the first segment can judge.
    /// `journal` is untouched in that case; it is changed only once every
    /// earlier segment has been found as it was left.
    fn extend_journal(&self, journal: &mut VerifiedJournal, paths: &[PathBuf]) -> Result<bool> {
        let sealed = journal.sealed.len();
        let known = sealed + usize::from(journal.tail.is_some());
        if paths.len() < known {
            return Ok(false);
        }
        for ((path, stamp), current) in journal.sealed.iter().zip(paths) {
            if path != current || self.segment_stamp(path)? != *stamp {
                return Ok(false);
            }
        }
        let mut segments = Vec::with_capacity(paths.len() - sealed);
        if let Some((path, verified)) = &journal.tail {
            if *path != paths[sealed] {
                return Ok(false);
            }
            let (stamp, contents) = self.read_stamped_segment(path)?;
            if !verified.begins(&contents) {
                return Ok(false);
            }
            segments.push(UnverifiedSegment {
                path: path.clone(),
                stamp,
                contents,
                verified: Some(verified.len()),
            });
        }
        for path in &paths[known..] {
            let (stamp, contents) = self.read_stamped_segment(path)?;
            segments.push(UnverifiedSegment {
                path: path.clone(),
                stamp,
                contents,
                verified: None,
            });
        }
        journal.append(segments)?;
        Ok(true)
    }

    /// A segment's contents and the metadata of the very file they were read
    /// from, so a replacement between the two cannot pair one file's identity
    /// with another's bytes.
    fn read_stamped_segment(&self, path: &Path) -> Result<(SegmentStamp, Vec<u8>)> {
        let mut file = paths::open_file(self.root, path, SEGMENT_LABEL)?;
        let stamp = SegmentStamp::of(&file)?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .with_context(|| format!("could not read {SEGMENT_LABEL}"))?;
        Ok((stamp, contents))
    }

    fn segment_stamp(&self, path: &Path) -> Result<SegmentStamp> {
        SegmentStamp::of(&paths::open_file(self.root, path, SEGMENT_LABEL)?)
    }

    /// Replay the chain once while also enforcing approval bindings.
    ///
    /// `cr check` needs both guarantees and the resulting state map. Keeping
    /// them in one pass avoids replaying the complete journal once for
    /// approval verification and again for record reconciliation.
    pub(crate) fn record_states_with_approvals(&self) -> Result<AuditedRecordStates> {
        let (states, _) = self.states(true)?;
        self.verify_legacy_representation_heads(&states)?;
        Ok(states)
    }

    /// Whether the latest audited state for this record is a deletion.
    pub(crate) fn record_is_tombstoned(&self, collection: &str, id: &str) -> Result<bool> {
        self.record_state(collection, id)
            .map(|(state, _)| state == Some(None))
    }

    /// Whether this principal participated in an event outside its own user
    /// lifecycle. The complete verified chain is examined; a page or recent
    /// history limit can never make an identity appear unused.
    pub(crate) fn principal_has_external_history(&self, principal: &str) -> Result<bool> {
        let mut used = false;
        self.verify_chain(|entry, _| {
            let access = entry.payload.access.as_ref();
            let actor_matches = access.map_or_else(
                || {
                    principal_id(&entry.payload.actor)
                        .ok()
                        .is_some_and(|actor| actor == principal)
                },
                |decision| {
                    decision.principal == principal
                        || decision
                            .impersonated_by
                            .as_ref()
                            .is_some_and(|identity| identity.principal == principal)
                },
            );
            let is_own_user_event = entry.payload.record.collection == USERS_COLLECTION
                && entry.payload.record.id == principal;
            if actor_matches && !is_own_user_event {
                used = true;
            }
            Ok(())
        })?;
        Ok(used)
    }

    /// Replay the chain into per-record state.
    ///
    /// `check_approvals` recomputes each event's previewed-change digest from
    /// its stored `changes`. Only `verify` asks for that. Reading history must
    /// not fail on it: an auditor who has just been told that a change set does
    /// not match its approval needs `audit log` to still show them the event.
    ///
    /// With a journal cache attached, the unchecked replay is also left in the
    /// cache for the readers that follow, but it never starts from the cache.
    fn states(&self, check_approvals: bool) -> Result<(AuditedRecordStates, ChainState)> {
        if !check_approvals && let Some(journal) = self.journal {
            return self.walk_into(journal);
        }
        let mut latest = AuditedRecordStates::new();
        let chain = self.verify_chain(|entry, payload| {
            if check_approvals {
                verify_approved_changes(entry, payload)?;
            }
            replay_entry(&mut latest, entry)
        })?;
        Ok((latest, chain))
    }

    /// Verify and semantically replay the complete chain once, exposing the
    /// exact manifest ownership immediately around every event to a caller
    /// that needs a derived projection.
    fn replay_encryption_chain<F>(&self, mut visitor: F) -> Result<ChainState>
    where
        F: FnMut(&AuditEntry, &str, AuditEncryptionTransition) -> Result<()>,
    {
        let mut latest = AuditedRecordStates::new();
        let chain = self.verify_chain(|entry, payload| {
            let key = (
                entry.payload.record.collection.clone(),
                entry.payload.record.id.clone(),
            );
            let before = latest
                .get(&key)
                .and_then(|state| state.document.as_ref())
                .and_then(audit_document_encryption_metadata);
            replay_entry(&mut latest, entry)?;
            let after = latest
                .get(&key)
                .and_then(|state| state.document.as_ref())
                .and_then(audit_document_encryption_metadata);
            visitor(entry, payload, AuditEncryptionTransition { before, after })
        })?;
        Ok(chain)
    }

    fn append(&self, entry: &PreparedEntry) -> Result<()> {
        // Recheck the complete journal immediately before publishing. Normal
        // mutation preparation already refuses a reused identity, but append
        // is also reached by pending recovery and must be safe on its own.
        let (states, chain) = self.states(false)?;
        let mut snapshot = ReconciliationSnapshot { states, chain };
        self.append_in_snapshot(entry, &mut snapshot)?;
        self.save_journal_cache();
        Ok(())
    }

    fn append_in_snapshot(
        &self,
        entry: &PreparedEntry,
        snapshot: &mut ReconciliationSnapshot,
    ) -> Result<()> {
        register_idempotency_identity(&mut snapshot.chain.idempotency_identities, &entry.parsed)?;
        let head = self.load_head()?;
        let disk_sequence = head.as_ref().map_or(0, |head| head.entry.payload.sequence);
        let disk_hash = head.as_ref().map(|head| head.entry.hash.as_str());
        if disk_sequence != snapshot.chain.entries
            || disk_hash != snapshot.chain.head_hash.as_deref()
            || entry.parsed.sequence != snapshot.chain.entries + 1
            || entry.parsed.previous_hash != snapshot.chain.head_hash
        {
            bail!("audit event does not extend the current chain head");
        }
        if let Some(head) = head.as_ref() {
            verify_version_progress(
                head.entry.payload.version,
                entry.parsed.version,
                entry.parsed.sequence,
            )?;
        }
        if event_hash(entry.payload.as_bytes()) != entry.hash {
            bail!("audit event hash does not match its payload");
        }
        let result = AuditEntry {
            hash: entry.hash.clone(),
            payload: entry.parsed.clone(),
        };
        replay_entry(&mut snapshot.states, &result)?;

        let line = stored_line(&entry.hash, &entry.payload)?;
        match head {
            Some(head)
                if head.segment_entries < self.segment_max_events
                    && paths::file_length(self.root, &head.segment_path, SEGMENT_LABEL)?
                        + line.len() as u64
                        <= self.segment_max_bytes =>
            {
                let mut contents = self.read_segment_bytes(&head.segment_path)?;
                if !contents.ends_with(b"\n") {
                    bail!("an audit segment has a truncated tail");
                }
                contents.extend_from_slice(line.as_bytes());
                paths::write_replace(self.root, &head.segment_path, &contents, SEGMENT_LABEL)?;
            }
            _ => {
                let path = Path::new(SEGMENT_DIRECTORY)
                    .join(format!("{:020}.jsonl", entry.parsed.sequence));
                paths::write_new(self.root, &path, line.as_bytes(), SEGMENT_LABEL)?;
            }
        }

        // The anchor is rewritten here, after the event is durable, because
        // every path that advances the chain — `commit`, `accept`, pending
        // recovery, and therefore `save`, `sync`, and `audit baseline` — funnels
        // through this one function. Writing it before the append would let the
        // anchor lead the journal, which is indistinguishable from events having
        // been removed; writing it after means a crash in between leaves the
        // anchor one event behind, which `anchor_status` reports as lagging and
        // never as tampering.
        //
        // A failure here is propagated rather than swallowed. The event is
        // already committed, and the message says so: a silently unmaintained
        // anchor is a security downgrade that nothing else would report, and
        // the caller's next command recovers the pending mutation cleanly.
        self.store_anchor(&AuditAnchor::at(
            entry.parsed.sequence,
            &entry.hash,
            &entry.parsed.timestamp,
        ))
        .context("the audit event was committed but the audit anchor could not be updated")?;
        snapshot.chain.entries = entry.parsed.sequence;
        snapshot.chain.head_hash = Some(entry.hash.clone());
        Ok(())
    }

    fn load_head(&self) -> Result<Option<LoadedHead>> {
        let paths = self.segment_paths()?;
        let Some(path) = paths.last() else {
            return Ok(None);
        };
        let entries = self.read_segment(path)?;
        let last = entries.last().context("audit segment cannot be empty")?;
        let segment_start = segment_start(path)?;
        if entries[0].entry.payload.sequence != segment_start {
            bail!("audit segment filename does not match its first sequence");
        }

        let expected_previous = if paths.len() == 1 {
            None
        } else {
            let prior_entries = self.read_segment(&paths[paths.len() - 2])?;
            let prior = prior_entries
                .last()
                .context("audit segment cannot be empty")?;
            if prior.entry.payload.sequence + 1 != segment_start {
                bail!("audit segment sequence gap before {segment_start}");
            }
            Some(prior.entry.hash.clone())
        };

        verify_entries(&entries, segment_start, expected_previous.as_deref())?;
        Ok(Some(LoadedHead {
            entry: last.entry.clone(),
            segment_path: path.clone(),
            segment_entries: entries.len(),
        }))
    }

    /// Walk every segment, checking sequence continuity and the hash chain, and
    /// hand each entry with its exact stored payload bytes to `visitor`.
    fn verify_chain<F>(&self, mut visitor: F) -> Result<ChainState>
    where
        F: FnMut(&AuditEntry, &str) -> Result<()>,
    {
        #[cfg(test)]
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut walk = ChainWalk::new();
        for path in self.segment_paths()? {
            walk.begin_segment(&path)?;
            let contents = self.read_segment_bytes(&path)?;
            if walk.lines(&path, &contents, &mut visitor)? == 0 {
                bail!("audit segment {} is empty", path.display());
            }
        }
        Ok(walk.finish())
    }

    fn record_state(
        &self,
        collection: &str,
        id: &str,
    ) -> Result<(Option<Option<String>>, ChainState)> {
        let (states, chain) = self.states(false)?;
        let state = states
            .get(&(collection.to_owned(), id.to_owned()))
            .map(|state| state.hash.clone());
        self.verify_legacy_representation_heads(&states)?;
        Ok((state, chain))
    }

    /// Close a legacy exact-representation gap with the materialized record
    /// when it is still the state named by the head event.
    ///
    /// A missing or hash-divergent file is left to ordinary reconciliation so
    /// direct edits keep their established diagnosis. Exact hash agreement
    /// makes the file a safe byte witness; its parsed document must then agree
    /// with semantic replay or the journal is internally inconsistent.
    fn verify_legacy_representation_heads(&self, states: &AuditedRecordStates) -> Result<()> {
        let mut gaps = states
            .iter()
            .filter(|(_, state)| state.legacy_representation_gap.is_some())
            .collect::<Vec<_>>();
        gaps.sort_unstable_by_key(|(_, state)| state.legacy_representation_gap);
        for ((collection, id), state) in gaps {
            let Some(sequence) = state.legacy_representation_gap else {
                continue;
            };
            let (Some(expected_hash), Some(expected_document)) =
                (state.hash.as_deref(), state.document.as_ref())
            else {
                continue;
            };
            validate_component(collection, "collection")?;
            validate_component(id, "id")?;
            let path = self.records_dir.join(collection).join(format!("{id}.md"));
            let label = record_label(collection, id);
            let Some(bytes) = paths::read_optional(self.root, &path, &label)? else {
                continue;
            };
            if record_hash(&bytes) != expected_hash {
                continue;
            }
            let raw = std::str::from_utf8(&bytes).map_err(|error| {
                anyhow::Error::new(error).context(DomainError::AuditIntegrity(format!(
                    "audit replay is inconsistent at sequence {sequence}: legacy record witness is not UTF-8"
                )))
            })?;
            let parsed = Document::parse(raw).map_err(|error| {
                error.context(DomainError::AuditIntegrity(format!(
                    "audit replay is inconsistent at sequence {sequence}: legacy record witness is not valid Markdown"
                )))
            })?;
            let parsed = document_value(&parsed).map_err(|error| {
                error.context(DomainError::AuditIntegrity(format!(
                    "audit replay is inconsistent at sequence {sequence}: legacy record witness cannot be decoded"
                )))
            })?;
            if parsed != *expected_document {
                return Err(audit_integrity(format!(
                    "audit replay is inconsistent at sequence {sequence}: legacy record witness does not describe the replayed document"
                )));
            }
        }
        Ok(())
    }

    fn verify_records(&self, latest: &HashMap<(String, String), Option<String>>) -> Result<()> {
        // Sorted, because verification reports the *first* record that
        // disagrees with the chain and stops. Iterating the map directly made
        // that choice depend on hash order, so an auditor running `audit
        // verify` twice on a database with two divergent records could be told
        // about a different one each time.
        let mut audited: Vec<_> = latest.iter().collect();
        audited.sort_unstable_by_key(|(record, _)| *record);
        for ((collection, id), expected_hash) in audited {
            validate_component(collection, "collection")?;
            validate_component(id, "id")?;
            let path = self.records_dir.join(collection).join(format!("{id}.md"));
            let actual_hash = self.record_file_hash(&path, collection, id)?;
            if &actual_hash != expected_hash {
                return Err(conflict(format!(
                    "record {collection}/{id} does not match its latest audited state"
                )));
            }
        }

        let collections =
            paths::list_directory(self.root, self.records_dir, RECORDS_LABEL)?.unwrap_or_default();
        for collection in collections {
            if !collection.kind.is_directory() {
                continue;
            }
            let collection_name = collection_directory_name(&collection.name)?;
            let directory = self.records_dir.join(&collection.name);
            let label = format!("collection '{collection_name}'");
            let records = paths::list_directory(self.root, &directory, &label)?.unwrap_or_default();
            for record in records {
                // Shared with `Database::list` and `Database::record_files`.
                // Without it this loop took the stem on trust, so `..md`
                // reached the check below as an ID of `.` and `audit verify`
                // reported a record named `deals/.` that nothing could name,
                // read, or repair.
                let CollectionEntry::Record(id) = collection_entry(&collection_name, &record.name)?
                else {
                    continue;
                };
                if !record.kind.is_file() {
                    return Err(paths::refuse_entry(
                        &record_label(&collection_name, &id),
                        record.kind,
                    ));
                }
                if !latest.contains_key(&(collection_name.clone(), id.clone())) {
                    return Err(conflict(format!(
                        "record {collection_name}/{id} has no audit history"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The exact bytes of one audit segment, read through verified components.
    fn read_segment_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        paths::read(self.root, path, SEGMENT_LABEL)
    }

    /// Hash a record file, refusing anything reached through a symbolic link
    /// and reporting a missing record as `None`.
    fn record_file_hash(&self, path: &Path, collection: &str, id: &str) -> Result<Option<String>> {
        let label = record_label(collection, id);
        match paths::entry_kind(self.root, path, &label)? {
            None => Ok(None),
            Some(EntryKind::File) => {
                paths::read(self.root, path, &label).map(|contents| Some(record_hash(&contents)))
            }
            Some(kind) => Err(paths::refuse_entry(&label, kind)),
        }
    }

    fn read_segment(&self, path: &Path) -> Result<Vec<StoredEntry>> {
        let file = paths::open_file(self.root, path, SEGMENT_LABEL)?;
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        loop {
            let mut line = Vec::new();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            if line.last() != Some(&b'\n') {
                bail!("audit segment {} has a truncated tail", path.display());
            }
            line.pop();
            entries.push(parse_line(&line)?);
        }
        Ok(entries)
    }

    fn segment_paths(&self) -> Result<Vec<PathBuf>> {
        self.ensure_layout()?;
        let directory = Path::new(SEGMENT_DIRECTORY);
        let entries = paths::list_directory(self.root, directory, SEGMENT_DIRECTORY_LABEL)?
            .unwrap_or_default();
        let mut segments = Vec::new();
        for entry in entries {
            if !entry.kind.is_file() {
                continue;
            }
            let path = directory.join(&entry.name);
            if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
                segment_start(&path)?;
                segments.push(path);
            }
        }
        segments.sort();
        Ok(segments)
    }

    fn clear_pending(&self) -> Result<()> {
        let path = Path::new(PENDING_PATH);
        if paths::entry_kind(self.root, path, PENDING_LABEL)?.is_some() {
            paths::remove_file(self.root, path, PENDING_LABEL)?;
        }
        Ok(())
    }
}

struct LoadedHead {
    entry: AuditEntry,
    segment_path: PathBuf,
    segment_entries: usize,
}

/// Classify an anchor whose bytes cannot be interpreted, keeping the parse
/// failure in the chain for logs and out of the caller-facing message.
fn unreadable_anchor(error: serde_json::Error) -> anyhow::Error {
    anyhow::Error::new(error).context(DomainError::AnchorMismatch(
        "the audit anchor is not a readable checkpoint".to_owned(),
    ))
}

fn stored_line(hash: &str, payload: &str) -> Result<String> {
    let hash = serde_json::to_string(hash)?;
    Ok(format!("{{\"hash\":{hash},\"payload\":{payload}}}\n"))
}

/// Fold one event into when each record in its collection was created and
/// last changed.
fn track_activity(collections: &mut CollectionsActivity, entry: &AuditEntry) {
    let collection = entry.payload.record.collection.as_str();
    if !collections.contains_key(collection) {
        collections.insert(collection.to_owned(), BTreeMap::new());
    }
    let activity = collections
        .get_mut(collection)
        .expect("the collection was just inserted");
    let id = entry.payload.record.id.as_str();
    if entry.payload.action == AuditAction::Delete {
        activity.remove(id);
        return;
    }
    let at = entry.payload.timestamp.as_str();
    let sequence = entry.payload.sequence;
    activity
        .entry(id.to_owned())
        .and_modify(|activity| {
            activity.updated_at = at.to_owned();
            activity.updated_sequence = sequence;
        })
        .or_insert_with(|| RecordActivity {
            created_at: at.to_owned(),
            created_sequence: sequence,
            updated_at: at.to_owned(),
            updated_sequence: sequence,
        });
}

fn parse_line(line: &[u8]) -> Result<StoredEntry> {
    let stored: StoredLine =
        serde_json::from_slice(line).context("audit line is not valid JSON")?;
    let payload = stored.payload.get().to_owned();
    let computed = event_hash(payload.as_bytes());
    if computed != stored.hash {
        bail!("audit event hash mismatch");
    }
    let parsed: AuditPayload = serde_json::from_str(&payload)?;
    if !(MIN_AUDIT_VERSION..=AUDIT_VERSION).contains(&parsed.version) {
        bail!("unsupported audit event version {}", parsed.version);
    }
    Ok(StoredEntry {
        entry: AuditEntry {
            hash: stored.hash,
            payload: parsed,
        },
        payload,
    })
}

fn take_string<E: serde::de::Error>(
    fields: &mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<String, E> {
    match fields.remove(field) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(E::custom(format!(
            "audit change '{field}' must be a string"
        ))),
        None => Err(E::missing_field(if field == "path" {
            "path"
        } else {
            "operation"
        })),
    }
}

fn take_value<E: serde::de::Error>(
    fields: &mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<Value, E> {
    fields
        .remove(field)
        .ok_or_else(|| E::custom(format!("audit change is missing '{field}'")))
}

fn verify_entries(
    entries: &[StoredEntry],
    expected_start: u64,
    previous_hash: Option<&str>,
) -> Result<()> {
    let mut expected_previous = previous_hash.map(str::to_owned);
    for (expected_sequence, stored) in (expected_start..).zip(entries.iter()) {
        if stored.entry.payload.sequence != expected_sequence {
            bail!("audit sequence gap at {expected_sequence}");
        }
        if stored.entry.payload.previous_hash != expected_previous {
            bail!("audit hash chain is broken at sequence {expected_sequence}");
        }
        if event_hash(stored.payload.as_bytes()) != stored.entry.hash {
            bail!("audit event hash mismatch at sequence {expected_sequence}");
        }
        expected_previous = Some(stored.entry.hash.clone());
    }
    Ok(())
}

fn segment_start(path: &Path) -> Result<u64> {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .with_context(|| format!("invalid audit segment filename {}", path.display()))?;
    if stem.len() != 20 || !stem.bytes().all(|value| value.is_ascii_digit()) {
        bail!("invalid audit segment filename {}", path.display());
    }
    stem.parse().context("invalid audit segment sequence")
}

/// Bind a stored retry result to the semantic state, exact bytes, and record
/// identity the surrounding event already attests to.
fn verify_idempotency_result(
    entry: &AuditEntry,
    before: Option<&Value>,
    after: Option<&Value>,
) -> Result<()> {
    let Some(idempotency) = entry.payload.idempotency.as_ref() else {
        return Ok(());
    };
    let invalid = |reason: &str| {
        audit_integrity(format!(
            "audit idempotency metadata is invalid at sequence {}: {reason}",
            entry.payload.sequence
        ))
    };
    if !valid_stored_digest(&idempotency.key_hash, "sha256:")
        || !valid_stored_digest(&idempotency.request_hash, "hmac-sha256:")
    {
        return Err(invalid("digest has an invalid format"));
    }
    let effective_principal = entry.payload.access.as_ref().map_or_else(
        || principal_id(&entry.payload.actor).map_err(|_| invalid("principal is invalid")),
        |decision| Ok(decision.principal.clone()),
    )?;
    if idempotency.principal != effective_principal {
        return Err(invalid("principal disagrees with the event"));
    }
    let expected_action = match idempotency.operation.as_str() {
        "create" => AuditAction::Create,
        "update" | "patch" | "replace" => AuditAction::Update,
        "link" => AuditAction::Link,
        "delete" => AuditAction::Delete,
        _ => return Err(invalid("operation is unknown")),
    };
    if entry.payload.action != expected_action {
        return Err(invalid("operation disagrees with the event"));
    }
    let (expected_document, expected_version) = if expected_action == AuditAction::Delete {
        (before, entry.payload.before_hash.as_deref())
    } else {
        (after, entry.payload.after_hash.as_deref())
    };
    let Some(expected_document) = expected_document else {
        return Err(invalid("result has no record state"));
    };
    let result = &idempotency.result;
    validate_idempotency_result_path(entry, &result.path)?;
    let parsed = Document::parse(&result.markdown).map_err(|error| {
        error.context(DomainError::AuditIntegrity(format!(
            "audit idempotency result is invalid at sequence {}",
            entry.payload.sequence
        )))
    })?;
    let result_document = document_value(&parsed).map_err(|error| {
        error.context(DomainError::AuditIntegrity(format!(
            "audit idempotency result is invalid at sequence {}",
            entry.payload.sequence
        )))
    })?;
    if expected_version != Some(result.version.as_str())
        || record_hash(result.markdown.as_bytes()) != result.version
        || &result_document != expected_document
    {
        return Err(audit_integrity(format!(
            "audit idempotency result is inconsistent at sequence {}",
            entry.payload.sequence
        )));
    }
    Ok(())
}

/// Register the durable identity of one retry result exactly once.
///
/// The request hash is deliberately not part of this identity: once a key is
/// committed for a principal, operation, and record, a second result is
/// corrupt history whether it claims the same request or a different one.
fn register_idempotency_identity(
    seen: &mut HashSet<IdempotencyIdentity>,
    payload: &AuditPayload,
) -> Result<()> {
    let Some(idempotency) = payload.idempotency.as_ref() else {
        return Ok(());
    };
    let identity = IdempotencyIdentity {
        principal: idempotency.principal.clone(),
        operation: idempotency.operation.clone(),
        collection: payload.record.collection.clone(),
        id: payload.record.id.clone(),
        key_hash: idempotency.key_hash.clone(),
    };
    if seen.insert(identity) {
        return Ok(());
    }
    Err(audit_integrity(format!(
        "audit replay is inconsistent at sequence {}: idempotency identity is duplicated",
        payload.sequence
    )))
}

fn valid_stored_digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn validate_idempotency_result_path(entry: &AuditEntry, path: &Path) -> Result<()> {
    let expected_file = format!("{}.md", entry.payload.record.id);
    let safe = !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        && path.file_name() == Some(OsStr::new(&expected_file))
        && path.parent().and_then(Path::file_name)
            == Some(OsStr::new(&entry.payload.record.collection));
    if safe {
        return Ok(());
    }
    Err(audit_integrity(format!(
        "audit idempotency result path is invalid at sequence {}",
        entry.payload.sequence
    )))
}

/// A record that has never been audited cannot take part in `action`.
fn missing_audit_history(collection: &str, id: &str, action: &str) -> anyhow::Error {
    conflict(format!(
        "record {collection}/{id} has no audit history; run 'cr audit baseline' before {action} it"
    ))
}

/// The stored record no longer matches the state the audit log recorded.
/// The digest of the change set carried by a serialized audit payload.
///
/// The canonical form is deliberately not a re-serialization. It is the exact
/// byte range the `changes` array occupies inside the payload, read back out
/// with `RawValue`, which is the same discipline the event hash already
/// follows: hash what is stored, never what a later parse happens to produce.
///
/// Preview and apply hash a payload this process just serialized; `audit
/// verify` hashes the payload as it sits on disk. All three go through here, so
/// there is exactly one definition of what was approved.
pub(crate) fn change_set_hash(payload: &str) -> Result<String> {
    let parsed: PayloadChanges<'_> = serde_json::from_str(payload)
        .context("audit payload does not carry a readable change set")?;
    Ok(digest(
        CHANGE_SET_HASH_DOMAIN,
        parsed.changes.get().as_bytes(),
    ))
}

/// Just enough of a payload to borrow its `changes` bytes unchanged.
#[derive(Deserialize)]
struct PayloadChanges<'a> {
    #[serde(borrow)]
    changes: &'a RawValue,
}

/// Recompute one event's previewed-change digest from its stored change set.
///
/// A mismatch is a different finding from a broken chain, and says so. The
/// chain being intact means nobody edited the journal after the fact; this
/// failing means the event itself records that a human approved one change set
/// while a different one was written.
fn verify_approved_changes(entry: &AuditEntry, payload: &str) -> Result<()> {
    let Some(approved) = entry
        .payload
        .authorization
        .as_ref()
        .and_then(|authorization| authorization.approved_changes.as_deref())
    else {
        return Ok(());
    };
    let actual = change_set_hash(payload)?;
    if approved == actual {
        return Ok(());
    }
    Err(approval_mismatch(format!(
        "audit event {} for record {} records an approved change set that is not the one it applied: {approved} was approved, but its changes hash to {actual}",
        entry.payload.sequence,
        entry.payload.record.reference()
    )))
}

fn stale_audit_state(collection: &str, id: &str) -> anyhow::Error {
    conflict(format!(
        "record {collection}/{id} does not match its latest audited state; run 'cr audit verify'"
    ))
}

fn validate_relative_target(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        bail!("pending audit target must be a safe relative path");
    }
    Ok(())
}

fn document_value(document: &Document) -> Result<Value> {
    Ok(serde_json::json!({
        "attributes": serde_json::to_value(&document.attributes)
            .map_err(|_| invalid("front matter cannot be represented as JSON for auditing"))?,
        "body": document.body,
    }))
}

/// Apply one event and prove that its semantic result reproduces the exact
/// state hash the event records.
fn replay_entry(latest: &mut AuditedRecordStates, entry: &AuditEntry) -> Result<()> {
    let sequence = entry.payload.sequence;
    let key = (
        entry.payload.record.collection.clone(),
        entry.payload.record.id.clone(),
    );
    let had_history = latest.contains_key(&key);
    let state = latest.entry(key).or_insert_with(|| AuditedRecordState {
        hash: None,
        document: None,
        protected_storage_owned: false,
        legacy_representation_gap: None,
    });
    if state.hash != entry.payload.before_hash {
        return Err(audit_integrity(format!(
            "audit replay is inconsistent at sequence {sequence}: before hash does not match the replayed state"
        )));
    }
    if had_history && entry.payload.action == AuditAction::Baseline {
        return Err(audit_integrity(format!(
            "audit replay is inconsistent at sequence {sequence}: baseline is not the first record event"
        )));
    }
    let before_document = state.document.clone();
    let existed_before = before_document.is_some();
    apply_changes(&mut state.document, &entry.payload.changes).map_err(|error| {
        error.context(DomainError::AuditIntegrity(format!(
            "audit replay is inconsistent at sequence {sequence}: change set cannot be applied"
        )))
    })?;
    verify_action_transition(entry, existed_before, state.document.is_some())?;
    state.legacy_representation_gap = if verify_replayed_after(entry, &state.document)? {
        None
    } else {
        Some(sequence)
    };
    verify_idempotency_result(entry, before_document.as_ref(), state.document.as_ref())?;
    if let Some(document) = state.document.as_ref() {
        state.protected_storage_owned = audit_document_encryption_metadata(document)
            .is_some_and(|metadata| metadata.has_envelopes);
    }
    state.hash = entry.payload.after_hash.clone();
    Ok(())
}

/// Require the verb recorded by an event to agree with the record-presence
/// transition its changes actually produce.
fn verify_action_transition(
    entry: &AuditEntry,
    existed_before: bool,
    exists_after: bool,
) -> Result<()> {
    let valid = match entry.payload.action {
        AuditAction::Create | AuditAction::Baseline => !existed_before && exists_after,
        AuditAction::Update | AuditAction::Link => existed_before && exists_after,
        AuditAction::Delete => existed_before && !exists_after,
    };
    if valid {
        return Ok(());
    }
    let before = if existed_before { "present" } else { "absent" };
    let after = if exists_after { "present" } else { "absent" };
    Err(audit_integrity(format!(
        "audit replay is inconsistent at sequence {}: {} action does not match the {before}-to-{after} record transition",
        entry.payload.sequence, entry.payload.action
    )))
}

/// `true` means the event itself proves its exact representation. `false` is
/// the narrow v1/v2 compatibility state whose current materialized file must
/// serve as the missing witness when the gap remains at a record head.
fn verify_replayed_after(entry: &AuditEntry, document: &Option<Value>) -> Result<bool> {
    let sequence = entry.payload.sequence;
    let mismatch = |reason: &str| {
        audit_integrity(format!(
            "audit replay is inconsistent at sequence {sequence}: {reason}"
        ))
    };
    let Some(expected_hash) = entry.payload.after_hash.as_deref() else {
        if document.is_some() || entry.payload.after_snapshot.is_some() {
            return Err(mismatch("deleted state still contains record content"));
        }
        return Ok(true);
    };
    let Some(document) = document else {
        return Err(mismatch("existing state has no replayed document"));
    };

    if entry.payload.version >= 3 && entry.payload.after_snapshot.is_none() {
        return Err(mismatch("existing state has no exact record snapshot"));
    }

    if let Some(snapshot) = entry.payload.after_snapshot.as_ref() {
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(mismatch("record snapshot uses an unsupported version"));
        }
        let parsed = Document::parse(&snapshot.markdown).map_err(|error| {
            error.context(DomainError::AuditIntegrity(format!(
                "audit replay is inconsistent at sequence {sequence}: record snapshot is not valid Markdown"
            )))
        })?;
        let value = document_value(&parsed).map_err(|error| {
            error.context(DomainError::AuditIntegrity(format!(
                "audit replay is inconsistent at sequence {sequence}: record snapshot cannot be decoded"
            )))
        })?;
        if &value != document {
            return Err(mismatch(
                "record snapshot does not describe the replayed document",
            ));
        }
        if record_hash(snapshot.markdown.as_bytes()) != expected_hash {
            return Err(mismatch("record snapshot does not match after hash"));
        }
        return Ok(true);
    }

    let replayed = Document::from_audit_value(document)
        .and_then(|document| document.render())
        .map_err(|error| {
            error.context(DomainError::AuditIntegrity(format!(
                "audit replay is inconsistent at sequence {sequence}: replayed document cannot be rendered"
            )))
        })?;
    if record_hash(replayed.as_bytes()) == expected_hash {
        return Ok(true);
    }

    // V1/v2 recorded semantic content and the hash of the exact source file,
    // but not its YAML spelling or mapping order. Those bytes cannot be
    // reconstructed after the fact. Mark this historical representation gap;
    // every later event is checked and clears it, while a gap that remains at
    // the record head must be closed with the materialized file as a witness.
    if entry.payload.version < 3 {
        return Ok(false);
    }
    Err(mismatch("replayed document does not match after hash"))
}

/// Retain the exact bytes for every version-3 state in which the record exists.
///
/// Making the witness unconditional keeps future serializer changes from
/// changing what an existing event can prove and prevents a forged event from
/// deleting the field to enter the legacy compatibility path.
fn exact_snapshot(
    document: Option<&Document>,
    bytes: Option<&[u8]>,
) -> Result<Option<AuditRecordSnapshot>> {
    let Some(document) = document else {
        if bytes.is_some() {
            bail!("a deleted audit state cannot contain record bytes");
        }
        return Ok(None);
    };
    let bytes = bytes.context("an existing audit state must contain record bytes")?;
    let markdown = std::str::from_utf8(bytes).context("audited record bytes are not UTF-8")?;
    let parsed = Document::parse(markdown).context("audited record bytes cannot be parsed")?;
    if document_value(&parsed)? != document_value(document)? {
        bail!("audited record bytes do not describe the recorded document");
    }
    Ok(Some(AuditRecordSnapshot {
        version: SNAPSHOT_VERSION,
        markdown: markdown.to_owned(),
    }))
}

fn verify_version_progress(previous: u32, current: u32, sequence: u64) -> Result<()> {
    if current >= previous {
        return Ok(());
    }
    Err(audit_integrity(format!(
        "audit replay is inconsistent at sequence {sequence}: payload version decreased from {previous} to {current}"
    )))
}

fn diff_documents(before: Option<&Value>, after: Option<&Value>) -> Vec<AuditChange> {
    match (before, after) {
        (None, Some(after)) => vec![AuditChange::Add {
            path: String::new(),
            after: after.clone(),
        }],
        (Some(before), None) => vec![AuditChange::Remove {
            path: String::new(),
            before: before.clone(),
        }],
        (Some(before), Some(after)) => {
            let mut changes = Vec::new();
            let protected_paths = crate::encryption::audit_document_encrypted_pointers(before)
                .into_iter()
                .chain(crate::encryption::audit_document_encrypted_pointers(after))
                .collect();
            diff_value("", before, after, &protected_paths, &mut changes);
            changes
        }
        (None, None) => Vec::new(),
    }
}

fn diff_value(
    path: &str,
    before: &Value,
    after: &Value,
    protected_paths: &BTreeSet<String>,
    changes: &mut Vec<AuditChange>,
) {
    if before == after {
        return;
    }
    // An encrypted envelope is one logical value. Expanding its key ID, nonce,
    // and ciphertext would expose storage mechanics as user fields and would
    // prevent the database layer from revealing the logical audit value.
    if protected_paths.contains(path) {
        changes.push(AuditChange::Replace {
            path: path.to_owned(),
            before: before.clone(),
            after: after.clone(),
        });
        return;
    }
    if let (Value::Object(before), Value::Object(after)) = (before, after) {
        let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        for key in keys {
            let child_path = format!("{path}/{}", escape_pointer(&key));
            match (before.get(&key), after.get(&key)) {
                (Some(before), Some(after)) => {
                    diff_value(&child_path, before, after, protected_paths, changes);
                }
                (Some(before), None) => changes.push(AuditChange::Remove {
                    path: child_path,
                    before: before.clone(),
                }),
                (None, Some(after)) => changes.push(AuditChange::Add {
                    path: child_path,
                    after: after.clone(),
                }),
                (None, None) => unreachable!(),
            }
        }
        return;
    }

    changes.push(AuditChange::Replace {
        path: path.to_owned(),
        before: before.clone(),
        after: after.clone(),
    });
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn apply_changes(state: &mut Option<Value>, changes: &[AuditChange]) -> Result<()> {
    for change in changes {
        apply_change(state, change)?;
    }
    Ok(())
}

fn apply_change(state: &mut Option<Value>, change: &AuditChange) -> Result<()> {
    if change.path().is_empty() {
        match change {
            AuditChange::Add { after, .. } => {
                if state.is_some() {
                    bail!("cannot add a root record that already exists");
                }
                *state = Some(after.clone());
            }
            AuditChange::Remove { before, .. } => {
                if state.as_ref() != Some(before) {
                    bail!("root record does not match the removed value");
                }
                *state = None;
            }
            AuditChange::Replace { before, after, .. } => {
                if state.as_ref() != Some(before) {
                    bail!("root record does not match the replaced value");
                }
                *state = Some(after.clone());
            }
        }
        return Ok(());
    }

    let segments = parse_pointer(change.path())?;
    let (key, parents) = segments
        .split_last()
        .context("audit change path has no field")?;
    let mut parent = state
        .as_mut()
        .context("cannot apply a field change to a deleted record")?;
    for segment in parents {
        parent = parent
            .as_object_mut()
            .with_context(|| format!("audit change parent is not an object at '{segment}'"))?
            .get_mut(segment)
            .with_context(|| format!("audit change parent field '{segment}' does not exist"))?;
    }
    let object = parent
        .as_object_mut()
        .context("audit change target parent is not an object")?;
    match change {
        AuditChange::Add { after, .. } => {
            if object.contains_key(key) {
                bail!("audit change cannot add existing field '{key}'");
            }
            object.insert(key.clone(), after.clone());
        }
        AuditChange::Remove { before, .. } => {
            if object.get(key) != Some(before) {
                bail!("audit change removed field '{key}' from an unexpected value");
            }
            object.remove(key);
        }
        AuditChange::Replace { before, after, .. } => {
            if object.get(key) != Some(before) {
                bail!("audit change replaced field '{key}' from an unexpected value");
            }
            object.insert(key.clone(), after.clone());
        }
    }
    Ok(())
}

fn parse_pointer(path: &str) -> Result<Vec<String>> {
    let path = path
        .strip_prefix('/')
        .context("audit change path must be empty or begin with '/'")?;
    path.split('/').map(unescape_pointer).collect()
}

fn unescape_pointer(value: &str) -> Result<String> {
    let mut result = String::with_capacity(value.len());
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            result.push(character);
            continue;
        }
        match characters.next() {
            Some('0') => result.push('~'),
            Some('1') => result.push('/'),
            Some(other) => bail!("invalid JSON Pointer escape '~{other}'"),
            None => bail!("incomplete JSON Pointer escape"),
        }
    }
    Ok(result)
}

fn event_hash(payload: &[u8]) -> String {
    digest(EVENT_HASH_DOMAIN, payload)
}

/// The stable record version: SHA-256 over the record domain followed by the
/// exact stored Markdown bytes.
///
/// Keeping the existing `cr:record:v1\0` domain is part of audit compatibility:
/// these values are stored as every event's `before_hash` and `after_hash`.
pub(crate) fn record_hash(contents: &[u8]) -> String {
    digest(RECORD_HASH_DOMAIN, contents)
}

/// A domain-separated SHA-256 digest rendered as `sha256:<hex>`.
///
/// Shared so every hash `cr` records is separated by an explicit domain string
/// rather than by each call site remembering to add one.
pub(crate) fn digest(domain: &[u8], contents: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(contents);
    let bytes = digest.finalize();
    let mut value = String::with_capacity(7 + bytes.len() * 2);
    value.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{
        AuditAction, AuditChange, AuditEntry, AuditFilter, AuditIdempotency,
        AuditIdempotencyResult, AuditLog, AuditMutation, AuditPayload, AuditRecord, AuditSource,
        CACHE_IGNORE_PATH, CHANGE_SET_HASH_DOMAIN, CollectionsActivity, JOURNAL_CACHE_HASH_DOMAIN,
        JOURNAL_CACHE_PATH, JournalVerification, PENDING_PATH, PendingMutation, PreparedEntry,
        ReconciledMutation, VERIFY_CHAIN_CALLS, apply_changes, change_set_hash, diff_documents,
        digest, event_hash, parse_line, record_hash, stored_line,
    };
    use crate::{
        Assignment, Database,
        attribution::{
            AgentEvidence, Attribution, AuditAgent, AuditAuthorization, AuditIntent,
            AuditIntentPart, AuthorizationMode, IntentAuthor,
        },
        error::DomainError,
        frontmatter::Document,
        paths,
    };
    use std::cell::Cell;

    /// One audit event written by `cr` at `0ca95fb`, before `agent`,
    /// `authorization`, and `intent` existed, copied verbatim out of
    /// `tests/fixtures/legacy-journal`.
    const LEGACY_PAYLOAD: &str = r#"{"version":2,"sequence":3,"timestamp":"2026-09-01T10:06:28.583165677Z","actor":"Ada Lovelace <ada@example.com>","source":"cli","action":"update","record":{"collection":"deals","id":"acme-renewal"},"changes":[{"operation":"replace","path":"/attributes/stage","before":"negotiation","after":"closed"},{"operation":"replace","path":"/attributes/status","before":"open","after":"closed-won"}],"before_hash":"sha256:bff41b4063a1c3174a78757ba233661b8e009f20023193b68d9024d39f48f7fe","after_hash":"sha256:6ae98ae2e84c09ef640b8c8c69c0a316a1b7c945274b4eb85d47eb3061519c8d","previous_hash":"sha256:df5581e0fabd9d6a1a96a3d863680dbead1e5a9efa18e6b62ece155390d41858"}"#;

    /// The hash that same `cr` wrote beside those bytes.
    const LEGACY_HASH: &str =
        "sha256:859fd73ce851c6098b4b186a67cb38ab54f855624c591cd3902e0c8633f0f8a3";

    /// One audit event from `tests/fixtures/future-journal`, copied verbatim.
    ///
    /// It names an `AgentEvidence`, an `AuthorizationMode`, and an
    /// `IntentAuthor` that this build has never heard of, standing in for a
    /// journal written by a later `cr` that grew a value.
    const FUTURE_PAYLOAD: &str = r#"{"version":2,"sequence":3,"timestamp":"2026-09-01T10:06:28.583165677Z","actor":"Ada Lovelace <ada@example.com>","source":"cli","agent":{"id":"future-agent","session":"s-1","detected_from":"attestation"},"authorization":{"mode":"escalated","grant":"planMode"},"intent":{"request":{"author":"operator","text":"close the renewal"}},"action":"update","record":{"collection":"deals","id":"acme-renewal"},"changes":[{"operation":"replace","path":"/attributes/stage","before":"negotiation","after":"closed"},{"operation":"replace","path":"/attributes/status","before":"open","after":"closed-won"}],"before_hash":"sha256:bff41b4063a1c3174a78757ba233661b8e009f20023193b68d9024d39f48f7fe","after_hash":"sha256:6ae98ae2e84c09ef640b8c8c69c0a316a1b7c945274b4eb85d47eb3061519c8d","previous_hash":"sha256:df5581e0fabd9d6a1a96a3d863680dbead1e5a9efa18e6b62ece155390d41858"}"#;

    /// The hash stored beside those bytes in the fixture.
    const FUTURE_HASH: &str =
        "sha256:e34dfe8559e82230cc466d143f547b75f4de3b1aa4eb8a75b3c5ebb7e2dc28a0";

    fn attributed_payload() -> AuditPayload {
        AuditPayload {
            version: 2,
            sequence: 2,
            timestamp: "2026-09-01T09:18:34.451476644Z".to_owned(),
            actor: "Ada Lovelace <ada@example.com>".to_owned(),
            source: AuditSource::Cli,
            agent: Some(AuditAgent {
                id: "claude-code".to_owned(),
                version: Some("2.1.237".to_owned()),
                model: Some("claude-opus-4-5".to_owned()),
                session: Some("6d1baa69".to_owned()),
                turn: Some("prompt_01HXZ".to_owned()),
                detected_from: AgentEvidence::Environment,
                via: Some(vec![AuditAgent {
                    id: "claude-code-parent".to_owned(),
                    version: None,
                    model: None,
                    session: Some("parent-session".to_owned()),
                    turn: None,
                    detected_from: AgentEvidence::Flag,
                    via: None,
                }]),
            }),
            authorization: Some(AuditAuthorization {
                mode: AuthorizationMode::Delegated,
                grant: Some("acceptEdits".to_owned()),
                approved_by: Some("Ada Lovelace <ada@example.com>".to_owned()),
                at: Some("2026-09-01T09:17:55Z".to_owned()),
                approved_changes: None,
            }),
            intent: Some(AuditIntent {
                request: Some(AuditIntentPart {
                    author: IntentAuthor::Human,
                    text: Some("update this deal to closed-won".to_owned()),
                    digest: None,
                    reference: None,
                    at: Some("2026-09-01T09:17:41Z".to_owned()),
                }),
                rationale: Some(AuditIntentPart {
                    author: IntentAuthor::Agent,
                    text: Some("set status to closed-won and stage to closed".to_owned()),
                    digest: None,
                    reference: None,
                    at: None,
                }),
            }),
            access: None,
            idempotency: None,
            message: None,
            action: AuditAction::Update,
            record: AuditRecord {
                collection: "deals".to_owned(),
                id: "acme-renewal".to_owned(),
            },
            changes: vec![AuditChange::Replace {
                path: "/attributes/status".to_owned(),
                before: json!("open"),
                after: json!("closed-won"),
            }],
            after_snapshot: None,
            before_hash: Some("sha256:70af0060".to_owned()),
            after_hash: Some("sha256:3c583cd6".to_owned()),
            previous_hash: Some("sha256:be4bd677".to_owned()),
        }
    }

    /// The whole compatibility argument, asserted against bytes this code did
    /// not produce.
    ///
    /// A payload written before `agent`, `authorization`, and `intent` existed
    /// must deserialize into the current struct with all three absent, and must
    /// serialize back to exactly the bytes on disk, under exactly the hash that
    /// was stored beside them. A round trip through the current serializer alone
    /// would agree with itself no matter what changed, so the expected value is
    /// a literal taken from a journal an older `cr` wrote.
    #[test]
    fn a_pre_change_payload_reserializes_to_identical_bytes_and_the_same_hash() {
        let payload: AuditPayload = serde_json::from_str(LEGACY_PAYLOAD).unwrap();
        assert!(payload.agent.is_none());
        assert!(payload.authorization.is_none());
        assert!(payload.intent.is_none());
        let reserialized = serde_json::to_string(&payload).unwrap();
        assert_eq!(reserialized, LEGACY_PAYLOAD);
        assert_eq!(event_hash(reserialized.as_bytes()), LEGACY_HASH);
    }

    /// Absent attribution must add no bytes at all, so a human-authored event
    /// written today is indistinguishable from one written before this change.
    #[test]
    fn absent_attribution_serializes_to_no_bytes() {
        let mut payload: AuditPayload = serde_json::from_str(LEGACY_PAYLOAD).unwrap();
        payload.sequence = 99;
        let without = serde_json::to_string(&payload).unwrap();
        assert!(!without.contains("agent"));
        assert!(!without.contains("authorization"));
        assert!(!without.contains("intent"));
        assert!(!without.contains("null,\"action\""));
    }

    /// A stored event that carries every new field must survive a read and a
    /// rewrite unchanged, so nothing in the schema depends on map ordering.
    #[test]
    fn an_attributed_payload_round_trips_byte_for_byte() {
        let payload = attributed_payload();
        let first = serde_json::to_string(&payload).unwrap();
        let parsed: AuditPayload = serde_json::from_str(&first).unwrap();
        let second = serde_json::to_string(&parsed).unwrap();
        assert_eq!(first, second);
        assert_eq!(event_hash(first.as_bytes()), event_hash(second.as_bytes()));
        assert_eq!(parsed, payload);
        assert_eq!(parsed.version, 2);
        assert!(first.contains(r#""detected_from":"environment""#));
        assert!(first.contains(r#""mode":"delegated""#));
        assert!(first.contains(r#""author":"human""#));
    }

    /// A journal that carries the new fields must verify, and it must verify by
    /// hashing the bytes as stored rather than anything reserialized.
    #[test]
    fn a_stored_attributed_event_verifies_from_its_own_bytes() {
        let payload = serde_json::to_string(&attributed_payload()).unwrap();
        let line = stored_line(&event_hash(payload.as_bytes()), &payload).unwrap();
        let stored = parse_line(line.trim_end().as_bytes()).unwrap();
        let agent = stored.entry.payload.agent.as_ref().unwrap();
        assert_eq!(agent.id, "claude-code");
        assert_eq!(agent.detected_from, AgentEvidence::Environment);
        assert_eq!(agent.via.as_ref().unwrap()[0].id, "claude-code-parent");
        assert_eq!(
            stored.entry.payload.authorization.as_ref().unwrap().mode,
            AuthorizationMode::Delegated
        );
        assert!(
            stored
                .entry
                .payload
                .intent
                .as_ref()
                .unwrap()
                .rationale
                .is_some()
        );
    }

    /// An attribution value this build does not know must survive a read and a
    /// rewrite byte for byte, under the hash that was stored beside it.
    ///
    /// This is the whole point of the tolerant reader. A closed enum rejects the
    /// label, and a payload that fails to deserialize fails the entire chain —
    /// exactly the hard failure that not bumping the audit version exists to
    /// prevent. A tolerant reader that *normalized* the unknown label to a
    /// default would be worse still: the read would succeed and the rewrite
    /// would silently change the bytes the hash covers. Neither is acceptable,
    /// so the assertion here is byte equality against a literal, not a round
    /// trip that would agree with itself.
    #[test]
    fn an_unknown_attribution_value_round_trips_byte_for_byte() {
        let payload: AuditPayload = serde_json::from_str(FUTURE_PAYLOAD).unwrap();
        let agent = payload.agent.as_ref().unwrap();
        let authorization = payload.authorization.as_ref().unwrap();
        let author = &payload
            .intent
            .as_ref()
            .unwrap()
            .request
            .as_ref()
            .unwrap()
            .author;

        assert_eq!(
            agent.detected_from,
            AgentEvidence::Other("attestation".to_owned())
        );
        assert_eq!(
            authorization.mode,
            AuthorizationMode::Other("escalated".to_owned())
        );
        assert_eq!(*author, IntentAuthor::Other("operator".to_owned()));
        assert!(!agent.detected_from.is_known());
        assert!(!authorization.mode.is_known());
        assert!(!author.is_known());
        assert_eq!(agent.detected_from.label(), "attestation");
        assert_eq!(authorization.mode.label(), "escalated");
        assert_eq!(author.label(), "operator");

        let reserialized = serde_json::to_string(&payload).unwrap();
        assert_eq!(reserialized, FUTURE_PAYLOAD);
        assert_eq!(event_hash(reserialized.as_bytes()), FUTURE_HASH);

        let line = stored_line(FUTURE_HASH, FUTURE_PAYLOAD).unwrap();
        let stored = parse_line(line.trim_end().as_bytes()).unwrap();
        assert_eq!(stored.entry.hash, FUTURE_HASH);
        assert_eq!(stored.payload, FUTURE_PAYLOAD);
    }

    /// An event written by a newer `cr` that added another optional sibling must
    /// still verify here. Verification hashes what is on disk, and the payload
    /// deliberately does not deny unknown fields, so an addition can never make
    /// `audit verify` fail for a reader that has not caught up.
    #[test]
    fn an_unknown_future_field_does_not_break_verification() {
        let payload = LEGACY_PAYLOAD.replacen(
            r#""source":"cli","#,
            r#""source":"cli","principal":{"id":"token-7","authenticated":true},"#,
            1,
        );
        let hash = event_hash(payload.as_bytes());
        let line = stored_line(&hash, &payload).unwrap();
        let stored = parse_line(line.trim_end().as_bytes()).unwrap();
        assert_eq!(stored.entry.hash, hash);
        assert_eq!(stored.entry.payload.sequence, 3);
    }

    /// The delegate has to be queryable, including through a chain, or
    /// recording it answers nothing.
    #[test]
    fn history_filters_match_the_acting_agent_and_its_chain() {
        let payload = attributed_payload();
        let plain = serde_json::from_str::<AuditPayload>(LEGACY_PAYLOAD).unwrap();

        assert!(AuditFilter::all().matches(&payload));
        assert!(
            AuditFilter {
                agent: Some("claude-code"),
                ..AuditFilter::all()
            }
            .matches(&payload)
        );
        assert!(
            AuditFilter {
                agent: Some("claude-code-parent"),
                ..AuditFilter::all()
            }
            .matches(&payload)
        );
        assert!(
            AuditFilter {
                session: Some("parent-session"),
                ..AuditFilter::all()
            }
            .matches(&payload)
        );
        assert!(
            !AuditFilter {
                agent: Some("cursor-agent"),
                ..AuditFilter::all()
            }
            .matches(&payload)
        );
        assert!(
            !AuditFilter {
                agent: Some("claude-code"),
                ..AuditFilter::all()
            }
            .matches(&plain)
        );
        assert!(AuditFilter::record("deals", "acme-renewal").matches(&payload));
        assert!(!AuditFilter::record("people", "ada").matches(&payload));
    }
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use yaml_serde::Mapping;

    /// The canonical form of a change set is the exact byte range it occupies
    /// inside the stored payload, and nothing else.
    ///
    /// The digest a preview prints comes from a payload this process serialized;
    /// the digest `audit verify` recomputes comes from a payload read off disk.
    /// They agree because both are the same substring, which is why this asserts
    /// against a hand-written slice rather than round-tripping the same value
    /// through the same serializer twice.
    #[test]
    fn a_change_set_digest_covers_the_stored_change_bytes_and_only_those() {
        let payload = attributed_payload();
        let serialized = serde_json::to_string(&payload).unwrap();
        let changes = r#"[{"operation":"replace","path":"/attributes/status","before":"open","after":"closed-won"}]"#;
        assert!(serialized.contains(&format!(r#""changes":{changes},"#)));
        assert_eq!(
            change_set_hash(&serialized).unwrap(),
            digest(CHANGE_SET_HASH_DOMAIN, changes.as_bytes())
        );

        // Everything outside `changes` is deliberately not covered: the digest
        // answers "was this the change set", not "was this the same event".
        let mut moved = payload.clone();
        moved.sequence = 41;
        moved.timestamp = "2027-01-01T00:00:00Z".to_owned();
        moved.actor = "Someone Else <else@example.com>".to_owned();
        let moved = serde_json::to_string(&moved).unwrap();
        assert_ne!(moved, serialized);
        assert_eq!(
            change_set_hash(&moved).unwrap(),
            change_set_hash(&serialized).unwrap()
        );

        // Any difference inside the change set does change it.
        let mut different = payload;
        different.changes = vec![AuditChange::Replace {
            path: "/attributes/status".to_owned(),
            before: json!("open"),
            after: json!("lost"),
        }];
        assert_ne!(
            change_set_hash(&serde_json::to_string(&different).unwrap()).unwrap(),
            change_set_hash(&serialized).unwrap()
        );

        // And the domain separator keeps it out of the other two hash spaces.
        assert_ne!(
            digest(CHANGE_SET_HASH_DOMAIN, changes.as_bytes()),
            event_hash(changes.as_bytes())
        );
        assert_ne!(
            digest(CHANGE_SET_HASH_DOMAIN, changes.as_bytes()),
            record_hash(changes.as_bytes())
        );
    }

    #[test]
    fn event_hashes_are_domain_separated_and_stable() {
        assert_eq!(event_hash(b"payload"), event_hash(b"payload"));
        assert_ne!(event_hash(b"payload"), event_hash(b"changed"));
        assert!(event_hash(b"payload").starts_with("sha256:"));
    }

    #[test]
    fn record_versions_have_a_stable_domain_separated_vector() {
        assert_eq!(
            record_hash(b"hello\n"),
            "sha256:3ad3d01bb32674f985458c4db5e1cf0a48fc031cf6d83ec99331af03d33a7f5a"
        );
        assert_ne!(
            record_hash(b"hello\n"),
            "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn document_diff_reports_nested_add_replace_and_remove() {
        let before = json!({
            "attributes": {"stage": "screening", "owner": "sam"},
            "body": "old"
        });
        let after = json!({
            "attributes": {"stage": "interview", "score": 42},
            "body": "old"
        });
        let changes = diff_documents(Some(&before), Some(&after));
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].path(), "/attributes/owner");
        assert_eq!(changes[1].path(), "/attributes/score");
        assert_eq!(changes[2].path(), "/attributes/stage");
    }

    #[test]
    fn create_and_delete_diffs_capture_a_full_snapshot() {
        let document = json!({"attributes": {"name": "Jane"}, "body": "Notes"});
        let created = diff_documents(None, Some(&document));
        assert_eq!(created.len(), 1);
        assert_eq!(
            created[0],
            AuditChange::Add {
                path: String::new(),
                after: document.clone()
            }
        );

        let deleted = diff_documents(Some(&document), None);
        assert_eq!(deleted.len(), 1);
        assert_eq!(
            deleted[0],
            AuditChange::Remove {
                path: String::new(),
                before: document
            }
        );
    }

    #[test]
    fn legacy_changes_preserve_present_null_values_and_replay() {
        let legacy: AuditChange =
            serde_json::from_str(r#"{"path":"/attributes/value","before":"ready","after":null}"#)
                .unwrap();
        assert_eq!(
            legacy,
            AuditChange::Replace {
                path: "/attributes/value".to_owned(),
                before: json!("ready"),
                after: Value::Null,
            }
        );
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert_eq!(encoded["operation"], "replace");
        assert!(encoded.get("after").unwrap().is_null());

        let mut state = Some(json!({"attributes": {"value": "ready"}, "body": ""}));
        apply_changes(&mut state, &[legacy]).unwrap();
        assert!(state.unwrap()["attributes"]["value"].is_null());
    }

    #[test]
    fn replay_rejects_changes_that_do_not_match_the_prior_state() {
        let mut state = Some(json!({"attributes": {"stage": "screening"}, "body": ""}));
        let error = apply_changes(
            &mut state,
            &[AuditChange::Replace {
                path: "/attributes/stage".to_owned(),
                before: json!("offer"),
                after: json!("hired"),
            }],
        )
        .unwrap_err();
        assert!(error.to_string().contains("unexpected value"));
    }

    #[test]
    fn version_one_payloads_remain_readable_with_cli_source() {
        let payload = r#"{"version":1,"sequence":1,"timestamp":"2026-01-01T00:00:00Z","actor":"legacy@example.com","action":"create","record":{"collection":"items","id":"one"},"changes":[{"path":"","after":{"attributes":{"value":null},"body":""}}],"before_hash":null,"after_hash":"sha256:legacy","previous_hash":null}"#;
        let line = stored_line(&event_hash(payload.as_bytes()), payload).unwrap();
        let stored = parse_line(line.trim_end().as_bytes()).unwrap();
        assert_eq!(stored.entry.payload.version, 1);
        assert_eq!(stored.entry.payload.source, AuditSource::Cli);
        assert!(stored.entry.payload.message.is_none());
        assert_eq!(
            stored.entry.payload.changes[0],
            AuditChange::Add {
                path: String::new(),
                after: json!({"attributes": {"value": null}, "body": ""})
            }
        );
    }

    #[test]
    fn accepting_a_direct_edit_rechecks_the_current_file_hash() {
        let root = tempfile::tempdir().unwrap();
        let attribution = Attribution::default();
        let audit = AuditLog::new(
            root.path(),
            Path::new("records"),
            10,
            1024 * 1024,
            "tester",
            &attribution,
        );
        let _lock = audit.lock().unwrap();
        let original = Document {
            attributes: Mapping::new(),
            body: "Original\n".to_owned(),
        };
        let original_raw = original.render().unwrap();
        let target = Path::new("records/items/one.md");
        let created = audit
            .prepare(AuditMutation {
                action: AuditAction::Create,
                collection: "items",
                id: "one",
                before_document: None,
                after_document: Some(&original),
                before_bytes: None,
                after_bytes: Some(original_raw.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: None,
            })
            .unwrap();
        audit
            .commit(created, target, || {
                paths::write_new(root.path(), target, original_raw.as_bytes(), "the record")
            })
            .unwrap();

        let accepted = Document {
            attributes: Mapping::new(),
            body: "Accepted\n".to_owned(),
        };
        let accepted_raw = accepted.render().unwrap();
        std::fs::write(root.path().join(target), &accepted_raw).unwrap();
        let mut snapshot = audit.reconciliation_snapshot().unwrap();
        let event = audit
            .prepare_reconciled_in(
                ReconciledMutation {
                    action: AuditAction::Update,
                    collection: "items",
                    id: "one",
                    before_document: Some(&original),
                    after_document: Some(&accepted),
                    before_hash: Some(&record_hash(original_raw.as_bytes())),
                    after_bytes: Some(accepted_raw.as_bytes()),
                    had_history: true,
                    message: None,
                    access: None,
                },
                &snapshot,
            )
            .unwrap();
        std::fs::write(root.path().join(target), "---\n---\nChanged again\n").unwrap();
        let error = audit
            .accept_reconciled_in(event, target, &mut snapshot)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being saved")
        );
        assert_eq!(audit.head().unwrap().sequence, 1);
    }

    #[test]
    fn history_selection_and_manifest_replay_share_one_forward_verification() {
        let root = tempfile::tempdir().unwrap();
        let attribution = Attribution::default();
        let audit = AuditLog::new(
            root.path(),
            Path::new("records"),
            2,
            1024 * 1024,
            "tester",
            &attribution,
        );
        let _lock = audit.lock().unwrap();
        for (collection, id) in [
            ("items", "one"),
            ("other", "two"),
            ("items", "three"),
            ("items", "four"),
            ("other", "five"),
            ("items", "six"),
        ] {
            let document = Document {
                attributes: Mapping::new(),
                body: format!("{collection}/{id}\n"),
            };
            let rendered = document.render().unwrap();
            let target = PathBuf::from(format!("records/{collection}/{id}.md"));
            let entry = audit
                .prepare(AuditMutation {
                    action: AuditAction::Create,
                    collection,
                    id,
                    before_document: None,
                    after_document: Some(&document),
                    before_bytes: None,
                    after_bytes: Some(rendered.as_bytes()),
                    source: AuditSource::Cli,
                    message: None,
                    access: None,
                    idempotency: None,
                })
                .unwrap();
            audit
                .commit(entry, &target, || {
                    paths::write_new(root.path(), &target, rendered.as_bytes(), "the record")
                })
                .unwrap();
        }

        let filter = || AuditFilter {
            collection: Some("items"),
            ..AuditFilter::all()
        };
        let visible = |entry: &AuditEntry| Ok(entry.payload.sequence != 4);
        let expected = audit.recent_where(2, filter(), visible).unwrap();

        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        let history = audit.recent_history_where(2, filter(), visible).unwrap();
        let verify_calls = VERIFY_CHAIN_CALLS.with(Cell::get);

        assert_eq!(history.entries, expected);
        assert_eq!(
            history
                .entries
                .iter()
                .map(|entry| entry.payload.sequence)
                .collect::<Vec<_>>(),
            [6, 3]
        );
        assert!(history.encryption_transitions.is_empty());
        assert_eq!(verify_calls, 1);
    }

    /// A database whose journal starts a new segment every
    /// `segment_max_events` events, once with a journal cache and once
    /// without, over the same files.
    fn cached_and_uncached(
        root: &std::path::Path,
        segment_max_events: usize,
    ) -> (Database, Database) {
        Database::init(root).unwrap();
        std::fs::write(
            root.join(".cr/config.yaml"),
            format!(
                "version: 1\ndata_dir: records\naudit:\n  segment_max_events: {segment_max_events}\n"
            ),
        )
        .unwrap();
        let uncached = Database::discover(Some(root))
            .unwrap()
            .with_actor("tester@example.com")
            .unwrap();
        (uncached.clone().with_journal_cache(), uncached)
    }

    type Replayed =
        std::collections::BTreeMap<(String, String), (Option<String>, Option<serde_json::Value>)>;

    fn replayed(database: &Database) -> Replayed {
        database
            .audit()
            .record_states()
            .unwrap()
            .iter()
            .map(|(key, state)| (key.clone(), (state.hash.clone(), state.document.clone())))
            .collect()
    }

    fn activity(database: &Database) -> CollectionsActivity {
        database.audit().collections_activity(|_| true).unwrap()
    }

    #[test]
    fn a_cached_journal_verifies_only_what_was_appended_since() {
        let root = tempfile::tempdir().unwrap();
        let (cached, uncached) = cached_and_uncached(root.path(), 2);
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        assert!(replayed(&cached).is_empty());
        assert_eq!(VERIFY_CHAIN_CALLS.with(Cell::get), 1);

        // Two events to a segment, so the newest segment fills, is sealed, and
        // is followed by a new one while the cache watches.
        for index in 0..7 {
            let id = format!("item-{index}");
            let assignment: Assignment = format!("value={index}").parse().unwrap();
            cached.create("items", &id, &[assignment], "").unwrap();
            if index % 3 == 1 {
                let assignment: Assignment = "value=changed".parse().unwrap();
                cached.update("items", &id, &[assignment], None).unwrap();
            }
            if index == 5 {
                cached.delete("items", "item-0").unwrap();
            }

            VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
            let states = replayed(&cached);
            let collections = activity(&cached);
            assert_eq!(
                VERIFY_CHAIN_CALLS.with(Cell::get),
                0,
                "reading after item {index} walked the whole chain"
            );
            assert_eq!(states, replayed(&uncached), "after item {index}");
            assert_eq!(collections, activity(&uncached), "after item {index}");
        }
        assert!(
            std::fs::read_dir(root.path().join(".cr/audit/segments"))
                .unwrap()
                .count()
                > 3
        );
    }

    #[test]
    fn a_rewritten_segment_is_verified_again_from_the_first_event() {
        use std::io::Write;

        let root = tempfile::tempdir().unwrap();
        let (cached, uncached) = cached_and_uncached(root.path(), 2);
        for index in 0..5 {
            let assignment: Assignment = format!("value={index}").parse().unwrap();
            cached
                .create("items", &format!("item-{index}"), &[assignment], "")
                .unwrap();
        }
        let expected = replayed(&uncached);
        assert_eq!(replayed(&cached), expected);

        let segments = root.path().join(".cr/audit/segments");
        for (segment, which) in [
            ("00000000000000000001.jsonl", "a sealed segment"),
            ("00000000000000000005.jsonl", "the newest segment"),
        ] {
            let path = segments.join(segment);
            let original = std::fs::read(&path).unwrap();
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            let forged = String::from_utf8(original.clone())
                .unwrap()
                .replacen("tester", "forger", 1);
            assert_eq!(forged.len(), original.len());
            // Coarse filesystem clocks tick every few milliseconds, and a
            // rewrite in the same tick as the write before it would keep that
            // write's change time. Nothing tampers that quickly by accident.
            std::thread::sleep(std::time::Duration::from_millis(20));
            // In place, the same length, and the modification time put back:
            // only the bytes and the change time say anything happened.
            let rewrite = |contents: &[u8]| {
                let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.write_all(contents).unwrap();
                file.set_modified(modified).unwrap();
            };
            rewrite(forged.as_bytes());
            assert_eq!(
                std::fs::metadata(&path).unwrap().modified().unwrap(),
                modified
            );

            let Err(error) = cached.audit().record_states() else {
                panic!("{which}: the forged event was accepted");
            };
            assert!(
                format!("{error:#}").contains("audit event hash mismatch"),
                "{which}: {error:#}"
            );
            // A failed walk caches nothing, so the restored journal is walked
            // afresh rather than half-remembered.
            rewrite(&original);
            assert_eq!(replayed(&cached), expected, "{which}");
        }
    }

    /// A database as a new `cr` process opens it: nothing verified in memory,
    /// and whatever walk the last write saved on disk.
    fn process(root: &std::path::Path, verification: JournalVerification) -> Database {
        Database::discover(Some(root))
            .unwrap()
            .with_actor("tester@example.com")
            .unwrap()
            .with_journal_verification(verification)
    }

    /// How many times `read` walked the journal from its first event.
    fn walks<T>(read: impl FnOnce() -> T) -> (T, usize) {
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        let result = read();
        (result, VERIFY_CHAIN_CALLS.with(Cell::get))
    }

    fn create_items(database: &Database, indices: std::ops::Range<usize>) {
        for index in indices {
            let assignment: Assignment = format!("value={index}").parse().unwrap();
            database
                .create("items", &format!("item-{index}"), &[assignment], "")
                .unwrap();
        }
    }

    fn saved_walk(root: &std::path::Path) -> std::path::PathBuf {
        root.join(JOURNAL_CACHE_PATH)
    }

    #[test]
    fn the_next_process_resumes_the_walk_the_last_write_saved() {
        let root = tempfile::tempdir().unwrap();
        let (_, uncached) = cached_and_uncached(root.path(), 2);
        create_items(&process(root.path(), JournalVerification::Resume), 0..5);
        assert!(saved_walk(root.path()).is_file());
        assert_eq!(
            std::fs::read_to_string(root.path().join(CACHE_IGNORE_PATH)).unwrap(),
            "*\n"
        );

        let expected = (replayed(&uncached), activity(&uncached));
        let reader = process(root.path(), JournalVerification::Resume);
        let (resumed, count) = walks(|| (replayed(&reader), activity(&reader)));
        assert_eq!(count, 0, "a read walked the journal despite a saved walk");
        assert_eq!(resumed, expected);

        // Events appended by something that saves nothing, such as an older
        // `cr`, are verified on top of the saved walk rather than from the
        // first event, and the reader leaves the file as it found it.
        let saved = std::fs::read(saved_walk(root.path())).unwrap();
        create_items(&uncached, 5..8);
        let expected = (replayed(&uncached), activity(&uncached));
        let reader = process(root.path(), JournalVerification::Resume);
        let (resumed, count) = walks(|| (replayed(&reader), activity(&reader)));
        assert_eq!(count, 0);
        assert_eq!(resumed, expected);
        assert_eq!(std::fs::read(saved_walk(root.path())).unwrap(), saved);
    }

    #[test]
    fn a_read_saves_no_walk_and_full_verification_ignores_the_saved_one() {
        let root = tempfile::tempdir().unwrap();
        let (_, uncached) = cached_and_uncached(root.path(), 2);
        create_items(&uncached, 0..3);
        let reader = process(root.path(), JournalVerification::Resume);
        let (_, count) = walks(|| replayed(&reader));
        assert_eq!(count, 1);
        assert!(!root.path().join(".cr/cache").exists());

        create_items(&process(root.path(), JournalVerification::Full), 3..4);
        assert!(saved_walk(root.path()).is_file());
        let verifier = process(root.path(), JournalVerification::Full);
        let (states, count) = walks(|| replayed(&verifier));
        assert_eq!(count, 1, "full verification resumed a saved walk");
        assert_eq!(states, replayed(&uncached));
    }

    #[test]
    fn a_saved_walk_does_not_hide_a_rewritten_segment() {
        use std::io::Write;

        let root = tempfile::tempdir().unwrap();
        let (_, uncached) = cached_and_uncached(root.path(), 2);
        create_items(&process(root.path(), JournalVerification::Resume), 0..5);
        let expected = replayed(&uncached);

        let segments = root.path().join(".cr/audit/segments");
        for (segment, which) in [
            ("00000000000000000001.jsonl", "a sealed segment"),
            ("00000000000000000005.jsonl", "the newest segment"),
        ] {
            let path = segments.join(segment);
            let original = std::fs::read(&path).unwrap();
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            let forged = String::from_utf8(original.clone())
                .unwrap()
                .replacen("tester", "forger", 1);
            std::thread::sleep(std::time::Duration::from_millis(20));
            let rewrite = |contents: &[u8]| {
                let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
                file.write_all(contents).unwrap();
                file.set_modified(modified).unwrap();
            };
            rewrite(forged.as_bytes());

            let reader = process(root.path(), JournalVerification::Resume);
            let Err(error) = reader.audit().record_states() else {
                panic!("{which}: the forged event was accepted");
            };
            assert!(
                format!("{error:#}").contains("audit event hash mismatch"),
                "{which}: {error:#}"
            );
            rewrite(&original);
            let reader = process(root.path(), JournalVerification::Resume);
            assert_eq!(replayed(&reader), expected, "{which}");
        }
    }

    /// Rewrite the saved walk's body with `forge` and seal it with a digest
    /// that matches, as anybody who can write `.cr/` could.
    fn forge_saved_walk(root: &std::path::Path, forge: impl FnOnce(&mut serde_json::Value)) {
        let path = saved_walk(root);
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        forge(&mut file["journal"]);
        let body = serde_json::to_string(&file["journal"]).unwrap();
        let digest = digest(JOURNAL_CACHE_HASH_DOMAIN, body.as_bytes());
        std::fs::write(
            &path,
            format!(
                r#"{{"version":{},"cr":{},"digest":"{digest}","journal":{body}}}"#,
                file["version"], file["cr"]
            ),
        )
        .unwrap();
    }

    fn forge_record_hash(journal: &mut serde_json::Value, id: &str, hash: &str) {
        let record = journal["records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|record| record[0][1] == id)
            .unwrap();
        record[1]["hash"] = serde_json::Value::from(hash);
    }

    #[test]
    fn a_damaged_or_foreign_saved_walk_is_walked_from_the_first_event() {
        let root = tempfile::tempdir().unwrap();
        let (_, uncached) = cached_and_uncached(root.path(), 2);
        create_items(&process(root.path(), JournalVerification::Resume), 0..5);
        let expected = replayed(&uncached);
        let original = std::fs::read(saved_walk(root.path())).unwrap();
        let text = String::from_utf8(original.clone()).unwrap();
        let hash = record_hash(b"forged");

        for (which, damaged) in [
            ("a torn file", original[..original.len() / 2].to_vec()),
            (
                "another release",
                text.replacen(env!("CARGO_PKG_VERSION"), "0.0.0", 1)
                    .into_bytes(),
            ),
            (
                "a body its digest does not cover",
                text.replacen("\"hash\":\"sha256:", "\"hash\":\"sha256:0", 1)
                    .into_bytes(),
            ),
        ] {
            std::fs::write(saved_walk(root.path()), &damaged).unwrap();
            let reader = process(root.path(), JournalVerification::Resume);
            let (states, count) = walks(|| replayed(&reader));
            assert_eq!(count, 1, "{which} was resumed");
            assert_eq!(states, expected, "{which}");
        }

        // A consistent forgery that no later event contradicts is believed:
        // that is the trade `JournalCache` states. The next write verifies
        // the whole journal and replaces it.
        std::fs::write(saved_walk(root.path()), &original).unwrap();
        forge_saved_walk(root.path(), |journal| {
            forge_record_hash(journal, "item-1", &hash);
        });
        let reader = process(root.path(), JournalVerification::Resume);
        let key = ("items".to_owned(), "item-1".to_owned());
        assert_eq!(replayed(&reader)[&key].0.as_deref(), Some(hash.as_str()));
        create_items(&process(root.path(), JournalVerification::Resume), 5..6);
        let reader = process(root.path(), JournalVerification::Resume);
        let (states, count) = walks(|| replayed(&reader));
        assert_eq!(count, 0);
        assert_eq!(states, replayed(&uncached));
    }

    #[test]
    fn a_saved_walk_that_a_later_event_contradicts_cannot_fail_a_read() {
        let root = tempfile::tempdir().unwrap();
        let (_, uncached) = cached_and_uncached(root.path(), 2);
        create_items(&process(root.path(), JournalVerification::Resume), 0..3);
        forge_saved_walk(root.path(), |journal| {
            forge_record_hash(journal, "item-1", &record_hash(b"forged"));
        });
        // The next event's before hash disagrees with the forged state, so
        // continuing the saved walk fails; a walk from the first event is the
        // answer instead.
        let assignment: Assignment = "value=changed".parse().unwrap();
        uncached
            .update("items", "item-1", &[assignment], None)
            .unwrap();

        let reader = process(root.path(), JournalVerification::Resume);
        let (states, count) = walks(|| replayed(&reader));
        assert_eq!(count, 1);
        assert_eq!(states, replayed(&uncached));
    }

    #[test]
    fn delegation_and_the_read_it_delegates_share_one_walk() {
        let root = tempfile::tempdir().unwrap();
        let owner = Database::init(root.path())
            .unwrap()
            .with_actor("owner@example.com")
            .unwrap();
        owner
            .initialize_access(Some("Owner"), Some("owner@example.com"))
            .unwrap();
        owner
            .add_user(
                "reader@example.com",
                "Reader",
                Some("reader@example.com"),
                crate::UserKind::Human,
            )
            .unwrap();
        owner
            .grant_access(
                "reader@example.com",
                crate::AccessResource::Collection {
                    collection: "items".to_owned(),
                },
                crate::Role::Viewer,
            )
            .unwrap();
        owner.create("items", "one", &[], "").unwrap();

        let (record, count) = walks(|| {
            owner
                .clone()
                .with_journal_verification(JournalVerification::Full)
                .impersonate_verified("reader@example.com")
                .unwrap()
                .get("items", "one")
                .unwrap()
        });
        assert_eq!(record.id, "one");
        assert_eq!(count, 1);
    }

    #[test]
    fn bulk_save_preview_and_apply_share_one_verified_replay() {
        let root = tempfile::tempdir().unwrap();
        let database = Database::init(root.path().join("database"))
            .unwrap()
            .with_actor("tester@example.com")
            .unwrap();
        for id in ["one", "two", "three"] {
            let assignment: Assignment = format!("value=before-{id}").parse().unwrap();
            database.create("items", id, &[assignment], "").unwrap();
            let path = database.root().join(format!("records/items/{id}.md"));
            let raw = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, raw.replace("before-", "after-")).unwrap();
        }

        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        let previews = database.preview_save(&[], true, None).unwrap();
        assert_eq!(previews.len(), 3);
        assert_eq!(VERIFY_CHAIN_CALLS.with(Cell::get), 1);

        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        let entries = database.save(&[], true, None).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(VERIFY_CHAIN_CALLS.with(Cell::get), 1);
    }

    #[test]
    fn pending_mutations_recover_committed_state_and_discard_unapplied_state() {
        let committed_root = tempfile::tempdir().unwrap();
        let attribution = Attribution::default();
        let committed = AuditLog::new(
            committed_root.path(),
            Path::new("records"),
            2,
            1024 * 1024,
            "tester",
            &attribution,
        );
        committed.ensure_layout().unwrap();
        let _lock = committed.lock().unwrap();
        let document = Document {
            attributes: Mapping::new(),
            body: "Committed\n".to_owned(),
        };
        let rendered = document.render().unwrap();
        let target = Path::new("records/items/one.md");
        let entry = committed
            .prepare(AuditMutation {
                action: AuditAction::Create,
                collection: "items",
                id: "one",
                before_document: None,
                after_document: Some(&document),
                before_bytes: None,
                after_bytes: Some(rendered.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: None,
            })
            .unwrap();
        store_pending(&committed, &entry, PathBuf::from("records/items/one.md"));
        paths::write_new(
            committed_root.path(),
            target,
            rendered.as_bytes(),
            "the record",
        )
        .unwrap();

        committed.recover_pending().unwrap();
        assert!(!committed_root.path().join(PENDING_PATH).exists());
        assert_eq!(committed.head().unwrap().sequence, 1);
        assert_eq!(committed.verify(None).unwrap().records_checked, 1);

        let aborted_root = tempfile::tempdir().unwrap();
        let aborted = AuditLog::new(
            aborted_root.path(),
            Path::new("records"),
            2,
            1024 * 1024,
            "tester",
            &attribution,
        );
        aborted.ensure_layout().unwrap();
        let _lock = aborted.lock().unwrap();
        let entry = aborted
            .prepare(AuditMutation {
                action: AuditAction::Create,
                collection: "items",
                id: "one",
                before_document: None,
                after_document: Some(&document),
                before_bytes: None,
                after_bytes: Some(rendered.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: None,
            })
            .unwrap();
        store_pending(&aborted, &entry, PathBuf::from("records/items/one.md"));

        aborted.recover_pending().unwrap();
        assert!(!aborted_root.path().join(PENDING_PATH).exists());
        assert_eq!(aborted.head().unwrap().sequence, 0);
    }

    #[test]
    fn preparation_and_append_each_refuse_a_second_idempotency_identity() {
        let root = tempfile::tempdir().unwrap();
        let attribution = Attribution::default();
        let audit = AuditLog::new(
            root.path(),
            Path::new("records"),
            10,
            1024 * 1024,
            "tester",
            &attribution,
        );
        let _lock = audit.lock().unwrap();
        let target = Path::new("records/items/one.md");
        let original = Document {
            attributes: Mapping::new(),
            body: "Original\n".to_owned(),
        };
        let original_raw = original.render().unwrap();
        let created = audit
            .prepare(AuditMutation {
                action: AuditAction::Create,
                collection: "items",
                id: "one",
                before_document: None,
                after_document: Some(&original),
                before_bytes: None,
                after_bytes: Some(original_raw.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: None,
            })
            .unwrap();
        audit
            .commit(created, target, || {
                paths::write_new(root.path(), target, original_raw.as_bytes(), "the record")
            })
            .unwrap();

        let first = Document {
            attributes: Mapping::new(),
            body: "First\n".to_owned(),
        };
        let first_raw = first.render().unwrap();
        let identity_key = digest(b"test:key\0", b"first");
        let metadata = |key_hash: String, request: &[u8], raw: &str| AuditIdempotency {
            principal: "tester".to_owned(),
            operation: "update".to_owned(),
            key_hash,
            request_hash: format!("hmac-{}", digest(b"test:request\0", request)),
            result: AuditIdempotencyResult {
                path: target.to_path_buf(),
                version: record_hash(raw.as_bytes()),
                markdown: raw.to_owned(),
            },
        };
        let first_idempotency = metadata(identity_key.clone(), b"first", &first_raw);
        let updated = audit
            .prepare(AuditMutation {
                action: AuditAction::Update,
                collection: "items",
                id: "one",
                before_document: Some(&original),
                after_document: Some(&first),
                before_bytes: Some(original_raw.as_bytes()),
                after_bytes: Some(first_raw.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: Some(&first_idempotency),
            })
            .unwrap();
        audit
            .commit(updated, target, || {
                paths::write_replace(root.path(), target, first_raw.as_bytes(), "the record")
            })
            .unwrap();

        let second = Document {
            attributes: Mapping::new(),
            body: "Second\n".to_owned(),
        };
        let second_raw = second.render().unwrap();
        let duplicate = metadata(identity_key.clone(), b"different request", &second_raw);
        let error = audit
            .prepare(AuditMutation {
                action: AuditAction::Update,
                collection: "items",
                id: "one",
                before_document: Some(&first),
                after_document: Some(&second),
                before_bytes: Some(first_raw.as_bytes()),
                after_bytes: Some(second_raw.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: Some(&duplicate),
            })
            .err()
            .expect("duplicate identity must be rejected");
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("audit_integrity_failed")
        );

        let alternate = metadata(digest(b"test:key\0", b"second"), b"second", &second_raw);
        let mut forged = audit
            .prepare(AuditMutation {
                action: AuditAction::Update,
                collection: "items",
                id: "one",
                before_document: Some(&first),
                after_document: Some(&second),
                before_bytes: Some(first_raw.as_bytes()),
                after_bytes: Some(second_raw.as_bytes()),
                source: AuditSource::Cli,
                message: None,
                access: None,
                idempotency: Some(&alternate),
            })
            .unwrap();
        forged.parsed.idempotency.as_mut().unwrap().key_hash = identity_key;
        forged.payload = serde_json::to_string(&forged.parsed).unwrap();
        forged.hash = event_hash(forged.payload.as_bytes());
        forged.change_digest = change_set_hash(&forged.payload).unwrap();
        let error = audit.append(&forged).unwrap_err();
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("audit_integrity_failed")
        );
        assert_eq!(audit.head().unwrap().sequence, 2);
    }

    fn store_pending(audit: &AuditLog<'_>, entry: &PreparedEntry, target: PathBuf) {
        let pending = PendingMutation {
            target,
            before_hash: entry.parsed.before_hash.clone(),
            after_hash: entry.parsed.after_hash.clone(),
            hash: entry.hash.clone(),
            payload: entry.payload.clone(),
        };
        paths::write_new(
            audit.root,
            Path::new(PENDING_PATH),
            &serde_json::to_vec_pretty(&pending).unwrap(),
            "the pending audit mutation",
        )
        .unwrap();
    }
}
