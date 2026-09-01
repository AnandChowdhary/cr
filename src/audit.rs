use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    attribution::{Attribution, AuditAgent, AuditAuthorization, AuditIntent},
    database::{RECORDS_LABEL, record_label, validate_component},
    error::{approval_mismatch, conflict},
    frontmatter::Document,
    paths::{self, EntryKind},
};

/// Where the tamper-evident journal lives beneath the database root.
const SEGMENT_DIRECTORY: &str = ".cr/audit/segments";
const PENDING_PATH: &str = ".cr/audit/pending.json";
const LOCK_PATH: &str = ".cr/audit/lock";
const SEGMENT_DIRECTORY_LABEL: &str = "the audit segment directory";
const SEGMENT_LABEL: &str = "an audit segment";
const PENDING_LABEL: &str = "the pending audit mutation";
const LOCK_LABEL: &str = "the audit lock";

const AUDIT_VERSION: u32 = 2;
const MIN_AUDIT_VERSION: u32 = 1;
const EVENT_HASH_DOMAIN: &[u8] = b"cr:audit:event:v1\0";
const RECORD_HASH_DOMAIN: &[u8] = b"cr:record:v1\0";
/// Domain separator for the previewed-change digest.
///
/// Distinct from the event and record domains so a change-set digest can never
/// be mistaken for, or substituted with, either of the other two hashes.
const CHANGE_SET_HASH_DOMAIN: &[u8] = b"cr:audit:changes:v1\0";

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub action: AuditAction,
    pub record: AuditRecord,
    pub changes: Vec<AuditChange>,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub previous_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AuditEntry {
    pub hash: String,
    #[serde(flatten)]
    pub payload: AuditPayload,
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

struct ChainState {
    entries: u64,
    head_hash: Option<String>,
}

pub(crate) struct AuditLog<'a> {
    root: &'a Path,
    records_dir: &'a Path,
    segment_max_events: usize,
    segment_max_bytes: u64,
    actor: &'a str,
    attribution: &'a Attribution,
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
}

struct PayloadMutation<'a> {
    action: AuditAction,
    collection: &'a str,
    id: &'a str,
    before_document: Option<&'a Document>,
    after_document: Option<&'a Document>,
    before_hash: Option<String>,
    after_hash: Option<String>,
    chain: ChainState,
    source: AuditSource,
    message: Option<&'a str>,
}

#[derive(Clone)]
pub(crate) struct AuditedRecordState {
    pub hash: Option<String>,
    pub document: Option<Value>,
}

pub(crate) type AuditedRecordStates = HashMap<(String, String), AuditedRecordState>;

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
        }
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
            chain,
            source: mutation.source,
            message: mutation.message,
        })
    }

    pub fn prepare_reconciled(&self, mutation: ReconciledMutation<'_>) -> Result<PreparedEntry> {
        let (audited_state, chain) = self.record_state(mutation.collection, mutation.id)?;
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
            chain,
            source: AuditSource::Filesystem,
            message: mutation.message,
        })
    }

    fn prepare_payload(&self, mutation: PayloadMutation<'_>) -> Result<PreparedEntry> {
        let sequence = mutation.chain.entries + 1;
        let previous_hash = mutation.chain.head_hash;
        let before = mutation.before_document.map(document_value).transpose()?;
        let after = mutation.after_document.map(document_value).transpose()?;
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
            message: mutation.message.map(str::to_owned),
            action: mutation.action,
            record: AuditRecord {
                collection: mutation.collection.to_owned(),
                id: mutation.id.to_owned(),
            },
            changes: diff_documents(before.as_ref(), after.as_ref()),
            before_hash: mutation.before_hash,
            after_hash: mutation.after_hash,
            previous_hash,
        };
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

    pub fn has_history(&self, collection: &str, id: &str) -> Result<bool> {
        Ok(self.record_state(collection, id)?.0.is_some())
    }

    pub fn assert_current(&self, collection: &str, id: &str, contents: &[u8]) -> Result<()> {
        let actual = Some(record_hash(contents));
        match self.record_state(collection, id)?.0 {
            Some(expected) if expected == actual => Ok(()),
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

    pub fn accept(&self, entry: PreparedEntry, target: &Path) -> Result<AuditEntry> {
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
        self.append(&entry)?;
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
        let head = self.load_head()?;

        if let Some(head) = head {
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
                result.push(stored.entry);
                if result.len() == limit {
                    return Ok(result);
                }
            }
        }

        Ok(result)
    }

    pub fn head(&self) -> Result<AuditHead> {
        let state = self.verify_chain(|_, _| Ok(()))?;
        Ok(AuditHead {
            sequence: state.entries,
            hash: state.head_hash,
        })
    }

    pub fn verify(&self, expected_head: Option<&str>) -> Result<AuditVerification> {
        let (latest, state) = self.states(true)?;

        if let Some(expected) = expected_head
            && state.head_hash.as_deref() != Some(expected)
        {
            return Err(conflict(format!(
                "audit head does not match expected checkpoint (actual: {})",
                state.head_hash.as_deref().unwrap_or("none")
            )));
        }

        let latest_hashes = latest
            .iter()
            .map(|(record, state)| (record.clone(), state.hash.clone()))
            .collect();
        self.verify_records(&latest_hashes)?;
        Ok(AuditVerification {
            entries: state.entries,
            records_checked: latest.len(),
            head: AuditHead {
                sequence: state.entries,
                hash: state.head_hash,
            },
        })
    }

    pub fn record_states(&self) -> Result<AuditedRecordStates> {
        self.states(false).map(|(states, _)| states)
    }

    /// Replay the chain checking every stored change set against the approval
    /// recorded beside it, discarding the replayed state.
    ///
    /// `cr check` needs this branch of [`Self::verify`] without the
    /// record reconciliation that `verify` performs in the same pass, because
    /// it reconciles records itself and reports every divergence instead of
    /// failing on the first.
    pub fn verify_approvals(&self) -> Result<()> {
        self.states(true).map(|_| ())
    }

    /// Replay the chain into per-record state.
    ///
    /// `check_approvals` recomputes each event's previewed-change digest from
    /// its stored `changes`. Only `verify` asks for that. Reading history must
    /// not fail on it: an auditor who has just been told that a change set does
    /// not match its approval needs `audit log` to still show them the event.
    fn states(&self, check_approvals: bool) -> Result<(AuditedRecordStates, ChainState)> {
        let mut latest = AuditedRecordStates::new();
        let chain = self.verify_chain(|entry, payload| {
            if check_approvals {
                verify_approved_changes(entry, payload)?;
            }
            let key = (
                entry.payload.record.collection.clone(),
                entry.payload.record.id.clone(),
            );
            let had_history = latest.contains_key(&key);
            let state = latest.entry(key).or_insert_with(|| AuditedRecordState {
                hash: None,
                document: None,
            });
            if state.hash != entry.payload.before_hash {
                bail!(
                    "audit record-state chain is broken at sequence {}",
                    entry.payload.sequence
                );
            }
            if !had_history
                && !matches!(
                    entry.payload.action,
                    AuditAction::Create | AuditAction::Baseline
                )
            {
                bail!(
                    "audit record history begins with an invalid action at sequence {}",
                    entry.payload.sequence
                );
            }
            apply_changes(&mut state.document, &entry.payload.changes).with_context(|| {
                format!(
                    "audit changes are inconsistent at sequence {}",
                    entry.payload.sequence
                )
            })?;
            if state.document.is_some() != entry.payload.after_hash.is_some() {
                bail!(
                    "audit record state is inconsistent at sequence {}",
                    entry.payload.sequence
                );
            }
            state.hash = entry.payload.after_hash.clone();
            Ok(())
        })?;
        Ok((latest, chain))
    }

    fn append(&self, entry: &PreparedEntry) -> Result<()> {
        let head = self.load_head()?;
        let expected_sequence = head
            .as_ref()
            .map_or(1, |head| head.entry.payload.sequence + 1);
        let expected_previous = head.as_ref().map(|head| head.entry.hash.as_str());
        if entry.parsed.sequence != expected_sequence
            || entry.parsed.previous_hash.as_deref() != expected_previous
        {
            bail!("audit event does not extend the current chain head");
        }
        if event_hash(entry.payload.as_bytes()) != entry.hash {
            bail!("audit event hash does not match its payload");
        }

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
        let paths = self.segment_paths()?;
        let mut expected_sequence = 1;
        let mut previous_hash: Option<String> = None;

        for path in paths {
            if segment_start(&path)? != expected_sequence {
                bail!("audit segment sequence gap at {expected_sequence}");
            }
            let file = paths::open_file(self.root, &path, SEGMENT_LABEL)?;
            let mut reader = BufReader::new(file);
            let mut segment_entries = 0usize;

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
                let stored = parse_line(&line)
                    .with_context(|| format!("invalid audit event in {}", path.display()))?;
                if stored.entry.payload.sequence != expected_sequence {
                    bail!("audit sequence gap at {expected_sequence}");
                }
                if stored.entry.payload.previous_hash != previous_hash {
                    bail!("audit hash chain is broken at sequence {expected_sequence}");
                }
                visitor(&stored.entry, &stored.payload)?;
                previous_hash = Some(stored.entry.hash);
                expected_sequence += 1;
                segment_entries += 1;
            }

            if segment_entries == 0 {
                bail!("audit segment {} is empty", path.display());
            }
        }

        Ok(ChainState {
            entries: expected_sequence - 1,
            head_hash: previous_hash,
        })
    }

    fn record_state(
        &self,
        collection: &str,
        id: &str,
    ) -> Result<(Option<Option<String>>, ChainState)> {
        let mut state = None;
        let chain = self.verify_chain(|entry, _| {
            if entry.payload.record.collection == collection && entry.payload.record.id == id {
                state = Some(entry.payload.after_hash.clone());
            }
            Ok(())
        })?;
        Ok((state, chain))
    }

    fn verify_records(&self, latest: &HashMap<(String, String), Option<String>>) -> Result<()> {
        for ((collection, id), expected_hash) in latest {
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
            let collection_name = collection
                .name
                .to_str()
                .context("collection filename is not valid UTF-8")?
                .to_owned();
            let directory = self.records_dir.join(&collection.name);
            let label = format!("collection '{collection_name}'");
            let records = paths::list_directory(self.root, &directory, &label)?.unwrap_or_default();
            for record in records {
                let name = Path::new(&record.name);
                if name.extension().and_then(|value| value.to_str()) != Some("md") {
                    continue;
                }
                let id = name
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .context("record filename is not valid UTF-8")?
                    .to_owned();
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

fn stored_line(hash: &str, payload: &str) -> Result<String> {
    let hash = serde_json::to_string(hash)?;
    Ok(format!("{{\"hash\":{hash},\"payload\":{payload}}}\n"))
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
            .context("front matter cannot be represented as JSON for auditing")?,
        "body": document.body,
    }))
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
            diff_value("", before, after, &mut changes);
            changes
        }
        (None, None) => Vec::new(),
    }
}

fn diff_value(path: &str, before: &Value, after: &Value, changes: &mut Vec<AuditChange>) {
    if before == after {
        return;
    }
    if let (Value::Object(before), Value::Object(after)) = (before, after) {
        let keys: BTreeSet<_> = before.keys().chain(after.keys()).cloned().collect();
        for key in keys {
            let child_path = format!("{path}/{}", escape_pointer(&key));
            match (before.get(&key), after.get(&key)) {
                (Some(before), Some(after)) => diff_value(&child_path, before, after, changes),
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
        AuditAction, AuditChange, AuditFilter, AuditLog, AuditMutation, AuditPayload, AuditRecord,
        AuditSource, CHANGE_SET_HASH_DOMAIN, PENDING_PATH, PendingMutation, PreparedEntry,
        ReconciledMutation, apply_changes, change_set_hash, diff_documents, digest, event_hash,
        parse_line, record_hash, stored_line,
    };
    use crate::{
        attribution::{
            AgentEvidence, Attribution, AuditAgent, AuditAuthorization, AuditIntent,
            AuditIntentPart, AuthorizationMode, IntentAuthor,
        },
        frontmatter::Document,
        paths,
    };

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
        let event = audit
            .prepare_reconciled(ReconciledMutation {
                action: AuditAction::Update,
                collection: "items",
                id: "one",
                before_document: Some(&original),
                after_document: Some(&accepted),
                before_hash: Some(&record_hash(original_raw.as_bytes())),
                after_bytes: Some(accepted_raw.as_bytes()),
                had_history: true,
                message: None,
            })
            .unwrap();
        std::fs::write(root.path().join(target), "---\n---\nChanged again\n").unwrap();
        let error = audit.accept(event, target).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed while it was being saved")
        );
        assert_eq!(audit.head().unwrap().sequence, 1);
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
            })
            .unwrap();
        store_pending(&aborted, &entry, PathBuf::from("records/items/one.md"));

        aborted.recover_pending().unwrap();
        assert!(!aborted_root.path().join(PENDING_PATH).exists());
        assert_eq!(aborted.head().unwrap().sequence, 0);
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
