use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use serde_json::{value::RawValue, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    database::{sync_parent, validate_component, write_new, write_replace},
    error::conflict,
    frontmatter::Document,
};

const AUDIT_VERSION: u32 = 2;
const MIN_AUDIT_VERSION: u32 = 1;
const EVENT_HASH_DOMAIN: &[u8] = b"cr:audit:event:v1\0";
const RECORD_HASH_DOMAIN: &[u8] = b"cr:record:v1\0";

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
                )))
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
                    ))
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
    ) -> Self {
        Self {
            root,
            records_dir,
            segment_max_events,
            segment_max_bytes,
            actor,
        }
    }

    pub fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(self.segments_dir()).context("could not create audit segments directory")
    }

    pub fn lock(&self) -> Result<File> {
        self.ensure_layout()?;
        let lock_path = self.audit_dir().join("lock");
        let lock = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("could not open audit lock {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("could not lock audit log {}", lock_path.display()))?;
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
        let hash = event_hash(serialized.as_bytes());

        Ok(PreparedEntry {
            hash,
            payload: serialized,
            parsed: payload,
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
        let target = target
            .strip_prefix(self.root)
            .context("audit target is outside the database")?
            .to_path_buf();
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
        write_new(&self.pending_path(), &pending_bytes)?;

        let result = apply();
        let current_hash = file_hash_optional(&self.root.join(&pending.target))?;

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
        let target = target
            .strip_prefix(self.root)
            .context("audit target is outside the database")?
            .to_path_buf();
        validate_relative_target(&target)?;
        let expected_target = self
            .records_dir
            .join(&entry.parsed.record.collection)
            .join(format!("{}.md", entry.parsed.record.id));
        if target != expected_target {
            bail!("audit target does not match its record identity");
        }
        let current_hash = file_hash_optional(&self.root.join(target))?;
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
        let path = self.pending_path();
        if !path.exists() {
            return Ok(());
        }

        let serialized = fs::read(&path)
            .with_context(|| format!("could not read pending mutation {}", path.display()))?;
        let pending: PendingMutation = serde_json::from_slice(&serialized)
            .with_context(|| format!("pending mutation {} is invalid", path.display()))?;
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

        let current_hash = file_hash_optional(&self.root.join(&pending.target))?;
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
            self.append(&PreparedEntry {
                hash: pending.hash,
                payload: pending.payload,
                parsed: payload,
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

    pub fn recent(
        &self,
        limit: usize,
        collection: Option<&str>,
        id: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        self.verify_chain(|_| Ok(()))?;
        let mut result = Vec::new();
        let paths = self.segment_paths()?;

        for path in paths.into_iter().rev() {
            let mut entries = self.read_segment(&path)?;
            entries.reverse();
            for stored in entries {
                let record = &stored.entry.payload.record;
                if collection.is_some_and(|value| record.collection != value)
                    || id.is_some_and(|value| record.id != value)
                {
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
        let state = self.verify_chain(|_| Ok(()))?;
        Ok(AuditHead {
            sequence: state.entries,
            hash: state.head_hash,
        })
    }

    pub fn verify(&self, expected_head: Option<&str>) -> Result<AuditVerification> {
        let (latest, state) = self.states()?;

        if let Some(expected) = expected_head {
            if state.head_hash.as_deref() != Some(expected) {
                return Err(conflict(format!(
                    "audit head does not match expected checkpoint (actual: {})",
                    state.head_hash.as_deref().unwrap_or("none")
                )));
            }
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
        self.states().map(|(states, _)| states)
    }

    fn states(&self) -> Result<(AuditedRecordStates, ChainState)> {
        let mut latest = AuditedRecordStates::new();
        let chain = self.verify_chain(|entry| {
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
                    && fs::metadata(&head.segment_path)?.len() + line.len() as u64
                        <= self.segment_max_bytes =>
            {
                let mut contents = fs::read(&head.segment_path).with_context(|| {
                    format!(
                        "could not read audit segment {}",
                        head.segment_path.display()
                    )
                })?;
                if !contents.ends_with(b"\n") {
                    bail!(
                        "audit segment {} has a truncated tail",
                        head.segment_path.display()
                    );
                }
                contents.extend_from_slice(line.as_bytes());
                write_replace(&head.segment_path, &contents)?;
            }
            _ => {
                let path = self
                    .segments_dir()
                    .join(format!("{:020}.jsonl", entry.parsed.sequence));
                write_new(&path, line.as_bytes())?;
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

    fn verify_chain<F>(&self, mut visitor: F) -> Result<ChainState>
    where
        F: FnMut(&AuditEntry) -> Result<()>,
    {
        let paths = self.segment_paths()?;
        let mut expected_sequence = 1;
        let mut previous_hash: Option<String> = None;

        for path in paths {
            if segment_start(&path)? != expected_sequence {
                bail!("audit segment sequence gap at {expected_sequence}");
            }
            let file = File::open(&path)
                .with_context(|| format!("could not open audit segment {}", path.display()))?;
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
                visitor(&stored.entry)?;
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
        let chain = self.verify_chain(|entry| {
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
            let path = self
                .root
                .join(self.records_dir)
                .join(collection)
                .join(format!("{id}.md"));
            let actual_hash = file_hash_optional(&path)?;
            if &actual_hash != expected_hash {
                return Err(conflict(format!(
                    "record {collection}/{id} does not match its latest audited state"
                )));
            }
        }

        let records_root = self.root.join(self.records_dir);
        if !records_root.exists() {
            return Ok(());
        }
        for collection in fs::read_dir(&records_root)? {
            let collection = collection?;
            if !collection.file_type()?.is_dir() {
                continue;
            }
            let collection_name = collection
                .file_name()
                .to_str()
                .context("collection filename is not valid UTF-8")?
                .to_owned();
            for record in fs::read_dir(collection.path())? {
                let record = record?;
                let path = record.path();
                if path.extension().and_then(|value| value.to_str()) != Some("md") {
                    continue;
                }
                if !record.file_type()?.is_file() {
                    bail!("record path {} must be a regular file", path.display());
                }
                let id = record
                    .path()
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .context("record filename is not valid UTF-8")?
                    .to_owned();
                if !latest.contains_key(&(collection_name.clone(), id.clone())) {
                    return Err(conflict(format!(
                        "record {collection_name}/{id} has no audit history"
                    )));
                }
            }
        }
        Ok(())
    }

    fn read_segment(&self, path: &Path) -> Result<Vec<StoredEntry>> {
        let file = File::open(path)
            .with_context(|| format!("could not open audit segment {}", path.display()))?;
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
        let mut paths = Vec::new();
        for entry in fs::read_dir(self.segments_dir())? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) == Some("jsonl") {
                segment_start(&path)?;
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }

    fn clear_pending(&self) -> Result<()> {
        let path = self.pending_path();
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("could not remove pending mutation {}", path.display()))?;
            sync_parent(self.audit_dir().as_path())?;
        }
        Ok(())
    }

    fn audit_dir(&self) -> PathBuf {
        self.root.join(".cr/audit")
    }

    fn segments_dir(&self) -> PathBuf {
        self.audit_dir().join("segments")
    }

    fn pending_path(&self) -> PathBuf {
        self.audit_dir().join("pending.json")
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

fn digest(domain: &[u8], contents: &[u8]) -> String {
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

fn file_hash_optional(path: &Path) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_file() => {
            bail!("record path {} must be a regular file", path.display())
        }
        Ok(_) => fs::read(path)
            .map(|contents| Some(record_hash(&contents)))
            .with_context(|| format!("could not hash {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(anyhow!(error)).with_context(|| format!("could not hash {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_changes, diff_documents, event_hash, parse_line, record_hash, stored_line,
        AuditAction, AuditChange, AuditLog, AuditMutation, AuditSource, PendingMutation,
        PreparedEntry, ReconciledMutation,
    };
    use crate::{database::write_new, frontmatter::Document};
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use yaml_serde::Mapping;

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
        let audit = AuditLog::new(root.path(), Path::new("records"), 10, 1024 * 1024, "tester");
        let _lock = audit.lock().unwrap();
        let original = Document {
            attributes: Mapping::new(),
            body: "Original\n".to_owned(),
        };
        let original_raw = original.render().unwrap();
        let target = root.path().join("records/items/one.md");
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
            .commit(created, &target, || {
                write_new(&target, original_raw.as_bytes())
            })
            .unwrap();

        let accepted = Document {
            attributes: Mapping::new(),
            body: "Accepted\n".to_owned(),
        };
        let accepted_raw = accepted.render().unwrap();
        std::fs::write(&target, &accepted_raw).unwrap();
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
        std::fs::write(&target, "---\n---\nChanged again\n").unwrap();
        let error = audit.accept(event, &target).unwrap_err();
        assert!(error
            .to_string()
            .contains("changed while it was being saved"));
        assert_eq!(audit.head().unwrap().sequence, 1);
    }

    #[test]
    fn pending_mutations_recover_committed_state_and_discard_unapplied_state() {
        let committed_root = tempfile::tempdir().unwrap();
        let committed = AuditLog::new(
            committed_root.path(),
            Path::new("records"),
            2,
            1024 * 1024,
            "tester",
        );
        committed.ensure_layout().unwrap();
        let _lock = committed.lock().unwrap();
        let document = Document {
            attributes: Mapping::new(),
            body: "Committed\n".to_owned(),
        };
        let rendered = document.render().unwrap();
        let target = committed_root.path().join("records/items/one.md");
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
        write_new(&target, rendered.as_bytes()).unwrap();

        committed.recover_pending().unwrap();
        assert!(!committed.pending_path().exists());
        assert_eq!(committed.head().unwrap().sequence, 1);
        assert_eq!(committed.verify(None).unwrap().records_checked, 1);

        let aborted_root = tempfile::tempdir().unwrap();
        let aborted = AuditLog::new(
            aborted_root.path(),
            Path::new("records"),
            2,
            1024 * 1024,
            "tester",
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
        assert!(!aborted.pending_path().exists());
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
        write_new(
            &audit.pending_path(),
            &serde_json::to_vec_pretty(&pending).unwrap(),
        )
        .unwrap();
    }
}
