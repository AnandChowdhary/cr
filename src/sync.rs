use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use tempfile::NamedTempFile;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use yaml_serde::Mapping;

use crate::{
    AuditFilter, AuditSource, AuditVerification, Database,
    database::validate_component,
    error::{conflict, is_missing},
    paths::{self, EntryKind},
};

/// Where sync definitions, checkpoints, and locks live beneath the root.
pub(crate) const SYNC_DEFINITION_DIRECTORY: &str = ".cr/syncs";
pub(crate) const SYNC_STATE_DIRECTORY: &str = ".cr/sync/state";
pub(crate) const SYNC_LOCK_DIRECTORY: &str = ".cr/sync/locks";
/// Where the ledger and recorded operation stream of an in-flight run live.
pub(crate) const SYNC_RUN_DIRECTORY: &str = ".cr/sync/runs";
const SYNC_WORK_DIRECTORY: &str = ".cr/sync";
const SYNC_DIRECTORY_LABEL: &str = "the sync directory";
const SYNC_WORK_LABEL: &str = "the sync working directory";
const SYNC_RUN_LABEL: &str = "the sync run ledger";
const SYNC_FORMAT_VERSION: u32 = 1;
const SYNC_RUN_FORMAT_VERSION: u32 = 1;
/// Domain separator for the digest binding a run ledger to its recorded stream.
///
/// Distinct from every audit domain so a stream digest can never be confused
/// with an event, record, or change-set hash.
const SYNC_STREAM_HASH_DOMAIN: &[u8] = b"cr:sync:stream:v1\0";
const DEFAULT_TIMEOUT_SECONDS: u64 = 300;
const MAX_TIMEOUT_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_MAX_OPERATIONS: usize = 10_000;
const MAX_OPERATIONS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncDefinition {
    pub name: String,
    pub version: u32,
    pub command: Vec<String>,
    pub timeout_seconds: u64,
    pub max_output_bytes: u64,
    pub max_operations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Software this sync records as acting for its actor.
    ///
    /// A sync is a program running for a person, so its audit events can name
    /// both. The value is stored configuration and is recorded with
    /// `detected_from: config`; like every other attribution value it is
    /// asserted rather than verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
}

/// Attribution a sync records on every audit event its runs append.
///
/// A sync is a program running on a person's behalf, so both parties can be
/// named. Both values are stored configuration and are asserted, never verified.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncAttribution {
    /// Identity recorded as the responsible human.
    pub actor: Option<String>,
    /// Software recorded as acting for that identity.
    pub agent: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSyncDefinition {
    version: u32,
    command: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    timeout_seconds: u64,
    #[serde(default = "default_max_output_bytes")]
    max_output_bytes: u64,
    #[serde(default = "default_max_operations")]
    max_operations: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncRunSummary {
    pub name: String,
    pub run_id: String,
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub unchanged: usize,
    pub checkpoint_updated: bool,
    /// True when this summary completed a previously interrupted run rather
    /// than starting a fresh one, so its `run_id` is that earlier run's.
    pub resumed: bool,
}

/// What is durably known about a run that started applying and never finished.
///
/// Every field is either read back from the ledger written before the first
/// mutation or derived from the audit chain. Nothing here is a second copy of
/// progress that could disagree with the journal: `events_committed` counts the
/// events the chain actually holds for this run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SyncRunLedger {
    pub name: String,
    pub run_id: String,
    pub started: String,
    /// Protocol messages the interrupted run recorded before applying any.
    pub operations: usize,
    /// Audit events this run has committed so far.
    ///
    /// Lower than the number of operations it applied when some of them matched
    /// what was already stored, because an exact upsert and a missing delete
    /// are counted as unchanged and append no event.
    pub events_committed: u64,
    /// True when the run recorded a checkpoint that has not been committed yet.
    pub checkpoint_pending: bool,
    /// True when audit events that do not belong to this run were committed
    /// after it was interrupted, so completing it could overwrite them.
    pub foreign_events: bool,
}

/// A sync that has a run ledger on disk, so a run stopped partway.
///
/// Carries only what can be learned without the audit chain. `cr sync recover
/// <name> --check` is the command that says how far the run actually got.
pub(crate) struct InterruptedSyncRun {
    pub name: String,
    /// The run identifier, absent when the ledger itself could not be read.
    pub run_id: Option<String>,
}

/// One side of a run ledger's checkpoint pair.
///
/// Stored as an explicit flag beside the value rather than as a JSON `null`,
/// because `null` is itself a checkpoint an adapter may legitimately emit and
/// "no checkpoint" has to stay distinguishable from "the checkpoint is null".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpoint {
    #[serde(default)]
    recorded: bool,
    #[serde(default)]
    state: JsonValue,
}

impl StoredCheckpoint {
    fn new(state: Option<&JsonValue>) -> Self {
        Self {
            recorded: state.is_some(),
            state: state.cloned().unwrap_or(JsonValue::Null),
        }
    }

    fn value(&self) -> Option<&JsonValue> {
        self.recorded.then_some(&self.state)
    }

    fn owned(&self) -> Option<JsonValue> {
        self.value().cloned()
    }
}

/// The durable ledger of a run that has begun applying records.
///
/// It is written, with the exact operation stream beside it, after preflight
/// and before the first mutation, and removed only once the checkpoint agrees
/// with the committed work. Its presence is therefore the single fact that
/// distinguishes "a run finished" from "a run stopped somewhere in the middle".
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSyncRun {
    version: u32,
    sync: String,
    run_id: String,
    started: String,
    operations: usize,
    stream_hash: String,
    audit_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_head: Option<String>,
    #[serde(default)]
    checkpoint_before: StoredCheckpoint,
    #[serde(default)]
    checkpoint_after: StoredCheckpoint,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum SyncMessage {
    Upsert {
        collection: String,
        id: String,
        #[serde(default)]
        front_matter: Mapping,
        #[serde(default)]
        markdown: String,
    },
    Delete {
        collection: String,
        id: String,
    },
    Checkpoint {
        state: JsonValue,
    },
}

impl Database {
    pub fn create_sync(
        &self,
        name: &str,
        command: Vec<String>,
        timeout_seconds: u64,
        max_output_bytes: u64,
        max_operations: usize,
        attribution: SyncAttribution,
    ) -> Result<SyncDefinition> {
        validate_component(name, "sync")?;
        let stored = StoredSyncDefinition {
            version: SYNC_FORMAT_VERSION,
            command,
            timeout_seconds,
            max_output_bytes,
            max_operations,
            actor: attribution.actor,
            agent: attribution.agent,
        };
        validate_stored(name, &stored)?;
        let serialized =
            yaml_serde::to_string(&stored).context("could not serialize sync definition")?;
        paths::write_new(
            self.root(),
            &sync_path(name),
            serialized.as_bytes(),
            &sync_label(name),
        )?;
        Ok(to_public(name, stored))
    }

    pub fn sync(&self, name: &str) -> Result<SyncDefinition> {
        validate_component(name, "sync")?;
        let serialized = paths::read_to_string(self.root(), &sync_path(name), &sync_label(name))
            .map_err(|error| {
                if is_missing(&error) {
                    error.context(format!("sync '{name}' does not exist"))
                } else {
                    error
                }
            })?;
        let stored: StoredSyncDefinition = yaml_serde::from_str(&serialized)
            .with_context(|| format!("sync '{name}' is not valid YAML"))?;
        validate_stored(name, &stored)?;
        Ok(to_public(name, stored))
    }

    pub fn syncs(&self) -> Result<Vec<SyncDefinition>> {
        let Some(entries) = paths::list_directory(
            self.root(),
            Path::new(SYNC_DEFINITION_DIRECTORY),
            SYNC_DIRECTORY_LABEL,
        )?
        else {
            return Ok(Vec::new());
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry_path = Path::new(&entry.name);
            if !entry.kind.is_file()
                || entry_path.extension().and_then(|value| value.to_str()) != Some("yaml")
            {
                continue;
            }
            let name = entry_path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("sync filename is not valid UTF-8")?
                .to_owned();
            validate_component(&name, "sync")?;
            names.push(name);
        }
        names.sort();
        names.into_iter().map(|name| self.sync(&name)).collect()
    }

    pub fn sync_state(&self, name: &str) -> Result<Option<JsonValue>> {
        validate_component(name, "sync")?;
        let Some(serialized) = paths::read_to_string_optional(
            self.root(),
            &sync_state_path(name),
            &sync_state_label(name),
        )?
        else {
            return Ok(None);
        };
        serde_json::from_str(&serialized)
            .with_context(|| format!("sync state for '{name}' is not valid JSON"))
            .map(Some)
    }

    /// Every sync that has left a run ledger behind, named and identified.
    ///
    /// Deliberately weaker than [`Self::pending_sync_run`]: it reads the run
    /// directory and the ledgers in it and nothing else. It never takes the
    /// audit lock, never replays the chain, and never fails because the
    /// database is dirty. `cr check` calls it while already holding the audit
    /// lock and while the database may be in any state at all, so anything
    /// stronger would either deadlock or refuse exactly when it is most needed.
    ///
    /// A ledger this cannot parse still yields an entry with no run
    /// identifier. The ledger is a durability record, not a hash-chained one,
    /// so a damaged one says nothing about tampering — but its presence still
    /// means a run stopped in the middle, which is the fact worth reporting.
    pub(crate) fn interrupted_sync_runs(&self) -> Result<Vec<InterruptedSyncRun>> {
        let entries = paths::list_directory(
            self.root(),
            Path::new(SYNC_RUN_DIRECTORY),
            "the sync run directory",
        )?
        .unwrap_or_default();

        let mut names = Vec::new();
        for entry in entries {
            let Some(file) = entry.name.to_str() else {
                continue;
            };
            let path = Path::new(file);
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Some(name) = path.file_stem().and_then(|value| value.to_str()) else {
                continue;
            };
            if validate_component(name, "sync").is_err() {
                continue;
            }
            names.push(name.to_owned());
        }
        names.sort();

        Ok(names
            .into_iter()
            .filter_map(|name| {
                let run_id = match self.read_sync_run(&name) {
                    Ok(Some(stored)) => Some(stored.run_id),
                    // A ledger that vanished between the listing and the read
                    // belongs to a run that just finished; report neither.
                    Ok(None) => return None,
                    Err(_) => None,
                };
                Some(InterruptedSyncRun { name, run_id })
            })
            .collect())
    }

    /// The interrupted run this sync has left behind, if any.
    ///
    /// Reports rather than repairs: it never applies an operation and never
    /// fails because another writer committed after the interruption, so an
    /// operator can look at a wedged sync before deciding what to do about it.
    pub fn pending_sync_run(&self, name: &str) -> Result<Option<SyncRunLedger>> {
        let Some(stored) = self.read_sync_run(name)? else {
            return Ok(None);
        };
        let audit = self
            .audit_verify(None)
            .context("database must be clean before an interrupted sync run can be described")?;
        self.describe_sync_run(&stored, &audit).map(Some)
    }

    pub fn run_sync(&self, name: &str) -> Result<SyncRunSummary> {
        let definition = self.sync(name)?;
        let _sync_lock = self.acquire_sync_lock(name)?;
        if let Some(stored) = self.read_sync_run(name)? {
            return Err(conflict(format!(
                "sync '{name}' has an interrupted run {} that has not been completed; \
                 complete it with 'cr sync recover {name}' before starting another run",
                stored.run_id
            )));
        }
        let starting_audit = self
            .audit_verify(None)
            .context("database must be clean before a sync can run")?;

        let run_id = random_run_id()?;
        // Verified rather than merely created: `.cr/sync` must be a real
        // directory beneath the root before adapter output is staged in it.
        let sync_directory = paths::create_directory_all(
            self.root(),
            Path::new(SYNC_WORK_DIRECTORY),
            SYNC_WORK_LABEL,
        )?
        .path()
        .to_path_buf();
        let output = NamedTempFile::new_in(&sync_directory)
            .context("could not create temporary sync output")?;
        let mut state_input = NamedTempFile::new_in(&sync_directory)
            .context("could not create temporary sync state input")?;
        let current_state = self.sync_state(name)?;
        serde_json::to_writer(
            state_input.as_file_mut(),
            current_state.as_ref().unwrap_or(&JsonValue::Null),
        )
        .context("could not serialize sync state input")?;
        state_input
            .write_all(b"\n")
            .context("could not write sync state input")?;
        state_input
            .as_file()
            .sync_all()
            .context("could not sync state input")?;

        let program = resolve_program(self.root(), &definition.command[0])?;
        let mut command = Command::new(program);
        command
            .args(&definition.command[1..])
            .current_dir(self.root())
            .stdin(Stdio::null())
            .stdout(Stdio::from(
                output
                    .reopen()
                    .context("could not open temporary sync output")?,
            ))
            .stderr(Stdio::inherit())
            .env("CR_DATABASE_ROOT", self.root())
            .env("CR_SYNC_NAME", name)
            .env("CR_SYNC_RUN_ID", &run_id)
            .env("CR_SYNC_PROTOCOL", "cr-jsonl-v1")
            .env("CR_SYNC_STATE_PATH", state_input.path())
            .env(
                "CR_SYNC_HAS_STATE",
                if current_state.is_some() {
                    "true"
                } else {
                    "false"
                },
            );
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .with_context(|| format!("could not start sync '{name}'"))?;
        let status = wait_for_sync(
            &mut child,
            name,
            Duration::from_secs(definition.timeout_seconds),
            output.path(),
            definition.max_output_bytes,
        )?;
        if !status.success() {
            bail!("sync '{name}' exited unsuccessfully ({status})");
        }

        let serialized = fs::read_to_string(output.path())
            .with_context(|| format!("sync '{name}' output is not valid UTF-8"))?;
        let messages = parse_messages(name, &serialized, definition.max_operations)?;
        preflight_messages(self, &messages)?;
        let _application_lock = self.acquire_sync_application_lock()?;
        let current_audit = self
            .audit_verify(None)
            .context("database changed while the sync command was running")?;
        if current_audit.head != starting_audit.head {
            bail!("database audit head changed while the sync command was running");
        }
        if messages
            .iter()
            .any(|message| matches!(message, SyncMessage::Checkpoint { .. }))
            && self.sync_state(name)? != current_state
        {
            bail!("sync '{name}' checkpoint changed while the command was running");
        }

        // The ledger and the exact operation stream become durable before the
        // first mutation, so from here on an interrupted run is a fact on disk
        // rather than something only the audit chain hints at.
        let checkpoint = final_checkpoint(&messages).cloned();
        self.write_sync_run(
            name,
            &StoredSyncRun {
                version: SYNC_RUN_FORMAT_VERSION,
                sync: name.to_owned(),
                run_id: run_id.clone(),
                started: OffsetDateTime::now_utc()
                    .format(&Rfc3339)
                    .context("could not format sync run timestamp")?,
                operations: messages.len(),
                stream_hash: stream_hash(serialized.as_bytes()),
                audit_sequence: current_audit.head.sequence,
                audit_head: current_audit.head.hash.clone(),
                checkpoint_before: StoredCheckpoint::new(current_state.as_ref()),
                checkpoint_after: StoredCheckpoint::new(checkpoint.as_ref()),
            },
            serialized.as_bytes(),
        )?;

        let mut summary = self.apply_sync_messages(name, &run_id, &definition, messages, false)?;
        if let Some(state) = checkpoint {
            summary.checkpoint_updated = self.write_sync_state(name, &state, &current_state)?;
        }
        self.clear_sync_run(name)?;
        Ok(summary)
    }

    /// Complete an interrupted run by replaying its recorded stream.
    ///
    /// Roll-forward rather than rollback: the audit chain is append-only, so an
    /// abandoned prefix is never unwound. The `cr-jsonl-v1` stream is idempotent
    /// by construction — every target appears at most once, an upsert carries
    /// the complete record, and a delete of a missing record is a no-op — so
    /// replaying it from the start commits exactly the operations the
    /// interrupted run had not reached and appends no event for the rest.
    ///
    /// Returns `Ok(None)` when there is nothing to complete, so an unattended
    /// caller can run it unconditionally before `run_sync`.
    pub fn recover_sync(&self, name: &str) -> Result<Option<SyncRunSummary>> {
        let definition = self.sync(name)?;
        let _sync_lock = self.acquire_sync_lock(name)?;
        let Some(stored) = self.read_sync_run(name)? else {
            return Ok(None);
        };
        let _application_lock = self.acquire_sync_application_lock()?;
        let audit = self
            .audit_verify(None)
            .context("database must be clean before an interrupted sync run can be completed")?;
        let (_, foreign) = self.sync_run_events(&stored, &audit)?;
        if audit.head.sequence == stored.audit_sequence && audit.head.hash != stored.audit_head {
            return Err(conflict(format!(
                "sync '{name}' cannot complete its interrupted run {} because audit history \
                 changed after it stopped",
                stored.run_id
            )));
        }

        let serialized = paths::read_to_string(
            self.root(),
            &sync_stream_path(name),
            &sync_stream_label(name),
        )
        .map_err(|error| {
            if is_missing(&error) {
                error.context(conflict(format!(
                    "sync '{name}' recorded an interrupted run {} whose operations were not kept",
                    stored.run_id
                )))
            } else {
                error
            }
        })?;
        if stream_hash(serialized.as_bytes()) != stored.stream_hash {
            return Err(conflict(format!(
                "the recorded operations of sync '{name}' run {} do not match its run ledger",
                stored.run_id
            )));
        }
        let messages = parse_messages(name, &serialized, definition.max_operations)?;
        if messages.len() != stored.operations {
            return Err(conflict(format!(
                "the recorded operations of sync '{name}' run {} do not match its run ledger",
                stored.run_id
            )));
        }
        preflight_messages(self, &messages)?;
        // An unrelated commit while the run was wedged is fine; a commit to a
        // record this run still has to write is not, because completing the run
        // would silently overwrite it.
        if let Some((collection, id)) = message_targets(&messages).intersection(&foreign).next() {
            return Err(conflict(format!(
                "sync '{name}' cannot complete its interrupted run {} because record \
                 {collection}/{id} changed after it stopped",
                stored.run_id
            )));
        }

        let current_state = self.sync_state(name)?;
        let expected_state = stored.checkpoint_before.owned();
        // A run interrupted after its checkpoint landed but before its ledger
        // was cleared is already truthful; replaying it must not treat the
        // committed checkpoint as somebody else's edit.
        let checkpoint_committed =
            stored.checkpoint_after.recorded && current_state == stored.checkpoint_after.owned();
        if !checkpoint_committed && current_state != expected_state {
            return Err(conflict(format!(
                "sync '{name}' checkpoint changed after its interrupted run {} stopped",
                stored.run_id
            )));
        }

        let mut summary =
            self.apply_sync_messages(name, &stored.run_id, &definition, messages, true)?;
        if let Some(state) = stored.checkpoint_after.value()
            && !checkpoint_committed
        {
            summary.checkpoint_updated = self.write_sync_state(name, state, &current_state)?;
        }
        self.clear_sync_run(name)?;
        Ok(Some(summary))
    }

    fn apply_sync_messages(
        &self,
        name: &str,
        run_id: &str,
        definition: &SyncDefinition,
        messages: Vec<SyncMessage>,
        resumed: bool,
    ) -> Result<SyncRunSummary> {
        let mut sync_database = self
            .clone()
            .with_source(AuditSource::Sync)
            .with_audit_message(format!("sync:{name} run:{run_id}"))?;
        if let Some(actor) = definition.actor.clone() {
            sync_database = sync_database.with_actor(actor)?;
        }
        if let Some(agent) = definition.agent.as_deref() {
            let mut attribution = sync_database.attribution().clone();
            attribution.apply(
                &crate::AttributionOverrides {
                    agent: Some(agent),
                    ..crate::AttributionOverrides::default()
                },
                crate::AgentEvidence::Config,
            )?;
            sync_database = sync_database.with_attribution(attribution);
        }

        let mut summary = SyncRunSummary {
            name: name.to_owned(),
            run_id: run_id.to_owned(),
            created: 0,
            updated: 0,
            deleted: 0,
            unchanged: 0,
            checkpoint_updated: false,
            resumed,
        };
        for message in messages {
            match message {
                SyncMessage::Upsert {
                    collection,
                    id,
                    front_matter,
                    markdown,
                } => match sync_database.get_optional(&collection, &id)? {
                    Some(record)
                        if record.attributes == front_matter && record.body == markdown =>
                    {
                        summary.unchanged += 1;
                    }
                    Some(_) => {
                        sync_database.replace(&collection, &id, front_matter, &markdown)?;
                        summary.updated += 1;
                    }
                    None => {
                        sync_database.create_record(&collection, &id, front_matter, &markdown)?;
                        summary.created += 1;
                    }
                },
                SyncMessage::Delete { collection, id } => {
                    if sync_database.get_optional(&collection, &id)?.is_some() {
                        sync_database.delete(&collection, &id)?;
                        summary.deleted += 1;
                    } else {
                        summary.unchanged += 1;
                    }
                }
                SyncMessage::Checkpoint { .. } => {}
            }
        }
        Ok(summary)
    }

    /// Read the run ledger, refusing one that does not describe this sync.
    fn read_sync_run(&self, name: &str) -> Result<Option<StoredSyncRun>> {
        validate_component(name, "sync")?;
        let Some(serialized) =
            paths::read_to_string_optional(self.root(), &sync_run_path(name), SYNC_RUN_LABEL)?
        else {
            return Ok(None);
        };
        let stored: StoredSyncRun = serde_json::from_str(&serialized)
            .with_context(|| format!("the run ledger for sync '{name}' is not valid JSON"))?;
        if stored.version != SYNC_RUN_FORMAT_VERSION {
            return Err(conflict(format!(
                "the run ledger for sync '{name}' uses unsupported format version {}",
                stored.version
            )));
        }
        if stored.sync != name || stored.run_id.trim().is_empty() {
            return Err(conflict(format!(
                "the run ledger for sync '{name}' does not describe this sync"
            )));
        }
        Ok(Some(stored))
    }

    /// Derive an interrupted run's committed progress from the audit chain.
    ///
    /// Progress is read back from the journal rather than counted into the
    /// ledger as the run goes, so the report can never claim work the chain
    /// does not hold.
    fn describe_sync_run(
        &self,
        stored: &StoredSyncRun,
        audit: &AuditVerification,
    ) -> Result<SyncRunLedger> {
        let name = stored.sync.as_str();
        let (events_committed, foreign) = self.sync_run_events(stored, audit)?;
        Ok(SyncRunLedger {
            name: name.to_owned(),
            run_id: stored.run_id.clone(),
            started: stored.started.clone(),
            operations: stored.operations,
            events_committed,
            checkpoint_pending: stored.checkpoint_after.recorded
                && self.sync_state(name)? != stored.checkpoint_after.owned(),
            foreign_events: !foreign.is_empty(),
        })
    }

    /// How many events an interrupted run committed, and which records were
    /// changed after it stopped by anything other than that run.
    fn sync_run_events(
        &self,
        stored: &StoredSyncRun,
        audit: &AuditVerification,
    ) -> Result<(u64, BTreeSet<(String, String)>)> {
        let name = stored.sync.as_str();
        if audit.head.sequence < stored.audit_sequence {
            return Err(conflict(format!(
                "sync '{name}' recorded run {} against audit history that no longer exists",
                stored.run_id
            )));
        }
        let appended = audit.head.sequence - stored.audit_sequence;
        let limit = usize::try_from(appended).context("audit history is too long to inspect")?;
        let expected = format!("sync:{name} run:{}", stored.run_id);
        let mut events_committed = 0;
        let mut foreign = BTreeSet::new();
        for entry in self.audit_recent(limit, AuditFilter::all())? {
            if entry.payload.sequence <= stored.audit_sequence {
                continue;
            }
            if entry.payload.message.as_deref() == Some(expected.as_str()) {
                events_committed += 1;
            } else {
                foreign.insert((
                    entry.payload.record.collection.clone(),
                    entry.payload.record.id.clone(),
                ));
            }
        }
        Ok((events_committed, foreign))
    }

    /// Make an in-flight run durable: the stream first, then the ledger that
    /// points at it, so a ledger on disk always has its operations beside it.
    fn write_sync_run(&self, name: &str, stored: &StoredSyncRun, stream: &[u8]) -> Result<()> {
        let stream_path = sync_stream_path(name);
        let stream_label = sync_stream_label(name);
        // A stream without a ledger is the residue of a run that finished and
        // was interrupted while tidying up. It describes no committed work.
        if paths::entry_kind(self.root(), &stream_path, &stream_label)?.is_some() {
            paths::remove_file(self.root(), &stream_path, &stream_label)?;
        }
        paths::write_new(self.root(), &stream_path, stream, &stream_label)?;
        let mut serialized =
            serde_json::to_vec_pretty(stored).context("could not serialize the sync run ledger")?;
        serialized.push(b'\n');
        paths::write_new(
            self.root(),
            &sync_run_path(name),
            &serialized,
            SYNC_RUN_LABEL,
        )
    }

    /// Retire a completed run: the ledger first, so a crash here can only leave
    /// a stream with no ledger, which claims nothing about committed work.
    fn clear_sync_run(&self, name: &str) -> Result<()> {
        for (path, label) in [
            (sync_run_path(name), SYNC_RUN_LABEL.to_owned()),
            (sync_stream_path(name), sync_stream_label(name)),
        ] {
            if paths::entry_kind(self.root(), &path, &label)?.is_some() {
                paths::remove_file(self.root(), &path, &label)?;
            }
        }
        Ok(())
    }

    fn write_sync_state(
        &self,
        name: &str,
        state: &JsonValue,
        expected: &Option<JsonValue>,
    ) -> Result<bool> {
        let current = self.sync_state(name)?;
        if &current != expected {
            bail!("sync '{name}' checkpoint changed while records were being applied");
        }
        if current.as_ref() == Some(state) {
            return Ok(false);
        }
        let path = sync_state_path(name);
        let label = sync_state_label(name);
        let mut serialized =
            serde_json::to_vec_pretty(state).context("could not serialize sync checkpoint")?;
        serialized.push(b'\n');
        match paths::entry_kind(self.root(), &path, &label)? {
            Some(EntryKind::File) => paths::write_replace(self.root(), &path, &serialized, &label)?,
            None => paths::write_new(self.root(), &path, &serialized, &label)?,
            Some(_) => bail!("{label} is not a regular file"),
        }
        Ok(true)
    }

    fn acquire_sync_lock(&self, name: &str) -> Result<File> {
        let path = Path::new(SYNC_LOCK_DIRECTORY).join(format!("{name}.lock"));
        let lock = paths::open_lock_file(self.root(), &path, "the sync lock")?;
        lock.try_lock()
            .with_context(|| format!("sync '{name}' is already running"))?;
        Ok(lock)
    }

    fn acquire_sync_application_lock(&self) -> Result<File> {
        let path = Path::new(SYNC_LOCK_DIRECTORY).join("application.lock");
        let lock = paths::open_lock_file(self.root(), &path, "the sync application lock")?;
        lock.lock()
            .context("could not lock sync operation application")?;
        Ok(lock)
    }
}

fn sync_path(name: &str) -> PathBuf {
    Path::new(SYNC_DEFINITION_DIRECTORY).join(format!("{name}.yaml"))
}

fn sync_state_path(name: &str) -> PathBuf {
    Path::new(SYNC_STATE_DIRECTORY).join(format!("{name}.json"))
}

fn sync_label(name: &str) -> String {
    format!("sync '{name}'")
}

fn sync_state_label(name: &str) -> String {
    format!("the checkpoint for sync '{name}'")
}

fn sync_run_path(name: &str) -> PathBuf {
    Path::new(SYNC_RUN_DIRECTORY).join(format!("{name}.json"))
}

fn sync_stream_path(name: &str) -> PathBuf {
    Path::new(SYNC_RUN_DIRECTORY).join(format!("{name}.jsonl"))
}

fn sync_stream_label(name: &str) -> String {
    format!("the recorded operations for sync '{name}'")
}

/// Bind a run ledger to the exact bytes it promised to apply.
fn stream_hash(stream: &[u8]) -> String {
    crate::audit::digest(SYNC_STREAM_HASH_DOMAIN, stream)
}

/// Every record a parsed stream writes or deletes.
fn message_targets(messages: &[SyncMessage]) -> BTreeSet<(String, String)> {
    messages
        .iter()
        .filter_map(|message| match message {
            SyncMessage::Upsert { collection, id, .. } | SyncMessage::Delete { collection, id } => {
                Some((collection.clone(), id.clone()))
            }
            SyncMessage::Checkpoint { .. } => None,
        })
        .collect()
}

/// The checkpoint a parsed stream ends with, which the protocol guarantees is
/// its final message when one is present at all.
fn final_checkpoint(messages: &[SyncMessage]) -> Option<&JsonValue> {
    match messages.last() {
        Some(SyncMessage::Checkpoint { state }) => Some(state),
        _ => None,
    }
}

fn validate_stored(name: &str, sync: &StoredSyncDefinition) -> Result<()> {
    if sync.version != SYNC_FORMAT_VERSION {
        bail!(
            "sync '{name}' uses unsupported format version {} (expected {})",
            sync.version,
            SYNC_FORMAT_VERSION
        );
    }
    if sync.command.is_empty() || sync.command[0].trim().is_empty() {
        bail!("sync '{name}' command must contain a program");
    }
    if sync.command.iter().any(|argument| argument.contains('\0')) {
        bail!("sync '{name}' command cannot contain NUL bytes");
    }
    if !(1..=MAX_TIMEOUT_SECONDS).contains(&sync.timeout_seconds) {
        bail!("sync '{name}' timeout_seconds must be between 1 and {MAX_TIMEOUT_SECONDS}");
    }
    if !(1..=MAX_OUTPUT_BYTES).contains(&sync.max_output_bytes) {
        bail!("sync '{name}' max_output_bytes must be between 1 and {MAX_OUTPUT_BYTES}");
    }
    if !(1..=MAX_OPERATIONS).contains(&sync.max_operations) {
        bail!("sync '{name}' max_operations must be between 1 and {MAX_OPERATIONS}");
    }
    if sync
        .actor
        .as_deref()
        .is_some_and(|actor| actor.trim().is_empty())
    {
        bail!("sync '{name}' actor cannot be empty");
    }
    if let Some(agent) = sync.agent.as_deref() {
        crate::attribution::parse_agent(agent, crate::AgentEvidence::Config)
            .with_context(|| format!("sync '{name}' agent is not valid"))?;
    }
    Ok(())
}

fn parse_messages(name: &str, output: &str, max_operations: usize) -> Result<Vec<SyncMessage>> {
    let mut messages = Vec::new();
    let mut targets = BTreeSet::new();
    let mut saw_checkpoint = false;
    for (index, line) in output.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if messages.len() == max_operations {
            bail!("sync '{name}' produced more than {max_operations} messages");
        }
        let message: SyncMessage = serde_json::from_str(line)
            .with_context(|| format!("sync '{name}' output line {} is invalid", index + 1))?;
        if saw_checkpoint {
            bail!("sync '{name}' checkpoint must be its final message");
        }
        match &message {
            SyncMessage::Upsert { collection, id, .. } | SyncMessage::Delete { collection, id } => {
                validate_component(collection, "collection")?;
                validate_component(id, "id")?;
                if !targets.insert((collection.clone(), id.clone())) {
                    bail!("sync '{name}' produced multiple operations for {collection}/{id}");
                }
            }
            SyncMessage::Checkpoint { .. } => saw_checkpoint = true,
        }
        messages.push(message);
    }
    Ok(messages)
}

fn preflight_messages(database: &Database, messages: &[SyncMessage]) -> Result<()> {
    for message in messages {
        if let SyncMessage::Upsert {
            collection,
            front_matter,
            ..
        } = message
        {
            database.validate_record_attributes(collection, front_matter)?;
        }
    }
    Ok(())
}

fn resolve_program(root: &Path, program: &str) -> Result<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    if path.components().count() > 1 {
        return root
            .join(path)
            .canonicalize()
            .with_context(|| format!("could not resolve sync program '{program}'"));
    }
    Ok(PathBuf::from(program))
}

fn wait_for_sync(
    child: &mut Child,
    name: &str,
    timeout: Duration,
    output_path: &Path,
    max_output_bytes: u64,
) -> Result<ExitStatus> {
    let started = Instant::now();
    loop {
        if fs::metadata(output_path)
            .with_context(|| format!("could not inspect sync '{name}' output"))?
            .len()
            > max_output_bytes
        {
            stop_child(child);
            bail!("sync '{name}' output exceeded {max_output_bytes} bytes");
        }
        if let Some(status) = child
            .try_wait()
            .with_context(|| format!("could not wait for sync '{name}'"))?
        {
            if fs::metadata(output_path)
                .with_context(|| format!("could not inspect sync '{name}' output"))?
                .len()
                > max_output_bytes
            {
                bail!("sync '{name}' output exceeded {max_output_bytes} bytes");
            }
            return Ok(status);
        }
        if started.elapsed() >= timeout {
            stop_child(child);
            bail!(
                "sync '{name}' exceeded its {} second timeout",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn stop_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let process_group = -(child.id() as i32);
        // The adapter starts in its own process group, so this also stops children it spawned.
        // SAFETY: `process_group` targets that known group and SIGKILL has no pointer arguments.
        unsafe {
            libc::kill(process_group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn random_run_id() -> Result<String> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow::anyhow!("could not generate sync run ID: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn to_public(name: &str, stored: StoredSyncDefinition) -> SyncDefinition {
    SyncDefinition {
        name: name.to_owned(),
        version: stored.version,
        command: stored.command,
        timeout_seconds: stored.timeout_seconds,
        max_output_bytes: stored.max_output_bytes,
        max_operations: stored.max_operations,
        actor: stored.actor,
        agent: stored.agent,
    }
}

const fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

const fn default_max_output_bytes() -> u64 {
    DEFAULT_MAX_OUTPUT_BYTES
}

const fn default_max_operations() -> usize {
    DEFAULT_MAX_OPERATIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_rejects_duplicates_and_messages_after_checkpoint() {
        let duplicate = concat!(
            "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n",
            "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n"
        );
        assert!(
            parse_messages("test", duplicate, 10)
                .unwrap_err()
                .to_string()
                .contains("multiple operations")
        );

        let after_checkpoint = concat!(
            "{\"type\":\"checkpoint\",\"state\":{\"cursor\":1}}\n",
            "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n"
        );
        assert!(
            parse_messages("test", after_checkpoint, 10)
                .unwrap_err()
                .to_string()
                .contains("final message")
        );
    }

    #[test]
    fn a_run_ledger_tells_a_null_checkpoint_apart_from_no_checkpoint() {
        let ledger = |checkpoint: Option<&JsonValue>| StoredSyncRun {
            version: SYNC_RUN_FORMAT_VERSION,
            sync: "test".to_owned(),
            run_id: "abc".to_owned(),
            started: "2026-01-01T00:00:00Z".to_owned(),
            operations: 1,
            stream_hash: stream_hash(b""),
            audit_sequence: 0,
            audit_head: None,
            checkpoint_before: StoredCheckpoint::default(),
            checkpoint_after: StoredCheckpoint::new(checkpoint),
        };
        let round_trip = |checkpoint: Option<&JsonValue>| {
            let serialized = serde_json::to_string(&ledger(checkpoint)).unwrap();
            let parsed: StoredSyncRun = serde_json::from_str(&serialized).unwrap();
            parsed.checkpoint_after.owned()
        };

        // A checkpoint of `null` is a checkpoint. Recovery has to commit it,
        // and must not confuse it with an adapter that emitted none at all.
        assert_eq!(round_trip(Some(&JsonValue::Null)), Some(JsonValue::Null));
        assert_eq!(round_trip(None), None);
        assert_eq!(
            round_trip(Some(&serde_json::json!({"cursor": 1}))),
            Some(serde_json::json!({"cursor": 1}))
        );
    }

    #[test]
    fn a_recorded_stream_is_bound_to_its_exact_bytes() {
        assert_eq!(stream_hash(b"one\n"), stream_hash(b"one\n"));
        assert_ne!(stream_hash(b"one\n"), stream_hash(b"one\n\n"));
        // Domain separation: the same bytes never digest to a record hash.
        assert_ne!(stream_hash(b"one\n"), crate::audit::record_hash(b"one\n"));
        assert!(stream_hash(b"").starts_with("sha256:"));
    }

    #[test]
    fn the_final_checkpoint_is_the_only_one_a_stream_can_carry() {
        let messages = parse_messages(
            "test",
            concat!(
                "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n",
                "{\"type\":\"checkpoint\",\"state\":{\"cursor\":7}}\n"
            ),
            10,
        )
        .unwrap();
        assert_eq!(
            final_checkpoint(&messages),
            Some(&serde_json::json!({"cursor": 7}))
        );
        assert_eq!(
            message_targets(&messages),
            BTreeSet::from([("notes".to_owned(), "one".to_owned())])
        );

        let without = parse_messages(
            "test",
            "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n",
            10,
        )
        .unwrap();
        assert_eq!(final_checkpoint(&without), None);
    }

    #[test]
    fn protocol_accepts_typed_front_matter() {
        let messages = parse_messages(
            "test",
            r#"{"type":"upsert","collection":"notes","id":"one","front_matter":{"active":true,"score":42},"markdown":"Hello"}"#,
            10,
        )
        .unwrap();
        let SyncMessage::Upsert { front_matter, .. } = &messages[0] else {
            panic!("expected upsert");
        };
        assert_eq!(front_matter["active"], true);
        assert_eq!(front_matter["score"], 42);
    }
}
