use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use tempfile::NamedTempFile;
use yaml_serde::Mapping;

use crate::{
    database::validate_component,
    error::is_missing,
    paths::{self, EntryKind},
    AuditSource, Database,
};

/// Where sync definitions, checkpoints, and locks live beneath the root.
pub(crate) const SYNC_DEFINITION_DIRECTORY: &str = ".cr/syncs";
pub(crate) const SYNC_STATE_DIRECTORY: &str = ".cr/sync/state";
pub(crate) const SYNC_LOCK_DIRECTORY: &str = ".cr/sync/locks";
const SYNC_WORK_DIRECTORY: &str = ".cr/sync";
const SYNC_DIRECTORY_LABEL: &str = "the sync directory";
const SYNC_WORK_LABEL: &str = "the sync working directory";
const SYNC_FORMAT_VERSION: u32 = 1;
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

    pub fn run_sync(&self, name: &str) -> Result<SyncRunSummary> {
        let definition = self.sync(name)?;
        let _sync_lock = self.acquire_sync_lock(name)?;
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

        let mut sync_database = self
            .clone()
            .with_source(AuditSource::Sync)
            .with_audit_message(format!("sync:{name} run:{run_id}"))?;
        if let Some(actor) = definition.actor {
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
            run_id,
            created: 0,
            updated: 0,
            deleted: 0,
            unchanged: 0,
            checkpoint_updated: false,
        };
        let mut checkpoint = None;
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
                SyncMessage::Checkpoint { state } => checkpoint = Some(state),
            }
        }
        if let Some(state) = checkpoint {
            summary.checkpoint_updated = self.write_sync_state(name, &state, &current_state)?;
        }
        Ok(summary)
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
        assert!(parse_messages("test", duplicate, 10)
            .unwrap_err()
            .to_string()
            .contains("multiple operations"));

        let after_checkpoint = concat!(
            "{\"type\":\"checkpoint\",\"state\":{\"cursor\":1}}\n",
            "{\"type\":\"delete\",\"collection\":\"notes\",\"id\":\"one\"}\n"
        );
        assert!(parse_messages("test", after_checkpoint, 10)
            .unwrap_err()
            .to_string()
            .contains("final message"));
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
