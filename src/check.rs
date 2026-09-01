//! Whole-database integrity checking.
//!
//! `cr check` answers one question — *is this database coherent?* — and answers
//! it exhaustively. Every other integrity-adjacent command in `cr` stops at the
//! first problem: `audit verify` returns a single classified failure, and a
//! mutation refuses rather than describes. That is right for a command that
//! guards a write, and wrong for a command an operator runs *because* something
//! is already broken. So this module never propagates a per-record failure. It
//! collects [`Finding`]s and keeps scanning, and a database with a damaged
//! journal is still fully inspectable for dangling links and schema drift.
//!
//! # What this is not
//!
//! It is strictly read-only. Nothing here creates, replaces, or removes a
//! record, an audit event, or a configuration file, and there is deliberately
//! no repair mode: a command that both diagnoses and mutates cannot be run
//! safely from cron against a database whose owner is asleep. See `TODO.md`.
//!
//! # The boundary with `status`
//!
//! `cr status` is the working-tree view. It answers *what would `cr save`
//! record next?* and every row it prints is an expected, resolvable direct
//! edit. `check` reports the same three physical conditions — a record with no
//! audit history, an audited record whose file is gone, and a file whose bytes
//! do not match the audited state — because a whole-database integrity report
//! that silently omitted them would be lying. But it reports them at
//! [`Severity::Warning`] and points at `status`, *provided `cr save` could
//! actually reconcile them*. When the same record also fails to parse, fails
//! its schema, or cannot be named, `save` will refuse it, the divergence is
//! permanent until a human intervenes, and the finding is escalated to
//! [`Severity::Error`]. That is the line: `status` enumerates the working set,
//! `check` says whether the working set is reconcilable and whether the journal
//! underneath it is sound.
//!
//! Everything else here — dangling links, malformed relation values, schema
//! drift, unusable schemas, invalid record names, chain damage, approval
//! mismatches, an audit anchor that disagrees with or lags the journal, and a
//! sync run that stopped halfway — is invisible to `status` entirely. The sync one is the sharpest case: an interrupted run leaves a
//! committed prefix that genuinely agrees with the journal, so `status` reports
//! clean and `audit verify` passes, and until now the only way to find it was
//! to already suspect the sync by name.
//!
//! # Cost
//!
//! `check` reads and parses every in-scope record and replays the journal, so
//! it is O(records + events) with no index to lean on, exactly like `list` and
//! `search`. `--collection` bounds the expensive phase; the cheap directory
//! index stays whole-database so a link into another collection can still be
//! resolved.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::Result;
use serde::Serialize;
use yaml_serde::{Mapping, Value};

use crate::{
    audit::{AnchorStatus, record_hash},
    database::{
        CollectionEntry, Database, collection_directory_name, collection_entry, validate_component,
    },
    error::{DomainError, invalid},
    frontmatter::Document,
    paths::{self, EntryKind},
};

/// How serious a finding is.
///
/// Two levels rather than four. The only decision a caller makes from a
/// severity is whether to fail, and every extra level would be a judgement
/// `cr` is not entitled to make about somebody else's database.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Reported for completeness; `cr save` or `cr status` already covers it.
    Warning,
    /// The database is not coherent and no ordinary command will repair it.
    Error,
}

impl Severity {
    /// The stable lowercase label used in output and in `--fail-on`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// What kind of problem a finding describes.
///
/// The five classes named in `TODO.md` are [`Self::DanglingLink`],
/// [`Self::MalformedRelation`], [`Self::SchemaViolation`],
/// [`Self::InvalidRecordName`], and the three audit-reconciliation kinds. The
/// rest exist because refusing to name them would have forced a whole-database
/// scan to abort on a single damaged file.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    /// A well-formed relation reference whose target record does not exist.
    DanglingLink,
    /// A `relations` value that is not a valid reference at all.
    MalformedRelation,
    /// A record whose front matter no longer satisfies its collection schema.
    SchemaViolation,
    /// A collection schema that is not usable, so its records cannot be checked.
    UnusableSchema,
    /// A file or directory name that cannot be a record ID or a collection.
    InvalidRecordName,
    /// A record that exists but cannot be read or parsed as Markdown.
    UnreadableRecord,
    /// A record file with no audit history at all.
    UnauditedRecord,
    /// A record the journal says exists whose file is missing.
    MissingRecord,
    /// A record file whose bytes do not match its latest audited state.
    RecordContentMismatch,
    /// The audit chain itself could not be replayed.
    AuditChainBroken,
    /// A stored change set does not match the approval recorded beside it.
    ApprovalMismatch,
    /// A sync run stopped partway and has not been completed.
    InterruptedSyncRun,
    /// The audit anchor does not agree with the journal it sits beside.
    AuditAnchorMismatch,
    /// The audit anchor attests to an earlier event than the current head.
    AuditAnchorBehind,
    /// The journal has events and no audit anchor attests to its head.
    AuditAnchorMissing,
}

impl FindingKind {
    /// The stable machine-readable label, identical to the JSON form.
    pub fn code(self) -> &'static str {
        match self {
            Self::DanglingLink => "dangling_link",
            Self::MalformedRelation => "malformed_relation",
            Self::SchemaViolation => "schema_violation",
            Self::UnusableSchema => "unusable_schema",
            Self::InvalidRecordName => "invalid_record_name",
            Self::UnreadableRecord => "unreadable_record",
            Self::UnauditedRecord => "unaudited_record",
            Self::MissingRecord => "missing_record",
            Self::RecordContentMismatch => "record_content_mismatch",
            Self::AuditChainBroken => "audit_chain_broken",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::InterruptedSyncRun => "interrupted_sync_run",
            Self::AuditAnchorMismatch => "audit_anchor_mismatch",
            Self::AuditAnchorBehind => "audit_anchor_behind",
            Self::AuditAnchorMissing => "audit_anchor_missing",
        }
    }

    /// Whether this kind prevents `cr save` from reconciling a record.
    ///
    /// `save` parses and schema-validates every selected file before appending
    /// anything, so any of these turns an ordinary unsaved edit into a
    /// divergence a human has to resolve by hand.
    fn blocks_save(self) -> bool {
        matches!(
            self,
            Self::MalformedRelation
                | Self::SchemaViolation
                | Self::UnusableSchema
                | Self::InvalidRecordName
                | Self::UnreadableRecord
        )
    }
}

/// One problem found in the database.
///
/// A finding names a record by collection and ID, a field by its dotted path,
/// and nothing by its location on disk. That is the same invariant every
/// caller-facing message in `cr` holds, and it matters more here: a check
/// report is the output most likely to be pasted into an issue tracker.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: FindingKind,
    /// The collection involved, absent for database-wide findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    /// The record involved, absent for collection-wide findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The dotted front matter path involved, where one applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// The `collection/id` a dangling relation pointed at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// A complete sentence naming records, fields, and collections only.
    pub message: String,
}

impl Finding {
    /// `collection/id` when the finding names a record.
    pub fn reference(&self) -> Option<String> {
        match (&self.collection, &self.id) {
            (Some(collection), Some(id)) => Some(format!("{collection}/{id}")),
            (Some(collection), None) => Some(collection.clone()),
            _ => None,
        }
    }

    fn database(kind: FindingKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            severity,
            kind,
            collection: None,
            id: None,
            field: None,
            target: None,
            message: message.into(),
        }
    }

    fn collection(kind: FindingKind, collection: &str, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            kind,
            collection: Some(collection.to_owned()),
            id: None,
            field: None,
            target: None,
            message: message.into(),
        }
    }

    fn record(
        kind: FindingKind,
        severity: Severity,
        collection: &str,
        id: &str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            kind,
            collection: Some(collection.to_owned()),
            id: Some(id.to_owned()),
            field: None,
            target: None,
            message: message.into(),
        }
    }

    fn at_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }

    fn pointing_at(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }
}

/// How much of the database a run looked at, and what it concluded.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckSummary {
    /// Collections whose records were read in full.
    pub collections: usize,
    /// Record files read in full.
    pub records: usize,
    /// Distinct records the journal carries history for, within scope.
    pub audited_records: usize,
    pub errors: usize,
    pub warnings: usize,
}

impl CheckSummary {
    /// Whether any finding reached `threshold`.
    pub fn fails(&self, threshold: Severity) -> bool {
        match threshold {
            Severity::Error => self.errors > 0,
            Severity::Warning => self.errors > 0 || self.warnings > 0,
        }
    }
}

/// The complete result of one `check` run.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CheckReport {
    /// The collection the run was limited to, when it was limited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection: Option<String>,
    pub summary: CheckSummary,
    /// Findings in deterministic order: severity, then kind, then record.
    pub findings: Vec<Finding>,
}

/// How much of the database to check.
#[derive(Clone, Debug, Default)]
pub struct CheckScope {
    /// Limit the expensive per-record phase to one collection.
    pub collection: Option<String>,
}

/// Everything one record contributed to the scan.
struct ScannedRecord {
    /// `None` when the file could not be read or hashed at all.
    hash: Option<String>,
    /// `None` when the file could not be parsed as a record.
    attributes: Option<Mapping>,
    /// True once a finding on this record would make `cr save` refuse it.
    blocked: bool,
}

/// Run every check against `database`, collecting rather than propagating.
pub(crate) fn run(database: &Database, scope: &CheckScope) -> Result<CheckReport> {
    let selected = match &scope.collection {
        Some(collection) => {
            validate_component(collection, "collection")?;
            Some(collection.clone())
        }
        None => None,
    };

    let root = database.root();
    let records_dir = database.records_dir();
    let audit = database.audit();

    // Serialize against writers for the length of the scan, exactly as `status`
    // does, so a mutation landing halfway through cannot manufacture a finding.
    // Deliberately *without* `recover_pending`: recovery appends an audit
    // event, and a read-only command may not write. An interrupted mutation is
    // instead visible here as an ordinary reconciliation finding.
    let _lock = audit.lock()?;

    let mut findings = Vec::new();

    // Phase one, always whole-database and cheap: directory listings only. The
    // index has to span every collection even under `--collection`, because a
    // relation from the selected collection may point into another one.
    let index = index_records(root, records_dir, selected.as_deref(), &mut findings)?;

    if let Some(collection) = &selected
        && !index.collections.contains(collection)
    {
        return Err(unknown_collection(collection, &audit)?);
    }

    // Phase two, bounded by scope and expensive: read, hash, parse, and
    // validate every selected record.
    let mut scanned: BTreeMap<(String, String), ScannedRecord> = BTreeMap::new();
    let mut validators = SchemaCache::default();
    let scanned_collections = index
        .collections
        .iter()
        .filter(|collection| selected.as_deref().is_none_or(|name| name == *collection))
        .count();

    for (collection, id) in &index.records {
        if selected.as_deref().is_some_and(|name| name != collection) {
            continue;
        }
        let record = scan_record(
            database,
            &mut validators,
            collection,
            id,
            index.symlinked.contains(&(collection.clone(), id.clone())),
            &mut findings,
        )?;
        scanned.insert((collection.clone(), id.clone()), record);
    }

    // Relations are checked after the whole index exists so that a link into a
    // collection scanned later is still resolved against reality.
    for ((collection, id), record) in &scanned {
        if let Some(attributes) = &record.attributes {
            check_relations(collection, id, attributes, &index.records, &mut findings);
        }
    }
    mark_blocked(&mut scanned, &findings);

    // Phase three: reconcile against the journal, or explain why we cannot.
    let audited_records = match audit.record_states() {
        Ok(states) => {
            if let Err(error) = audit.verify_approvals() {
                findings.push(approval_finding(&error));
            }
            reconcile(&states, &scanned, selected.as_deref(), &mut findings)
        }
        Err(error) => {
            findings.push(chain_finding(&error));
            0
        }
    };

    // Database-wide, and therefore reported under `--collection` too: a
    // half-applied import is not a property of one collection.
    report_interrupted_syncs(database, &mut findings)?;
    report_anchor(&audit, &mut findings);

    findings.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.kind.code().cmp(right.kind.code()))
            .then_with(|| left.collection.cmp(&right.collection))
            .then_with(|| left.id.cmp(&right.id))
            .then_with(|| left.field.cmp(&right.field))
            .then_with(|| left.message.cmp(&right.message))
    });

    let errors = findings
        .iter()
        .filter(|finding| finding.severity == Severity::Error)
        .count();
    Ok(CheckReport {
        collection: selected,
        summary: CheckSummary {
            collections: scanned_collections,
            records: scanned.len(),
            audited_records,
            errors,
            warnings: findings.len() - errors,
        },
        findings,
    })
}

/// Report every sync that stopped partway through applying a run.
///
/// An interrupted run is a *durability* problem, not an integrity one, and the
/// distinction decides the severity. The run ledger is deliberately not
/// hash-chained, so its presence is evidence that a run stopped and evidence of
/// nothing else; the records the run did commit genuinely agree with the
/// journal, which is exactly why `cr status` reports clean and `cr audit
/// verify` passes over a wedged sync. It is reported at [`Severity::Warning`]
/// for a second reason as well: `check` deliberately does not take the per-sync
/// lock, so it cannot tell an abandoned run from one that is running right now,
/// and failing a build because an import happened to be in flight would be
/// wrong.
///
/// `check` never recovers. It names the sync and the command that inspects it.
fn report_interrupted_syncs(database: &Database, findings: &mut Vec<Finding>) -> Result<()> {
    for run in database.interrupted_sync_runs()? {
        let name = &run.name;
        let identified = match &run.run_id {
            Some(run_id) => format!("run {run_id}"),
            None => "a run whose ledger could not be read".to_owned(),
        };
        findings.push(Finding::database(
            FindingKind::InterruptedSyncRun,
            Severity::Warning,
            format!(
                "sync '{name}' has {identified} that never finished, so part of an import is applied and its checkpoint is behind; inspect it with 'cr sync recover {name} --check'"
            ),
        ));
    }
    Ok(())
}

/// What the cheap directory walk learned.
#[derive(Default)]
struct RecordIndex {
    /// Every directory beneath the records root that is a valid collection.
    collections: BTreeSet<String>,
    /// Every `collection/id` a valid `.md` file exists for.
    records: BTreeSet<(String, String)>,
    /// Records whose entry is a symbolic link or another special file.
    symlinked: BTreeSet<(String, String)>,
}

/// Walk the records tree by listing directories only, reporting names that
/// cannot be a collection or a record ID.
///
/// Name findings are limited to `selected`, because reporting another
/// collection's problems under `--collection` would be noise; the index itself
/// always spans the database so link targets stay resolvable.
fn index_records(
    root: &Path,
    records_dir: &Path,
    selected: Option<&str>,
    findings: &mut Vec<Finding>,
) -> Result<RecordIndex> {
    let mut index = RecordIndex::default();
    let Some(entries) = paths::list_directory(root, records_dir, "the records directory")? else {
        return Ok(index);
    };

    let mut collections = Vec::new();
    for entry in entries {
        if !entry.kind.is_directory() {
            continue;
        }
        // The same definition every other path uses, reported instead of
        // propagated: `check` exists to describe a database nothing else will
        // touch, so it must keep scanning past exactly the names that stop
        // `list`, `status`, and `audit verify`.
        match collection_directory_name(&entry.name) {
            Ok(name) => collections.push(name),
            Err(error) => findings.push(Finding::database(
                FindingKind::InvalidRecordName,
                Severity::Error,
                safe(&error),
            )),
        }
    }
    collections.sort();

    for collection in collections {
        index.collections.insert(collection.clone());
        let in_scope = selected.is_none_or(|name| name == collection);
        let directory = records_dir.join(&collection);
        let label = format!("collection '{collection}'");
        let Some(entries) = paths::list_directory(root, &directory, &label)? else {
            continue;
        };
        for entry in entries {
            let id = match collection_entry(&collection, &entry.name) {
                Ok(CollectionEntry::Record(id)) => id,
                Ok(CollectionEntry::Ignored) => continue,
                Err(error) => {
                    if in_scope {
                        findings.push(Finding::collection(
                            FindingKind::InvalidRecordName,
                            &collection,
                            safe(&error),
                        ));
                    }
                    continue;
                }
            };
            if !entry.kind.is_file() {
                index.symlinked.insert((collection.clone(), id.clone()));
            }
            index.records.insert((collection.clone(), id));
        }
    }
    Ok(index)
}

/// Read, parse, and schema-validate one record, turning every failure into a
/// finding rather than aborting the run.
fn scan_record(
    database: &Database,
    validators: &mut SchemaCache,
    collection: &str,
    id: &str,
    special: bool,
    findings: &mut Vec<Finding>,
) -> Result<ScannedRecord> {
    let mut record = ScannedRecord {
        hash: None,
        attributes: None,
        blocked: false,
    };
    if special {
        findings.push(Finding::record(
            FindingKind::UnreadableRecord,
            Severity::Error,
            collection,
            id,
            format!(
                "record {collection}/{id} is not a regular file, so the database refuses to read it"
            ),
        ));
        return Ok(record);
    }

    let path = database
        .records_dir()
        .join(collection)
        .join(format!("{id}.md"));
    let label = format!("record {collection}/{id}");
    let contents = match paths::read(database.root(), &path, &label) {
        Ok(contents) => contents,
        Err(error) => {
            findings.push(Finding::record(
                FindingKind::UnreadableRecord,
                Severity::Error,
                collection,
                id,
                format!(
                    "record {collection}/{id} could not be read: {}",
                    safe(&error)
                ),
            ));
            return Ok(record);
        }
    };
    record.hash = Some(record_hash(&contents));

    let Ok(text) = String::from_utf8(contents) else {
        findings.push(Finding::record(
            FindingKind::UnreadableRecord,
            Severity::Error,
            collection,
            id,
            format!("record {collection}/{id} is not valid UTF-8"),
        ));
        return Ok(record);
    };
    let document = match Document::parse(&text) {
        Ok(document) => document,
        Err(error) => {
            findings.push(Finding::record(
                FindingKind::UnreadableRecord,
                Severity::Error,
                collection,
                id,
                format!("record {collection}/{id} could not be parsed: {error}"),
            ));
            return Ok(record);
        }
    };

    match validators.get(database, collection, findings)? {
        SchemaState::Absent => {}
        SchemaState::Unusable => record.blocked = true,
        SchemaState::Ready(validator) => {
            let instance = serde_json::to_value(&document.attributes);
            match instance {
                Ok(instance) => {
                    for error in validator.iter_errors(&instance) {
                        let mut finding = Finding::record(
                            FindingKind::SchemaViolation,
                            Severity::Error,
                            collection,
                            id,
                            format!(
                                "record {collection}/{id} does not match the schema for collection '{collection}': {error}"
                            ),
                        );
                        finding.field = dotted_path(&error.instance_path().to_string());
                        findings.push(finding);
                    }
                }
                Err(_) => findings.push(Finding::record(
                    FindingKind::UnreadableRecord,
                    Severity::Error,
                    collection,
                    id,
                    format!(
                        "record {collection}/{id} has front matter that cannot be represented as JSON for schema validation"
                    ),
                )),
            }
        }
    }

    record.attributes = Some(document.attributes);
    Ok(record)
}

/// Check one record's `relations` mapping for shape and for target existence.
fn check_relations(
    collection: &str,
    id: &str,
    attributes: &Mapping,
    known: &BTreeSet<(String, String)>,
    findings: &mut Vec<Finding>,
) {
    let Some(relations) = attributes.get(Value::String("relations".to_owned())) else {
        return;
    };
    let Value::Mapping(relations) = relations else {
        findings.push(
            malformed(
                collection,
                id,
                format!("record {collection}/{id} stores 'relations' as {}, but relations must be an object of named relation lists", kind_of(relations)),
            )
            .at_field("relations"),
        );
        return;
    };

    for (name, targets) in relations {
        let Value::String(name) = name else {
            findings.push(
                malformed(
                    collection,
                    id,
                    format!("record {collection}/{id} has a relation name that is not a string"),
                )
                .at_field("relations"),
            );
            continue;
        };
        let field = format!("relations.{name}");
        if validate_component(name, "relation").is_err() {
            findings.push(
                malformed(
                    collection,
                    id,
                    format!("record {collection}/{id} has a relation name that cannot be used"),
                )
                .at_field(field.clone()),
            );
            continue;
        }
        let Value::Sequence(targets) = targets else {
            findings.push(
                malformed(
                    collection,
                    id,
                    format!(
                        "record {collection}/{id} stores relation '{name}' as {}, but a relation must be a list of references",
                        kind_of(targets)
                    ),
                )
                .at_field(field),
            );
            continue;
        };
        for (position, target) in targets.iter().enumerate() {
            let field = format!("{field}[{position}]");
            match reference_of(target) {
                Err(reason) => findings.push(
                    malformed(
                        collection,
                        id,
                        format!(
                            "record {collection}/{id} has an entry in relation '{name}' that is not a valid reference: {reason}"
                        ),
                    )
                    .at_field(field),
                ),
                Ok((target_collection, target_id)) => {
                    if !known.contains(&(target_collection.clone(), target_id.clone())) {
                        findings.push(
                            Finding::record(
                                FindingKind::DanglingLink,
                                Severity::Error,
                                collection,
                                id,
                                format!(
                                    "record {collection}/{id} has a relation '{name}' pointing at {target_collection}/{target_id}, which does not exist"
                                ),
                            )
                            .at_field(field)
                            .pointing_at(format!("{target_collection}/{target_id}")),
                        );
                    }
                }
            }
        }
    }
}

/// Read one relation element as a `collection/id` reference.
///
/// Extra keys are deliberately tolerated. `cr link` never writes them, but a
/// hand-annotated reference is still a reference, and a check that fires on one
/// would be a false positive on a database that works.
fn reference_of(value: &Value) -> std::result::Result<(String, String), String> {
    let Value::Mapping(mapping) = value else {
        return Err(format!(
            "it is {}, not an object with 'collection' and 'id'",
            kind_of(value)
        ));
    };
    let mut parts = Vec::with_capacity(2);
    for key in ["collection", "id"] {
        match mapping.get(Value::String(key.to_owned())) {
            None => return Err(format!("it has no '{key}'")),
            Some(Value::String(value)) => {
                if validate_component(value, key).is_err() {
                    return Err(format!("its '{key}' is not a usable name"));
                }
                parts.push(value.clone());
            }
            Some(other) => return Err(format!("its '{key}' is {}, not a string", kind_of(other))),
        }
    }
    Ok((parts[0].clone(), parts[1].clone()))
}

/// Compare the scanned records against the replayed journal.
///
/// Returns how many distinct in-scope records the journal carries history for.
fn reconcile(
    states: &crate::audit::AuditedRecordStates,
    scanned: &BTreeMap<(String, String), ScannedRecord>,
    selected: Option<&str>,
    findings: &mut Vec<Finding>,
) -> usize {
    let audited: BTreeMap<_, _> = states
        .iter()
        .filter(|((collection, _), _)| selected.is_none_or(|name| name == collection))
        .map(|(key, state)| (key.clone(), state.hash.clone()))
        .collect();

    let references: BTreeSet<_> = audited.keys().chain(scanned.keys()).cloned().collect();
    for (collection, id) in references {
        let key = (collection.clone(), id.clone());
        let record = scanned.get(&key);
        // A record we could not read at all already has its own finding; a
        // second one about hashes it does not have would only be noise.
        if record.is_some_and(|record| record.hash.is_none()) {
            continue;
        }
        let severity = if record.is_some_and(|record| record.blocked) {
            Severity::Error
        } else {
            Severity::Warning
        };
        let current = record.and_then(|record| record.hash.clone());
        let audited_hash = audited.get(&key);

        let finding = match (audited_hash, current) {
            (None, Some(_)) => Some(Finding::record(
                FindingKind::UnauditedRecord,
                severity,
                &collection,
                &id,
                format!(
                    "record {collection}/{id} exists but has no audit history; 'cr status' reports it as added and 'cr save' records it"
                ),
            )),
            (Some(Some(_)), None) => Some(Finding::record(
                FindingKind::MissingRecord,
                severity,
                &collection,
                &id,
                format!(
                    "record {collection}/{id} is audited but its file is missing; 'cr status' reports it as deleted and 'cr save' records the deletion"
                ),
            )),
            (Some(Some(expected)), Some(actual)) if expected != &actual => Some(Finding::record(
                FindingKind::RecordContentMismatch,
                severity,
                &collection,
                &id,
                format!(
                    "record {collection}/{id} does not match its latest audited state; 'cr status' reports it as modified and 'cr save' records the change"
                ),
            )),
            (Some(None), Some(_)) => Some(Finding::record(
                FindingKind::RecordContentMismatch,
                severity,
                &collection,
                &id,
                format!(
                    "record {collection}/{id} exists but its audit history ends with a deletion; 'cr status' reports it as added and 'cr save' records it"
                ),
            )),
            _ => None,
        };
        if let Some(mut finding) = finding {
            if finding.severity == Severity::Error {
                finding.message.push_str(
                    ", but this record cannot be saved until the problems reported above it are fixed",
                );
            }
            findings.push(finding);
        }
    }
    audited.len()
}

/// Raise reconciliation severity for records that `cr save` would refuse.
fn mark_blocked(scanned: &mut BTreeMap<(String, String), ScannedRecord>, findings: &[Finding]) {
    for finding in findings {
        if !finding.kind.blocks_save() {
            continue;
        }
        match (&finding.collection, &finding.id) {
            (Some(collection), Some(id)) => {
                if let Some(record) = scanned.get_mut(&(collection.clone(), id.clone())) {
                    record.blocked = true;
                }
            }
            (Some(collection), None) => {
                for ((other, _), record) in scanned.iter_mut() {
                    if other == collection {
                        record.blocked = true;
                    }
                }
            }
            _ => {}
        }
    }
}

/// Whether a collection's schema is absent, broken, or ready to validate with.
enum SchemaState<'a> {
    Absent,
    Unusable,
    Ready(&'a jsonschema::Validator),
}

/// One compiled validator per collection.
///
/// `Database::validate` recompiles a schema for every record it checks, which
/// is right for a single mutation and quadratic-feeling for a whole-database
/// scan. Compiling once per collection is the one performance decision this
/// module makes, and it also means an unusable schema is reported once rather
/// than once per record.
#[derive(Default)]
struct SchemaCache {
    compiled: BTreeMap<String, Option<jsonschema::Validator>>,
}

impl SchemaCache {
    fn get(
        &mut self,
        database: &Database,
        collection: &str,
        findings: &mut Vec<Finding>,
    ) -> Result<SchemaState<'_>> {
        if !self.compiled.contains_key(collection) {
            let compiled = compile_schema(database, collection, findings)?;
            self.compiled.insert(collection.to_owned(), compiled);
        }
        Ok(match &self.compiled[collection] {
            Some(validator) => SchemaState::Ready(validator),
            None => match schema_exists(database, collection)? {
                true => SchemaState::Unusable,
                false => SchemaState::Absent,
            },
        })
    }
}

fn schema_path(collection: &str) -> std::path::PathBuf {
    Path::new(crate::database::SCHEMA_DIRECTORY).join(format!("{collection}.json"))
}

fn schema_exists(database: &Database, collection: &str) -> Result<bool> {
    Ok(paths::entry_kind(
        database.root(),
        &schema_path(collection),
        "a collection schema",
    )?
    .is_some_and(|kind| kind == EntryKind::File))
}

/// Compile a collection's schema, reporting an unusable one as a finding.
fn compile_schema(
    database: &Database,
    collection: &str,
    findings: &mut Vec<Finding>,
) -> Result<Option<jsonschema::Validator>> {
    let label = format!("the JSON Schema for collection '{collection}'");
    let Some(serialized) =
        paths::read_to_string_optional(database.root(), &schema_path(collection), &label)?
    else {
        return Ok(None);
    };
    let unusable = |reason: String| {
        Some(Finding::collection(
            FindingKind::UnusableSchema,
            collection,
            format!(
                "collection '{collection}' has an unusable JSON Schema, so its records cannot be validated: {reason}"
            ),
        ))
    };
    let schema: serde_json::Value = match serde_json::from_str(&serialized) {
        Ok(schema) => schema,
        Err(error) => {
            findings.extend(unusable(format!("it is not valid JSON: {error}")));
            return Ok(None);
        }
    };
    if let Err(error) = jsonschema::meta::validate(&schema) {
        findings.extend(unusable(format!("it is not a valid JSON Schema: {error}")));
        return Ok(None);
    }
    match jsonschema::validator_for(&schema) {
        Ok(validator) => Ok(Some(validator)),
        Err(error) => {
            findings.extend(unusable(format!("it could not be compiled: {error}")));
            Ok(None)
        }
    }
}

/// Explain a scoped collection that the database does not have.
///
/// A typo in a scheduled `cr check --collection` must not report a clean
/// database, so this is a failure to run rather than an empty report.
fn unknown_collection(
    collection: &str,
    audit: &crate::audit::AuditLog<'_>,
) -> Result<anyhow::Error> {
    let audited = audit
        .record_states()
        .map(|states| states.keys().any(|(name, _)| name == collection))
        .unwrap_or(false);
    Ok(if audited {
        // The directory is gone but the journal remembers records in it, which
        // is itself worth checking, so this is not an error.
        anyhow::Error::new(DomainError::Conflict(format!(
            "collection '{collection}' has no directory but still has audit history; check the whole database instead"
        )))
    } else {
        anyhow::Error::new(DomainError::NotFound(format!(
            "collection '{collection}' does not exist"
        )))
    })
}

/// Report how the audit anchor stands against the journal.
///
/// Three separable findings rather than one, because they call for three
/// different responses. A mismatch is an [`Severity::Error`]: the journal is
/// not the one the anchor attests to, and the anchor's committed history is the
/// place to find out which side moved. A lagging anchor and a missing anchor
/// are [`Severity::Warning`]s: nothing has been altered, the guarantee is
/// merely thinner than it should be, and `cr audit anchor --write` restores it.
///
/// Deliberately silent when the chain itself could not be replayed: that
/// failure is not an anchor mismatch, so it falls through to no finding and the
/// journal's own [`FindingKind::AuditChainBroken`] stands alone. Stacking an
/// anchor complaint on top of a broken journal would send an operator after the
/// wrong thing.
fn report_anchor(audit: &crate::audit::AuditLog<'_>, findings: &mut Vec<Finding>) {
    let finding = match audit.anchor_report() {
        Ok(report) => match report.status {
            AnchorStatus::Empty | AnchorStatus::Matched { .. } | AnchorStatus::Overridden => return,
            AnchorStatus::Absent => Finding::database(
                FindingKind::AuditAnchorMissing,
                Severity::Warning,
                "the journal has events and no audit anchor attests to its head; run 'cr audit anchor --write' and commit the result",
            ),
            AnchorStatus::Behind { sequence, head } => Finding::database(
                FindingKind::AuditAnchorBehind,
                Severity::Warning,
                format!(
                    "the audit anchor attests to sequence {sequence} and the journal is at {head}; the journal still agrees with the anchor, so this is a lagging anchor rather than altered history"
                ),
            ),
        },
        Err(error) => match DomainError::of(&error) {
            Some(DomainError::AnchorMismatch(message)) => Finding::database(
                FindingKind::AuditAnchorMismatch,
                Severity::Error,
                message.clone(),
            ),
            // The chain replayed a moment ago, so anything else here is an
            // environment failure rather than a finding about the database.
            _ => return,
        },
    };
    findings.push(finding);
}

/// A database-wide finding for a journal that could not be replayed.
///
/// The message is authored here rather than taken from the error, because chain
/// failures name segment files and a finding may not carry a path.
fn chain_finding(error: &anyhow::Error) -> Finding {
    Finding::database(
        FindingKind::AuditChainBroken,
        Severity::Error,
        match DomainError::of(error) {
            Some(domain) => format!(
                "the audit chain could not be replayed, so no record could be reconciled against it: {domain}"
            ),
            None => "the audit chain could not be replayed, so no record could be reconciled against it; run 'cr audit verify' for the detailed cause".to_owned(),
        },
    )
}

/// A database-wide finding for an event whose approval does not match.
fn approval_finding(error: &anyhow::Error) -> Finding {
    match DomainError::of(error) {
        Some(DomainError::ApprovalMismatch(message)) => Finding::database(
            FindingKind::ApprovalMismatch,
            Severity::Error,
            message.clone(),
        ),
        Some(domain) => Finding::database(
            FindingKind::AuditChainBroken,
            Severity::Error,
            format!("the audit chain could not be fully verified: {domain}"),
        ),
        None => Finding::database(
            FindingKind::AuditChainBroken,
            Severity::Error,
            "the audit chain could not be fully verified; run 'cr audit verify' for the detailed cause",
        ),
    }
}

fn malformed(collection: &str, id: &str, message: String) -> Finding {
    Finding::record(
        FindingKind::MalformedRelation,
        Severity::Error,
        collection,
        id,
        message,
    )
}

/// Turn a JSON Pointer from the schema validator into `cr`'s dotted field
/// syntax, so a finding names a field the way `--set` and `--where` do.
///
/// An empty pointer means the whole document rather than a field, and becomes
/// `None`.
fn dotted_path(pointer: &str) -> Option<String> {
    let trimmed = pointer.trim_start_matches('/');
    (!trimmed.is_empty()).then(|| trimmed.replace('/', "."))
}

/// Name a YAML value's type for a message, without quoting its contents.
fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Sequence(_) => "a list",
        Value::Mapping(_) => "an object",
        Value::Tagged(_) => "a tagged value",
    }
}

/// The part of an error that is safe to put in a finding.
///
/// Only a `DomainError`'s own message is authored to be caller-facing; anything
/// else in the chain may name a file or an operating-system error, so it stays
/// in the chain rather than reaching a report.
fn safe(error: &anyhow::Error) -> String {
    match DomainError::of(error) {
        Some(domain) => domain.message().to_owned(),
        None => "the database refused to read it".to_owned(),
    }
}

/// Parse a `--fail-on` value into the severity at which `check` fails.
pub fn parse_threshold(value: &str) -> Result<Option<Severity>> {
    match value {
        "error" => Ok(Some(Severity::Error)),
        "warning" => Ok(Some(Severity::Warning)),
        "never" => Ok(None),
        other => Err(invalid(format!(
            "'{other}' is not a failure threshold; use error, warning, or never"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{FindingKind, Severity, kind_of, parse_threshold, reference_of};
    use yaml_serde::Value;

    #[test]
    fn thresholds_parse_to_the_documented_three_values() {
        assert_eq!(parse_threshold("error").unwrap(), Some(Severity::Error));
        assert_eq!(parse_threshold("warning").unwrap(), Some(Severity::Warning));
        assert_eq!(parse_threshold("never").unwrap(), None);
        assert!(parse_threshold("fatal").is_err());
    }

    #[test]
    fn an_error_outranks_a_warning() {
        assert!(Severity::Error > Severity::Warning);
        assert_eq!(Severity::Error.label(), "error");
    }

    #[test]
    fn only_kinds_that_stop_save_block_reconciliation() {
        assert!(FindingKind::SchemaViolation.blocks_save());
        assert!(FindingKind::UnreadableRecord.blocks_save());
        assert!(!FindingKind::DanglingLink.blocks_save());
        assert!(!FindingKind::UnauditedRecord.blocks_save());
    }

    #[test]
    fn references_accept_extra_keys_but_not_missing_or_unusable_ones() {
        let reference: Value =
            yaml_serde::from_str("collection: people\nid: ada\nrole: owner\n").unwrap();
        assert_eq!(
            reference_of(&reference).unwrap(),
            ("people".to_owned(), "ada".to_owned())
        );

        let missing: Value = yaml_serde::from_str("collection: people\n").unwrap();
        assert!(reference_of(&missing).unwrap_err().contains("no 'id'"));

        let traversal: Value = yaml_serde::from_str("collection: people\nid: ../escape\n").unwrap();
        assert!(
            reference_of(&traversal)
                .unwrap_err()
                .contains("not a usable name")
        );

        let scalar = Value::String("people/ada".to_owned());
        assert!(reference_of(&scalar).unwrap_err().contains("a string"));
    }

    #[test]
    fn value_kinds_are_named_without_quoting_their_contents() {
        assert_eq!(kind_of(&Value::String("secret".to_owned())), "a string");
        assert_eq!(kind_of(&Value::Null), "null");
    }
}
