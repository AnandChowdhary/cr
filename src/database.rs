use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use yaml_serde::{Mapping, Value};

use crate::{
    attribution::{Attribution, AuditAgent, AuditAuthorization, AuditIntent},
    audit::{record_hash, AuditFilter, AuditLog, AuditMutation, ChangePreview, ReconciledMutation},
    error::{conflict, invalid, is_already_exists, is_missing, DomainError},
    frontmatter::Document,
    paths,
    sync::{SYNC_DEFINITION_DIRECTORY, SYNC_LOCK_DIRECTORY, SYNC_STATE_DIRECTORY},
    value::{compare_yaml_values, get_path, parse_path, remove_path},
    views::VIEW_DIRECTORY,
    Assignment, AuditAction, AuditEntry, AuditHead, AuditSource, AuditVerification, SearchQuery,
};

const CONFIG_PATH: &str = ".cr/config.yaml";
const DATABASE_DIRECTORY: &str = ".cr";
const SCHEMA_DIRECTORY: &str = ".cr/schemas";
const CURRENT_FORMAT_VERSION: u32 = 1;

/// How the database directory itself is named to a caller.
pub(crate) const DATABASE_LABEL: &str = "the database directory";
/// How the configured records directory is named to a caller.
pub(crate) const RECORDS_LABEL: &str = "the records directory";
/// How the collection schema directory is named to a caller.
const SCHEMA_LABEL: &str = "the schema directory";

/// Name one collection's JSON Schema in caller-facing words.
fn schema_label(collection: &str) -> String {
    format!("the JSON Schema for collection '{collection}'")
}

/// Name one record in caller-facing words, never by path.
pub(crate) fn record_label(collection: &str, id: &str) -> String {
    format!("record {collection}/{id}")
}

/// Name one collection in caller-facing words, never by path.
fn collection_label(collection: &str) -> String {
    format!("collection '{collection}'")
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    version: u32,
    data_dir: PathBuf,
    #[serde(default)]
    audit: AuditConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(default)]
struct AuditConfig {
    segment_max_events: usize,
    segment_max_bytes: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            segment_max_events: 256,
            segment_max_bytes: 8 * 1024 * 1024,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_FORMAT_VERSION,
            data_dir: PathBuf::from("records"),
            audit: AuditConfig::default(),
        }
    }
}

/// Whether a mutation should be written or only computed.
///
/// `Preview` stops after the change set is known: nothing is written, no audit
/// event is appended, no pending-mutation file is created, and the audit lock is
/// released on the way out. It deliberately does not run pending-mutation
/// recovery either, because recovery appends an event, and a preview that
/// writes is not a preview. An interrupted mutation therefore makes a preview
/// fail loudly on the audited-state check rather than quietly predicting the
/// wrong result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationMode {
    Apply,
    Preview,
}

/// What running a mutation in one of those two modes produced.
enum MutationOutcome {
    Applied(Record),
    Previewed(ChangePreview),
}

impl MutationOutcome {
    fn record(self) -> Result<Record> {
        match self {
            Self::Applied(record) => Ok(record),
            Self::Previewed(_) => bail!("an applied mutation returned a preview"),
        }
    }

    fn preview(self) -> Result<ChangePreview> {
        match self {
            Self::Previewed(preview) => Ok(preview),
            Self::Applied(_) => bail!("a previewed mutation returned a record"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Database {
    root: PathBuf,
    config: Config,
    actor: String,
    source: AuditSource,
    audit_message: Option<String>,
    attribution: Attribution,
}

#[derive(Clone, Debug, Serialize)]
pub struct CollectionModel {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub collection: String,
    pub id: String,
    pub path: PathBuf,
    pub attributes: Mapping,
    pub body: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingChangeKind {
    Added,
    Modified,
    Deleted,
}

impl WorkingChangeKind {
    pub fn short_code(&self) -> char {
        match self {
            Self::Added => 'A',
            Self::Modified => 'M',
            Self::Deleted => 'D',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkingChange {
    pub status: WorkingChangeKind,
    pub collection: String,
    pub id: String,
    pub path: PathBuf,
    pub audited_hash: Option<String>,
    pub current_hash: Option<String>,
}

impl WorkingChange {
    pub fn reference(&self) -> String {
        format!("{}/{}", self.collection, self.id)
    }
}

impl Record {
    pub fn reference(&self) -> String {
        format!("{}/{}", self.collection, self.id)
    }

    pub fn field(&self, path: &str) -> Result<Option<&Value>> {
        let path = parse_path(path)?;
        Ok(get_path(&self.attributes, &path))
    }
}

pub fn sort_records_by_field(
    records: &mut [Record],
    field: &str,
    direction: SortDirection,
) -> Result<()> {
    let field = field.trim();
    if field.is_empty() {
        return Err(invalid("sort field cannot be empty"));
    }
    if !matches!(field, "$id" | "$collection" | "$path") {
        parse_path(field)?;
    }

    records.sort_by(|left, right| {
        let ordering = match field {
            "$id" => direction_ordering(left.id.cmp(&right.id), direction),
            "$collection" => direction_ordering(left.collection.cmp(&right.collection), direction),
            "$path" => direction_ordering(left.path.cmp(&right.path), direction),
            _ => {
                let left_value = left.field(field).expect("sort field path was validated");
                let right_value = right.field(field).expect("sort field path was validated");
                match (left_value, right_value) {
                    (Some(left), Some(right)) => {
                        direction_ordering(compare_yaml_values(left, right), direction)
                    }
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            }
        };
        ordering
            .then_with(|| left.collection.cmp(&right.collection))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(())
}

fn direction_ordering(
    ordering: std::cmp::Ordering,
    direction: SortDirection,
) -> std::cmp::Ordering {
    match direction {
        SortDirection::Asc => ordering,
        SortDirection::Desc => ordering.reverse(),
    }
}

impl Database {
    pub fn init(path: impl AsRef<Path>) -> Result<Self> {
        let root = path.as_ref();
        fs::create_dir_all(root)
            .with_context(|| format!("could not create database root {}", root.display()))?;
        let root = root
            .canonicalize()
            .with_context(|| format!("could not resolve database root {}", root.display()))?;

        // A dangling or hostile symbolic link named `.cr` must not be treated as
        // absent and then created through, so existence is judged without
        // following links.
        if paths::entry_kind(&root, Path::new(DATABASE_DIRECTORY), DATABASE_LABEL)?.is_some() {
            bail!("a database already exists at {}", root.display());
        }

        for (relative, label) in [
            (SCHEMA_DIRECTORY, "the schema directory"),
            (VIEW_DIRECTORY, "the view directory"),
            (SYNC_DEFINITION_DIRECTORY, "the sync directory"),
            (SYNC_STATE_DIRECTORY, "the sync state directory"),
            (SYNC_LOCK_DIRECTORY, "the sync lock directory"),
            ("records", RECORDS_LABEL),
        ] {
            paths::create_directory_all(&root, Path::new(relative), label)?;
        }

        let database = Self {
            root,
            config: Config::default(),
            actor: String::new(),
            source: AuditSource::Cli,
            audit_message: None,
            attribution: Attribution::from_environment()?,
        };
        let database = database.with_default_actor();
        database.audit().ensure_layout()?;
        Ok(database)
    }

    pub fn discover(explicit_root: Option<&Path>) -> Result<Self> {
        let root = match explicit_root {
            Some(path) => path
                .canonicalize()
                .with_context(|| format!("could not resolve database root {}", path.display()))?,
            None => {
                let current =
                    std::env::current_dir().context("could not read current directory")?;
                current
                    .ancestors()
                    .find(|path| path.join(DATABASE_DIRECTORY).is_dir())
                    .map(Path::to_path_buf)
                    .context("no database found; run 'cr init' or pass --database <PATH>")?
            }
        };

        // Refuses a `.cr` that is a symbolic link rather than a real directory,
        // which would otherwise relocate the whole database.
        if paths::open_directory_optional(&root, Path::new(DATABASE_DIRECTORY), DATABASE_LABEL)?
            .is_none()
        {
            bail!(
                "no database found at {}; run 'cr init' first",
                root.display()
            );
        }

        let config = match paths::read_to_string_optional(
            &root,
            Path::new(CONFIG_PATH),
            "the database configuration",
        )? {
            Some(serialized) => yaml_serde::from_str(&serialized)
                .context("the database configuration is not valid YAML")?,
            None => Config::default(),
        };

        if config.version != CURRENT_FORMAT_VERSION {
            bail!(
                "database format version {} is unsupported (expected {})",
                config.version,
                CURRENT_FORMAT_VERSION
            );
        }
        validate_relative_path(&config.data_dir, "data_dir")?;
        // The configured records directory, and every directory above it, must
        // be a real directory beneath the root rather than a redirection.
        paths::open_directory_optional(&root, &config.data_dir, RECORDS_LABEL)?;
        if config.audit.segment_max_events == 0 {
            bail!("audit.segment_max_events must be greater than zero");
        }
        if config.audit.segment_max_bytes == 0 {
            bail!("audit.segment_max_bytes must be greater than zero");
        }

        let database = Self {
            root,
            config,
            actor: String::new(),
            source: AuditSource::Cli,
            audit_message: None,
            attribution: Attribution::from_environment()?,
        };
        let database = database.with_default_actor();
        let audit = database.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        Ok(database)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Result<Self> {
        let actor = actor.into();
        if actor.trim().is_empty() {
            return Err(invalid("audit actor cannot be empty"));
        }
        self.actor = actor;
        Ok(self)
    }

    /// The agent, authorization, and intent that will be recorded beside
    /// `actor` on every event this database appends.
    pub fn attribution(&self) -> &Attribution {
        &self.attribution
    }

    /// The agent that carried out changes on the actor's behalf, if any.
    pub fn agent(&self) -> Option<&AuditAgent> {
        self.attribution.agent.as_ref()
    }

    /// The approval recorded for changes, if any.
    pub fn authorization(&self) -> Option<&AuditAuthorization> {
        self.attribution.authorization.as_ref()
    }

    /// The intent recorded for changes, if any.
    pub fn intent(&self) -> Option<&AuditIntent> {
        self.attribution.intent.as_ref()
    }

    /// Replace the attribution recorded beside `actor`.
    ///
    /// Nothing here is authenticated. It is a cooperating process's claim about
    /// itself, exactly like `actor`, and it never affects what an operation is
    /// permitted to do.
    pub fn with_attribution(mut self, attribution: Attribution) -> Self {
        self.attribution = attribution;
        self
    }

    pub fn with_source(mut self, source: AuditSource) -> Self {
        self.source = source;
        self
    }

    pub fn with_audit_message(mut self, message: impl Into<String>) -> Result<Self> {
        let message = message.into();
        if message.trim().is_empty() {
            return Err(invalid("audit message cannot be empty"));
        }
        self.audit_message = Some(message);
        Ok(self)
    }

    pub fn create(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: &str,
    ) -> Result<Record> {
        let mut attributes = Mapping::new();
        apply_all(&mut attributes, assignments)?;
        self.create_record(collection, id, attributes, body)
    }

    /// Compute what `create` would record, without creating anything.
    pub fn preview_create(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: &str,
    ) -> Result<ChangePreview> {
        let mut attributes = Mapping::new();
        apply_all(&mut attributes, assignments)?;
        self.preview_create_record(collection, id, attributes, body)
    }

    pub fn create_record(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
    ) -> Result<Record> {
        self.run_create(collection, id, attributes, body, MutationMode::Apply)?
            .record()
    }

    /// Compute what `create_record` would record, without creating anything.
    pub fn preview_create_record(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
    ) -> Result<ChangePreview> {
        self.run_create(collection, id, attributes, body, MutationMode::Preview)?
            .preview()
    }

    fn run_create(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
        mode: MutationMode,
    ) -> Result<MutationOutcome> {
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        if paths::entry_kind(&self.root, &path, &label)?.is_some() {
            return Err(DomainError::record_exists(collection, id).into());
        }
        let document = Document {
            attributes,
            body: body.to_owned(),
        };
        self.validate(collection, &document.attributes)?;
        let rendered = document.render()?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Create,
            collection,
            id,
            before_document: None,
            after_document: Some(&document),
            before_bytes: None,
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(event.into_preview()));
        }
        audit.commit(event, &path, || {
            paths::write_new(&self.root, &path, rendered.as_bytes(), &label).map_err(|error| {
                if is_already_exists(&error) {
                    error.context(DomainError::record_exists(collection, id))
                } else {
                    error
                }
            })
        })?;
        Ok(MutationOutcome::Applied(record_from_document(
            collection, id, path, document,
        )))
    }

    pub fn get(&self, collection: &str, id: &str) -> Result<Record> {
        let path = self.record_path(collection, id)?;
        let document = self.read_document(collection, id, &path)?;
        Ok(record_from_document(collection, id, path, document))
    }

    pub fn get_optional(&self, collection: &str, id: &str) -> Result<Option<Record>> {
        let path = self.record_path(collection, id)?;
        match paths::entry_kind(&self.root, &path, &record_label(collection, id))? {
            Some(_) => self.get(collection, id).map(Some),
            None => Ok(None),
        }
    }

    pub fn read_raw(&self, collection: &str, id: &str) -> Result<String> {
        let path = self.record_path(collection, id)?;
        self.read_record(collection, id, &path)
    }

    pub fn list(&self, collection: &str, filters: &[Assignment]) -> Result<Vec<Record>> {
        validate_component(collection, "collection")?;
        let directory = self.config.data_dir.join(collection);
        let label = collection_label(collection);
        let Some(entries) = paths::list_directory(&self.root, &directory, &label)? else {
            return Ok(Vec::new());
        };

        let mut identifiers = Vec::new();
        for entry in entries {
            if !entry.kind.is_file() {
                continue;
            }
            let name = Path::new(&entry.name);
            if name.extension().and_then(|value| value.to_str()) != Some("md") {
                continue;
            }
            let id = name
                .file_stem()
                .and_then(|value| value.to_str())
                .with_context(|| {
                    DomainError::Invalid(format!(
                        "{label} contains a record filename that is not valid UTF-8"
                    ))
                })?
                .to_owned();
            identifiers.push(id);
        }
        identifiers.sort();

        identifiers
            .into_iter()
            .map(|id| {
                let path = directory.join(format!("{id}.md"));
                let document = self.read_document(collection, &id, &path)?;
                Ok(record_from_document(collection, &id, path, document))
            })
            .filter(|record: &Result<Record>| {
                record
                    .as_ref()
                    .map(|record| {
                        filters
                            .iter()
                            .all(|filter| filter.matches(&record.attributes))
                    })
                    .unwrap_or(true)
            })
            .collect()
    }

    pub fn search(
        &self,
        collection: Option<&str>,
        filters: &[Assignment],
        query: &SearchQuery,
    ) -> Result<Vec<Record>> {
        let collections = match collection {
            Some(collection) => {
                validate_component(collection, "collection")?;
                vec![collection.to_owned()]
            }
            None => self.collection_names()?,
        };

        let mut matches = Vec::new();
        for collection in collections {
            for record in self.list(&collection, filters)? {
                let raw_document = self.read_record(&collection, &record.id, &record.path)?;
                if query.matches(&record, &raw_document)? {
                    matches.push(record);
                }
            }
        }
        Ok(matches)
    }

    pub fn collection_models(&self) -> Result<Vec<CollectionModel>> {
        let mut models: BTreeMap<String, Option<serde_json::Value>> = self
            .collection_names()?
            .into_iter()
            .map(|name| (name, None))
            .collect();
        let schema_root = Path::new(SCHEMA_DIRECTORY);
        let entries =
            paths::list_directory(&self.root, schema_root, SCHEMA_LABEL)?.unwrap_or_default();

        for entry in entries {
            let entry_path = Path::new(&entry.name);
            if !entry.kind.is_file()
                || entry_path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                continue;
            }
            let name = entry_path
                .file_stem()
                .and_then(|value| value.to_str())
                .context("schema filename is not valid UTF-8")?
                .to_owned();
            validate_component(&name, "collection")?;
            let serialized = paths::read_to_string(
                &self.root,
                &schema_root.join(&entry.name),
                &schema_label(&name),
            )?;
            let schema: serde_json::Value =
                serde_json::from_str(&serialized).with_context(|| {
                    DomainError::Invalid(format!(
                        "schema for collection '{name}' is not valid JSON"
                    ))
                })?;
            jsonschema::meta::validate(&schema).map_err(|error| {
                anyhow!("{error}").context(DomainError::Invalid(format!(
                    "invalid JSON Schema for collection '{name}'"
                )))
            })?;
            models.insert(name, Some(schema));
        }

        Ok(models
            .into_iter()
            .map(|(name, schema)| CollectionModel { name, schema })
            .collect())
    }

    pub fn validate_record_attributes(&self, collection: &str, attributes: &Mapping) -> Result<()> {
        validate_component(collection, "collection")?;
        self.validate(collection, attributes)
    }

    pub fn update(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: Option<&str>,
    ) -> Result<Record> {
        self.run_update(
            collection,
            id,
            update_with(assignments, body),
            MutationMode::Apply,
        )?
        .record()
    }

    /// Compute what `update` would record, without writing anything.
    pub fn preview_update(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: Option<&str>,
    ) -> Result<ChangePreview> {
        self.run_update(
            collection,
            id,
            update_with(assignments, body),
            MutationMode::Preview,
        )?
        .preview()
    }

    pub fn patch(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
    ) -> Result<Record> {
        self.run_patch(
            collection,
            id,
            attributes,
            remove,
            body,
            MutationMode::Apply,
        )?
        .record()
    }

    /// Compute what `patch` would record, without writing anything.
    pub fn preview_patch(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
    ) -> Result<ChangePreview> {
        self.run_patch(
            collection,
            id,
            attributes,
            remove,
            body,
            MutationMode::Preview,
        )?
        .preview()
    }

    fn run_patch(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
        mode: MutationMode,
    ) -> Result<MutationOutcome> {
        if attributes.is_empty() && remove.is_empty() && body.is_none() {
            return Err(invalid("patch must change front matter or Markdown"));
        }
        let remove = remove
            .iter()
            .map(|path| Ok((path, parse_path(path)?)))
            .collect::<Result<Vec<_>>>()?;
        self.run_update(
            collection,
            id,
            |document| {
                merge_mapping(&mut document.attributes, attributes);
                for (raw, path) in &remove {
                    if !remove_path(&mut document.attributes, path) {
                        return Err(invalid(format!("field '{raw}' does not exist")));
                    }
                }
                if let Some(body) = body {
                    document.body = body.to_owned();
                }
                Ok(())
            },
            mode,
        )
    }

    /// Replace a record's complete front matter and Markdown body atomically.
    ///
    /// This is used by server-rendered edit forms, where the user submits the
    /// complete document rather than a partial API patch.
    pub fn replace(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
    ) -> Result<Record> {
        self.run_update(
            collection,
            id,
            |document| {
                document.attributes = attributes;
                document.body = body.to_owned();
                Ok(())
            },
            MutationMode::Apply,
        )?
        .record()
    }

    fn run_update(
        &self,
        collection: &str,
        id: &str,
        mutate: impl FnOnce(&mut Document) -> Result<()>,
        mode: MutationMode,
    ) -> Result<MutationOutcome> {
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        let before_raw = self.read_record(collection, id, &path)?;
        let before = parse_record(collection, id, &before_raw)?;
        let mut document = before.clone();
        mutate(&mut document)?;
        self.validate(collection, &document.attributes)?;
        let rendered = document.render()?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Update,
            collection,
            id,
            before_document: Some(&before),
            after_document: Some(&document),
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(event.into_preview()));
        }
        audit.commit(event, &path, || {
            paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)
        })?;
        Ok(MutationOutcome::Applied(record_from_document(
            collection, id, path, document,
        )))
    }

    pub fn link(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
    ) -> Result<Record> {
        self.run_link(
            collection,
            id,
            relation,
            target_collection,
            target_id,
            MutationMode::Apply,
        )?
        .record()
    }

    /// Compute what `link` would record, without writing anything.
    pub fn preview_link(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
    ) -> Result<ChangePreview> {
        self.run_link(
            collection,
            id,
            relation,
            target_collection,
            target_id,
            MutationMode::Preview,
        )?
        .preview()
    }

    fn run_link(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
        mode: MutationMode,
    ) -> Result<MutationOutcome> {
        validate_component(relation, "relation")?;
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        let target_path = self.record_path(target_collection, target_id)?;
        let target_raw = self
            .read_record(target_collection, target_id, &target_path)
            .map_err(|error| {
                if is_missing(&error) {
                    error.context(DomainError::NotFound(format!(
                        "relation target {target_collection}/{target_id} does not exist"
                    )))
                } else {
                    error
                }
            })?;
        parse_record(target_collection, target_id, &target_raw)?;
        audit.assert_current(target_collection, target_id, target_raw.as_bytes())?;

        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let before_raw = self.read_record(collection, id, &path)?;
        let before = parse_record(collection, id, &before_raw)?;
        let mut document = before.clone();
        let relations = mapping_field(&mut document.attributes, "relations")?;
        let targets = sequence_field(relations, relation)?;
        let reference = relation_value(target_collection, target_id);

        if !targets.contains(&reference) {
            targets.push(reference);
        }

        self.validate(collection, &document.attributes)?;
        let rendered = document.render()?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Link,
            collection,
            id,
            before_document: Some(&before),
            after_document: Some(&document),
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(event.into_preview()));
        }
        audit.commit(event, &path, || {
            paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)
        })?;
        Ok(MutationOutcome::Applied(record_from_document(
            collection, id, path, document,
        )))
    }

    pub fn delete(&self, collection: &str, id: &str) -> Result<Record> {
        self.run_delete(collection, id, MutationMode::Apply)?
            .record()
    }

    /// Compute what `delete` would record, without deleting anything.
    pub fn preview_delete(&self, collection: &str, id: &str) -> Result<ChangePreview> {
        self.run_delete(collection, id, MutationMode::Preview)?
            .preview()
    }

    fn run_delete(
        &self,
        collection: &str,
        id: &str,
        mode: MutationMode,
    ) -> Result<MutationOutcome> {
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        let before_raw = self.read_record(collection, id, &path)?;
        let document = parse_record(collection, id, &before_raw)?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Delete,
            collection,
            id,
            before_document: Some(&document),
            after_document: None,
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: None,
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(event.into_preview()));
        }
        audit.commit(event, &path, || {
            paths::remove_file(&self.root, &path, &label)
        })?;
        Ok(MutationOutcome::Applied(record_from_document(
            collection, id, path, document,
        )))
    }

    pub fn status(&self) -> Result<Vec<WorkingChange>> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.working_changes(&audit)
    }

    pub fn save(
        &self,
        references: &[String],
        all: bool,
        message: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        self.run_save(references, all, message, MutationMode::Apply)
            .map(|(entries, _)| entries)
    }

    /// Compute what `save` would record for each selected record, without
    /// recording anything.
    pub fn preview_save(
        &self,
        references: &[String],
        all: bool,
        message: Option<&str>,
    ) -> Result<Vec<ChangePreview>> {
        self.run_save(references, all, message, MutationMode::Preview)
            .map(|(_, previews)| previews)
    }

    fn run_save(
        &self,
        references: &[String],
        all: bool,
        message: Option<&str>,
        mode: MutationMode,
    ) -> Result<(Vec<AuditEntry>, Vec<ChangePreview>)> {
        if all && !references.is_empty() {
            return Err(invalid("--all cannot be combined with record references"));
        }
        if !all && references.is_empty() {
            return Err(invalid("provide at least one COLLECTION/ID or use --all"));
        }
        if message.is_some_and(|value| value.trim().is_empty()) {
            return Err(invalid("save message cannot be empty"));
        }

        let selected = references
            .iter()
            .map(|reference| parse_reference(reference))
            .collect::<Result<BTreeSet<_>>>()?;
        // One digest cannot approve several independent change sets, and
        // silently checking it against only one of them would be worse than
        // refusing. Approving a multi-record save needs a per-record mapping;
        // that waits on the bulk-mutation design in `TODO.md`.
        if self
            .attribution
            .authorization
            .as_ref()
            .is_some_and(|authorization| authorization.approved_changes.is_some())
            && (all || selected.len() != 1)
        {
            return Err(invalid(
                "an approved change set applies to one record, so save it by naming exactly one COLLECTION/ID",
            ));
        }
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        let states = audit.record_states()?;
        let changes = self.working_changes_from_states(&states)?;
        let available: BTreeMap<_, _> = changes
            .into_iter()
            .map(|change| ((change.collection.clone(), change.id.clone()), change))
            .collect();

        if !all {
            for reference in &selected {
                if !available.contains_key(reference) {
                    return Err(conflict(format!(
                        "record {}/{} has no unsaved changes",
                        reference.0, reference.1
                    )));
                }
            }
        }
        let selected_changes: Vec<_> = available
            .into_iter()
            .filter(|(reference, _)| all || selected.contains(reference))
            .map(|(_, change)| change)
            .collect();

        let mut prepared = Vec::with_capacity(selected_changes.len());
        for change in &selected_changes {
            let key = (change.collection.clone(), change.id.clone());
            let prior = states.get(&key);
            let before = prior
                .and_then(|state| state.document.as_ref())
                .map(Document::from_audit_value)
                .transpose()?;
            let after_raw = match change.status {
                WorkingChangeKind::Deleted => None,
                WorkingChangeKind::Added | WorkingChangeKind::Modified => {
                    Some(self.read_record(&change.collection, &change.id, &change.path)?)
                }
            };
            let after = after_raw
                .as_deref()
                .map(|raw| parse_record(&change.collection, &change.id, raw))
                .transpose()?;
            if let Some(document) = &after {
                self.validate(&change.collection, &document.attributes)?;
            }
            let action = match change.status {
                WorkingChangeKind::Added => AuditAction::Create,
                WorkingChangeKind::Modified => AuditAction::Update,
                WorkingChangeKind::Deleted => AuditAction::Delete,
            };
            prepared.push((change, before, after, after_raw, action));
        }

        let mut entries = Vec::with_capacity(prepared.len());
        let mut previews = Vec::with_capacity(prepared.len());
        for (change, before, after, after_raw, action) in prepared {
            let event = audit.prepare_reconciled(ReconciledMutation {
                action,
                collection: &change.collection,
                id: &change.id,
                before_document: before.as_ref(),
                after_document: after.as_ref(),
                before_hash: change.audited_hash.as_deref(),
                after_bytes: after_raw.as_deref().map(str::as_bytes),
                had_history: states.contains_key(&(change.collection.clone(), change.id.clone())),
                message,
            })?;
            if mode == MutationMode::Preview {
                previews.push(event.into_preview());
                continue;
            }
            entries.push(audit.accept(event, &change.path)?);
        }
        Ok((entries, previews))
    }

    pub fn audit_recent(&self, limit: usize, filter: AuditFilter<'_>) -> Result<Vec<AuditEntry>> {
        if filter.id.is_some() && filter.collection.is_none() {
            return Err(invalid("an audit record ID requires a collection"));
        }
        if let Some(collection) = filter.collection {
            validate_component(collection, "collection")?;
        }
        if let Some(id) = filter.id {
            validate_component(id, "id")?;
        }
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        audit.recent(limit, filter)
    }

    pub fn audit_head(&self) -> Result<AuditHead> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        audit.head()
    }

    pub fn audit_verify(&self, expected_head: Option<&str>) -> Result<AuditVerification> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        audit.verify(expected_head)
    }

    pub fn audit_baseline(&self) -> Result<usize> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        let mut added = 0;

        for (collection, id, path) in self.record_files()? {
            if audit.has_history(&collection, &id)? {
                continue;
            }
            let raw = self.read_record(&collection, &id, &path)?;
            let document = parse_record(&collection, &id, &raw)?;
            let event = audit.prepare(AuditMutation {
                action: AuditAction::Baseline,
                collection: &collection,
                id: &id,
                before_document: None,
                after_document: Some(&document),
                before_bytes: None,
                after_bytes: Some(raw.as_bytes()),
                source: self.source.clone(),
                message: self.audit_message.as_deref(),
            })?;
            audit.commit(event, &path, || Ok(()))?;
            added += 1;
        }

        audit.verify(None)?;
        Ok(added)
    }

    fn working_changes(&self, audit: &AuditLog<'_>) -> Result<Vec<WorkingChange>> {
        let states = audit.record_states()?;
        self.working_changes_from_states(&states)
    }

    fn working_changes_from_states(
        &self,
        states: &crate::audit::AuditedRecordStates,
    ) -> Result<Vec<WorkingChange>> {
        let mut current = BTreeMap::new();
        for (collection, id, path) in self.record_files()? {
            let contents = paths::read(&self.root, &path, &record_label(&collection, &id))?;
            current.insert((collection, id), (path, record_hash(&contents)));
        }
        let references: BTreeSet<_> = states
            .keys()
            .cloned()
            .chain(current.keys().cloned())
            .collect();
        let mut changes = Vec::new();
        for (collection, id) in references {
            let audited_hash = states
                .get(&(collection.clone(), id.clone()))
                .and_then(|state| state.hash.clone());
            let current_entry = current.get(&(collection.clone(), id.clone()));
            let current_hash = current_entry.map(|(_, hash)| hash.clone());
            if audited_hash == current_hash {
                continue;
            }
            let status = match (audited_hash.is_some(), current_hash.is_some()) {
                (false, true) => WorkingChangeKind::Added,
                (true, false) => WorkingChangeKind::Deleted,
                (true, true) => WorkingChangeKind::Modified,
                (false, false) => continue,
            };
            let path = match current_entry {
                Some((path, _)) => path.clone(),
                None => self.record_path(&collection, &id)?,
            };
            changes.push(WorkingChange {
                status,
                collection,
                id,
                path,
                audited_hash,
                current_hash,
            });
        }
        Ok(changes)
    }

    /// A record's location relative to the database root.
    ///
    /// The path is never resolved here; every component is opened safely when
    /// the record is actually read or written.
    fn record_path(&self, collection: &str, id: &str) -> Result<PathBuf> {
        validate_component(collection, "collection")?;
        validate_component(id, "id")?;
        Ok(self
            .config
            .data_dir
            .join(collection)
            .join(format!("{id}.md")))
    }

    /// Read a record's exact bytes through verified path components,
    /// classifying a missing file as a typed not-found failure.
    fn read_record(&self, collection: &str, id: &str, path: &Path) -> Result<String> {
        paths::read_to_string(&self.root, path, &record_label(collection, id)).map_err(|error| {
            if is_missing(&error) {
                error.context(DomainError::record_not_found(collection, id))
            } else {
                error
            }
        })
    }

    fn read_document(&self, collection: &str, id: &str, path: &Path) -> Result<Document> {
        let input = self.read_record(collection, id, path)?;
        parse_record(collection, id, &input)
    }

    fn validate(&self, collection: &str, attributes: &Mapping) -> Result<()> {
        let schema_path = Path::new(SCHEMA_DIRECTORY).join(format!("{collection}.json"));
        let label = schema_label(collection);
        let Some(serialized) = paths::read_to_string_optional(&self.root, &schema_path, &label)?
        else {
            return Ok(());
        };

        let unusable = || {
            DomainError::Invalid(format!(
                "collection '{collection}' has an unusable JSON Schema"
            ))
        };
        let schema: serde_json::Value = serde_json::from_str(&serialized)
            .with_context(|| format!("{label} is not valid JSON"))
            .with_context(unusable)?;
        jsonschema::meta::validate(&schema)
            .map_err(|error| anyhow!("invalid JSON Schema for {label}: {error}"))
            .with_context(unusable)?;
        let validator = jsonschema::validator_for(&schema)
            .map_err(|error| anyhow!("could not compile {label}: {error}"))
            .with_context(unusable)?;
        let instance = serde_json::to_value(attributes)
            .context("front matter cannot be represented as JSON for schema validation")?;
        let errors: Vec<_> = validator
            .iter_errors(&instance)
            .map(|error| format!("- {error}"))
            .collect();

        if !errors.is_empty() {
            return Err(invalid(format!(
                "record does not match schema for collection '{collection}':\n{}",
                errors.join("\n")
            )));
        }

        Ok(())
    }

    fn record_files(&self) -> Result<Vec<(String, String, PathBuf)>> {
        let mut records = Vec::new();
        for collection_name in self.collection_names()? {
            let directory = self.config.data_dir.join(&collection_name);
            let label = collection_label(&collection_name);
            let entries =
                paths::list_directory(&self.root, &directory, &label)?.unwrap_or_default();
            for entry in entries {
                let name = Path::new(&entry.name);
                if name.extension().and_then(|value| value.to_str()) != Some("md") {
                    continue;
                }
                let id = name
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .context("record filename is not valid UTF-8")?
                    .to_owned();
                validate_component(&id, "id")?;
                if !entry.kind.is_file() {
                    return Err(paths::refuse_entry(
                        &record_label(&collection_name, &id),
                        entry.kind,
                    ));
                }
                records.push((collection_name.clone(), id, directory.join(&entry.name)));
            }
        }
        records.sort_by(|left, right| (&left.0, &left.1).cmp(&(&right.0, &right.1)));
        Ok(records)
    }

    fn collection_names(&self) -> Result<Vec<String>> {
        let Some(entries) =
            paths::list_directory(&self.root, &self.config.data_dir, RECORDS_LABEL)?
        else {
            return Ok(Vec::new());
        };

        let mut collections = Vec::new();
        for entry in entries {
            if !entry.kind.is_directory() {
                continue;
            }
            let name = entry
                .name
                .to_str()
                .context("collection filename is not valid UTF-8")?
                .to_owned();
            validate_component(&name, "collection")?;
            collections.push(name);
        }
        collections.sort();
        Ok(collections)
    }

    fn audit(&self) -> AuditLog<'_> {
        AuditLog::new(
            &self.root,
            &self.config.data_dir,
            self.config.audit.segment_max_events,
            self.config.audit.segment_max_bytes,
            &self.actor,
            &self.attribution,
        )
    }

    fn with_default_actor(mut self) -> Self {
        self.actor = default_actor(&self.root);
        self
    }
}

fn default_actor(root: &Path) -> String {
    nonempty_environment("CR_ACTOR")
        .or_else(|| {
            identity(
                nonempty_environment("CR_NAME"),
                nonempty_environment("CR_EMAIL"),
            )
        })
        .or_else(|| {
            identity(
                nonempty_environment("GIT_AUTHOR_NAME"),
                nonempty_environment("GIT_AUTHOR_EMAIL"),
            )
        })
        .or_else(|| git_identity(root))
        .or_else(|| nonempty_environment("EMAIL"))
        .or_else(|| nonempty_environment("USER"))
        .or_else(|| std::env::var("USERNAME").ok())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn nonempty_environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn identity(name: Option<String>, email: Option<String>) -> Option<String> {
    match (name, email) {
        (Some(name), Some(email)) => Some(format!("{name} <{email}>")),
        (None, Some(email)) => Some(email),
        _ => None,
    }
}

fn git_identity(root: &Path) -> Option<String> {
    let read = |key: &str| {
        Command::new("git")
            .args(["-C"])
            .arg(root)
            .args(["config", "--get", key])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    identity(read("user.name"), read("user.email"))
}

fn parse_reference(reference: &str) -> Result<(String, String)> {
    let (collection, id) = reference.split_once('/').with_context(|| {
        DomainError::Invalid(format!(
            "record reference '{reference}' must be COLLECTION/ID"
        ))
    })?;
    if id.contains('/') {
        return Err(invalid(format!(
            "record reference '{reference}' must contain exactly one '/'"
        )));
    }
    validate_component(collection, "collection")?;
    validate_component(id, "id")?;
    Ok((collection.to_owned(), id.to_owned()))
}

/// The mutation `update` applies: assignments over front matter, and an
/// optional whole-body replacement.
fn update_with<'a>(
    assignments: &'a [Assignment],
    body: Option<&'a str>,
) -> impl FnOnce(&mut Document) -> Result<()> + 'a {
    move |document| {
        apply_all(&mut document.attributes, assignments)?;
        if let Some(body) = body {
            document.body = body.to_owned();
        }
        Ok(())
    }
}

fn apply_all(attributes: &mut Mapping, assignments: &[Assignment]) -> Result<()> {
    for assignment in assignments {
        assignment.apply(attributes)?;
    }
    Ok(())
}

fn merge_mapping(target: &mut Mapping, patch: &Mapping) {
    for (key, value) in patch {
        match (target.get_mut(key), value) {
            (Some(Value::Mapping(target)), Value::Mapping(patch)) => merge_mapping(target, patch),
            _ => {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

fn mapping_field<'a>(attributes: &'a mut Mapping, field: &str) -> Result<&'a mut Mapping> {
    let key = Value::String(field.to_owned());
    if !attributes.contains_key(&key) {
        attributes.insert(key.clone(), Value::Mapping(Mapping::new()));
    }
    match attributes.get_mut(&key) {
        Some(Value::Mapping(mapping)) => Ok(mapping),
        _ => Err(invalid(format!(
            "field '{field}' must be an object to store relations"
        ))),
    }
}

fn sequence_field<'a>(mapping: &'a mut Mapping, field: &str) -> Result<&'a mut Vec<Value>> {
    let key = Value::String(field.to_owned());
    if !mapping.contains_key(&key) {
        mapping.insert(key.clone(), Value::Sequence(Vec::new()));
    }
    match mapping.get_mut(&key) {
        Some(Value::Sequence(sequence)) => Ok(sequence),
        _ => Err(invalid(format!("relation '{field}' must be a list"))),
    }
}

fn relation_value(collection: &str, id: &str) -> Value {
    let mut reference = Mapping::new();
    reference.insert("collection".into(), collection.into());
    reference.insert("id".into(), id.into());
    Value::Mapping(reference)
}

fn record_from_document(collection: &str, id: &str, path: PathBuf, document: Document) -> Record {
    Record {
        collection: collection.to_owned(),
        id: id.to_owned(),
        path,
        attributes: document.attributes,
        body: document.body,
    }
}

/// Parse a stored record, naming it by collection and ID rather than by path.
fn parse_record(collection: &str, id: &str, raw: &str) -> Result<Document> {
    Document::parse(raw)
        .with_context(|| DomainError::Invalid(format!("could not parse record {collection}/{id}")))
}

pub(crate) fn validate_component(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value == "." || value == ".." {
        return Err(invalid(format!(
            "{label} must be a non-empty path component"
        )));
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return Err(invalid(format!(
            "{label} '{value}' cannot contain path separators"
        )));
    }
    Ok(())
}

fn validate_relative_path(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("{label} must be a relative path without '.' or '..'");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_component, validate_relative_path};
    use std::path::Path;

    #[test]
    fn path_validation_blocks_traversal_but_allows_unicode() {
        assert!(validate_component("candidates", "collection").is_ok());
        assert!(validate_component("候補者", "collection").is_ok());
        assert!(validate_component("", "id").is_err());
        assert!(validate_component("..", "id").is_err());
        assert!(validate_component("../outside", "id").is_err());
        assert!(validate_component("nested/item", "id").is_err());

        assert!(validate_relative_path(Path::new("records"), "data_dir").is_ok());
        assert!(validate_relative_path(Path::new("data/records"), "data_dir").is_ok());
        assert!(validate_relative_path(Path::new("../records"), "data_dir").is_err());
        assert!(validate_relative_path(Path::new("/records"), "data_dir").is_err());
    }
}
