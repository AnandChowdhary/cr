use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sha2::{Digest, Sha256};
use yaml_serde::{Mapping, Value};

use crate::{
    AnchorReport, Assignment, AuditAction, AuditAnchor, AuditChange, AuditEntry, AuditHead,
    AuditSource, AuditVerification, SearchQuery,
    access::{
        AccessAction, AccessDecision, AccessIdentity, Resource as AccessResource, Role,
        USERS_COLLECTION, User, UserDeleteOptions, UserEnsureOutcome, UserKind,
        UserRegistrationOptions, UserStatus, UserUpdate, display_name, principal_id, users_schema,
    },
    attribution::{Attribution, AuditAgent, AuditAuthorization, AuditIntent},
    audit::{
        AuditEncryptionTransition, AuditFilter, AuditIdempotency, AuditIdempotencyResult, AuditLog,
        AuditMutation, ChangePreview, ReconciledMutation, record_hash,
    },
    check::{CheckReport, CheckScope},
    encryption::{
        CONTEXT_LABEL, CONTEXT_PATH, EncryptionContext, EncryptionPolicy,
        EncryptionStorageMetadata, audit_document_encryption_metadata,
        document_has_encrypted_storage,
    },
    error::{
        DomainError, conflict, forbidden, invalid, is_already_exists, is_missing,
        precondition_failed,
    },
    frontmatter::Document,
    paths,
    sync::{SYNC_DEFINITION_DIRECTORY, SYNC_LOCK_DIRECTORY, SYNC_STATE_DIRECTORY},
    value::{canonical_yaml_value, compare_yaml_values, get_path, parse_path, remove_path},
    views::VIEW_DIRECTORY,
};

const CONFIG_PATH: &str = ".cr/config.yaml";
const DATABASE_DIRECTORY: &str = ".cr";
pub(crate) const SCHEMA_DIRECTORY: &str = ".cr/schemas";
const CURRENT_FORMAT_VERSION: u32 = 1;
const IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] = b"cr:idempotency:key:v1\0";
const IDEMPOTENCY_REQUEST_HASH_DOMAIN: &[u8] = b"cr:idempotency:request:v2\0";
const MIN_IDEMPOTENCY_KEY_BYTES: usize = 16;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

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

/// A validated, scoped request whose success may be replayed from the audit
/// journal. This is constructed before locking, but looked up and committed
/// only while the audit lock is held.
#[derive(Clone, Debug)]
struct IdempotencyRequest {
    operation: &'static str,
    collection: String,
    id: String,
    key_hash: String,
    request_hash: String,
}

#[derive(Clone, Debug)]
struct AccessRequest {
    action: AccessAction,
    resource: AccessResource,
    owner_only: bool,
    user_fields: bool,
    user_name: bool,
}

struct CreateRequest {
    mode: MutationMode,
    access: Option<AccessRequest>,
    reuse_deleted_user_id: bool,
    expected_audit_sequence: Option<u64>,
    idempotency: Option<IdempotencyRequest>,
}

impl CreateRequest {
    fn new(mode: MutationMode, access: Option<AccessRequest>) -> Self {
        Self {
            mode,
            access,
            reuse_deleted_user_id: false,
            expected_audit_sequence: None,
            idempotency: None,
        }
    }

    fn user_registration(access: AccessRequest, options: UserRegistrationOptions) -> Self {
        Self {
            mode: MutationMode::Apply,
            access: Some(access),
            reuse_deleted_user_id: options.reuse_deleted_id,
            expected_audit_sequence: None,
            idempotency: None,
        }
    }

    fn at_audit_sequence(mut self, sequence: u64) -> Self {
        self.expected_audit_sequence = Some(sequence);
        self
    }

    fn with_idempotency(mut self, idempotency: Option<IdempotencyRequest>) -> Self {
        self.idempotency = idempotency;
        self
    }
}

impl AccessRequest {
    fn new(action: AccessAction, resource: AccessResource) -> Self {
        Self {
            action,
            resource,
            owner_only: false,
            user_fields: false,
            user_name: false,
        }
    }

    fn owner(resource: AccessResource) -> Self {
        Self {
            action: AccessAction::ManageAccess,
            resource,
            owner_only: true,
            user_fields: false,
            user_name: false,
        }
    }

    fn user_fields(id: &str, user_name: bool) -> Self {
        Self {
            action: AccessAction::Update,
            resource: AccessResource::record(USERS_COLLECTION, id),
            owner_only: false,
            user_fields: true,
            user_name,
        }
    }
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
    principal: String,
    impersonated_by: Option<AccessIdentity>,
    source: AuditSource,
    audit_message: Option<String>,
    attribution: Attribution,
    idempotency_key: Option<String>,
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
    /// `sha256:` plus SHA-256 of `b"cr:record:v1\0" || stored_markdown_bytes`.
    ///
    /// The domain prefix keeps record digests distinct from audit event and
    /// change-set digests. This is the authoritative record version used by
    /// conditional writes and emitted as a strong HTTP ETag.
    pub version: String,
    pub attributes: Mapping,
    pub body: String,
}

/// A condition that an existing record must satisfy before it is mutated.
///
/// The comparison is performed only after the mutation has acquired the
/// database-wide audit lock and read the current bytes. A list represents the
/// strong validators in an HTTP `If-Match` field; [`Self::any_current`] builds
/// its `*` form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPrecondition {
    versions: Option<Vec<String>>,
    expected_audit_sequence: Option<u64>,
}

impl RecordPrecondition {
    /// Require one exact record hash, as used by the CLI.
    pub fn version(version: impl Into<String>) -> Result<Self> {
        let version = version.into();
        validate_record_version(&version)?;
        Ok(Self {
            versions: Some(vec![version]),
            expected_audit_sequence: None,
        })
    }

    /// Require any one of several exact record hashes, as used by `If-Match`.
    pub fn versions(versions: impl IntoIterator<Item = String>) -> Result<Self> {
        let versions = versions.into_iter().collect::<Vec<_>>();
        for version in &versions {
            validate_record_version(version)?;
        }
        Ok(Self {
            versions: Some(versions),
            expected_audit_sequence: None,
        })
    }

    /// Require that the mutation target currently exists, as for `If-Match: *`.
    pub fn any_current() -> Self {
        Self {
            versions: None,
            expected_audit_sequence: None,
        }
    }

    /// Bind an internal sync condition to the complete audit generation.
    ///
    /// Record hashes deliberately identify bytes, so an edit followed by an
    /// exact restoration is the same public ETag. Sync additionally needs to
    /// know that no audited writer ran after its head-bound snapshot.
    pub(crate) fn at_audit_sequence(mut self, sequence: u64) -> Self {
        self.expected_audit_sequence = Some(sequence);
        self
    }

    fn assert_audit_sequence(&self, audit: &AuditLog<'_>) -> Result<()> {
        if let Some(expected) = self.expected_audit_sequence {
            assert_audit_sequence(audit, expected)?;
        }
        Ok(())
    }

    fn assert_matches(&self, collection: &str, id: &str, current: &str) -> Result<()> {
        if self
            .versions
            .as_ref()
            .is_none_or(|versions| versions.iter().any(|version| version == current))
        {
            return Ok(());
        }
        Err(precondition_failed(format!(
            "record {collection}/{id} changed since the expected version"
        )))
    }

    fn idempotency_value(&self) -> JsonValue {
        let versions = self.versions.as_ref().map(|versions| {
            let mut versions = versions.clone();
            versions.sort();
            versions.dedup();
            versions
        });
        json!({
            "versions": versions,
            "expected_audit_sequence": self.expected_audit_sequence,
        })
    }
}

fn assert_audit_sequence(audit: &AuditLog<'_>, expected: u64) -> Result<()> {
    if audit.head()?.sequence == expected {
        return Ok(());
    }
    Err(precondition_failed(
        "database changed since the expected audit generation",
    ))
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

        let encryption_context = EncryptionContext::generate()?;
        paths::write_new(
            &root,
            Path::new(CONTEXT_PATH),
            &encryption_context.render()?,
            CONTEXT_LABEL,
        )?;

        let database = Self {
            root,
            config: Config::default(),
            actor: String::new(),
            principal: String::new(),
            impersonated_by: None,
            source: AuditSource::Cli,
            audit_message: None,
            attribution: Attribution::from_environment()?,
            idempotency_key: None,
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
            principal: String::new(),
            impersonated_by: None,
            source: AuditSource::Cli,
            audit_message: None,
            attribution: Attribution::from_environment()?,
            idempotency_key: None,
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

    /// The configured records directory, relative to the root.
    pub(crate) fn records_dir(&self) -> &Path {
        &self.config.data_dir
    }

    /// Report every integrity problem in the database without changing it.
    ///
    /// The whole implementation lives in [`crate::check`]; this is the seam
    /// that gives it the root, the records directory, and the audit log.
    pub fn check(&self, scope: &CheckScope) -> Result<CheckReport> {
        self.authorize_owner(&AccessResource::Database)?;
        crate::check::run(self, scope)
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Stable policy identity derived from the audit actor.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// The owner operating this perspective, when the server is impersonating
    /// another registered principal.
    pub fn impersonated_by(&self) -> Option<&AccessIdentity> {
        self.impersonated_by.as_ref()
    }

    pub fn with_actor(mut self, actor: impl Into<String>) -> Result<Self> {
        let actor = actor.into();
        if actor.trim().is_empty() {
            return Err(invalid("audit actor cannot be empty"));
        }
        let principal = principal_id(&actor)?;
        if self.access_enabled()? && principal != self.principal {
            return Err(forbidden(format!(
                "access control is enabled, so --actor cannot impersonate principal '{principal}'"
            )));
        }
        self.actor = actor;
        self.principal = principal;
        self.impersonated_by = None;
        Ok(self)
    }

    /// Evaluate subsequent operations as another registered user while
    /// retaining the launching owner as explicit audit evidence.
    pub fn impersonate(&self, principal: &str) -> Result<Self> {
        if !self.access_enabled()? {
            return Err(conflict("access control is not initialized"));
        }
        self.authorize_owner(&AccessResource::Database)?;
        let canonical = principal_id(principal)?;
        if canonical != principal {
            return Err(invalid(format!(
                "principal '{principal}' is not canonical; use '{canonical}'"
            )));
        }
        let Some((user, _)) = self.user_unchecked_optional(principal)? else {
            return Err(DomainError::record_not_found(USERS_COLLECTION, principal).into());
        };
        if principal == self.principal {
            let mut database = self.clone();
            database.impersonated_by = None;
            return Ok(database);
        }

        let mut database = self.clone();
        database.impersonated_by = Some(AccessIdentity {
            principal: self.principal.clone(),
            display: self.actor.clone(),
        });
        database.principal = principal.to_owned();
        database.actor = format!(
            "{} <{}>",
            user.name,
            user.email.as_deref().unwrap_or(principal)
        );
        Ok(database)
    }

    /// Evaluate a delegated CLI command as another registered principal after
    /// proving the launching owner's policy still matches its audited state.
    ///
    /// The server perspective console validates its owner at startup and calls
    /// [`Self::impersonate`] for each request. A standalone CLI invocation has
    /// no such long-lived boundary, so it must pin the policy at delegation
    /// time or a manually edited access-manager record could promote itself
    /// just long enough to select an owner perspective.
    pub fn impersonate_verified(&self, principal: &str) -> Result<Self> {
        if !self.access_enabled()? {
            return Err(conflict("access control is not initialized"));
        }
        let canonical = principal_id(principal)?;
        if canonical != principal {
            return Err(invalid(format!(
                "principal '{principal}' is not canonical; use '{canonical}'"
            )));
        }

        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        let states = audit.record_states()?;

        // Validate and authorize the operator before looking up the target.
        // This keeps missing and drifted target identities private from callers
        // who are not allowed to delegate in the first place.
        let operator_path = self.record_path(USERS_COLLECTION, &self.principal)?;
        let operator_raw = self.read_record(USERS_COLLECTION, &self.principal, &operator_path)?;
        AuditLog::assert_current_in(
            &states,
            USERS_COLLECTION,
            &self.principal,
            operator_raw.as_bytes(),
        )?;
        let operator_document = parse_record(USERS_COLLECTION, &self.principal, &operator_raw)?;
        let operator = User::from_attributes(&operator_document.attributes)?;
        let operator_hash = record_hash(operator_raw.as_bytes());
        let owner = operator.decision(
            &self.principal,
            &self.actor,
            AccessAction::ManageAccess,
            &AccessResource::Database,
            &operator_hash,
        );
        if !owner.is_some_and(|decision| decision.role == Role::Owner) {
            return Err(forbidden(format!(
                "principal '{}' must be an owner of database",
                self.principal
            )));
        }

        if principal == self.principal {
            let mut database = self.clone();
            database.impersonated_by = None;
            return Ok(database);
        }

        let target_path = self.record_path(USERS_COLLECTION, principal)?;
        let target_raw = self.read_record(USERS_COLLECTION, principal, &target_path)?;
        AuditLog::assert_current_in(&states, USERS_COLLECTION, principal, target_raw.as_bytes())?;
        let target_document = parse_record(USERS_COLLECTION, principal, &target_raw)?;
        let target = User::from_attributes(&target_document.attributes)?;

        let mut database = self.clone();
        database.impersonated_by = Some(AccessIdentity {
            principal: self.principal.clone(),
            display: self.actor.clone(),
        });
        database.principal = principal.to_owned();
        database.actor = format!(
            "{} <{}>",
            target.name,
            target.email.as_deref().unwrap_or(principal)
        );
        Ok(database)
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

    /// Attach a retry key to the next supported single-record mutation.
    ///
    /// Keys are bounded visible ASCII so the CLI and HTTP header share one
    /// portable contract. Only a domain-separated hash is written to history.
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Result<Self> {
        let key = key.into();
        validate_idempotency_key(&key)?;
        self.idempotency_key = Some(key);
        Ok(self)
    }

    /// Clear a caller retry identity before entering a multi-record internal
    /// workflow. Sync has its own durable run ledger and must never consume a
    /// key attached to the `Database` handle that invoked it.
    pub(crate) fn without_idempotency_key(mut self) -> Self {
        self.idempotency_key = None;
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

    fn idempotency_request(
        &self,
        operation: &'static str,
        collection: &str,
        id: &str,
        input: impl FnOnce() -> Result<JsonValue>,
    ) -> Result<Option<IdempotencyRequest>> {
        let Some(key) = self.idempotency_key.as_deref() else {
            return Ok(None);
        };
        let input = input()?;
        let envelope = json!({
            "version": 1,
            "operation": operation,
            "record": { "collection": collection, "id": id },
            "input": input,
            "actor": self.actor,
            "source": self.source,
            "message": self.audit_message,
            "agent": self.attribution.agent,
            "authorization": self.attribution.authorization,
            "intent": self.attribution.intent,
            "impersonated_by": self.impersonated_by,
        });
        let serialized =
            serde_json::to_vec(&envelope).context("could not serialize idempotency request")?;
        Ok(Some(IdempotencyRequest {
            operation,
            collection: collection.to_owned(),
            id: id.to_owned(),
            key_hash: idempotency_digest(IDEMPOTENCY_KEY_HASH_DOMAIN, key.as_bytes()),
            request_hash: idempotency_request_digest(key.as_bytes(), &serialized),
        }))
    }

    fn replay_idempotent_record(
        &self,
        audit: &AuditLog<'_>,
        request: Option<&IdempotencyRequest>,
    ) -> Result<Option<Record>> {
        let Some(request) = request else {
            return Ok(None);
        };
        let Some(value) = audit.idempotency_result(
            &self.principal,
            request.operation,
            &request.collection,
            &request.id,
            &request.key_hash,
            &request.request_hash,
        )?
        else {
            return Ok(None);
        };
        let result = value;
        validate_record_version(&result.version)
            .context("the committed idempotency result has an invalid version")?;
        let stored = Document::parse(&result.markdown)
            .context("the committed idempotency result is not valid Markdown")?;
        let document = self.reveal_document(&request.collection, &request.id, &stored)?;
        Ok(Some(record_from_document(
            &request.collection,
            &request.id,
            result.path,
            document,
            result.version,
        )))
    }

    fn audit_idempotency(
        &self,
        request: Option<&IdempotencyRequest>,
        record: &Record,
        markdown: &str,
    ) -> Result<Option<AuditIdempotency>> {
        request
            .map(|request| {
                Ok(AuditIdempotency {
                    principal: self.principal.clone(),
                    operation: request.operation.to_owned(),
                    key_hash: request.key_hash.clone(),
                    request_hash: request.request_hash.clone(),
                    result: AuditIdempotencyResult {
                        path: record.path.clone(),
                        version: record.version.clone(),
                        markdown: markdown.to_owned(),
                    },
                })
            })
            .transpose()
    }

    /// Whether the reserved users collection has bootstrapped access control.
    ///
    /// Existing databases remain open until the first user record is created
    /// by `cr access init`. An empty directory is not enough to enable RBAC,
    /// which keeps an interrupted bootstrap recoverable.
    pub fn access_enabled(&self) -> Result<bool> {
        let directory = self.config.data_dir.join(USERS_COLLECTION);
        let Some(entries) = paths::list_directory(&self.root, &directory, "the users collection")?
        else {
            return Ok(false);
        };
        Ok(entries.into_iter().any(|entry| {
            entry.kind.is_file()
                && Path::new(&entry.name)
                    .extension()
                    .and_then(|value| value.to_str())
                    == Some("md")
        }))
    }

    /// The current principal's fixed-schema user record.
    pub fn current_user(&self) -> Result<Option<User>> {
        if !self.access_enabled()? {
            return Ok(None);
        }
        self.user_unchecked_optional(&self.principal)
            .map(|user| user.map(|(user, _)| user))
    }

    /// Evaluate the current principal without performing an operation.
    pub fn access_check(
        &self,
        action: AccessAction,
        resource: &AccessResource,
    ) -> Result<Option<AccessDecision>> {
        self.authorize(action, resource)
    }

    /// Whether an operation would be permitted, without performing it.
    pub fn access_allowed(&self, action: AccessAction, resource: &AccessResource) -> Result<bool> {
        self.can_access(action, resource)
    }

    /// Whether the current principal owns the resource, without performing an
    /// operation.
    pub fn owner_access_allowed(&self, resource: &AccessResource) -> Result<bool> {
        if !self.access_enabled()? {
            return Ok(true);
        }
        match self.authorize(AccessAction::ManageAccess, resource) {
            Ok(Some(decision)) => Ok(decision.role == Role::Owner),
            Ok(None) => Ok(true),
            Err(error) if matches!(DomainError::of(&error), Some(DomainError::Forbidden(_))) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn authorize(
        &self,
        action: AccessAction,
        resource: &AccessResource,
    ) -> Result<Option<AccessDecision>> {
        if !self.access_enabled()? {
            return Ok(None);
        }
        let Some((mut user, policy_hash)) = self.user_unchecked_optional(&self.principal)? else {
            return Err(forbidden(format!(
                "principal '{}' is not registered in the users collection",
                self.principal
            )));
        };
        if user.access.iter().any(|grant| &grant.resource == resource)
            && let AccessResource::Record { collection, id } = resource
            && collection == USERS_COLLECTION
            && !self.user_record_exists_unchecked(id)?
        {
            // A record-scoped grant to a deleted principal must not keep
            // authorizing a resource that no longer exists. Broader grants
            // still evaluate normally, and explicit ID reuse is the boundary
            // at which this resource can exist again.
            user.access.retain(|grant| &grant.resource != resource);
        }
        user.decision(&self.principal, &self.actor, action, resource, &policy_hash)
            .map(|mut decision| {
                decision.impersonated_by = self.impersonated_by.clone();
                decision
            })
            .map(Some)
            .ok_or_else(|| {
                forbidden(format!(
                    "principal '{}' cannot {action} {resource}",
                    self.principal
                ))
            })
    }

    /// Whether a user record has a materialized file, without parsing or
    /// otherwise revealing its contents before authorization succeeds.
    fn user_record_exists_unchecked(&self, id: &str) -> Result<bool> {
        let path = self.record_path(USERS_COLLECTION, id)?;
        Ok(paths::entry_kind(&self.root, &path, &record_label(USERS_COLLECTION, id))?.is_some())
    }

    /// Authorize an ordinary user-field update, including the built-in rule
    /// that lets an active principal maintain its own name and profile.
    fn authorize_user_field_update(&self, id: &str) -> Result<Option<AccessDecision>> {
        if !self.access_enabled()? {
            return Ok(None);
        }
        let resource = AccessResource::record(USERS_COLLECTION, id);
        if id != self.principal {
            return self.authorize(AccessAction::Update, &resource);
        }
        let Some((user, policy_hash)) = self.user_unchecked_optional(&self.principal)? else {
            return Err(forbidden(format!(
                "principal '{}' is not registered in the users collection",
                self.principal
            )));
        };
        if user.status != UserStatus::Active {
            return Err(forbidden(format!(
                "principal '{}' is not active",
                self.principal
            )));
        }
        let mut decision =
            AccessDecision::self_service(&self.principal, &self.actor, resource, &policy_hash);
        decision.impersonated_by = self.impersonated_by.clone();
        Ok(Some(decision))
    }

    fn can_access(&self, action: AccessAction, resource: &AccessResource) -> Result<bool> {
        match self.authorize(action, resource) {
            Ok(_) => Ok(true),
            Err(error) if matches!(DomainError::of(&error), Some(DomainError::Forbidden(_))) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn authorize_owner(
        &self,
        resource: &AccessResource,
    ) -> Result<Option<AccessDecision>> {
        let decision = self.authorize(AccessAction::ManageAccess, resource)?;
        if self.access_enabled()?
            && decision
                .as_ref()
                .is_some_and(|decision| decision.role != Role::Owner)
        {
            return Err(forbidden(format!(
                "principal '{}' must be an owner of {resource}",
                self.principal
            )));
        }
        Ok(decision)
    }

    fn user_unchecked_optional(&self, id: &str) -> Result<Option<(User, String)>> {
        let path = self.record_path(USERS_COLLECTION, id)?;
        if paths::entry_kind(&self.root, &path, &record_label(USERS_COLLECTION, id))?.is_none() {
            return Ok(None);
        }
        let raw = self.read_record(USERS_COLLECTION, id, &path)?;
        let document = parse_record(USERS_COLLECTION, id, &raw)?;
        let user = User::from_attributes(&document.attributes)?;
        Ok(Some((user, record_hash(raw.as_bytes()))))
    }

    /// Pin one security-sensitive operation to the current principal's
    /// audited policy before any permission from the working file is trusted.
    ///
    /// This is intentionally done once at the mutation boundary instead of in
    /// `authorize`: list/search may authorize thousands of records, and
    /// replaying the audit chain for every one would make them quadratic.
    fn assert_current_principal_policy(&self, audit: &AuditLog<'_>) -> Result<()> {
        if !self.access_enabled()? {
            return Ok(());
        }
        self.assert_current_user_policy(audit, &self.principal)
    }

    fn assert_current_user_policy(&self, audit: &AuditLog<'_>, principal: &str) -> Result<()> {
        let path = self.record_path(USERS_COLLECTION, principal)?;
        let raw = self.read_record(USERS_COLLECTION, principal, &path)?;
        audit.assert_current(USERS_COLLECTION, principal, raw.as_bytes())
    }

    /// Bootstrap RBAC by creating the current principal as database owner.
    pub fn initialize_access(&self, name: Option<&str>, email: Option<&str>) -> Result<Record> {
        self.initialize_access_with_kind(name, email, UserKind::Human)
    }

    /// Bootstrap RBAC with an explicitly typed owner principal.
    ///
    /// The original two-argument API remains a human-defaulting wrapper for
    /// compatibility; unattended deployments can select `Service` here.
    pub fn initialize_access_with_kind(
        &self,
        name: Option<&str>,
        email: Option<&str>,
        kind: UserKind,
    ) -> Result<Record> {
        if self.access_enabled()? {
            return Err(conflict("access control is already initialized"));
        }
        if self.principal == "unknown" {
            return Err(invalid(
                "set CR_EMAIL, CR_ACTOR, or Git user.email before initializing access control",
            ));
        }
        let user = User {
            name: name
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| display_name(&self.actor)),
            email: email
                .map(str::to_owned)
                .or_else(|| self.principal.contains('@').then(|| self.principal.clone())),
            kind,
            status: UserStatus::Active,
            profile: Mapping::new(),
            access: vec![crate::AccessGrant {
                resource: AccessResource::Database,
                role: Role::Owner,
            }],
        };
        self.run_create(
            USERS_COLLECTION,
            &self.principal,
            user.attributes()?,
            "",
            CreateRequest::new(MutationMode::Apply, None),
        )?
        .record()
    }

    /// Register a principal without granting it access to any resource.
    pub fn add_user(
        &self,
        id: &str,
        name: &str,
        email: Option<&str>,
        kind: UserKind,
    ) -> Result<Record> {
        self.add_user_with_profile(id, name, email, kind, Mapping::new())
    }

    /// Register a principal with application-owned namespaced metadata.
    pub fn add_user_with_profile(
        &self,
        id: &str,
        name: &str,
        email: Option<&str>,
        kind: UserKind,
        profile: Mapping,
    ) -> Result<Record> {
        self.add_user_with_options(
            id,
            name,
            email,
            kind,
            profile,
            UserRegistrationOptions::default(),
        )
    }

    /// Register a principal with explicit lifecycle options.
    pub fn add_user_with_options(
        &self,
        id: &str,
        name: &str,
        email: Option<&str>,
        kind: UserKind,
        profile: Mapping,
        options: UserRegistrationOptions,
    ) -> Result<Record> {
        if !self.access_enabled()? {
            return Err(conflict(
                "access control is not initialized; run 'cr access init' first",
            ));
        }
        validate_component(id, "user")?;
        let canonical = principal_id(id)?;
        if canonical != id {
            return Err(invalid(format!(
                "user ID '{id}' is not canonical; use '{canonical}'"
            )));
        }
        let user = User {
            name: name.to_owned(),
            email: email.map(str::to_owned),
            kind,
            status: UserStatus::Active,
            profile,
            access: Vec::new(),
        };
        self.run_create(
            USERS_COLLECTION,
            id,
            user.attributes()?,
            "",
            CreateRequest::user_registration(
                AccessRequest::new(AccessAction::ManageAccess, AccessResource::Database),
                options,
            ),
        )?
        .record()
    }

    /// Declaratively ensure a principal's non-access definition.
    ///
    /// Existing grants are deliberately ignored: access remains managed by
    /// `grant_access`/`revoke_access`. Every requested identity/profile field
    /// must match, however, so bootstrap code cannot silently accept drift.
    /// The absence check and create are performed under the audit lock, making
    /// concurrent daemon starts converge on one creation and one no-op.
    pub fn ensure_user(
        &self,
        id: &str,
        name: &str,
        email: Option<&str>,
        kind: UserKind,
        profile: Mapping,
    ) -> Result<UserEnsureOutcome> {
        self.ensure_user_with_options(
            id,
            name,
            email,
            kind,
            profile,
            UserRegistrationOptions::default(),
        )
    }

    /// Declaratively ensure a principal with explicit lifecycle options.
    pub fn ensure_user_with_options(
        &self,
        id: &str,
        name: &str,
        email: Option<&str>,
        kind: UserKind,
        profile: Mapping,
        options: UserRegistrationOptions,
    ) -> Result<UserEnsureOutcome> {
        if !self.access_enabled()? {
            return Err(conflict(
                "access control is not initialized; run 'cr access init' first",
            ));
        }
        validate_component(id, "user")?;
        let canonical = principal_id(id)?;
        if canonical != id {
            return Err(invalid(format!(
                "user ID '{id}' is not canonical; use '{canonical}'"
            )));
        }
        let requested = User {
            name: name.to_owned(),
            email: email.map(str::to_owned),
            kind,
            status: UserStatus::Active,
            profile,
            access: Vec::new(),
        };
        let attributes = requested.attributes()?;
        let requested = User::from_attributes(&attributes)?;
        self.validate(USERS_COLLECTION, &attributes)?;

        let path = self.record_path(USERS_COLLECTION, id)?;
        let label = record_label(USERS_COLLECTION, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.assert_current_principal_policy(&audit)?;
        let decision = self.authorize(AccessAction::ManageAccess, &AccessResource::Database)?;

        if paths::entry_kind(&self.root, &path, &label)?.is_some() {
            let raw = self.read_record(USERS_COLLECTION, id, &path)?;
            audit.assert_current(USERS_COLLECTION, id, raw.as_bytes())?;
            let document = parse_record(USERS_COLLECTION, id, &raw)?;
            let existing = User::from_attributes(&document.attributes)?;
            if existing.name == requested.name
                && existing.email == requested.email
                && existing.kind == requested.kind
                && existing.status == requested.status
                && existing.profile == requested.profile
            {
                return Ok(UserEnsureOutcome::Unchanged);
            }
            return Err(conflict(format!(
                "user '{id}' exists but does not match the requested definition"
            )));
        }
        if audit.record_is_tombstoned(USERS_COLLECTION, id)? {
            if !options.reuse_deleted_id {
                return Err(user_id_tombstoned(id));
            }
            self.authorize_owner(&AccessResource::Database)?;
        }

        let document = Document {
            attributes,
            body: String::new(),
        };
        let rendered = document.render()?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Create,
            collection: USERS_COLLECTION,
            id,
            before_document: None,
            after_document: Some(&document),
            before_bytes: None,
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: None,
        })?;
        audit.commit(event, &path, || {
            paths::write_new(&self.root, &path, rendered.as_bytes(), &label).map_err(|error| {
                if is_already_exists(&error) {
                    error.context(DomainError::record_exists(USERS_COLLECTION, id))
                } else {
                    error
                }
            })
        })?;
        Ok(UserEnsureOutcome::Created)
    }

    /// Update the non-access portion of a registered principal.
    ///
    /// Managed identity fields require a database owner, and disabling the
    /// final active database owner is refused. Profile-only updates follow
    /// ordinary editor grants, while active principals may maintain their own
    /// name and profile. The stable user ID is never renamed when `email`
    /// changes.
    pub fn update_user(&self, id: &str, update: UserUpdate) -> Result<Record> {
        if update.is_empty() {
            return Err(invalid("user update must change at least one field"));
        }
        validate_component(id, "user")?;
        let canonical = principal_id(id)?;
        if canonical != id {
            return Err(invalid(format!(
                "user ID '{id}' is not canonical; use '{canonical}'"
            )));
        }

        let path = self.record_path(USERS_COLLECTION, id)?;
        let label = record_label(USERS_COLLECTION, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.assert_current_principal_policy(&audit)?;
        let decision =
            if (id == self.principal && update.is_self_service()) || update.is_profile_only() {
                self.authorize_user_field_update(id)?
            } else {
                self.authorize_owner(&AccessResource::Database)?
            };

        let before_raw = self.read_record(USERS_COLLECTION, id, &path)?;
        audit.assert_current(USERS_COLLECTION, id, before_raw.as_bytes())?;
        let before = parse_record(USERS_COLLECTION, id, &before_raw)?;
        let before_user = User::from_attributes(&before.attributes)?;

        let mut after_user = before_user.clone();
        update.apply(&mut after_user)?;
        after_user.validate()?;
        if before_user.status == UserStatus::Active
            && before_user.is_database_owner()
            && after_user.status != UserStatus::Active
            && !self.has_database_owner_other_than(id)?
        {
            return Err(conflict("cannot disable the final database owner"));
        }
        if after_user == before_user {
            return Err(conflict(format!(
                "user '{id}' already has the requested values"
            )));
        }

        let after = Document {
            attributes: after_user.attributes()?,
            body: before.body.clone(),
        };
        self.validate(USERS_COLLECTION, &after.attributes)?;
        let rendered = after.render()?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Update,
            collection: USERS_COLLECTION,
            id,
            before_document: Some(&before),
            after_document: Some(&after),
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: None,
        })?;
        audit.commit(event, &path, || {
            paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)
        })?;
        Ok(record_from_document(
            USERS_COLLECTION,
            id,
            path,
            after,
            record_hash(rendered.as_bytes()),
        ))
    }

    /// Restore a manually drifted user file to the exact latest audited bytes.
    ///
    /// Authorization is evaluated from the replayed journal, never from the
    /// potentially edited current policy. No audit event is appended because
    /// this operation changes no audited state; it only rematerializes it.
    pub fn restore_user(&self, id: &str) -> Result<Record> {
        validate_component(id, "user")?;
        let canonical = principal_id(id)?;
        if canonical != id {
            return Err(invalid(format!(
                "user ID '{id}' is not canonical; use '{canonical}'"
            )));
        }

        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        let states = audit.record_states()?;
        let principal_state = states
            .get(&(USERS_COLLECTION.to_owned(), self.principal.clone()))
            .and_then(|state| state.document.as_ref().zip(state.hash.as_deref()))
            .ok_or_else(|| {
                forbidden(format!(
                    "principal '{}' has no active audited user policy",
                    self.principal
                ))
            })?;
        let principal_document = Document::from_audit_value(principal_state.0)?;
        let principal_user = User::from_attributes(&principal_document.attributes)?;
        principal_user
            .decision(
                &self.principal,
                &self.actor,
                AccessAction::ManageAccess,
                &AccessResource::Database,
                principal_state.1,
            )
            .filter(|decision| decision.role == Role::Owner)
            .ok_or_else(|| {
                forbidden(format!(
                    "principal '{}' must be an owner of database",
                    self.principal
                ))
            })?;

        let state = states
            .get(&(USERS_COLLECTION.to_owned(), id.to_owned()))
            .and_then(|state| state.document.as_ref().zip(state.hash.as_deref()))
            .ok_or_else(|| DomainError::record_not_found(USERS_COLLECTION, id))?;
        let audited_document = Document::from_audit_value(state.0)?;
        let audited_user = User::from_attributes(&audited_document.attributes)?;
        // Re-serialize through the fixed User schema. Audit JSON orders object
        // fields independently of the YAML struct, while managed user records
        // have always used the struct's canonical field order.
        let document = Document {
            attributes: audited_user.attributes()?,
            body: audited_document.body,
        };
        let rendered = document.render()?;
        if record_hash(rendered.as_bytes()) != state.1 {
            return Err(conflict(format!(
                "record users/{id} cannot be reconstructed byte-for-byte from its audit history"
            )));
        }

        let path = self.record_path(USERS_COLLECTION, id)?;
        let label = record_label(USERS_COLLECTION, id);
        match paths::entry_kind(&self.root, &path, &label)? {
            Some(_) => paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)?,
            None => paths::write_new(&self.root, &path, rendered.as_bytes(), &label)?,
        }
        let restored = self.read_record(USERS_COLLECTION, id, &path)?;
        if record_hash(restored.as_bytes()) != state.1 {
            bail!("restoring record users/{id} did not reproduce its audited state");
        }
        Ok(record_from_document(
            USERS_COLLECTION,
            id,
            path,
            document,
            record_hash(rendered.as_bytes()),
        ))
    }

    /// Read one registered user. Everyone may inspect their own effective
    /// policy; inspecting another principal requires access management.
    pub fn user(&self, id: &str) -> Result<User> {
        if !self.access_enabled()? {
            return Err(conflict("access control is not initialized"));
        }
        if id != self.principal {
            self.authorize(AccessAction::ReadAccess, &AccessResource::Database)?;
        }
        self.user_unchecked_optional(id)?
            .map(|(user, _)| user)
            .ok_or_else(|| DomainError::record_not_found(USERS_COLLECTION, id).into())
    }

    /// List the user registry for owners and access managers.
    pub fn users(&self) -> Result<Vec<(String, User)>> {
        self.authorize(AccessAction::ReadAccess, &AccessResource::Database)?;
        let mut users = Vec::new();
        for id in self.user_ids_unchecked()? {
            let Some((user, _)) = self.user_unchecked_optional(&id)? else {
                continue;
            };
            users.push((id, user));
        }
        Ok(users)
    }

    /// Create or replace the target user's role at one resource.
    pub fn grant_access(&self, id: &str, resource: AccessResource, role: Role) -> Result<Record> {
        if self.user_unchecked_optional(id)?.is_none() {
            return Err(DomainError::record_not_found(USERS_COLLECTION, id).into());
        }
        let access = if matches!(role, Role::Owner | Role::AccessManager) {
            self.authorize_owner(&resource)?;
            AccessRequest::owner(resource.clone())
        } else {
            AccessRequest::new(AccessAction::ManageAccess, resource.clone())
        };
        self.run_update(
            USERS_COLLECTION,
            id,
            move |document| {
                let mut user = User::from_attributes(&document.attributes)?;
                user.grant(resource, role);
                document.attributes = user.attributes()?;
                Ok(())
            },
            MutationMode::Apply,
            access,
            None,
            None,
        )?
        .record()
    }

    /// Remove the target user's role at one resource.
    pub fn revoke_access(&self, id: &str, resource: &AccessResource) -> Result<Record> {
        let Some((existing, _)) = self.user_unchecked_optional(id)? else {
            return Err(DomainError::record_not_found(USERS_COLLECTION, id).into());
        };
        let existing_role = existing
            .access
            .iter()
            .find(|grant| &grant.resource == resource)
            .map(|grant| grant.role)
            .ok_or_else(|| conflict(format!("user '{id}' has no direct role at {resource}")))?;
        let access = if matches!(existing_role, Role::Owner | Role::AccessManager) {
            self.authorize_owner(resource)?;
            AccessRequest::owner(resource.clone())
        } else {
            AccessRequest::new(AccessAction::ManageAccess, resource.clone())
        };
        let removing_database_owner =
            resource == &AccessResource::Database && existing_role == Role::Owner;
        let resource = resource.clone();
        self.run_update(
            USERS_COLLECTION,
            id,
            move |document| {
                if removing_database_owner && !self.has_database_owner_other_than(id)? {
                    return Err(conflict("cannot remove the final database owner"));
                }
                let mut user = User::from_attributes(&document.attributes)?;
                if !user.revoke(&resource) {
                    return Err(conflict(format!(
                        "user '{id}' has no direct role at {resource}"
                    )));
                }
                document.attributes = user.attributes()?;
                Ok(())
            },
            MutationMode::Apply,
            access,
            None,
            None,
        )?
        .record()
    }

    fn user_ids_unchecked(&self) -> Result<Vec<String>> {
        let directory = self.config.data_dir.join(USERS_COLLECTION);
        let entries = paths::list_directory(&self.root, &directory, "the users collection")?
            .unwrap_or_default();
        let mut ids = Vec::new();
        for entry in entries {
            let CollectionEntry::Record(id) = collection_entry(USERS_COLLECTION, &entry.name)?
            else {
                continue;
            };
            if !entry.kind.is_file() {
                return Err(paths::refuse_entry(
                    &record_label(USERS_COLLECTION, &id),
                    entry.kind,
                ));
            }
            ids.push(id);
        }
        ids.sort();
        Ok(ids)
    }

    fn has_database_owner_other_than(&self, excluded: &str) -> Result<bool> {
        let states = self.audit().record_states()?;
        for ((collection, id), state) in states {
            if collection != USERS_COLLECTION || id == excluded {
                continue;
            }
            let Some((document, expected_hash)) =
                state.document.as_ref().zip(state.hash.as_deref())
            else {
                continue;
            };
            let document = Document::from_audit_value(document)?;
            let user = User::from_attributes(&document.attributes)?;
            if user.status != UserStatus::Active || !user.is_database_owner() {
                continue;
            }
            let path = self.record_path(USERS_COLLECTION, &id)?;
            let Some(raw) = paths::read_to_string_optional(
                &self.root,
                &path,
                &record_label(USERS_COLLECTION, &id),
            )?
            else {
                continue;
            };
            if record_hash(raw.as_bytes()) == expected_hash {
                return Ok(true);
            }
        }
        Ok(false)
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
        if collection == USERS_COLLECTION {
            return Err(invalid(
                "the users collection is managed through 'cr user' and 'cr access'",
            ));
        }
        let idempotency = self.idempotency_request("create", collection, id, || {
            Ok(json!({
                "attributes": canonical_yaml_value(&Value::Mapping(attributes.clone()))?,
                "body": body,
            }))
        })?;
        self.run_create(
            collection,
            id,
            attributes,
            body,
            CreateRequest::new(
                MutationMode::Apply,
                Some(AccessRequest::new(
                    AccessAction::Create,
                    AccessResource::record(collection, id),
                )),
            )
            .with_idempotency(idempotency),
        )?
        .record()
    }

    /// Create a sync target only if the complete audited database is still at
    /// the generation against which the adapter output was accepted.
    pub(crate) fn create_record_at_audit_sequence(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
        expected_audit_sequence: u64,
    ) -> Result<Record> {
        if collection == USERS_COLLECTION {
            return Err(invalid(
                "the users collection is managed through 'cr user' and 'cr access'",
            ));
        }
        self.run_create(
            collection,
            id,
            attributes,
            body,
            CreateRequest::new(
                MutationMode::Apply,
                Some(AccessRequest::new(
                    AccessAction::Create,
                    AccessResource::record(collection, id),
                )),
            )
            .at_audit_sequence(expected_audit_sequence),
        )?
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
        if collection == USERS_COLLECTION {
            return Err(invalid(
                "the users collection is managed through 'cr user' and 'cr access'",
            ));
        }
        self.run_create(
            collection,
            id,
            attributes,
            body,
            CreateRequest::new(
                MutationMode::Preview,
                Some(AccessRequest::new(
                    AccessAction::Create,
                    AccessResource::record(collection, id),
                )),
            ),
        )?
        .preview()
    }

    fn run_create(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
        request: CreateRequest,
    ) -> Result<MutationOutcome> {
        let CreateRequest {
            mode,
            access,
            reuse_deleted_user_id,
            expected_audit_sequence,
            idempotency,
        } = request;
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        if let Some(expected) = expected_audit_sequence {
            assert_audit_sequence(&audit, expected)?;
        }
        if access.is_none() && self.access_enabled()? {
            return Err(conflict(
                "access control was initialized by another process; retry as a registered principal",
            ));
        }
        if access
            .as_ref()
            .is_some_and(|request| request.action == AccessAction::ManageAccess)
        {
            self.assert_current_principal_policy(&audit)?;
        }
        let decision = access
            .as_ref()
            .map(|access| {
                if access.owner_only {
                    self.authorize_owner(&access.resource)
                } else {
                    self.authorize(access.action, &access.resource)
                }
            })
            .transpose()?
            .flatten();
        if let Some(record) = self.replay_idempotent_record(&audit, idempotency.as_ref())? {
            return Ok(MutationOutcome::Applied(record));
        }
        if paths::entry_kind(&self.root, &path, &label)?.is_some() {
            return Err(DomainError::record_exists(collection, id).into());
        }
        let tombstoned =
            collection == USERS_COLLECTION && audit.record_is_tombstoned(collection, id)?;
        if tombstoned {
            if !reuse_deleted_user_id {
                return Err(user_id_tombstoned(id));
            }
            self.authorize_owner(&AccessResource::Database)?;
        }
        let document = Document {
            attributes,
            body: body.to_owned(),
        };
        self.validate(collection, &document.attributes)?;
        let stored = self.protect_document(collection, id, &document, None, mode)?;
        let rendered = stored.render()?;
        let record = record_from_document(
            collection,
            id,
            path.clone(),
            document.clone(),
            record_hash(rendered.as_bytes()),
        );
        let idempotency = self.audit_idempotency(idempotency.as_ref(), &record, &rendered)?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Create,
            collection,
            id,
            before_document: None,
            after_document: Some(&stored),
            before_bytes: None,
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: idempotency.as_ref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(
                self.reveal_preview(event.into_preview())?,
            ));
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
        Ok(MutationOutcome::Applied(record))
    }

    pub fn get(&self, collection: &str, id: &str) -> Result<Record> {
        self.authorize(AccessAction::Read, &AccessResource::record(collection, id))?;
        let path = self.record_path(collection, id)?;
        let raw = self.read_record(collection, id, &path)?;
        let document = self.parse_logical_record(collection, id, &raw)?;
        Ok(record_from_document(
            collection,
            id,
            path,
            document,
            record_hash(raw.as_bytes()),
        ))
    }

    pub fn get_optional(&self, collection: &str, id: &str) -> Result<Option<Record>> {
        let path = self.record_path(collection, id)?;
        match paths::entry_kind(&self.root, &path, &record_label(collection, id))? {
            Some(_) => self.get(collection, id).map(Some),
            None => Ok(None),
        }
    }

    pub fn read_raw(&self, collection: &str, id: &str) -> Result<String> {
        self.read_raw_versioned(collection, id).map(|(raw, _)| raw)
    }

    /// Read the exact document bytes and the version derived from that same read.
    pub fn read_raw_versioned(&self, collection: &str, id: &str) -> Result<(String, String)> {
        self.authorize(AccessAction::Read, &AccessResource::record(collection, id))?;
        let path = self.record_path(collection, id)?;
        let stored_raw = self.read_record(collection, id, &path)?;
        let version = record_hash(stored_raw.as_bytes());
        if self.encryption_policy(collection)?.is_empty() {
            return Ok((stored_raw, version));
        }
        let document = self.parse_logical_record(collection, id, &stored_raw)?;
        Ok((document.render()?, version))
    }

    /// Assert one target state while holding the same audit lock as writers.
    ///
    /// Sync uses this for idempotent operations that need no audit event: an
    /// exact upsert that is already present, or a delete whose target was
    /// already absent at the run's recorded audit head. The complete audit
    /// generation is checked in the same lock scope, so byte-identical ABA
    /// changes and unrelated audited writers cannot race the comparison.
    pub(crate) fn assert_record_version(
        &self,
        collection: &str,
        id: &str,
        expected: Option<&str>,
        expected_audit_sequence: u64,
    ) -> Result<()> {
        let precondition = expected.map(RecordPrecondition::version).transpose()?;
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        assert_audit_sequence(&audit, expected_audit_sequence)?;
        self.authorize(AccessAction::Read, &AccessResource::record(collection, id))?;
        if let Some(precondition) = precondition {
            let raw = self.read_record_for_mutation(collection, id, &path, Some(&precondition))?;
            return precondition.assert_matches(collection, id, &record_hash(raw.as_bytes()));
        }
        if paths::entry_kind(&self.root, &path, &label)?.is_none() {
            return Ok(());
        }
        Err(precondition_failed(format!(
            "record {collection}/{id} changed since the expected version"
        )))
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
            // The name decides whether this claims to be a record, and the
            // kind decides whether it is usable as one — in that order, as in
            // `record_files` and `cr check`, so a `.md` name that cannot be an
            // ID is refused rather than quietly listed.
            let CollectionEntry::Record(id) = collection_entry(collection, &entry.name)? else {
                continue;
            };
            if !entry.kind.is_file() {
                continue;
            }
            identifiers.push(id);
        }
        identifiers.sort();

        identifiers
            .into_iter()
            .filter_map(|id| {
                match self.can_access(AccessAction::Read, &AccessResource::record(collection, &id))
                {
                    Ok(true) => {}
                    Ok(false) => return None,
                    Err(error) => return Some(Err(error)),
                }
                Some((|| {
                    let path = directory.join(format!("{id}.md"));
                    let raw = self.read_record(collection, &id, &path)?;
                    let document = self.parse_logical_record(collection, &id, &raw)?;
                    Ok(record_from_document(
                        collection,
                        &id,
                        path,
                        document,
                        record_hash(raw.as_bytes()),
                    ))
                })())
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
                let raw_document = Document {
                    attributes: record.attributes.clone(),
                    body: record.body.clone(),
                }
                .render()?;
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
        if models.contains_key(USERS_COLLECTION) {
            models.insert(USERS_COLLECTION.to_owned(), Some(users_schema()));
        }
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
            // The schema directory names collections the same way the records
            // directory does, so an unusable name is refused the same way:
            // classified, and naming the file rather than only the rule it
            // broke.
            let unusable = || {
                anyhow::Error::new(DomainError::Conflict(format!(
                    "the schema directory contains a file named '{}' whose name cannot be a collection",
                    entry.name.to_string_lossy()
                )))
            };
            let name = entry_path
                .file_stem()
                .and_then(|value| value.to_str())
                .ok_or_else(unusable)?
                .to_owned();
            if name == USERS_COLLECTION {
                return Err(invalid(
                    "the users collection has a built-in schema and cannot define .cr/schemas/users.json",
                ));
            }
            if validate_component(&name, "collection").is_err() {
                return Err(unusable());
            }
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
            EncryptionPolicy::from_schema(Some(&schema)).with_context(|| {
                DomainError::Invalid(format!(
                    "invalid encryption annotations for collection '{name}'"
                ))
            })?;
            models.insert(name, Some(schema));
        }

        if self.access_enabled()? {
            let user = self.current_user()?.ok_or_else(|| {
                forbidden(format!(
                    "principal '{}' is not registered in the users collection",
                    self.principal
                ))
            })?;
            let mut visible = BTreeMap::new();
            for (name, schema) in models {
                let has_record_grant = user.status == UserStatus::Active
                    && user.access.iter().any(|grant| {
                        matches!(
                            &grant.resource,
                            AccessResource::Record { collection, .. } if collection == &name
                        )
                    });
                if has_record_grant
                    || self
                        .can_access(AccessAction::Discover, &AccessResource::collection(&name))?
                {
                    visible.insert(name, schema);
                }
            }
            models = visible;
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
        self.update_conditionally(collection, id, assignments, body, None)
    }

    /// Update a record, optionally requiring its exact current version.
    pub fn update_conditionally(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: Option<&str>,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<Record> {
        let user_fields = validate_users_field_update(collection, assignments, body)?;
        let idempotency = self.idempotency_request("update", collection, id, || {
            Ok(json!({
                "assignments": assignments
                    .iter()
                    .map(Assignment::idempotency_value)
                    .collect::<Result<Vec<_>>>()?,
                "body": body,
                "precondition": precondition.map(RecordPrecondition::idempotency_value),
            }))
        })?;
        self.run_update(
            collection,
            id,
            update_with(assignments, body),
            MutationMode::Apply,
            if let Some(includes_name) = user_fields {
                AccessRequest::user_fields(id, includes_name)
            } else {
                AccessRequest::new(AccessAction::Update, AccessResource::record(collection, id))
            },
            precondition,
            idempotency,
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
        self.preview_update_conditionally(collection, id, assignments, body, None)
    }

    /// Preview an update against an optional exact current version.
    pub fn preview_update_conditionally(
        &self,
        collection: &str,
        id: &str,
        assignments: &[Assignment],
        body: Option<&str>,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<ChangePreview> {
        let user_fields = validate_users_field_update(collection, assignments, body)?;
        self.run_update(
            collection,
            id,
            update_with(assignments, body),
            MutationMode::Preview,
            if let Some(includes_name) = user_fields {
                AccessRequest::user_fields(id, includes_name)
            } else {
                AccessRequest::new(AccessAction::Update, AccessResource::record(collection, id))
            },
            precondition,
            None,
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
        self.patch_conditionally(collection, id, attributes, remove, body, None)
    }

    /// Atomically merge a patch, optionally requiring an exact current version.
    pub fn patch_conditionally(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<Record> {
        self.run_patch(
            collection,
            id,
            attributes,
            remove,
            body,
            MutationMode::Apply,
            precondition,
            self.idempotency_request("patch", collection, id, || {
                Ok(json!({
                    "attributes": canonical_yaml_value(&Value::Mapping(attributes.clone()))?,
                    "remove": remove,
                    "body": body,
                    "precondition": precondition.map(RecordPrecondition::idempotency_value),
                }))
            })?,
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
        self.preview_patch_conditionally(collection, id, attributes, remove, body, None)
    }

    /// Preview an atomic patch against an optional exact current version.
    pub fn preview_patch_conditionally(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<ChangePreview> {
        self.run_patch(
            collection,
            id,
            attributes,
            remove,
            body,
            MutationMode::Preview,
            precondition,
            None,
        )?
        .preview()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_patch(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        remove: &[String],
        body: Option<&str>,
        mode: MutationMode,
        precondition: Option<&RecordPrecondition>,
        idempotency: Option<IdempotencyRequest>,
    ) -> Result<MutationOutcome> {
        let user_fields = validate_users_field_patch(collection, attributes, remove, body)?;
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
            if let Some(includes_name) = user_fields {
                AccessRequest::user_fields(id, includes_name)
            } else {
                AccessRequest::new(AccessAction::Update, AccessResource::record(collection, id))
            },
            precondition,
            idempotency,
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
        self.replace_conditionally(collection, id, attributes, body, None)
    }

    /// Replace a complete document under an exact-version precondition.
    pub fn replace_conditionally(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<Record> {
        reject_users_mutation(collection)?;
        let idempotency = self.idempotency_request("replace", collection, id, || {
            Ok(json!({
                "attributes": canonical_yaml_value(&Value::Mapping(attributes.clone()))?,
                "body": body,
                "precondition": precondition.map(RecordPrecondition::idempotency_value),
            }))
        })?;
        self.run_update(
            collection,
            id,
            |document| {
                document.attributes = attributes;
                document.body = body.to_owned();
                Ok(())
            },
            MutationMode::Apply,
            AccessRequest::new(AccessAction::Update, AccessResource::record(collection, id)),
            precondition,
            idempotency,
        )?
        .record()
    }

    /// Preview a complete-document replacement under a version precondition.
    pub fn preview_replace_conditionally(
        &self,
        collection: &str,
        id: &str,
        attributes: Mapping,
        body: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<ChangePreview> {
        reject_users_mutation(collection)?;
        self.run_update(
            collection,
            id,
            |document| {
                document.attributes = attributes;
                document.body = body.to_owned();
                Ok(())
            },
            MutationMode::Preview,
            AccessRequest::new(AccessAction::Update, AccessResource::record(collection, id)),
            precondition,
            None,
        )?
        .preview()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_update(
        &self,
        collection: &str,
        id: &str,
        mutate: impl FnOnce(&mut Document) -> Result<()>,
        mode: MutationMode,
        access: AccessRequest,
        precondition: Option<&RecordPrecondition>,
        idempotency: Option<IdempotencyRequest>,
    ) -> Result<MutationOutcome> {
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        if let Some(precondition) = precondition {
            precondition.assert_audit_sequence(&audit)?;
        }
        if access.action == AccessAction::ManageAccess || access.user_fields {
            self.assert_current_principal_policy(&audit)?;
        }
        let decision = if access.owner_only {
            self.authorize_owner(&access.resource)?
        } else if access.user_fields && access.user_name && id != self.principal {
            self.authorize_owner(&AccessResource::Database)?
        } else if access.user_fields {
            self.authorize_user_field_update(id)?
        } else {
            self.authorize(access.action, &access.resource)?
        };
        if let Some(record) = self.replay_idempotent_record(&audit, idempotency.as_ref())? {
            return Ok(MutationOutcome::Applied(record));
        }
        let before_raw = self.read_record_for_mutation(collection, id, &path, precondition)?;
        if let Some(precondition) = precondition {
            precondition.assert_matches(collection, id, &record_hash(before_raw.as_bytes()))?;
        }
        let before_stored = parse_record(collection, id, &before_raw)?;
        let before = self.reveal_document(collection, id, &before_stored)?;
        let mut document = before.clone();
        mutate(&mut document)?;
        if collection == USERS_COLLECTION {
            document.attributes = User::from_attributes(&document.attributes)?.attributes()?;
        }
        self.validate(collection, &document.attributes)?;
        let after_stored =
            self.protect_document(collection, id, &document, Some(&before_stored), mode)?;
        let rendered = after_stored.render()?;
        let record = record_from_document(
            collection,
            id,
            path.clone(),
            document.clone(),
            record_hash(rendered.as_bytes()),
        );
        let idempotency = self.audit_idempotency(idempotency.as_ref(), &record, &rendered)?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Update,
            collection,
            id,
            before_document: Some(&before_stored),
            after_document: Some(&after_stored),
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: idempotency.as_ref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(
                self.reveal_preview(event.into_preview())?,
            ));
        }
        audit.commit(event, &path, || {
            paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)
        })?;
        Ok(MutationOutcome::Applied(record))
    }

    pub fn link(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
    ) -> Result<Record> {
        self.link_conditionally(collection, id, relation, target_collection, target_id, None)
    }

    /// Add a relation, optionally requiring the source record's exact version.
    pub fn link_conditionally(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<Record> {
        reject_users_mutation(collection)?;
        let idempotency = self.idempotency_request("link", collection, id, || {
            Ok(json!({
                "relation": relation,
                "target_collection": target_collection,
                "target_id": target_id,
                "precondition": precondition.map(RecordPrecondition::idempotency_value),
            }))
        })?;
        self.run_link(
            collection,
            id,
            relation,
            target_collection,
            target_id,
            MutationMode::Apply,
            precondition,
            idempotency,
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
        self.preview_link_conditionally(
            collection,
            id,
            relation,
            target_collection,
            target_id,
            None,
        )
    }

    /// Preview a relation against an optional source-record version.
    pub fn preview_link_conditionally(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<ChangePreview> {
        reject_users_mutation(collection)?;
        self.run_link(
            collection,
            id,
            relation,
            target_collection,
            target_id,
            MutationMode::Preview,
            precondition,
            None,
        )?
        .preview()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_link(
        &self,
        collection: &str,
        id: &str,
        relation: &str,
        target_collection: &str,
        target_id: &str,
        mode: MutationMode,
        precondition: Option<&RecordPrecondition>,
        idempotency: Option<IdempotencyRequest>,
    ) -> Result<MutationOutcome> {
        validate_component(relation, "relation")?;
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        if let Some(precondition) = precondition {
            precondition.assert_audit_sequence(&audit)?;
        }
        let decision =
            self.authorize(AccessAction::Link, &AccessResource::record(collection, id))?;
        self.authorize(
            AccessAction::Read,
            &AccessResource::record(target_collection, target_id),
        )?;
        if let Some(record) = self.replay_idempotent_record(&audit, idempotency.as_ref())? {
            return Ok(MutationOutcome::Applied(record));
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
        self.parse_logical_record(target_collection, target_id, &target_raw)?;
        audit.assert_current(target_collection, target_id, target_raw.as_bytes())?;

        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let before_raw = self.read_record_for_mutation(collection, id, &path, precondition)?;
        if let Some(precondition) = precondition {
            precondition.assert_matches(collection, id, &record_hash(before_raw.as_bytes()))?;
        }
        let before_stored = parse_record(collection, id, &before_raw)?;
        let before = self.reveal_document(collection, id, &before_stored)?;
        let mut document = before.clone();
        let relations = mapping_field(&mut document.attributes, "relations")?;
        let targets = sequence_field(relations, relation)?;
        let reference = relation_value(target_collection, target_id);

        if !targets.contains(&reference) {
            targets.push(reference);
        }

        self.validate(collection, &document.attributes)?;
        let after_stored =
            self.protect_document(collection, id, &document, Some(&before_stored), mode)?;
        let rendered = after_stored.render()?;
        let record = record_from_document(
            collection,
            id,
            path.clone(),
            document.clone(),
            record_hash(rendered.as_bytes()),
        );
        let idempotency = self.audit_idempotency(idempotency.as_ref(), &record, &rendered)?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Link,
            collection,
            id,
            before_document: Some(&before_stored),
            after_document: Some(&after_stored),
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: Some(rendered.as_bytes()),
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: idempotency.as_ref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(
                self.reveal_preview(event.into_preview())?,
            ));
        }
        audit.commit(event, &path, || {
            paths::write_replace(&self.root, &path, rendered.as_bytes(), &label)
        })?;
        Ok(MutationOutcome::Applied(record))
    }

    pub fn delete(&self, collection: &str, id: &str) -> Result<Record> {
        self.delete_conditionally(collection, id, None)
    }

    /// Delete a record, optionally requiring its exact current version.
    pub fn delete_conditionally(
        &self,
        collection: &str,
        id: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<Record> {
        reject_users_mutation(collection)?;
        let idempotency = self.idempotency_request("delete", collection, id, || {
            Ok(json!({
                "precondition": precondition.map(RecordPrecondition::idempotency_value),
            }))
        })?;
        self.run_delete(
            collection,
            id,
            MutationMode::Apply,
            AccessRequest::new(AccessAction::Delete, AccessResource::record(collection, id)),
            false,
            precondition,
            idempotency,
        )?
        .record()
    }

    /// Compute what `delete` would record, without deleting anything.
    pub fn preview_delete(&self, collection: &str, id: &str) -> Result<ChangePreview> {
        self.preview_delete_conditionally(collection, id, None)
    }

    /// Preview a deletion against an optional exact current version.
    pub fn preview_delete_conditionally(
        &self,
        collection: &str,
        id: &str,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<ChangePreview> {
        reject_users_mutation(collection)?;
        self.run_delete(
            collection,
            id,
            MutationMode::Preview,
            AccessRequest::new(AccessAction::Delete, AccessResource::record(collection, id)),
            false,
            precondition,
            None,
        )?
        .preview()
    }

    /// Delete a registered principal while retaining its complete prior state
    /// in the audit tombstone.
    pub fn delete_user(&self, id: &str, options: UserDeleteOptions) -> Result<Record> {
        validate_component(id, "user")?;
        let canonical = principal_id(id)?;
        if canonical != id {
            return Err(invalid(format!(
                "user ID '{id}' is not canonical; use '{canonical}'"
            )));
        }
        self.run_delete(
            USERS_COLLECTION,
            id,
            MutationMode::Apply,
            AccessRequest::owner(AccessResource::Database),
            options.if_unused,
            None,
            None,
        )?
        .record()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_delete(
        &self,
        collection: &str,
        id: &str,
        mode: MutationMode,
        access: AccessRequest,
        if_unused: bool,
        precondition: Option<&RecordPrecondition>,
        idempotency: Option<IdempotencyRequest>,
    ) -> Result<MutationOutcome> {
        let path = self.record_path(collection, id)?;
        let label = record_label(collection, id);
        let audit = self.audit();
        let _lock = audit.lock()?;
        if mode == MutationMode::Apply {
            audit.recover_pending()?;
        }
        if let Some(precondition) = precondition {
            precondition.assert_audit_sequence(&audit)?;
        }
        if access.action == AccessAction::ManageAccess {
            self.assert_current_principal_policy(&audit)?;
        }
        let decision = if access.owner_only {
            self.authorize_owner(&access.resource)?
        } else {
            self.authorize(access.action, &access.resource)?
        };
        if let Some(record) = self.replay_idempotent_record(&audit, idempotency.as_ref())? {
            return Ok(MutationOutcome::Applied(record));
        }
        let before_raw = self.read_record_for_mutation(collection, id, &path, precondition)?;
        if let Some(precondition) = precondition {
            precondition.assert_matches(collection, id, &record_hash(before_raw.as_bytes()))?;
        }
        let stored_document = parse_record(collection, id, &before_raw)?;
        let document = self.reveal_document(collection, id, &stored_document)?;
        if collection == USERS_COLLECTION {
            audit.assert_current(collection, id, before_raw.as_bytes())?;
            let user = User::from_attributes(&document.attributes)?;
            if user.status == UserStatus::Active
                && user.is_database_owner()
                && !self.has_database_owner_other_than(id)?
            {
                return Err(conflict("cannot delete the final active database owner"));
            }
            if if_unused && audit.principal_has_external_history(id)? {
                return Err(conflict(format!(
                    "user '{id}' has been used as an audited principal; omit --if-unused to delete it explicitly"
                )));
            }
        }
        let record = record_from_document(
            collection,
            id,
            path.clone(),
            document.clone(),
            record_hash(before_raw.as_bytes()),
        );
        let idempotency = self.audit_idempotency(idempotency.as_ref(), &record, &before_raw)?;
        let event = audit.prepare(AuditMutation {
            action: AuditAction::Delete,
            collection,
            id,
            before_document: Some(&stored_document),
            after_document: None,
            before_bytes: Some(before_raw.as_bytes()),
            after_bytes: None,
            source: self.source.clone(),
            message: self.audit_message.as_deref(),
            access: decision.as_ref(),
            idempotency: idempotency.as_ref(),
        })?;
        if mode == MutationMode::Preview {
            return Ok(MutationOutcome::Previewed(
                self.reveal_preview(event.into_preview())?,
            ));
        }
        audit.commit(event, &path, || {
            paths::remove_file(&self.root, &path, &label)
        })?;
        Ok(MutationOutcome::Applied(record))
    }

    pub fn status(&self) -> Result<Vec<WorkingChange>> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.authorize_owner(&AccessResource::Database)?;
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
        if all {
            self.authorize_owner(&AccessResource::Database)?;
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
            reject_users_mutation(&change.collection)?;
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
                let logical = self.reveal_document(&change.collection, &change.id, document)?;
                self.encryption_policy(&change.collection)?
                    .validate_logical_for_write(&logical)?;
                self.validate(&change.collection, &logical.attributes)?;
            }
            let action = match change.status {
                WorkingChangeKind::Added => AuditAction::Create,
                WorkingChangeKind::Modified => AuditAction::Update,
                WorkingChangeKind::Deleted => AuditAction::Delete,
            };
            let access_action = match change.status {
                WorkingChangeKind::Added => AccessAction::Create,
                WorkingChangeKind::Modified => AccessAction::Update,
                WorkingChangeKind::Deleted => AccessAction::Delete,
            };
            let resource = match change.status {
                WorkingChangeKind::Added => AccessResource::record(&change.collection, &change.id),
                WorkingChangeKind::Modified | WorkingChangeKind::Deleted => {
                    AccessResource::record(&change.collection, &change.id)
                }
            };
            let decision = self.authorize(access_action, &resource)?;
            prepared.push((change, before, after, after_raw, action, decision));
        }

        let mut previews = Vec::with_capacity(prepared.len());
        let mut projected_changes = Vec::with_capacity(prepared.len());
        // Projection can require decryption keys or reject stale schema
        // metadata. Prove every selected event is displayable before accepting
        // the first one, so `save --all` can never commit a prefix and then
        // return an error while formatting its response.
        for (change, before, after, after_raw, action, decision) in &prepared {
            let event = audit.prepare_reconciled(ReconciledMutation {
                action: action.clone(),
                collection: &change.collection,
                id: &change.id,
                before_document: before.as_ref(),
                after_document: after.as_ref(),
                before_hash: change.audited_hash.as_deref(),
                after_bytes: after_raw.as_deref().map(str::as_bytes),
                had_history: states.contains_key(&(change.collection.clone(), change.id.clone())),
                message,
                access: decision.as_ref(),
            })?;
            let preview = self.reveal_preview(event.into_preview())?;
            if mode == MutationMode::Preview {
                previews.push(preview);
            } else {
                projected_changes.push(preview.changes);
            }
        }
        if mode == MutationMode::Preview {
            return Ok((Vec::new(), previews));
        }

        let mut entries = Vec::with_capacity(prepared.len());
        for ((change, before, after, after_raw, action, decision), changes) in
            prepared.into_iter().zip(projected_changes)
        {
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
                access: decision.as_ref(),
            })?;
            let mut entry = audit.accept(event, &change.path)?;
            entry.payload.changes = changes;
            entries.push(entry);
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
        match (filter.collection, filter.id) {
            (Some(USERS_COLLECTION), Some(id)) if id == self.principal => {
                let Some((user, _)) = self.user_unchecked_optional(&self.principal)? else {
                    return Err(forbidden(format!(
                        "principal '{}' is not registered in the users collection",
                        self.principal
                    )));
                };
                if user.status != UserStatus::Active {
                    return Err(forbidden(format!(
                        "principal '{}' is not active",
                        self.principal
                    )));
                }
                self.assert_current_principal_policy(&audit)?;
            }
            (Some(USERS_COLLECTION), _) => {
                self.authorize(AccessAction::ReadAccess, &AccessResource::Database)?;
            }
            (Some(collection), Some(id)) => {
                self.authorize(
                    AccessAction::ReadAudit,
                    &AccessResource::record(collection, id),
                )?;
            }
            (Some(collection), None) => {
                self.authorize(
                    AccessAction::ReadAudit,
                    &AccessResource::collection(collection),
                )?;
            }
            (None, None) => {
                if self.owner_access_allowed(&AccessResource::Database)? {
                    return self.reveal_audit_entries(audit.recent(limit, filter)?);
                }
                let Some((user, policy_hash)) = self.user_unchecked_optional(&self.principal)?
                else {
                    return Err(forbidden(format!(
                        "principal '{}' is not registered in the users collection",
                        self.principal
                    )));
                };
                let entries = audit.recent_where(limit, filter, |entry| {
                    if entry.payload.record.collection == USERS_COLLECTION {
                        if entry.payload.record.id == self.principal {
                            return Ok(true);
                        }
                        return Ok(user
                            .decision(
                                &self.principal,
                                &self.actor,
                                AccessAction::ReadAccess,
                                &AccessResource::Database,
                                &policy_hash,
                            )
                            .is_some());
                    }
                    Ok(user
                        .decision(
                            &self.principal,
                            &self.actor,
                            AccessAction::ReadAudit,
                            &AccessResource::record(
                                &entry.payload.record.collection,
                                &entry.payload.record.id,
                            ),
                            &policy_hash,
                        )
                        .is_some())
                })?;
                return self.reveal_audit_entries(entries);
            }
            (None, Some(_)) => unreachable!(),
        }
        self.reveal_audit_entries(audit.recent(limit, filter)?)
    }

    pub fn audit_head(&self) -> Result<AuditHead> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.authorize_owner(&AccessResource::Database)?;
        audit.head()
    }

    /// Report the audit anchor recorded at the database root.
    ///
    /// Fails when it disagrees with the journal, so this is an inspection that
    /// can refuse rather than a status that always prints.
    pub fn audit_anchor(&self) -> Result<AnchorReport> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.authorize_owner(&AccessResource::Database)?;
        audit.anchor_report()
    }

    /// Rewrite the audit anchor to the current head.
    ///
    /// For adopting the anchor on a database that predates it, and for
    /// repairing one a crash left behind. Refuses when the stored anchor
    /// already disagrees with the journal.
    pub fn audit_anchor_write(&self) -> Result<AuditAnchor> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.authorize_owner(&AccessResource::Database)?;
        audit.write_anchor()
    }

    pub fn audit_verify(&self, expected_head: Option<&str>) -> Result<AuditVerification> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        self.authorize_owner(&AccessResource::Database)?;
        audit.verify(expected_head)
    }

    pub fn audit_baseline(&self) -> Result<usize> {
        let audit = self.audit();
        let _lock = audit.lock()?;
        audit.recover_pending()?;
        let decision = self.authorize_owner(&AccessResource::Database)?;
        let mut added = 0;

        for (collection, id, path) in self.record_files()? {
            if audit.has_history(&collection, &id)? {
                continue;
            }
            let raw = self.read_record(&collection, &id, &path)?;
            let document = parse_record(&collection, &id, &raw)?;
            let logical = self.reveal_document(&collection, &id, &document)?;
            self.validate(&collection, &logical.attributes)?;
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
                access: decision.as_ref(),
                idempotency: None,
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

    /// Read an existing mutation target without turning a failed conditional
    /// write into an ordinary not-found response. `If-Match` is false when no
    /// current representation exists, so an expected version maps that state
    /// to the same typed precondition failure as a changed representation.
    fn read_record_for_mutation(
        &self,
        collection: &str,
        id: &str,
        path: &Path,
        precondition: Option<&RecordPrecondition>,
    ) -> Result<String> {
        self.read_record(collection, id, path).map_err(|error| {
            if precondition.is_some()
                && matches!(DomainError::of(&error), Some(DomainError::NotFound(_)))
            {
                precondition_failed(format!(
                    "record {collection}/{id} changed since the expected version"
                ))
            } else {
                error
            }
        })
    }

    fn validate(&self, collection: &str, attributes: &Mapping) -> Result<()> {
        if collection == USERS_COLLECTION {
            let schema = users_schema();
            validate_schema_instance(
                collection,
                attributes,
                &schema,
                "the built-in users schema",
                false,
            )?;
            User::from_attributes(attributes)?;
            return Ok(());
        }
        let Some(schema) = self.collection_schema(collection)? else {
            return Ok(());
        };
        let redact_values = !EncryptionPolicy::from_schema(Some(&schema))?.is_empty();
        validate_schema_instance(
            collection,
            attributes,
            &schema,
            &schema_label(collection),
            redact_values,
        )
    }

    fn collection_schema(&self, collection: &str) -> Result<Option<serde_json::Value>> {
        if collection == USERS_COLLECTION {
            return Ok(Some(users_schema()));
        }
        let schema_path = Path::new(SCHEMA_DIRECTORY).join(format!("{collection}.json"));
        let label = schema_label(collection);
        let Some(serialized) = paths::read_to_string_optional(&self.root, &schema_path, &label)?
        else {
            return Ok(None);
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
        EncryptionPolicy::from_schema(Some(&schema)).with_context(unusable)?;
        Ok(Some(schema))
    }

    fn encryption_policy(&self, collection: &str) -> Result<EncryptionPolicy> {
        let schema = self.collection_schema(collection)?;
        EncryptionPolicy::from_schema(schema.as_ref())
    }

    pub(crate) fn encryption_context_optional(&self) -> Result<Option<EncryptionContext>> {
        paths::read_to_string_optional(&self.root, Path::new(CONTEXT_PATH), CONTEXT_LABEL)?
            .map(|serialized| EncryptionContext::parse(&serialized))
            .transpose()
    }

    pub(crate) fn encryption_context_required(&self) -> Result<EncryptionContext> {
        self.encryption_context_optional()?
            .ok_or_else(|| conflict("database encryption context is missing for protected data"))
    }

    /// Create the portable context for a database initialized before encrypted
    /// storage existed, but only while there is no ciphertext that could have
    /// belonged to a different missing context.
    pub(crate) fn ensure_encryption_context(&self) -> Result<EncryptionContext> {
        if let Some(context) = self.encryption_context_optional()? {
            return Ok(context);
        }
        for (collection, id, path) in self.record_files()? {
            let raw = self.read_record(&collection, &id, &path)?;
            let document = parse_record(&collection, &id, &raw)?;
            if document_has_encrypted_storage(&document) {
                return Err(conflict(
                    "database encryption context is missing for existing protected data",
                ));
            }
        }
        if self.audit().contains_protected_storage()? {
            return Err(conflict(
                "database encryption context is missing for existing protected history",
            ));
        }

        let generated = EncryptionContext::generate()?;
        match paths::write_new(
            &self.root,
            Path::new(CONTEXT_PATH),
            &generated.render()?,
            CONTEXT_LABEL,
        ) {
            Ok(()) => Ok(generated),
            Err(error) if is_already_exists(&error) => self
                .encryption_context_optional()?
                .context("database encryption context appeared but could not be read"),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn collection_uses_encryption(&self, collection: &str) -> Result<bool> {
        Ok(!self.encryption_policy(collection)?.is_empty())
    }

    pub(crate) fn stored_record_matches_logical(
        &self,
        collection: &str,
        id: &str,
        attributes: &Mapping,
        body: &str,
        version: &str,
    ) -> Result<bool> {
        let path = self.record_path(collection, id)?;
        let Some(raw) =
            paths::read_to_string_optional(&self.root, &path, &record_label(collection, id))?
        else {
            return Ok(false);
        };
        if record_hash(raw.as_bytes()) != version {
            return Ok(false);
        }
        let logical = self.parse_logical_record(collection, id, &raw)?;
        Ok(&logical.attributes == attributes && logical.body == body)
    }

    pub(crate) fn reveal_document(
        &self,
        collection: &str,
        id: &str,
        stored: &Document,
    ) -> Result<Document> {
        let policy = self.encryption_policy(collection)?;
        let context = if policy.is_empty() {
            None
        } else {
            self.encryption_context_optional()?
        };
        policy.reveal(
            context.as_ref().map(EncryptionContext::id),
            collection,
            id,
            stored,
        )
    }

    fn parse_logical_record(&self, collection: &str, id: &str, raw: &str) -> Result<Document> {
        let stored = parse_record(collection, id, raw)?;
        self.reveal_document(collection, id, &stored)
    }

    fn protect_document(
        &self,
        collection: &str,
        id: &str,
        logical: &Document,
        previous_stored: Option<&Document>,
        mode: MutationMode,
    ) -> Result<Document> {
        let policy = self.encryption_policy(collection)?;
        if previous_stored.is_none() && policy.would_encrypt_on_create(logical) {
            if mode == MutationMode::Preview {
                return Err(invalid(
                    "preview approval is unavailable when protected values would receive fresh encryption",
                ));
            }
            if self
                .attribution
                .authorization
                .as_ref()
                .is_some_and(|authorization| authorization.approved_changes.is_some())
            {
                return Err(invalid(
                    "--approved-changes cannot bind a mutation that creates fresh encrypted values",
                ));
            }
        }
        let context = if policy.is_empty() {
            None
        } else if mode == MutationMode::Apply {
            Some(self.ensure_encryption_context()?)
        } else {
            self.encryption_context_optional()?
        };
        let protected = policy.protect(
            context.as_ref().map(EncryptionContext::id),
            collection,
            id,
            logical,
            previous_stored,
        )?;
        if protected.encrypted_new_value {
            if mode == MutationMode::Preview {
                return Err(invalid(
                    "preview approval is unavailable when protected values would receive fresh encryption",
                ));
            }
            if self
                .attribution
                .authorization
                .as_ref()
                .is_some_and(|authorization| authorization.approved_changes.is_some())
            {
                return Err(invalid(
                    "--approved-changes cannot bind a mutation that creates fresh encrypted values",
                ));
            }
        }
        Ok(protected.document)
    }

    fn reveal_preview(&self, mut preview: ChangePreview) -> Result<ChangePreview> {
        let policy = self.encryption_policy(&preview.record.collection)?;
        let states = self.audit().record_states()?;
        let current = states
            .get(&(preview.record.collection.clone(), preview.record.id.clone()))
            .and_then(|state| state.document.as_ref());
        let mut metadata = current
            .and_then(audit_document_encryption_metadata)
            .into_iter()
            .collect::<Vec<_>>();
        metadata.extend(changes_encryption_metadata(&preview.changes));
        let manifest_owned_storage = projection_uses_policy(&policy, metadata.iter())?;
        self.reveal_changes(
            &preview.record.collection,
            &preview.record.id,
            &mut preview.changes,
            &policy,
            manifest_owned_storage,
        )?;
        Ok(preview)
    }

    fn reveal_audit_entries(&self, mut entries: Vec<AuditEntry>) -> Result<Vec<AuditEntry>> {
        let transitions = self.audit().encryption_storage_transitions()?;
        // Preflight every selected event before decrypting any of them. The
        // response is built in memory and already all-or-nothing, but this also
        // keeps plaintext out of the working projection when a later selected
        // event proves that its historical manifest belongs to another policy.
        let projections = entries
            .iter()
            .map(|entry| {
                let policy = self.encryption_policy(&entry.payload.record.collection)?;
                let transition = transitions.get(&entry.payload.sequence);
                let manifest_owned_storage = projection_uses_policy(
                    &policy,
                    transition
                        .into_iter()
                        .flat_map(AuditEncryptionTransition::metadata),
                )?;
                Ok((policy, manifest_owned_storage))
            })
            .collect::<Result<Vec<_>>>()?;
        for (entry, (policy, manifest_owned_storage)) in entries.iter_mut().zip(projections.iter())
        {
            self.reveal_changes(
                &entry.payload.record.collection,
                &entry.payload.record.id,
                &mut entry.payload.changes,
                policy,
                *manifest_owned_storage,
            )?;
            if *manifest_owned_storage {
                let context = self.encryption_context_optional()?;
                let context = context.as_ref().map(EncryptionContext::id);
                if let Some(snapshot) = entry.payload.after_snapshot.as_mut() {
                    reveal_audit_markdown(
                        policy,
                        context,
                        &entry.payload.record.collection,
                        &entry.payload.record.id,
                        &mut snapshot.markdown,
                    )?;
                }
                if let Some(idempotency) = entry.payload.idempotency.as_mut() {
                    reveal_audit_markdown(
                        policy,
                        context,
                        &entry.payload.record.collection,
                        &entry.payload.record.id,
                        &mut idempotency.result.markdown,
                    )?;
                }
            }
        }
        Ok(entries)
    }

    fn reveal_changes(
        &self,
        collection: &str,
        id: &str,
        changes: &mut [AuditChange],
        policy: &EncryptionPolicy,
        manifest_owned_storage: bool,
    ) -> Result<()> {
        // A current schema cannot retroactively assign storage meaning to old
        // history. Only the manifest in that event's reconstructed document
        // state owns envelope-shaped values; everything else remains ordinary
        // application data and needs neither a context nor a keyring.
        if !manifest_owned_storage {
            return Ok(());
        }
        let context = self.encryption_context_optional()?;
        let context = context.as_ref().map(EncryptionContext::id);
        for change in changes {
            match change {
                AuditChange::Add { path, after } => {
                    policy.reveal_audit_value(context, collection, id, path, after)?;
                }
                AuditChange::Remove { path, before } => {
                    policy.reveal_audit_value(context, collection, id, path, before)?;
                }
                AuditChange::Replace {
                    path,
                    before,
                    after,
                } => {
                    policy.reveal_audit_value(context, collection, id, path, before)?;
                    policy.reveal_audit_value(context, collection, id, path, after)?;
                }
            }
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
                let CollectionEntry::Record(id) = collection_entry(&collection_name, &entry.name)?
                else {
                    continue;
                };
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
            collections.push(collection_directory_name(&entry.name)?);
        }
        collections.sort();
        Ok(collections)
    }

    pub(crate) fn audit(&self) -> AuditLog<'_> {
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
        self.principal = principal_id(&self.actor).unwrap_or_else(|_| "unknown".to_owned());
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

fn record_from_document(
    collection: &str,
    id: &str,
    path: PathBuf,
    document: Document,
    version: String,
) -> Record {
    Record {
        collection: collection.to_owned(),
        id: id.to_owned(),
        path,
        version,
        attributes: document.attributes,
        body: document.body,
    }
}

fn validate_record_version(version: &str) -> Result<()> {
    let digest = version.strip_prefix("sha256:").ok_or_else(|| {
        invalid("record version must use the form sha256: followed by 64 lowercase hex digits")
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "record version must use the form sha256: followed by 64 lowercase hex digits",
        ));
    }
    Ok(())
}

fn validate_idempotency_key(key: &str) -> Result<()> {
    if key.len() < MIN_IDEMPOTENCY_KEY_BYTES || key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(invalid(format!(
            "idempotency key must contain between {MIN_IDEMPOTENCY_KEY_BYTES} and {MAX_IDEMPOTENCY_KEY_BYTES} visible ASCII bytes"
        )));
    }
    if !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(invalid(
            "idempotency key must contain visible ASCII without whitespace",
        ));
    }
    Ok(())
}

fn idempotency_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    let digest = digest.finalize();
    let hexadecimal = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hexadecimal}")
}

/// Authenticate canonical plaintext request identity with the never-persisted
/// retry key. This prevents the durable request digest from becoming an
/// offline dictionary oracle for low-entropy protected request values.
fn idempotency_request_digest(key: &[u8], canonical_request: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts retry keys of every validated length");
    mac.update(IDEMPOTENCY_REQUEST_HASH_DOMAIN);
    mac.update(canonical_request);
    let hexadecimal = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("hmac-sha256:{hexadecimal}")
}

/// Parse a stored record, naming it by collection and ID rather than by path.
fn parse_record(collection: &str, id: &str, raw: &str) -> Result<Document> {
    Document::parse(raw)
        .with_context(|| DomainError::Invalid(format!("could not parse record {collection}/{id}")))
}

fn reject_users_mutation(collection: &str) -> Result<()> {
    if collection == USERS_COLLECTION {
        return Err(invalid(
            "the users collection is managed through 'cr user' and 'cr access'",
        ));
    }
    Ok(())
}

/// Classify the ordinary user update surface without opening reserved fields.
fn validate_users_field_update(
    collection: &str,
    assignments: &[Assignment],
    body: Option<&str>,
) -> Result<Option<bool>> {
    if collection != USERS_COLLECTION {
        return Ok(None);
    }
    let includes_name = assignments
        .iter()
        .any(|assignment| assignment.targets_field("name"));
    if body.is_some()
        || assignments.is_empty()
        || assignments.iter().any(|assignment| {
            !assignment.targets_nested("profile") && !assignment.targets_field("name")
        })
    {
        return Err(invalid(
            "ordinary users updates may change only profile.* and the target's name; email, kind, status, access, and Markdown stay on managed commands",
        ));
    }
    Ok(Some(includes_name))
}

/// Classify REST-style user patches without opening reserved fields.
fn validate_users_field_patch(
    collection: &str,
    attributes: &Mapping,
    remove: &[String],
    body: Option<&str>,
) -> Result<Option<bool>> {
    if collection != USERS_COLLECTION {
        return Ok(None);
    }
    let includes_name = attributes
        .keys()
        .any(|key| matches!(key, Value::String(key) if key == "name"));
    let attributes_are_allowed = attributes.iter().all(|(key, value)| {
        matches!((key, value), (Value::String(key), Value::Mapping(_)) if key == "profile")
            || matches!((key, value), (Value::String(key), Value::String(_)) if key == "name")
    });
    let removes_are_profile = remove.iter().try_fold(true, |allowed, raw| {
        let path = parse_path(raw)?;
        Ok::<_, anyhow::Error>(
            allowed && path.len() > 1 && path.first().is_some_and(|part| part == "profile"),
        )
    })?;
    if body.is_some() || !attributes_are_allowed || !removes_are_profile {
        return Err(invalid(
            "ordinary users patches may change only profile.* and the target's name; email, kind, status, access, and Markdown stay on managed commands",
        ));
    }
    Ok(Some(includes_name))
}

fn user_id_tombstoned(id: &str) -> anyhow::Error {
    conflict(format!(
        "user ID '{id}' was previously deleted; pass --reuse-deleted-id to reuse its audit identity"
    ))
}

fn validate_schema_instance(
    collection: &str,
    attributes: &Mapping,
    schema: &serde_json::Value,
    label: &str,
    redact_values: bool,
) -> Result<()> {
    let validator = jsonschema::validator_for(schema)
        .map_err(|error| anyhow!("could not compile {label}: {error}"))?;
    let instance = serde_json::to_value(attributes)
        .context("front matter cannot be represented as JSON for schema validation")?;
    if redact_values && !validator.is_valid(&instance) {
        return Err(invalid(format!(
            "record does not match schema for collection '{collection}' (protected values redacted)"
        )));
    }
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

fn changes_encryption_metadata(changes: &[AuditChange]) -> Vec<EncryptionStorageMetadata> {
    changes
        .iter()
        .flat_map(|change| match change {
            AuditChange::Add { path, after } if path.is_empty() => {
                [audit_document_encryption_metadata(after), None]
            }
            AuditChange::Remove { path, before } if path.is_empty() => {
                [audit_document_encryption_metadata(before), None]
            }
            AuditChange::Replace {
                path,
                before,
                after,
            } if path.is_empty() => [
                audit_document_encryption_metadata(before),
                audit_document_encryption_metadata(after),
            ],
            _ => [None, None],
        })
        .flatten()
        .collect()
}

/// Decide whether one historical event may be projected through the current
/// schema. A manifest without any envelope contains no protected value to
/// expose, so a removed marker may leave it as inert historical metadata. As
/// soon as real ciphertext exists, every before/after policy must exactly
/// equal the current policy; marker moves fail closed without naming paths.
fn projection_uses_policy<'a>(
    current: &EncryptionPolicy,
    metadata: impl Iterator<Item = &'a EncryptionStorageMetadata>,
) -> Result<bool> {
    let metadata = metadata.collect::<Vec<_>>();
    if metadata.is_empty() {
        return Ok(false);
    }
    let has_envelopes = metadata.iter().any(|state| state.has_envelopes);
    if metadata.iter().all(|state| &state.policy == current) {
        return Ok(true);
    }
    if has_envelopes {
        return Err(conflict(
            "stored protected history is no longer declared by the current collection schema",
        ));
    }
    Ok(false)
}

fn reveal_audit_markdown(
    policy: &EncryptionPolicy,
    context: Option<&str>,
    collection: &str,
    id: &str,
    markdown: &mut String,
) -> Result<()> {
    let stored = Document::parse(markdown)
        .map_err(|_| conflict("stored protected history cannot be decoded"))?;
    let logical = policy.reveal(context, collection, id, &stored)?;
    *markdown = logical
        .render()
        .map_err(|_| conflict("stored protected history cannot be decoded"))?;
    Ok(())
}

/// What one entry of a collection's directory is, as far as records go.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CollectionEntry {
    /// Not a Markdown file, so not a record — and not a problem either.
    Ignored,
    /// A Markdown file whose stem is a usable record ID.
    Record(String),
}

/// Decide what the collection-directory entry named `file_name` is.
///
/// This is the single definition of "a file in this directory is a record".
/// Four paths enumerate a collection directory — [`Database::list`] (and so
/// `search` and every view), [`Database::record_files`] (and so `status`,
/// `save`, `audit baseline`, and `sync run`), `AuditLog::verify_records`, and
/// `cr check`'s index — and before this they disagreed: `list` never checked
/// the stem and returned `..md` as a record, `verify_records` never checked it
/// either and reported a record called `deals/.`, and `record_files` refused
/// the whole database with a message naming neither the file nor its
/// collection. They now share this function, so a name is a record ID
/// everywhere or nowhere.
///
/// The refusal is a `DomainError` so the CLI and the HTTP layer classify it
/// the same way, and it names the collection and the filename so the file can
/// be found without a path ever reaching the caller. `cr check` calls this too
/// and turns the refusal into a finding instead of propagating it, which is
/// what keeps a wedged database diagnosable.
pub(crate) fn collection_entry(collection: &str, file_name: &OsStr) -> Result<CollectionEntry> {
    let path = Path::new(file_name);
    if path.extension().and_then(|value| value.to_str()) != Some("md") {
        return Ok(CollectionEntry::Ignored);
    }
    let Some(id) = path.file_stem().and_then(|value| value.to_str()) else {
        return Err(anyhow::Error::new(DomainError::non_utf8_record_name(
            collection,
            &file_name.to_string_lossy(),
        )));
    };
    if validate_component(id, "id").is_err() {
        return Err(anyhow::Error::new(DomainError::invalid_record_name(
            collection,
            &file_name.to_string_lossy(),
        )));
    }
    Ok(CollectionEntry::Record(id.to_owned()))
}

/// The collection that the records-directory entry named `file_name` names.
///
/// The counterpart of [`collection_entry`] one level up, shared by
/// [`Database::collection_names`], `AuditLog::verify_records`, and `cr check`
/// for the same reason: a directory is a collection everywhere or nowhere, and
/// a refusal says which directory rather than only that some name was
/// unusable. Callers skip entries that are not directories before calling.
pub(crate) fn collection_directory_name(file_name: &OsStr) -> Result<String> {
    let Some(name) = file_name.to_str() else {
        return Err(anyhow::Error::new(DomainError::non_utf8_collection_name(
            &file_name.to_string_lossy(),
        )));
    };
    if validate_component(name, "collection").is_err() {
        return Err(anyhow::Error::new(DomainError::invalid_collection_name(
            name,
        )));
    }
    Ok(name.to_owned())
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
