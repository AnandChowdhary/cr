//! Record-level role-based access control backed by the reserved `users` collection.
//!
//! A user record is both the principal registry entry and the principal's
//! policy document. Keeping the grants in ordinary audited records gives CR a
//! versioned policy history without introducing a second journal. The access
//! evaluator is deliberately pure: storage and locking remain `Database`
//! responsibilities, while this module owns the vocabulary and inheritance
//! rules.

use std::{fmt, str::FromStr};

use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value as JsonValue, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use yaml_serde::{Mapping, Value};

use crate::{
    attribution::AuthenticationMethod,
    audit::digest,
    error::{conflict, invalid},
    value::Assignment,
};

/// The collection CR reserves for authenticated principals and their grants.
pub const USERS_COLLECTION: &str = "users";

/// JSON Schema extension that opts a collection into creator-owned records.
pub const COLLECTION_ACCESS_EXTENSION: &str = "x-cr-access";

/// Front matter reserved for CR's per-record access policy.
pub const RECORD_ACCESS_FIELD: &str = "$cr_access";

/// Every principal token starts with this, so a secret scanner can name one
/// and a server can tell a token that failed from a shared `CR_API_TOKEN`.
pub const TOKEN_PREFIX: &str = "crt_";

/// Tokens one principal may hold at a time. Authentication searches every
/// active token of every user, and a registry is small, but a bound keeps a
/// scripted loop from making that search, and the user record, unbounded.
pub const MAX_USER_TOKENS: usize = 32;

const TOKEN_HASH_DOMAIN: &[u8] = b"cr:access:token:v1\0";
const TOKEN_ID_BYTES: usize = 8;
const TOKEN_SECRET_BYTES: usize = 32;
const MAX_TOKEN_LABEL_CHARS: usize = 200;

/// The access behavior selected for an ordinary collection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionAccessMode {
    RecordOwned,
}

/// Collection-level policy stored as a JSON Schema extension.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionAccessPolicy {
    pub mode: CollectionAccessMode,
    pub default_visibility: RecordVisibility,
}

impl CollectionAccessPolicy {
    pub fn record_owned() -> Self {
        Self {
            mode: CollectionAccessMode::RecordOwned,
            default_visibility: RecordVisibility::Private,
        }
    }

    pub fn from_schema(schema: Option<&JsonValue>) -> Result<Option<Self>> {
        let Some(value) = schema.and_then(|schema| schema.get(COLLECTION_ACCESS_EXTENSION)) else {
            return Ok(None);
        };
        if schema
            .and_then(|schema| schema.get("properties"))
            .and_then(JsonValue::as_object)
            .is_some_and(|properties| properties.contains_key(RECORD_ACCESS_FIELD))
        {
            return Err(invalid(format!(
                "JSON Schema property '{RECORD_ACCESS_FIELD}' is reserved"
            )));
        }
        let policy: Self = serde_json::from_value(value.clone()).map_err(|error| {
            invalid(format!(
                "collection has an invalid {COLLECTION_ACCESS_EXTENSION} policy: {error}"
            ))
        })?;
        if policy.default_visibility != RecordVisibility::Private {
            return Err(invalid(format!(
                "{COLLECTION_ACCESS_EXTENSION}.default_visibility must be private"
            )));
        }
        Ok(Some(policy))
    }
}

/// Who may read a creator-owned record in addition to its owner and direct grants.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordVisibility {
    Private,
    Shared,
}

impl fmt::Display for RecordVisibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Private => "private",
            Self::Shared => "shared",
        })
    }
}

/// CR-managed access metadata stored atomically with a record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecordAccess {
    pub owner: String,
    pub visibility: RecordVisibility,
}

impl RecordAccess {
    pub fn new(owner: impl Into<String>, visibility: RecordVisibility) -> Result<Self> {
        let owner = owner.into();
        if principal_id(&owner)? != owner {
            return Err(invalid(format!("record owner '{owner}' is not canonical")));
        }
        Ok(Self { owner, visibility })
    }

    pub fn from_attributes(attributes: &Mapping) -> Result<Self> {
        Self::from_attributes_optional(attributes)?.ok_or_else(|| {
            invalid(format!(
                "record is missing reserved '{RECORD_ACCESS_FIELD}' metadata"
            ))
        })
    }

    pub fn from_attributes_optional(attributes: &Mapping) -> Result<Option<Self>> {
        let Some(value) = attributes.get(Value::String(RECORD_ACCESS_FIELD.to_owned())) else {
            return Ok(None);
        };
        let access: Self = yaml_serde::from_value(value.clone()).map_err(|error| {
            invalid(format!(
                "record has invalid '{RECORD_ACCESS_FIELD}' metadata: {error}"
            ))
        })?;
        Self::new(access.owner, access.visibility).map(Some)
    }

    pub fn insert_into(&self, attributes: &mut Mapping) -> Result<()> {
        attributes.insert(
            Value::String(RECORD_ACCESS_FIELD.to_owned()),
            yaml_serde::to_value(self).map_err(|error| {
                invalid(format!(
                    "record access cannot be represented as YAML: {error}"
                ))
            })?,
        );
        Ok(())
    }
}

/// A user that CR can authenticate and authorize.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default)]
    pub kind: UserKind,
    #[serde(default)]
    pub status: UserStatus,
    /// Application-owned metadata about this principal.
    ///
    /// CR deliberately keeps extensibility below one namespace so future
    /// access-control fields can be added without colliding with application
    /// data. This does not turn `users` into a public people collection: user
    /// visibility remains governed by the access-management rules.
    #[serde(default, skip_serializing_if = "Mapping::is_empty")]
    pub profile: Mapping,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<AccessGrant>,
    /// Verifiers for the tokens that authenticate as this principal.
    ///
    /// Like `access`, CR-owned: only `cr access token` changes them, so every
    /// issue and revocation is an ordinary audited policy version.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<UserToken>,
}

impl User {
    /// Parse a fixed-schema user from record front matter.
    pub fn from_attributes(attributes: &Mapping) -> Result<Self> {
        let user: Self = yaml_serde::from_value(Value::Mapping(attributes.clone()))
            .map_err(|error| invalid(format!("user record has invalid access data: {error}")))?;
        user.validate()?;
        Ok(user)
    }

    /// Serialize a user into record front matter.
    pub fn attributes(&self) -> Result<Mapping> {
        self.validate()?;
        // Canonicalize application metadata through JSON before serializing.
        // Audit replay stores documents as JSON, so deterministic key order is
        // what makes an exact policy file recoverable from that journal later.
        let mut canonical = self.clone();
        canonical.profile =
            serde_json::from_value(serde_json::to_value(&self.profile).map_err(|error| {
                invalid(format!("user profile is not JSON-compatible: {error}"))
            })?)
            .map_err(|error| {
                invalid(format!(
                    "user profile cannot be represented as YAML: {error}"
                ))
            })?;
        match yaml_serde::to_value(&canonical)
            .map_err(|error| invalid(format!("user cannot be represented as YAML: {error}")))?
        {
            Value::Mapping(attributes) => Ok(attributes),
            _ => bail!("a user did not serialize as a front matter mapping"),
        }
    }

    /// The effective decision for one action, if a matching role permits it.
    ///
    /// Grants inherit from database to collection to record. A grant at a more
    /// specific resource replaces a broader grant for this principal. An
    /// ownership grant is the exception: ownership is never accidentally
    /// narrowed by a more specific viewer/editor grant.
    pub fn decision(
        &self,
        principal: &str,
        display: &str,
        action: AccessAction,
        resource: &Resource,
        policy_hash: &str,
    ) -> Option<AccessDecision> {
        if self.status != UserStatus::Active {
            return None;
        }

        if let Some(grant) = self
            .access
            .iter()
            .filter(|grant| grant.role == Role::Owner && grant.resource.contains(resource))
            .max_by_key(|grant| grant.resource.specificity())
        {
            return Some(AccessDecision::new(
                principal,
                display,
                action,
                resource,
                grant,
                policy_hash,
            ));
        }

        let specificity = self
            .access
            .iter()
            .filter(|grant| grant.resource.contains(resource))
            .map(|grant| grant.resource.specificity())
            .max()?;
        self.access
            .iter()
            .filter(|grant| {
                grant.resource.contains(resource)
                    && grant.resource.specificity() == specificity
                    && grant.role.permits(action)
            })
            .max_by_key(|grant| grant.role.rank())
            .map(|grant| {
                AccessDecision::new(principal, display, action, resource, grant, policy_hash)
            })
    }

    /// Evaluate a record in a creator-owned collection.
    ///
    /// Collection roles deliberately stop at the collection boundary here:
    /// editors may create records, but an existing record is readable only
    /// through ownership, a direct record grant, or shared visibility.
    #[allow(clippy::too_many_arguments)]
    pub fn record_owned_decision(
        &self,
        principal: &str,
        display: &str,
        action: AccessAction,
        resource: &Resource,
        access: &RecordAccess,
        policy_hash: &str,
        resource_policy_hash: &str,
    ) -> Option<AccessDecision> {
        if self.status != UserStatus::Active {
            return None;
        }

        if let Some(grant) = self
            .access
            .iter()
            .filter(|grant| grant.role == Role::Owner && grant.resource.contains(resource))
            .max_by_key(|grant| grant.resource.specificity())
        {
            return Some(
                AccessDecision::new(principal, display, action, resource, grant, policy_hash)
                    .with_resource_policy_hash(resource_policy_hash),
            );
        }

        if let Some(grant) = self
            .access
            .iter()
            .filter(|grant| &grant.resource == resource && grant.role.permits(action))
            .max_by_key(|grant| grant.role.rank())
        {
            return Some(
                AccessDecision::new(principal, display, action, resource, grant, policy_hash)
                    .with_resource_policy_hash(resource_policy_hash),
            );
        }

        if access.owner == principal && Role::Owner.permits(action) {
            return Some(AccessDecision::record_policy(
                principal,
                display,
                action,
                resource,
                Role::Owner,
                policy_hash,
                resource_policy_hash,
            ));
        }

        if access.visibility == RecordVisibility::Shared && Role::Viewer.permits(action) {
            return Some(AccessDecision::record_policy(
                principal,
                display,
                action,
                resource,
                Role::Viewer,
                policy_hash,
                resource_policy_hash,
            ));
        }
        None
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(invalid("user name cannot be empty"));
        }
        if self
            .email
            .as_deref()
            .is_some_and(|email| email.trim().is_empty() || !email.contains('@'))
        {
            return Err(invalid("user email must be a non-empty email address"));
        }
        for (index, grant) in self.access.iter().enumerate() {
            if self.access[..index]
                .iter()
                .any(|earlier| earlier.resource == grant.resource)
            {
                return Err(invalid(format!(
                    "user has more than one access role for resource '{}'",
                    grant.resource
                )));
            }
        }
        if self.tokens.len() > MAX_USER_TOKENS {
            return Err(invalid(format!(
                "user has more than {MAX_USER_TOKENS} tokens"
            )));
        }
        for (index, token) in self.tokens.iter().enumerate() {
            token.validate()?;
            if self.tokens[..index]
                .iter()
                .any(|earlier| earlier.id == token.id)
            {
                return Err(invalid(format!(
                    "user has more than one token with ID '{}'",
                    token.id
                )));
            }
        }
        Ok(())
    }

    /// Add a token, refusing one past the per-principal bound.
    pub(crate) fn add_token(&mut self, token: UserToken) -> Result<()> {
        if self.tokens.len() >= MAX_USER_TOKENS {
            return Err(conflict(format!(
                "user already holds {MAX_USER_TOKENS} tokens; revoke one first"
            )));
        }
        self.tokens.push(token);
        Ok(())
    }

    /// Remove one token by ID, reporting whether it was present.
    pub(crate) fn revoke_token(&mut self, id: &str) -> bool {
        let before = self.tokens.len();
        self.tokens.retain(|token| token.id != id);
        self.tokens.len() != before
    }

    pub fn grant(&mut self, resource: Resource, role: Role) {
        if let Some(grant) = self
            .access
            .iter_mut()
            .find(|grant| grant.resource == resource)
        {
            grant.role = role;
        } else {
            self.access.push(AccessGrant { resource, role });
        }
        self.access.sort_by_key(|grant| grant.resource.to_string());
    }

    pub fn revoke(&mut self, resource: &Resource) -> bool {
        let before = self.access.len();
        self.access.retain(|grant| &grant.resource != resource);
        self.access.len() != before
    }

    pub fn is_database_owner(&self) -> bool {
        self.access
            .iter()
            .any(|grant| grant.resource == Resource::Database && grant.role == Role::Owner)
    }
}

/// The mutable, non-access portion of a user record.
///
/// `access` is intentionally absent. Grants continue to move exclusively
/// through `grant_access` and `revoke_access`, so an application-profile edit
/// cannot become a privilege escalation.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct UserUpdate {
    pub name: Option<String>,
    /// `None` leaves email unchanged; `Some(None)` clears it.
    pub email: Option<Option<String>>,
    pub kind: Option<UserKind>,
    pub status: Option<UserStatus>,
    /// Replace the complete application-owned profile mapping.
    pub profile: Option<Mapping>,
    /// Apply dotted-path changes inside the application-owned profile.
    pub profile_assignments: Vec<Assignment>,
}

impl UserUpdate {
    pub(crate) fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.email.is_none()
            && self.kind.is_none()
            && self.status.is_none()
            && self.profile.is_none()
            && self.profile_assignments.is_empty()
    }

    pub(crate) fn apply(self, user: &mut User) -> Result<()> {
        if let Some(name) = self.name {
            user.name = name;
        }
        if let Some(email) = self.email {
            user.email = email;
        }
        if let Some(kind) = self.kind {
            user.kind = kind;
        }
        if let Some(status) = self.status {
            user.status = status;
        }
        if let Some(profile) = self.profile {
            user.profile = profile;
        }
        for assignment in self.profile_assignments {
            assignment.apply(&mut user.profile)?;
        }
        Ok(())
    }

    /// Whether this update changes only application-owned profile data.
    pub(crate) fn is_profile_only(&self) -> bool {
        self.name.is_none()
            && self.email.is_none()
            && self.kind.is_none()
            && self.status.is_none()
            && (self.profile.is_some() || !self.profile_assignments.is_empty())
    }

    /// Whether the target principal may apply this update to itself.
    pub(crate) fn is_self_service(&self) -> bool {
        self.email.is_none()
            && self.kind.is_none()
            && self.status.is_none()
            && (self.name.is_some()
                || self.profile.is_some()
                || !self.profile_assignments.is_empty())
    }
}

/// The result of declaratively ensuring a principal exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserEnsureOutcome {
    Created,
    Unchanged,
}

/// Controls the exceptional reuse of an audited, deleted principal ID.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserRegistrationOptions {
    /// Allow a fresh user generation to be created over a delete tombstone.
    ///
    /// This deliberately joins both generations under one audit identity.
    pub reuse_deleted_id: bool,
}

/// Safety checks applied when deleting a registered principal.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserDeleteOptions {
    /// Refuse deletion once this identity has participated in any event other
    /// than changes to its own user record.
    pub if_unused: bool,
}

/// Whether a principal is a person or unattended software.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserKind {
    #[default]
    Human,
    Service,
}

/// Disabled users authenticate to no permissions.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    #[default]
    Active,
    Disabled,
}

impl fmt::Display for UserStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        })
    }
}

/// One role assigned to this principal at one resource scope.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessGrant {
    pub resource: Resource,
    pub role: Role,
}

/// The stored verifier for one principal token.
///
/// The token itself is shown once, when it is issued, and never stored. What
/// is kept is a domain-separated SHA-256 of it: the secret carries 256 random
/// bits, so a fast hash is the right verifier and is safe to leave readable to
/// whoever may read the user record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserToken {
    /// Public identifier, embedded in the token and recorded in every event
    /// the token authenticates.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub hash: String,
    /// When it was issued, as an RFC 3339 UTC timestamp.
    pub created: String,
    /// When it stops authenticating, as an RFC 3339 UTC timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// What may be shown about a token after it was issued: everything but its
/// verifier, which is useless to a reader and is nobody's business.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TokenSummary {
    pub principal: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    pub expired: bool,
}

/// A newly issued token: the secret to hand over once, and what is stored.
#[derive(Debug)]
pub struct IssuedToken {
    pub token: zeroize::Zeroizing<String>,
    pub stored: UserToken,
}

impl UserToken {
    /// Generate a token and its stored verifier.
    pub(crate) fn issue(
        label: Option<String>,
        created: OffsetDateTime,
        expires: Option<OffsetDateTime>,
    ) -> Result<IssuedToken> {
        let label = label.map(|label| label.trim().to_owned());
        let mut id = [0_u8; TOKEN_ID_BYTES];
        let mut secret = zeroize::Zeroizing::new([0_u8; TOKEN_SECRET_BYTES]);
        getrandom::fill(&mut id)
            .and_then(|()| getrandom::fill(secret.as_mut_slice()))
            .map_err(|_| conflict("secure randomness is unavailable"))?;
        let id = id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let token = zeroize::Zeroizing::new(format!(
            "{TOKEN_PREFIX}{id}_{}",
            URL_SAFE_NO_PAD.encode(secret.as_slice())
        ));
        let stored = Self {
            id,
            label,
            hash: token_hash(&token),
            created: rfc3339(created)?,
            expires: expires.map(rfc3339).transpose()?,
        };
        stored.validate()?;
        Ok(IssuedToken { token, stored })
    }

    /// Whether `token` is the secret this verifier was made from.
    ///
    /// The comparison runs over every byte whatever the first difference, so
    /// its time does not say how much of a guess was right.
    pub(crate) fn verifies(&self, token: &str) -> bool {
        let expected = self.hash.as_bytes();
        let actual = token_hash(token);
        let actual = actual.as_bytes();
        expected.len() == actual.len()
            && expected
                .iter()
                .zip(actual)
                .fold(0_u8, |difference, (left, right)| {
                    difference | (left ^ right)
                })
                == 0
    }

    pub fn summary(&self, principal: &str, now: OffsetDateTime) -> TokenSummary {
        TokenSummary {
            principal: principal.to_owned(),
            id: self.id.clone(),
            label: self.label.clone(),
            created: self.created.clone(),
            expires: self.expires.clone(),
            expired: self.expired_at(now),
        }
    }

    /// Whether this token no longer authenticates at `now`.
    pub fn expired_at(&self, now: OffsetDateTime) -> bool {
        self.expires
            .as_deref()
            .and_then(|expires| OffsetDateTime::parse(expires, &Rfc3339).ok())
            .is_some_and(|expires| expires <= now)
    }

    fn validate(&self) -> Result<()> {
        if self.id.len() != TOKEN_ID_BYTES * 2
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid(format!(
                "token ID '{}' must be {} lowercase hexadecimal characters",
                self.id,
                TOKEN_ID_BYTES * 2
            )));
        }
        if let Some(label) = &self.label
            && (label.is_empty()
                || label.chars().count() > MAX_TOKEN_LABEL_CHARS
                || label.chars().any(char::is_control))
        {
            return Err(invalid(format!(
                "token label must be 1 to {MAX_TOKEN_LABEL_CHARS} characters without control characters"
            )));
        }
        let hash_is_valid = self.hash.strip_prefix("sha256:").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if !hash_is_valid {
            return Err(invalid(format!(
                "token '{}' must store a sha256: verifier",
                self.id
            )));
        }
        let created = OffsetDateTime::parse(&self.created, &Rfc3339).map_err(|_| {
            invalid(format!(
                "token '{}' has an invalid created timestamp",
                self.id
            ))
        })?;
        if let Some(expires) = &self.expires {
            let expires = OffsetDateTime::parse(expires, &Rfc3339).map_err(|_| {
                invalid(format!(
                    "token '{}' has an invalid expires timestamp",
                    self.id
                ))
            })?;
            if expires <= created {
                return Err(invalid(format!(
                    "token '{}' must expire after it was created",
                    self.id
                )));
            }
        }
        Ok(())
    }
}

/// The public ID inside a principal token, or `None` for anything that does
/// not have a token's shape.
pub fn token_id(token: &str) -> Option<&str> {
    let (id, secret) = token.strip_prefix(TOKEN_PREFIX)?.split_once('_')?;
    (id.len() == TOKEN_ID_BYTES * 2
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !secret.is_empty())
    .then_some(id)
}

fn token_hash(token: &str) -> String {
    digest(TOKEN_HASH_DOMAIN, token.as_bytes())
}

fn rfc3339(moment: OffsetDateTime) -> Result<String> {
    moment
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .map_err(|error| invalid(format!("invalid timestamp: {error}")))?
        .format(&Rfc3339)
        .map_err(|error| invalid(format!("invalid timestamp: {error}")))
}

/// How the principal of an allowed mutation was established, when a server
/// checked it rather than taking the caller's word.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Authentication {
    pub method: AuthenticationMethod,
    /// The public ID of the credential that passed, such as a token ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

/// RBAC roles exposed by the CLI and stored in user records.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Viewer,
    Editor,
    AccessManager,
    Owner,
}

impl Role {
    pub fn permits(self, action: AccessAction) -> bool {
        match self {
            Self::Viewer => matches!(
                action,
                AccessAction::Discover | AccessAction::Read | AccessAction::ReadAudit
            ),
            Self::Editor => matches!(
                action,
                AccessAction::Discover
                    | AccessAction::Read
                    | AccessAction::ReadAudit
                    | AccessAction::Create
                    | AccessAction::Update
                    | AccessAction::Link
            ),
            Self::AccessManager => matches!(
                action,
                AccessAction::Discover | AccessAction::ReadAccess | AccessAction::ManageAccess
            ),
            Self::Owner => true,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Viewer => 1,
            Self::Editor => 2,
            Self::AccessManager => 3,
            Self::Owner => 4,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Viewer => "viewer",
            Self::Editor => "editor",
            Self::AccessManager => "access_manager",
            Self::Owner => "owner",
        })
    }
}

impl FromStr for Role {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "editor" => Ok(Self::Editor),
            "access_manager" | "access-manager" => Ok(Self::AccessManager),
            "owner" => Ok(Self::Owner),
            _ => Err(invalid(format!(
                "role must be viewer, editor, access_manager, or owner, not '{value}'"
            ))),
        }
    }
}

/// Operations authorization can permit independently.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    Discover,
    Read,
    Create,
    Update,
    Link,
    Delete,
    ReadAudit,
    ReadAccess,
    ManageAccess,
}

impl fmt::Display for AccessAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Discover => "discover",
            Self::Read => "read",
            Self::Create => "create",
            Self::Update => "update",
            Self::Link => "link",
            Self::Delete => "delete",
            Self::ReadAudit => "read_audit",
            Self::ReadAccess => "read_access",
            Self::ManageAccess => "manage_access",
        })
    }
}

impl FromStr for AccessAction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "discover" => Ok(Self::Discover),
            "read" => Ok(Self::Read),
            "create" => Ok(Self::Create),
            "update" | "edit" => Ok(Self::Update),
            "link" => Ok(Self::Link),
            "delete" => Ok(Self::Delete),
            "read_audit" | "read-audit" => Ok(Self::ReadAudit),
            "read_access" | "read-access" => Ok(Self::ReadAccess),
            "manage_access" | "manage-access" => Ok(Self::ManageAccess),
            _ => Err(invalid(format!("unknown access action '{value}'"))),
        }
    }
}

/// A database, collection, or individual record protected by RBAC.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Resource {
    Database,
    Collection { collection: String },
    Record { collection: String, id: String },
}

impl Resource {
    pub fn collection(collection: impl Into<String>) -> Self {
        Self::Collection {
            collection: collection.into(),
        }
    }

    pub fn record(collection: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Record {
            collection: collection.into(),
            id: id.into(),
        }
    }

    fn specificity(&self) -> u8 {
        match self {
            Self::Database => 0,
            Self::Collection { .. } => 1,
            Self::Record { .. } => 2,
        }
    }

    pub(crate) fn contains(&self, target: &Self) -> bool {
        match (self, target) {
            (Self::Database, _) => true,
            (
                Self::Collection { collection },
                Self::Collection { collection: target }
                | Self::Record {
                    collection: target, ..
                },
            ) => collection == target,
            (
                Self::Record { collection, id },
                Self::Record {
                    collection: target_collection,
                    id: target_id,
                },
            ) => collection == target_collection && id == target_id,
            _ => false,
        }
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database => formatter.write_str("database"),
            Self::Collection { collection } => write!(formatter, "collection:{collection}"),
            Self::Record { collection, id } => write!(formatter, "record:{collection}/{id}"),
        }
    }
}

impl FromStr for Resource {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if value == "database" {
            return Ok(Self::Database);
        }
        if let Some(collection) = value.strip_prefix("collection:") {
            validate_part(collection, "collection")?;
            return Ok(Self::collection(collection));
        }
        if let Some(reference) = value.strip_prefix("record:") {
            let (collection, id) = reference
                .split_once('/')
                .ok_or_else(|| invalid("record resource must be record:COLLECTION/ID"))?;
            if id.contains('/') {
                return Err(invalid("record resource must contain exactly one '/'"));
            }
            validate_part(collection, "collection")?;
            validate_part(id, "id")?;
            return Ok(Self::record(collection, id));
        }
        Err(invalid(format!(
            "resource must be database, collection:NAME, or record:COLLECTION/ID, not '{value}'"
        )))
    }
}

impl Serialize for Resource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Resource {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Evidence recorded beside an allowed record mutation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessDecision {
    pub principal: String,
    pub display: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<AccessIdentity>,
    /// How a server authenticated `principal`. Absent when the principal is
    /// the process's own assertion, as it was for every event before tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    pub action: AccessAction,
    pub resource: Resource,
    pub role: Role,
    pub granted_at: Resource,
    /// Whether permission came from stored policy (a user grant or CR-managed
    /// record policy) or the built-in self-service user rule.
    #[serde(default, skip_serializing_if = "AccessDecisionBasis::is_grant")]
    pub basis: AccessDecisionBasis,
    pub policy_hash: String,
    /// Hash of CR-managed record policy when a creator-owned collection made
    /// or constrained this decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_policy_hash: Option<String>,
}

/// Why an access decision was allowed.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecisionBasis {
    #[default]
    Grant,
    SelfService,
}

impl AccessDecisionBasis {
    fn is_grant(&self) -> bool {
        *self == Self::Grant
    }
}

impl AccessDecision {
    fn new(
        principal: &str,
        display: &str,
        action: AccessAction,
        resource: &Resource,
        grant: &AccessGrant,
        policy_hash: &str,
    ) -> Self {
        Self {
            principal: principal.to_owned(),
            display: display.to_owned(),
            impersonated_by: None,
            authentication: None,
            action,
            resource: resource.clone(),
            role: grant.role,
            granted_at: grant.resource.clone(),
            basis: AccessDecisionBasis::Grant,
            policy_hash: policy_hash.to_owned(),
            resource_policy_hash: None,
        }
    }

    fn with_resource_policy_hash(mut self, resource_policy_hash: &str) -> Self {
        self.resource_policy_hash = Some(resource_policy_hash.to_owned());
        self
    }

    fn record_policy(
        principal: &str,
        display: &str,
        action: AccessAction,
        resource: &Resource,
        role: Role,
        policy_hash: &str,
        resource_policy_hash: &str,
    ) -> Self {
        Self {
            principal: principal.to_owned(),
            display: display.to_owned(),
            impersonated_by: None,
            authentication: None,
            action,
            resource: resource.clone(),
            role,
            granted_at: resource.clone(),
            basis: AccessDecisionBasis::Grant,
            policy_hash: policy_hash.to_owned(),
            resource_policy_hash: Some(resource_policy_hash.to_owned()),
        }
    }

    pub(crate) fn self_service(
        principal: &str,
        display: &str,
        resource: Resource,
        policy_hash: &str,
    ) -> Self {
        Self {
            principal: principal.to_owned(),
            display: display.to_owned(),
            impersonated_by: None,
            authentication: None,
            action: AccessAction::Update,
            granted_at: resource.clone(),
            resource,
            role: Role::Editor,
            basis: AccessDecisionBasis::SelfService,
            policy_hash: policy_hash.to_owned(),
            resource_policy_hash: None,
        }
    }
}

/// The owner operating an explicitly impersonated server perspective.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessIdentity {
    pub principal: String,
    pub display: String,
}

/// The stable policy identity derived from the human-readable actor.
pub fn principal_id(actor: &str) -> Result<String> {
    let actor = actor.trim();
    if actor.is_empty() {
        return Err(invalid("principal cannot be empty"));
    }
    let identity = actor
        .strip_suffix('>')
        .and_then(|value| value.rsplit_once('<').map(|(_, email)| email.trim()))
        .filter(|email| !email.is_empty())
        .unwrap_or(actor);
    if identity.contains('/') || identity.contains('\\') || identity.contains('\0') {
        return Err(invalid("principal cannot contain path separators"));
    }
    Ok(if identity.contains('@') {
        identity.to_lowercase()
    } else {
        identity.to_owned()
    })
}

/// A display name suitable for the first bootstrapped user record.
pub fn display_name(actor: &str) -> String {
    actor
        .split_once('<')
        .map(|(name, _)| name.trim())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| actor.trim())
        .to_owned()
}

/// The built-in schema exposed for the reserved `users` collection.
pub fn users_schema() -> JsonValue {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "email": { "type": "string", "format": "email" },
            "kind": { "enum": ["human", "service"] },
            "status": { "enum": ["active", "disabled"] },
            "profile": {
                "type": "object",
                "additionalProperties": true
            },
            "access": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["resource", "role"],
                    "properties": {
                        "resource": { "type": "string", "minLength": 1 },
                        "role": { "enum": ["viewer", "editor", "access_manager", "owner"] }
                    }
                }
            },
            "tokens": {
                "type": "array",
                "maxItems": MAX_USER_TOKENS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "hash", "created"],
                    "properties": {
                        "id": { "type": "string", "pattern": "^[0-9a-f]{16}$" },
                        "label": { "type": "string", "minLength": 1 },
                        "hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                        "created": { "type": "string" },
                        "expires": { "type": "string" }
                    }
                }
            }
        }
    })
}

fn validate_part(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
    {
        return Err(invalid(format!("{label} is not a usable path component")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};

    use super::{
        AccessAction, AccessGrant, MAX_USER_TOKENS, RecordAccess, RecordVisibility, Resource, Role,
        TOKEN_PREFIX, User, UserKind, UserStatus, UserToken, principal_id, token_id,
    };

    fn user(access: Vec<AccessGrant>) -> User {
        User {
            name: "Ada".into(),
            email: Some("ada@example.com".into()),
            kind: UserKind::Human,
            status: UserStatus::Active,
            profile: Default::default(),
            access,
            tokens: Vec::new(),
        }
    }

    #[test]
    fn principal_prefers_and_normalizes_the_email() {
        assert_eq!(
            principal_id("Ada Lovelace <ADA@Example.com>").unwrap(),
            "ada@example.com"
        );
        assert_eq!(principal_id("local-user").unwrap(), "local-user");
    }

    #[test]
    fn collection_grants_inherit_and_record_grants_override() {
        let user = user(vec![
            AccessGrant {
                resource: Resource::collection("deals"),
                role: Role::Editor,
            },
            AccessGrant {
                resource: Resource::record("deals", "sensitive"),
                role: Role::Viewer,
            },
        ]);
        assert!(
            user.decision(
                "ada@example.com",
                "Ada <ada@example.com>",
                AccessAction::Update,
                &Resource::record("deals", "ordinary"),
                "sha256:policy",
            )
            .is_some()
        );
        assert!(
            user.decision(
                "ada@example.com",
                "Ada <ada@example.com>",
                AccessAction::Update,
                &Resource::record("deals", "sensitive"),
                "sha256:policy",
            )
            .is_none()
        );
    }

    #[test]
    fn record_owned_policy_stops_collection_inheritance_but_keeps_direct_grants() {
        let user = user(vec![
            AccessGrant {
                resource: Resource::collection("secrets"),
                role: Role::Editor,
            },
            AccessGrant {
                resource: Resource::record("secrets", "shared-with-ada"),
                role: Role::Editor,
            },
        ]);
        let private = RecordAccess::new("bob@example.com", RecordVisibility::Private).unwrap();
        let shared = RecordAccess::new("bob@example.com", RecordVisibility::Shared).unwrap();

        assert!(
            user.record_owned_decision(
                "ada@example.com",
                "Ada",
                AccessAction::Read,
                &Resource::record("secrets", "private"),
                &private,
                "sha256:user",
                "sha256:record",
            )
            .is_none()
        );
        assert!(
            user.record_owned_decision(
                "ada@example.com",
                "Ada",
                AccessAction::Read,
                &Resource::record("secrets", "shared"),
                &shared,
                "sha256:user",
                "sha256:record",
            )
            .is_some()
        );
        assert!(
            user.record_owned_decision(
                "ada@example.com",
                "Ada",
                AccessAction::Update,
                &Resource::record("secrets", "shared"),
                &shared,
                "sha256:user",
                "sha256:record",
            )
            .is_none()
        );
        assert!(
            user.record_owned_decision(
                "ada@example.com",
                "Ada",
                AccessAction::Update,
                &Resource::record("secrets", "shared-with-ada"),
                &private,
                "sha256:user",
                "sha256:record",
            )
            .is_some()
        );
    }

    #[test]
    fn database_ownership_is_not_narrowed_by_a_specific_grant() {
        let user = user(vec![
            AccessGrant {
                resource: Resource::Database,
                role: Role::Owner,
            },
            AccessGrant {
                resource: Resource::record("deals", "sensitive"),
                role: Role::Viewer,
            },
        ]);
        assert!(
            user.decision(
                "ada@example.com",
                "Ada <ada@example.com>",
                AccessAction::Delete,
                &Resource::record("deals", "sensitive"),
                "sha256:policy",
            )
            .is_some()
        );
    }

    #[test]
    fn an_issued_token_verifies_only_its_own_secret() {
        let created = OffsetDateTime::now_utc();
        let issued = UserToken::issue(Some("nightly".into()), created, None).unwrap();
        let token = issued.token.as_str();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert_eq!(token_id(token), Some(issued.stored.id.as_str()));
        assert!(issued.stored.hash.starts_with("sha256:"));
        assert!(!issued.stored.hash.contains(token));
        assert!(issued.stored.verifies(token));

        let (prefix, secret) = token.rsplit_once('_').unwrap();
        let mut forged = secret.to_owned();
        let last = forged.pop().unwrap();
        forged.push(if last == 'A' { 'B' } else { 'A' });
        assert!(!issued.stored.verifies(&format!("{prefix}_{forged}")));
        assert!(!issued.stored.verifies(""));

        let other = UserToken::issue(None, created, None).unwrap();
        assert_ne!(other.stored.id, issued.stored.id);
        assert!(!issued.stored.verifies(&other.token));
    }

    #[test]
    fn token_ids_are_read_only_from_a_tokens_shape() {
        assert_eq!(
            token_id("crt_0123456789abcdef_secret"),
            Some("0123456789abcdef")
        );
        for malformed in [
            "",
            "secret",
            "crt_",
            "crt_0123456789abcdef",
            "crt_0123456789abcdef_",
            "crt_0123456789ABCDEF_secret",
            "crt_0123456789abcde_secret",
            "Bearer crt_0123456789abcdef_secret",
        ] {
            assert_eq!(token_id(malformed), None, "{malformed:?}");
        }
    }

    #[test]
    fn a_token_expires_at_its_expiry_and_not_before() {
        let created = OffsetDateTime::now_utc();
        let expires = created + Duration::hours(1);
        let issued = UserToken::issue(None, created, Some(expires)).unwrap();
        assert!(!issued.stored.expired_at(created));
        assert!(issued.stored.expired_at(expires));
        assert!(issued.stored.expired_at(expires + Duration::seconds(1)));
        assert!(UserToken::issue(None, created, Some(created - Duration::hours(1))).is_err());
        let summary = issued.stored.summary("ada@example.com", expires);
        assert!(summary.expired);
        assert_eq!(summary.principal, "ada@example.com");
    }

    #[test]
    fn stored_tokens_are_validated_with_the_user() {
        let issued = UserToken::issue(None, OffsetDateTime::now_utc(), None).unwrap();
        let mut ada = user(Vec::new());
        ada.add_token(issued.stored.clone()).unwrap();
        assert!(ada.validate().is_ok());

        let mut duplicate = ada.clone();
        duplicate.tokens.push(issued.stored.clone());
        assert!(duplicate.validate().is_err());

        for broken in [
            UserToken {
                id: "not-hex".into(),
                ..issued.stored.clone()
            },
            UserToken {
                hash: "md5:abc".into(),
                ..issued.stored.clone()
            },
            UserToken {
                created: "yesterday".into(),
                ..issued.stored.clone()
            },
            UserToken {
                label: Some("two\nlines".into()),
                ..issued.stored.clone()
            },
        ] {
            let mut ada = user(Vec::new());
            ada.tokens.push(broken);
            assert!(ada.validate().is_err());
        }

        let mut full = user(Vec::new());
        for _ in 0..MAX_USER_TOKENS {
            full.add_token(
                UserToken::issue(None, OffsetDateTime::now_utc(), None)
                    .unwrap()
                    .stored,
            )
            .unwrap();
        }
        assert!(
            full.add_token(
                UserToken::issue(None, OffsetDateTime::now_utc(), None)
                    .unwrap()
                    .stored
            )
            .is_err()
        );
        assert!(full.revoke_token(&full.tokens[0].id.clone()));
        assert!(!full.revoke_token("0000000000000000"));
    }
}
