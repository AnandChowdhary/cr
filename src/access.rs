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
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value as JsonValue, json};
use yaml_serde::{Mapping, Value};

use crate::{error::invalid, value::Assignment};

/// The collection CR reserves for authenticated principals and their grants.
pub const USERS_COLLECTION: &str = "users";

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
        Ok(())
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

    fn contains(&self, target: &Self) -> bool {
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
    pub action: AccessAction,
    pub resource: Resource,
    pub role: Role,
    pub granted_at: Resource,
    /// Whether permission came from a stored grant or the built-in rule that
    /// lets an active principal maintain its own name and profile.
    #[serde(default, skip_serializing_if = "AccessDecisionBasis::is_grant")]
    pub basis: AccessDecisionBasis,
    pub policy_hash: String,
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
            action,
            resource: resource.clone(),
            role: grant.role,
            granted_at: grant.resource.clone(),
            basis: AccessDecisionBasis::Grant,
            policy_hash: policy_hash.to_owned(),
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
            action: AccessAction::Update,
            granted_at: resource.clone(),
            resource,
            role: Role::Editor,
            basis: AccessDecisionBasis::SelfService,
            policy_hash: policy_hash.to_owned(),
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
    use super::{
        AccessAction, AccessGrant, Resource, Role, User, UserKind, UserStatus, principal_id,
    };

    fn user(access: Vec<AccessGrant>) -> User {
        User {
            name: "Ada".into(),
            email: Some("ada@example.com".into()),
            kind: UserKind::Human,
            status: UserStatus::Active,
            profile: Default::default(),
            access,
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
}
