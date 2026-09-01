mod attribution;
mod audit;
mod check;
mod database;
mod error;
mod frontmatter;
mod paths;
mod search;
pub mod server;
mod sync;
mod value;
mod views;

pub use attribution::{
    AgentEvidence, Attribution, AttributionOverrides, AuditAgent, AuditAuthorization, AuditIntent,
    AuditIntentPart, AuthorizationMode, IntentAuthor, parse_agent, parse_authorization,
    parse_intent,
};
pub use audit::{
    AnchorReport, AnchorStatus, AuditAction, AuditAnchor, AuditChange, AuditEntry, AuditFilter,
    AuditHead, AuditSource, AuditVerification, ChangePreview,
};
pub use check::{
    CheckReport, CheckScope, CheckSummary, Finding, FindingKind, Severity, parse_threshold,
};
pub use database::{
    CollectionModel, Database, Record, SortDirection, WorkingChange, WorkingChangeKind,
    sort_records_by_field,
};
pub use error::DomainError;
pub use search::{SearchQuery, SearchTarget};
pub use sync::{SyncAttribution, SyncDefinition, SyncRunLedger, SyncRunSummary};
pub use value::{Assignment, FilterExpression, FilterOperator, compare_yaml_values};
pub use views::{ViewDefinition, ViewFilterGroup, ViewLayout, ViewPredicateMatch};
