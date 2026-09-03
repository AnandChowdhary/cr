use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    net::SocketAddr,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, RawForm, RawQuery, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use percent_encoding::{
    AsciiSet, CONTROLS, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value as JsonValue, json};
use sha2::{Digest, Sha256};
use yaml_serde::{Mapping, Value as YamlValue};

use crate::{
    AccessAction, AccessIdentity, AccessResource, AgentEvidence, Assignment, Attribution,
    AttributionOverrides, AuditAgent, AuditAuthorization, AuditEntry, AuditFilter, AuditIntent,
    AuditIntentPart, AuditSource, CheckScope, CheckSummary, CollectionModel, Database, DomainError,
    FilterExpression, FilterOperator, Finding, Record, RecordPrecondition, SearchQuery,
    SearchTarget, SortDirection, UserStatus, ViewDefinition, ViewFilterGroup, ViewLayout,
    ViewPredicateMatch, audit::AuditChange, sort_records_by_field,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const DEFAULT_MAX_PAGE_SIZE: usize = 200;
const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE_OFFSET: usize = 1_000_000;
const MAX_VIEW_FILTERS: usize = 20;
const MAX_VIEW_COLUMNS: usize = 50;
const ACTOR_HEADER: &str = "x-cr-actor";
/// Attribution headers. Like `X-CR-Actor`, every one of them is an assertion by
/// the caller: the server records what it is told and authenticates none of it.
const AGENT_HEADER: &str = "x-cr-agent";
const AUTHORIZATION_ATTRIBUTION_HEADER: &str = "x-cr-authorization";
const INTENT_HEADER: &str = "x-cr-intent";
/// The digest of a change set a caller previewed and approved.
///
/// A precondition as well as a recorded value: a mutation whose change set
/// hashes differently is refused. Like `If-Match`, and unlike the attribution
/// headers beside it, omitting it is not neutral — it is the difference between
/// a checked write and an unchecked one, which is why the event records
/// whether it was present.
const APPROVED_CHANGES_HEADER: &str = "x-cr-approved-changes";
const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const REQUEST_ID_HEADER: &str = "x-request-id";
const PERSPECTIVE_COOKIE: &str = "cr_perspective";
/// The only message an unexpected failure may reveal. Everything else about it
/// stays in the server log, correlated by request ID.
const INTERNAL_MESSAGE: &str =
    "the server could not complete this request; quote the request ID when reporting it";
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub max_page_size: usize,
    pub max_body_bytes: usize,
    pub api_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:3000"
                .parse()
                .expect("default bind address is valid"),
            max_page_size: DEFAULT_MAX_PAGE_SIZE,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            api_token: None,
        }
    }
}

#[derive(Clone)]
struct AppState {
    database: Database,
    access_controlled: bool,
    max_page_size: usize,
    api_token: Option<Arc<str>>,
    csrf_token: Arc<str>,
}

#[derive(Clone, Debug)]
struct UiUser {
    id: String,
    name: String,
    role: String,
    status: UserStatus,
}

#[derive(Clone, Debug)]
struct UiContext {
    operator: AccessIdentity,
    selected: String,
    selected_name: String,
    selected_status: UserStatus,
    can_view_global_audit: bool,
    users: Vec<UiUser>,
}

#[derive(Clone, Copy, Debug)]
struct RecordPermissions {
    update: bool,
    delete: bool,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ApiRecord {
    collection: String,
    id: String,
    path: String,
    version: String,
    front_matter: JsonValue,
    markdown: String,
}

#[derive(Debug, Serialize)]
struct ApiRecordSummary {
    path: String,
    version: String,
    front_matter: JsonValue,
}

impl TryFrom<Record> for ApiRecord {
    type Error = ApiError;

    fn try_from(record: Record) -> ApiResult<Self> {
        Ok(Self {
            collection: record.collection,
            id: record.id,
            path: display_path(&record.path),
            version: record.version,
            front_matter: json_front_matter(record.attributes)?,
            markdown: record.body,
        })
    }
}

impl TryFrom<Record> for ApiRecordSummary {
    type Error = ApiError;

    fn try_from(record: Record) -> ApiResult<Self> {
        Ok(Self {
            path: display_path(&record.path),
            version: record.version,
            front_matter: json_front_matter(record.attributes)?,
        })
    }
}

#[derive(Debug, Serialize)]
struct Page<T> {
    data: Vec<T>,
    pagination: Pagination,
}

#[derive(Debug, Serialize)]
struct Pagination {
    limit: usize,
    offset: usize,
    returned: usize,
    total: Option<usize>,
    has_more: bool,
    next_offset: Option<usize>,
    previous_offset: Option<usize>,
}

/// Whether a mutating request should compute its change set instead of writing.
///
/// This lives in the request target rather than a header on purpose. It changes
/// what the request *does*, so it belongs in the URI, and a header is the one
/// part of a request an intermediary may rewrite. `deny_unknown_fields` makes a
/// misspelled parameter a rejection rather than an unintended write.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewQuery {
    #[serde(default)]
    preview: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Scope and window for an integrity report.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckQuery {
    collection: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default, rename = "where")]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    sort: Option<String>,
    #[serde(default)]
    direction: SortDirectionParameter,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewQuery {
    q: Option<String>,
    #[serde(default)]
    filter_match: ViewFilterMatch,
    #[serde(default)]
    filter_field: Vec<String>,
    #[serde(default)]
    filter_operator: Vec<ViewFilterOperator>,
    #[serde(default)]
    filter_value: Vec<String>,
    sort_field: Option<String>,
    #[serde(default)]
    sort_direction: ViewSortDirection,
    #[serde(default)]
    columns: ViewColumnsMode,
    #[serde(default)]
    column: Vec<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    notice: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ViewColumnsMode {
    #[default]
    Default,
    Custom,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ViewFilterMatch {
    #[default]
    All,
    Any,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ViewSortDirection {
    #[default]
    Asc,
    Desc,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SortDirectionParameter {
    #[default]
    Asc,
    Desc,
}

impl From<SortDirectionParameter> for SortDirection {
    fn from(direction: SortDirectionParameter) -> Self {
        match direction {
            SortDirectionParameter::Asc => Self::Asc,
            SortDirectionParameter::Desc => Self::Desc,
        }
    }
}

impl From<ViewSortDirection> for SortDirection {
    fn from(direction: ViewSortDirection) -> Self {
        match direction {
            ViewSortDirection::Asc => Self::Asc,
            ViewSortDirection::Desc => Self::Desc,
        }
    }
}

impl ViewSortDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ViewFilterOperator {
    #[default]
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    IsEmpty,
    IsNotEmpty,
}

impl ViewFilterOperator {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Contains => "contains",
            Self::NotContains => "not-contains",
            Self::StartsWith => "starts-with",
            Self::EndsWith => "ends-with",
            Self::IsEmpty => "is-empty",
            Self::IsNotEmpty => "is-not-empty",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Eq => "is",
            Self::Ne => "is not",
            Self::Gt => "is greater than",
            Self::Gte => "is at least",
            Self::Lt => "is less than",
            Self::Lte => "is at most",
            Self::Contains => "contains",
            Self::NotContains => "does not contain",
            Self::StartsWith => "starts with",
            Self::EndsWith => "ends with",
            Self::IsEmpty => "is empty",
            Self::IsNotEmpty => "is not empty",
        }
    }

    fn requires_value(self) -> bool {
        !matches!(self, Self::IsEmpty | Self::IsNotEmpty)
    }

    fn expression_token(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Contains => " contains ",
            Self::NotContains => " not-contains ",
            Self::StartsWith => " starts-with ",
            Self::EndsWith => " ends-with ",
            Self::IsEmpty => " is-empty",
            Self::IsNotEmpty => " is-not-empty",
        }
    }
}

impl From<ViewFilterOperator> for FilterOperator {
    fn from(operator: ViewFilterOperator) -> Self {
        match operator {
            ViewFilterOperator::Eq => Self::Equal,
            ViewFilterOperator::Ne => Self::NotEqual,
            ViewFilterOperator::Gt => Self::GreaterThan,
            ViewFilterOperator::Gte => Self::GreaterThanOrEqual,
            ViewFilterOperator::Lt => Self::LessThan,
            ViewFilterOperator::Lte => Self::LessThanOrEqual,
            ViewFilterOperator::Contains => Self::Contains,
            ViewFilterOperator::NotContains => Self::NotContains,
            ViewFilterOperator::StartsWith => Self::StartsWith,
            ViewFilterOperator::EndsWith => Self::EndsWith,
            ViewFilterOperator::IsEmpty => Self::IsEmpty,
            ViewFilterOperator::IsNotEmpty => Self::IsNotEmpty,
        }
    }
}

impl ViewFilterMatch {
    fn matches(self, filters: &[FilterExpression], attributes: &Mapping) -> bool {
        filters.is_empty()
            || match self {
                Self::All => filters.iter().all(|filter| filter.matches(attributes)),
                Self::Any => filters.iter().any(|filter| filter.matches(attributes)),
            }
    }
}

fn saved_filter_group_matches(
    match_mode: ViewPredicateMatch,
    expressions: &[FilterExpression],
    attributes: &Mapping,
) -> bool {
    match match_mode {
        ViewPredicateMatch::All => expressions
            .iter()
            .all(|expression| expression.matches(attributes)),
        ViewPredicateMatch::Any => expressions
            .iter()
            .any(|expression| expression.matches(attributes)),
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditViewQuery {
    collection: Option<String>,
    id: Option<String>,
    agent: Option<String>,
    session: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug)]
struct HtmlDocumentForm {
    csrf: String,
    expected_record_hash: Option<String>,
    id: Option<String>,
    front_matter: Option<String>,
    markdown: String,
    structured: bool,
    additional_attributes: String,
    fields: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug)]
struct SchemaFormField {
    key: String,
    label: String,
    description: Option<String>,
    required: bool,
    value: Option<YamlValue>,
    kind: SchemaFieldKind,
}

#[derive(Clone, Debug)]
struct ViewFilterField {
    key: String,
    label: String,
    kind: SchemaFieldKind,
}

#[derive(Clone, Debug)]
enum SchemaFieldKind {
    Select(Vec<YamlValue>),
    MultiSelect(Vec<YamlValue>),
    String {
        input_type: &'static str,
        min_length: Option<usize>,
        max_length: Option<usize>,
    },
    Integer {
        minimum: Option<String>,
        maximum: Option<String>,
    },
    Number {
        minimum: Option<String>,
        maximum: Option<String>,
    },
    Boolean,
    Yaml,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlDeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(rename = "_expected_record_hash")]
    expected_record_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlPerspectiveForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    principal: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlKanbanMoveForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    target: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlSaveViewForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    filter_match: ViewFilterMatch,
    #[serde(default)]
    filter_field: Vec<String>,
    #[serde(default)]
    filter_operator: Vec<ViewFilterOperator>,
    #[serde(default)]
    filter_value: Vec<String>,
    sort_field: Option<String>,
    #[serde(default)]
    sort_direction: ViewSortDirection,
    #[serde(default)]
    column: Vec<String>,
    layout: Option<ViewLayout>,
    group_by: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum KanbanTarget {
    Value { value: String },
    Unset,
}

struct KanbanLane<'a> {
    target: KanbanTarget,
    label: String,
    records: Vec<&'a Record>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SearchTargetParameter {
    Document,
    FrontMatter,
    Field,
    Body,
    Path,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchParameters {
    q: String,
    collection: Option<String>,
    #[serde(default, rename = "where")]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    sort: Option<String>,
    #[serde(default)]
    direction: SortDirectionParameter,
    target: Option<SearchTargetParameter>,
    field: Option<String>,
    #[serde(default)]
    ignore_case: bool,
    #[serde(default)]
    regex: bool,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditLogParameters {
    collection: Option<String>,
    id: Option<String>,
    agent: Option<String>,
    session: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditVerifyParameters {
    expected_head: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecordRequest {
    id: String,
    #[serde(default)]
    front_matter: Mapping,
    #[serde(default)]
    markdown: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRecordRequest {
    #[serde(default)]
    front_matter: Mapping,
    #[serde(default)]
    remove: Vec<String>,
    markdown: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceRecordRequest {
    front_matter: Mapping,
    markdown: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkRequest {
    relation: String,
    target_collection: String,
    target_id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveRequest {
    #[serde(default)]
    records: Vec<String>,
    #[serde(default)]
    all: bool,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    deleted: bool,
    record: ApiRecord,
}

#[derive(Debug, Serialize)]
struct BaselineResponse {
    added: usize,
}

#[derive(Debug, Serialize)]
struct IdentityResponse {
    actor: String,
    principal: String,
    impersonated_by: Option<AccessIdentity>,
    agent: Option<AuditAgent>,
    authorization: Option<AuditAuthorization>,
    intent: Option<AuditIntent>,
}

type ApiResult<T> = std::result::Result<T, ApiError>;

/// A failure on its way back to a caller.
///
/// `message` is the only text a caller ever sees, so every construction site
/// keeps it free of filesystem paths, operating-system errors, and other
/// internal context. `detail` carries the complete `anyhow` chain, which is
/// written to the server log and never serialized into a response.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    detail: Option<anyhow::Error>,
}

/// An error after logging and redaction, shared by the JSON and HTML renderers.
struct PublicError {
    status: StatusCode,
    code: &'static str,
    message: String,
    request_id: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    request_id: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            detail: None,
        }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    fn unprocessable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            message,
        )
    }

    /// Report a failure that no caller can act on, keeping its diagnostics.
    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: INTERNAL_MESSAGE.to_owned(),
            detail: Some(error),
        }
    }

    /// Classify a failure from the domain layer by its typed [`DomainError`],
    /// falling back to an unexpected-failure response when it carries none.
    fn from_domain(error: anyhow::Error) -> Self {
        let Some(domain) = DomainError::of(&error) else {
            return Self::internal(error);
        };
        let status = match domain {
            DomainError::NotFound(_) => StatusCode::NOT_FOUND,
            DomainError::AlreadyExists(_)
            | DomainError::Conflict(_)
            | DomainError::IdempotencyConflict(_)
            | DomainError::ApprovalMismatch(_)
            | DomainError::AuditIntegrity(_)
            | DomainError::AnchorMismatch(_) => StatusCode::CONFLICT,
            DomainError::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
            DomainError::Forbidden(_) => StatusCode::FORBIDDEN,
            DomainError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        let code = domain.code();
        let message = domain.message().to_owned();
        Self {
            status,
            code,
            message,
            detail: Some(error),
        }
    }

    /// Write complete diagnostics to the server log and reduce the error to the
    /// part a caller may see.
    fn publish(self) -> PublicError {
        let request_id = current_request_id();
        let detail = self
            .detail
            .as_ref()
            .map_or_else(|| self.message.clone(), |error| format!("{error:#}"));
        log_error(self.status, self.code, &request_id, &detail);
        let message = if self.status.is_server_error() {
            INTERNAL_MESSAGE.to_owned()
        } else {
            self.message
        };
        PublicError {
            status: self.status,
            code: self.code,
            message,
            request_id,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let unauthorized = self.status == StatusCode::UNAUTHORIZED;
        let error = self.publish();
        let mut response = (
            error.status,
            Json(ErrorEnvelope {
                error: ErrorDetail {
                    code: error.code,
                    message: error.message,
                    request_id: error.request_id,
                },
            }),
        )
            .into_response();
        if unauthorized {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"cr\""),
            );
        }
        response
    }
}

/// Per-request correlation data, published for the duration of the handler so
/// that error reporting can name the request without threading it everywhere.
#[derive(Clone, Debug)]
struct RequestContext {
    id: Arc<str>,
    method: Method,
    path: Arc<str>,
}

tokio::task_local! {
    static REQUEST_CONTEXT: RequestContext;
}

/// The current request's correlation ID, or a fresh one outside a request.
fn current_request_id() -> String {
    REQUEST_CONTEXT
        .try_with(|context| context.id.to_string())
        .unwrap_or_else(|_| random_id())
}

/// Record the complete diagnostic chain, which never leaves the server.
fn log_error(status: StatusCode, code: &str, request_id: &str, detail: &str) {
    let (method, path) = REQUEST_CONTEXT
        .try_with(|context| (context.method.to_string(), context.path.to_string()))
        .unwrap_or_else(|_| ("-".to_owned(), "-".to_owned()));
    eprintln!(
        "cr error request_id={request_id} status={} code={code} method={method} path={path} detail={detail:?}",
        status.as_u16()
    );
}

pub fn router(database: Database, config: ServerConfig) -> Result<Router> {
    // A malformed or linked records directory is stored-state corruption, not
    // a reason to make the HTTP application impossible to construct. Defer a
    // classified conflict to the request that touches it, as the rest of the
    // server does for record-path failures. A healthy RBAC database still gets
    // the stricter owner and loopback startup boundary below.
    let access_controlled = match database.access_enabled() {
        Ok(enabled) => enabled,
        Err(error) if matches!(DomainError::of(&error), Some(DomainError::Conflict(_))) => false,
        Err(error) => return Err(error),
    };
    if access_controlled && !config.bind.ip().is_loopback() {
        bail!(
            "the RBAC perspective switcher is an owner-only local console and must bind to a loopback address"
        );
    }
    if access_controlled {
        database.impersonate_verified(database.principal())?;
    }
    if config.max_page_size == 0 {
        bail!("maximum page size must be greater than zero");
    }
    if config.max_body_bytes == 0 {
        bail!("maximum request body size must be greater than zero");
    }
    if config.api_token.as_deref().is_some_and(str::is_empty) {
        bail!("API token cannot be empty");
    }

    let state = AppState {
        database: database.with_source(AuditSource::Api),
        access_controlled,
        max_page_size: config.max_page_size,
        api_token: config.api_token.map(Arc::from),
        csrf_token: Arc::from(random_token()?),
    };
    let protected = Router::new()
        .route("/openapi.json", get(openapi))
        .route("/", get(views_home))
        .route("/perspective", post(switch_perspective))
        .route("/audit", get(audit_view))
        .route("/{view}", get(view_records))
        .route("/{view}/save-view", post(save_view_form))
        .route("/{view}/new", get(new_record_form))
        .route("/{view}/records", post(create_record_form))
        .route(
            "/{view}/records/{id}",
            get(edit_record_form).post(update_record_form),
        )
        .route("/{view}/records/{id}/move", post(move_kanban_card))
        .route("/{view}/records/{id}/delete", post(delete_record_form))
        .nest(
            "/api/v1",
            Router::new()
                .route("/identity", get(identity))
                .route("/collections", get(collections))
                .route(
                    "/collections/{collection}/records",
                    get(list_records).post(create_record),
                )
                .route(
                    "/collections/{collection}/records/{id}",
                    get(get_record)
                        .put(replace_record)
                        .patch(patch_record)
                        .delete(delete_record),
                )
                .route(
                    "/collections/{collection}/records/{id}/document",
                    get(get_document),
                )
                .route(
                    "/collections/{collection}/records/{id}/fields/{field}",
                    get(get_field),
                )
                .route(
                    "/collections/{collection}/records/{id}/links",
                    post(link_record),
                )
                .route("/search", get(search_records))
                .route("/status", get(status))
                .route("/check", get(check))
                .route("/save", post(save))
                .route("/audit/log", get(audit_log))
                .route("/audit/head", get(audit_head))
                .route("/audit/verify", get(audit_verify))
                .route("/audit/baseline", post(audit_baseline)),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), authorize));

    Ok(Router::new()
        .route("/health", get(health))
        .merge(protected)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .layer(middleware::from_fn(request_context))
        .with_state(state))
}

pub async fn serve(database: Database, config: ServerConfig) -> Result<()> {
    let bind = config.bind;
    let application = router(database, config)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("could not bind HTTP server to {bind}"))?;
    let address = listener
        .local_addr()
        .context("could not read HTTP listener address")?;
    println!("Serving cr on http://{address}");
    println!("Views: http://{address}/");
    println!("Audit: http://{address}/audit");
    println!("OpenAPI: http://{address}/openapi.json");
    std::io::stdout()
        .flush()
        .context("could not flush server address")?;
    axum::serve(listener, application)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server failed")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Give every request a correlation ID, publish it to the handlers beneath
/// this layer, and return it so an operator can find the matching log line.
async fn request_context(request: Request<Body>, next: Next) -> Response {
    let id = random_id();
    let header = HeaderValue::from_str(&id).ok();
    let context = RequestContext {
        id: Arc::from(id),
        method: request.method().clone(),
        path: Arc::from(request.uri().path()),
    };
    let mut response = REQUEST_CONTEXT.scope(context, next.run(request)).await;
    if let Some(header) = header {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID_HEADER), header);
    }
    response
}

async fn authorize(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    if let Some(token) = &state.api_token {
        let authorized = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|value| value == token.as_ref());
        if !authorized {
            return ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "provide a valid Bearer token",
            )
            .into_response();
        }
    }
    let mut response = next.run(request).await;
    if state.access_controlled {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Cookie"));
    }
    response
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn switch_perspective(State(state): State<AppState>, RawForm(raw): RawForm) -> Response {
    let result: ApiResult<Response> = async {
        if !state.access_controlled {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "route_not_found",
                "route not found",
            ));
        }
        let form: HtmlPerspectiveForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let principal = form.principal.trim().to_owned();
        let database = state.database.clone();
        let principal_for_check = principal.clone();
        tokio::task::spawn_blocking(move || database.impersonate_verified(&principal_for_check))
            .await
            .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
            .map_err(ApiError::from_domain)?;

        let cookie = format!(
            "{PERSPECTIVE_COOKIE}={}; Path=/; HttpOnly; SameSite=Strict",
            utf8_percent_encode(&principal, NON_ALPHANUMERIC)
        );
        let cookie = HeaderValue::from_str(&cookie)
            .map_err(|error| ApiError::bad_request("invalid_principal", error.to_string()))?;
        let mut response = see_other("/")?;
        response.headers_mut().insert(header::SET_COOKIE, cookie);
        Ok(response)
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn views_home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result: ApiResult<Markup> = async {
        let views = run_database(&state, &headers, Database::views).await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_views_home(&views, ui.as_ref(), &state.csrf_token))
    }
    .await;
    html_result(result)
}

async fn audit_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let query: AuditViewQuery = parse_query(raw)?;
        let bounds = page_bounds(
            query
                .limit
                .or(Some(DEFAULT_PAGE_SIZE.min(state.max_page_size))),
            query.offset,
            state.max_page_size,
        )?;
        let collection = query
            .collection
            .clone()
            .filter(|value| !value.trim().is_empty());
        let id = query.id.clone().filter(|value| !value.trim().is_empty());
        let agent = query.agent.clone().filter(|value| !value.trim().is_empty());
        let session = query
            .session
            .clone()
            .filter(|value| !value.trim().is_empty());
        if id.is_some() && collection.is_none() {
            return Err(ApiError::bad_request(
                "invalid_audit_filter",
                "collection is required when filtering by record ID",
            ));
        }
        let requested = bounds
            .offset
            .checked_add(bounds.limit)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| ApiError::unprocessable("pagination window is too large"))?;
        let entries = run_database(&state, &headers, move |database| {
            database.audit_recent(
                requested,
                AuditFilter {
                    collection: collection.as_deref(),
                    id: id.as_deref(),
                    agent: agent.as_deref(),
                    session: session.as_deref(),
                },
            )
        })
        .await?;
        let page = paginate_unknown_total(entries, bounds);
        let navigation = run_database(&state, &headers, Database::views).await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_audit_view(
            &page,
            &query,
            &navigation,
            ui.as_ref(),
            &state.csrf_token,
        ))
    }
    .await;
    html_result(result)
}

async fn view_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(view_name): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let mut query: ViewQuery = parse_query(raw)?;
        let ad_hoc_filters = view_filter_expressions(&query)?;
        let query_for_database = query.clone();
        let requested_view = view_name.clone();
        let (view, mut records, schema, navigation, can_create, can_manage_views, updatable) =
            run_database(&state, &headers, move |database| {
                let view = database.view(&requested_view)?;
                let view_filters = view
                    .filters
                    .iter()
                    .map(|filter| Assignment::from_str(filter))
                    .collect::<Result<Vec<_>>>()?;
                let view_expressions = view
                    .where_expr
                    .iter()
                    .map(|expression| FilterExpression::from_str(expression))
                    .collect::<Result<Vec<_>>>()?;
                let view_filter_groups = view
                    .filter_groups
                    .iter()
                    .map(|group| {
                        let expressions = group
                            .expressions
                            .iter()
                            .map(|expression| FilterExpression::from_str(expression))
                            .collect::<Result<Vec<_>>>()?;
                        Ok((group.match_mode, expressions))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let mut records = match query_for_database.q.as_deref().filter(|q| !q.is_empty()) {
                    Some(pattern) => {
                        let search =
                            SearchQuery::new(pattern, SearchTarget::Document, false, true)?;
                        database.search(Some(&view.collection), &view_filters, &search)?
                    }
                    None => database.list(&view.collection, &view_filters)?,
                };
                records.retain(|record| {
                    view_expressions
                        .iter()
                        .all(|expression| expression.matches(&record.attributes))
                        && view_filter_groups.iter().all(|(match_mode, expressions)| {
                            saved_filter_group_matches(*match_mode, expressions, &record.attributes)
                        })
                        && query_for_database
                            .filter_match
                            .matches(&ad_hoc_filters, &record.attributes)
                });
                let schema = database
                    .collection_models()?
                    .into_iter()
                    .find(|model| model.name == view.collection)
                    .and_then(|model| model.schema);
                let navigation = database.views()?;
                let can_create = can_create_in_collection(database, &view.collection)?;
                let can_manage_views = database.owner_access_allowed(&AccessResource::Database)?;
                let mut updatable = BTreeSet::new();
                for record in &records {
                    if database.access_allowed(
                        AccessAction::Update,
                        &AccessResource::record(&record.collection, &record.id),
                    )? {
                        updatable.insert(record.id.clone());
                    }
                }
                Ok((
                    view,
                    records,
                    schema,
                    navigation,
                    can_create,
                    can_manage_views,
                    updatable,
                ))
            })
            .await?;

        if query.sort_field.is_none() {
            query.sort_field = view.sort_by.clone();
            query.sort_direction = match view.sort_direction {
                SortDirection::Asc => ViewSortDirection::Asc,
                SortDirection::Desc => ViewSortDirection::Desc,
            };
        }

        let available_columns = view_available_columns(&view, &records, schema.as_ref());
        let columns = selected_view_columns(&view, &query, &available_columns)?;
        sort_view_records(&mut records, &query)?;
        let bounds = page_bounds(
            query
                .limit
                .or(Some(view.page_size.min(state.max_page_size))),
            query.offset,
            state.max_page_size,
        )?;
        let page = paginate(records, bounds);
        let ui = ui_context(&state, &headers).await?;
        Ok(render_view_records(
            &view,
            &columns,
            &available_columns,
            &page,
            &query,
            schema.as_ref(),
            &state.csrf_token,
            &navigation,
            ui.as_ref(),
            can_create,
            can_manage_views,
            &updatable,
        ))
    }
    .await;
    html_result(result)
}

async fn save_view_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(view_name): Path<String>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form: HtmlSaveViewForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let name = form.name.trim().to_owned();
        if name.is_empty() {
            return Err(ApiError::bad_request(
                "invalid_form",
                "view name cannot be empty",
            ));
        }
        let title = (!form.title.trim().is_empty()).then(|| form.title.trim().to_owned());
        let filter_group = save_view_filter_group(&form)?;
        let sort_by = form
            .sort_field
            .as_deref()
            .map(str::trim)
            .filter(|field| !field.is_empty())
            .map(str::to_owned);
        let sort_direction = match (sort_by.as_ref(), form.sort_direction) {
            (None, _) | (Some(_), ViewSortDirection::Asc) => SortDirection::Asc,
            (Some(_), ViewSortDirection::Desc) => SortDirection::Desc,
        };
        let requested_view = view_name;
        let saved = run_database(&state, &headers, move |database| {
            let source = database.view(&requested_view)?;
            let mut filter_groups = source.filter_groups.clone();
            if let Some(filter_group) = filter_group {
                filter_groups.push(filter_group);
            }
            let columns = if form.column.is_empty() {
                source.columns.clone()
            } else {
                form.column.clone()
            };
            let layout = form.layout.unwrap_or(source.layout);
            let submitted_group_by = form
                .group_by
                .as_deref()
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .map(str::to_owned);
            let group_by = match layout {
                ViewLayout::Table => None,
                ViewLayout::Kanban => Some(
                    submitted_group_by
                        .or_else(|| {
                            (source.layout == ViewLayout::Kanban)
                                .then(|| source.group_by.clone())
                                .flatten()
                        })
                        .context(DomainError::Invalid(
                            "Kanban layout must provide group_by".to_owned(),
                        ))?,
                ),
            };
            database.create_view_with_options(
                &name,
                title.as_deref(),
                &source.collection,
                source.filters.clone(),
                source.where_expr.clone(),
                filter_groups,
                columns,
                source.page_size,
                layout,
                group_by,
                sort_by,
                sort_direction,
            )
        })
        .await?;
        see_other(&notice_url(&saved.name, "View saved"))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn new_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(view_name): Path<String>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let requested_view = view_name.clone();
        let (view, schema, navigation, can_create) =
            run_database(&state, &headers, move |database| {
                let view = database.view(&requested_view)?;
                let schema = collection_schema(database, &view.collection)?;
                let navigation = database.views()?;
                let can_create = can_create_in_collection(database, &view.collection)?;
                Ok((view, schema, navigation, can_create))
            })
            .await?;
        if !can_create {
            return Err(ApiError::from_domain(
                DomainError::Forbidden(format!(
                    "principal cannot create records in collection:{}",
                    view.collection
                ))
                .into(),
            ));
        }
        let ui = ui_context(&state, &headers).await?;
        Ok(render_record_form(
            &view,
            None,
            &[],
            schema.as_ref(),
            &state.csrf_token,
            None,
            &navigation,
            ui.as_ref(),
            RecordPermissions {
                update: true,
                delete: false,
            },
        ))
    }
    .await;
    html_result(result)
}

async fn edit_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let requested_view = view_name.clone();
        let requested_id = id.clone();
        let (view, record, audit_entries, schema, navigation, permissions) =
            run_database(&state, &headers, move |database| {
                let view = database.view(&requested_view)?;
                let record = database.get(&view.collection, &requested_id)?;
                let audit_entries = database.audit_recent(
                    DEFAULT_PAGE_SIZE,
                    AuditFilter::record(&view.collection, &requested_id),
                )?;
                let schema = collection_schema(database, &view.collection)?;
                let navigation = database.views()?;
                let resource = AccessResource::record(&view.collection, &record.id);
                let permissions = RecordPermissions {
                    update: database.access_allowed(AccessAction::Update, &resource)?,
                    delete: database.access_allowed(AccessAction::Delete, &resource)?,
                };
                Ok((view, record, audit_entries, schema, navigation, permissions))
            })
            .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_record_form(
            &view,
            Some(&record),
            &audit_entries,
            schema.as_ref(),
            &state.csrf_token,
            None,
            &navigation,
            ui.as_ref(),
            permissions,
        ))
    }
    .await;
    html_result(result)
}

async fn create_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(view_name): Path<String>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form = parse_document_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let id = form
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_form", "record ID cannot be empty"))?
            .to_owned();
        let requested_view = view_name.clone();
        let (view, schema) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let schema = collection_schema(database, &view.collection)?;
            Ok((view, schema))
        })
        .await?;
        let attributes = document_form_attributes(&form, schema.as_ref())?;
        let collection = view.collection;
        let markdown = form.markdown;
        run_database(&state, &headers, move |database| {
            database.create_record(&collection, &id, attributes, &markdown)
        })
        .await?;
        see_other(&notice_url(&view_name, "Record created"))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn update_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form = parse_document_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        if form.id.is_some() {
            return Err(ApiError::bad_request(
                "invalid_form",
                "record ID cannot be changed",
            ));
        }
        let requested_view = view_name.clone();
        let (view, schema) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let schema = collection_schema(database, &view.collection)?;
            Ok((view, schema))
        })
        .await?;
        let attributes = document_form_attributes(&form, schema.as_ref())?;
        let collection = view.collection;
        let markdown = form.markdown;
        let expected = form.expected_record_hash.ok_or_else(|| {
            ApiError::bad_request("invalid_form", "expected record hash is required")
        })?;
        let precondition = RecordPrecondition::version(expected).map_err(ApiError::from_domain)?;
        run_database(&state, &headers, move |database| {
            database.replace_conditionally(
                &collection,
                &id,
                attributes,
                &markdown,
                Some(&precondition),
            )
        })
        .await?;
        see_other(&notice_url(&view_name, "Record updated"))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn move_kanban_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form: HtmlKanbanMoveForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let target: KanbanTarget = serde_json::from_str(&form.target).map_err(|error| {
            ApiError::bad_request("invalid_kanban_target", error.to_string())
        })?;
        let requested_view = view_name.clone();
        run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            if view.layout != ViewLayout::Kanban {
                return Err(DomainError::Invalid(format!(
                    "cannot move a card through view '{}' because it does not use the kanban layout",
                    view.name
                ))
                .into());
            }
            let group_by = view
                .group_by
                .as_deref()
                .context(DomainError::Invalid(
                    "kanban view is missing group_by".to_owned(),
                ))?;
            let record = database.get(&view.collection, &id)?;
            match target {
                KanbanTarget::Value { value } => {
                    let target_value: YamlValue = yaml_serde::from_str(&value)
                        .with_context(|| {
                            DomainError::Invalid(format!(
                                "kanban target '{value}' is not valid YAML"
                            ))
                        })?;
                    if record.field(group_by)? == Some(&target_value) {
                        return Ok(record);
                    }
                    let assignment = Assignment::from_str(&format!("{group_by}={value}"))?;
                    database.update(&view.collection, &id, &[assignment], None)
                }
                KanbanTarget::Unset => {
                    if record.field(group_by)?.is_none() {
                        return Ok(record);
                    }
                    database.patch(
                        &view.collection,
                        &id,
                        &Mapping::new(),
                        &[group_by.to_owned()],
                        None,
                    )
                }
            }
        })
        .await?;
        see_other(&notice_url(&view_name, "Card moved"))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn delete_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form: HtmlDeleteForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let precondition = RecordPrecondition::version(form.expected_record_hash)
            .map_err(ApiError::from_domain)?;
        let requested_view = view_name.clone();
        run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            database.delete_conditionally(&view.collection, &id, Some(&precondition))
        })
        .await?;
        see_other(&notice_url(&view_name, "Record deleted"))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn identity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<IdentityResponse>> {
    let database = request_database(&state, &headers)?;
    let attribution: Attribution = database.attribution().clone();
    Ok(Json(IdentityResponse {
        actor: database.actor().to_owned(),
        principal: database.principal().to_owned(),
        impersonated_by: database.impersonated_by().cloned(),
        agent: attribution.agent,
        authorization: attribution.authorization,
        intent: attribution.intent,
    }))
}

async fn collections(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Page<CollectionModel>>> {
    let query: PageQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let models = run_database(&state, &headers, Database::collection_models).await?;
    Ok(Json(paginate(models, bounds)))
}

async fn list_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Page<ApiRecordSummary>>> {
    let query: ListQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let sort = query.sort;
    let direction = query.direction.into();
    let records = run_database(&state, &headers, move |database| {
        let mut records = database.list(&collection, &filters)?;
        records.retain(|record| {
            expressions
                .iter()
                .all(|expression| expression.matches(&record.attributes))
        });
        if let Some(field) = sort {
            sort_records_by_field(&mut records, &field, direction)?;
        }
        Ok(records)
    })
    .await?;
    let page = paginate(records, bounds).try_map(ApiRecordSummary::try_from)?;
    Ok(Json(page))
}

async fn get_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let record = run_database(&state, &headers, move |database| {
        database.get(&collection, &id)
    })
    .await?;
    api_record_response(StatusCode::OK, record)
}

async fn get_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (document, version) = run_database(&state, &headers, move |database| {
        database.read_raw_versioned(&collection, &id)
    })
    .await?;
    let mut response = (
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        document,
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::ETAG, entity_tag(&version)?);
    Ok(response)
}

async fn get_field(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id, field)): Path<(String, String, String)>,
) -> ApiResult<Json<JsonValue>> {
    let value = run_database(&state, &headers, move |database| {
        let record = database.get(&collection, &id)?;
        let value = record
            .field(&field)?
            .cloned()
            .with_context(|| DomainError::NotFound(format!("field '{field}' does not exist")))?;
        serde_json::to_value(value).context(DomainError::Invalid(
            "field cannot be represented as JSON".to_owned(),
        ))
    })
    .await?;
    Ok(Json(json!({ "value": value })))
}

async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<CreateRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_create_record(
                &collection,
                &payload.id,
                payload.front_matter,
                &payload.markdown,
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let id = payload.id.clone();
    let location = format!(
        "/api/v1/collections/{}/records/{}",
        encode_segment(&collection),
        encode_segment(&id)
    );
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.create_record(
            &collection,
            &payload.id,
            payload.front_matter,
            &payload.markdown,
        )
    })
    .await?;
    let mut response = api_record_response(StatusCode::CREATED, record)?;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .map_err(|error| ApiError::bad_request("invalid_location", error.to_string()))?,
    );
    Ok(response)
}

async fn patch_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<PatchRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    let precondition = if_match(&headers, false)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_patch_conditionally(
                &collection,
                &id,
                &payload.front_matter,
                &payload.remove,
                payload.markdown.as_deref(),
                precondition.as_ref(),
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.patch_conditionally(
            &collection,
            &id,
            &payload.front_matter,
            &payload.remove,
            payload.markdown.as_deref(),
            precondition.as_ref(),
        )
    })
    .await?;
    api_record_response(StatusCode::OK, record)
}

async fn replace_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<ReplaceRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    let precondition = if_match(&headers, true)?.expect("required If-Match was parsed");
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_replace_conditionally(
                &collection,
                &id,
                payload.front_matter,
                &payload.markdown,
                Some(&precondition),
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.replace_conditionally(
            &collection,
            &id,
            payload.front_matter,
            &payload.markdown,
            Some(&precondition),
        )
    })
    .await?;
    api_record_response(StatusCode::OK, record)
}

async fn delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let precondition = if_match(&headers, false)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_delete_conditionally(&collection, &id, precondition.as_ref())
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.delete_conditionally(&collection, &id, precondition.as_ref())
    })
    .await?;
    Ok(Json(DeleteResponse {
        deleted: true,
        record: record.try_into()?,
    })
    .into_response())
}

async fn link_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<LinkRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    let precondition = if_match(&headers, false)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_link_conditionally(
                &collection,
                &id,
                &payload.relation,
                &payload.target_collection,
                &payload.target_id,
                precondition.as_ref(),
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.link_conditionally(
            &collection,
            &id,
            &payload.relation,
            &payload.target_collection,
            &payload.target_id,
            precondition.as_ref(),
        )
    })
    .await?;
    api_record_response(StatusCode::OK, record)
}

async fn search_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Page<ApiRecordSummary>>> {
    let parameters: SearchParameters = parse_query(raw)?;
    let bounds = page_bounds(parameters.limit, parameters.offset, state.max_page_size)?;
    let filters = parse_filters(parameters.filters)?;
    let expressions = parse_filter_expressions(parameters.where_expr)?;
    let sort = parameters.sort;
    let direction = parameters.direction.into();
    let target = search_target(parameters.target, parameters.field)?;
    let query = SearchQuery::new(
        &parameters.q,
        target,
        parameters.regex,
        parameters.ignore_case,
    )
    .map_err(ApiError::from_domain)?;
    let collection = parameters.collection;
    let records = run_database(&state, &headers, move |database| {
        let mut records = database.search(collection.as_deref(), &filters, &query)?;
        records.retain(|record| {
            expressions
                .iter()
                .all(|expression| expression.matches(&record.attributes))
        });
        if let Some(field) = sort {
            sort_records_by_field(&mut records, &field, direction)?;
        }
        Ok(records)
    })
    .await?;
    let page = paginate(records, bounds).try_map(ApiRecordSummary::try_from)?;
    Ok(Json(page))
}

async fn status(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Page<crate::WorkingChange>>> {
    let query: PageQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let changes = run_database(&state, &headers, Database::status).await?;
    Ok(Json(paginate(changes, bounds)))
}

/// A page of findings with the counts the page was drawn from.
///
/// The summary is deliberately not paginated away: a caller that reads only the
/// first page still has to be able to tell a clean database from a broken one,
/// and `data.is_empty()` on page three does not mean that.
#[derive(Debug, Serialize)]
struct CheckResponse {
    #[serde(flatten)]
    page: Page<Finding>,
    summary: CheckSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    collection: Option<String>,
}

/// Report integrity problems without changing anything.
///
/// A successful run always answers `200`, including when it found problems:
/// the findings are the resource, and a database being broken is not an HTTP
/// error. Callers decide from `summary.errors`, which is what the CLI's exit
/// status is computed from too.
async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<CheckResponse>> {
    let query: CheckQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let report = run_database(&state, &headers, move |database| {
        database.check(&CheckScope {
            collection: query.collection,
        })
    })
    .await?;
    Ok(Json(CheckResponse {
        page: paginate(report.findings, bounds),
        summary: report.summary,
        collection: report.collection,
    }))
}

async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<SaveRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    if query.preview {
        let previews = run_database(&state, &headers, move |database| {
            database.preview_save(&payload.records, payload.all, payload.message.as_deref())
        })
        .await?;
        return Ok(Json(previews).into_response());
    }
    let entries = run_database(&state, &headers, move |database| {
        database.save(&payload.records, payload.all, payload.message.as_deref())
    })
    .await?;
    Ok(Json(entries).into_response())
}

async fn audit_log(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<Page<crate::AuditEntry>>> {
    let parameters: AuditLogParameters = parse_query(raw)?;
    let bounds = page_bounds(parameters.limit, parameters.offset, state.max_page_size)?;
    let requested = bounds
        .offset
        .checked_add(bounds.limit)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| ApiError::unprocessable("pagination window is too large"))?;
    let entries = run_database(&state, &headers, move |database| {
        database.audit_recent(
            requested,
            AuditFilter {
                collection: parameters.collection.as_deref(),
                id: parameters.id.as_deref(),
                agent: parameters.agent.as_deref(),
                session: parameters.session.as_deref(),
            },
        )
    })
    .await?;
    Ok(Json(paginate_unknown_total(entries, bounds)))
}

async fn audit_head(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<crate::AuditHead>> {
    let head = run_database(&state, &headers, Database::audit_head).await?;
    Ok(Json(head))
}

async fn audit_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<crate::AuditVerification>> {
    let parameters: AuditVerifyParameters = parse_query(raw)?;
    let verification = run_database(&state, &headers, move |database| {
        database.audit_verify(parameters.expected_head.as_deref())
    })
    .await?;
    Ok(Json(verification))
}

async fn audit_baseline(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<BaselineResponse>> {
    let added = run_database(&state, &headers, Database::audit_baseline).await?;
    Ok(Json(BaselineResponse { added }))
}

async fn openapi(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<JsonValue>> {
    let token_enabled = state.api_token.is_some();
    let document = run_database(&state, &headers, move |database| {
        openapi_document(database, token_enabled)
    })
    .await?;
    Ok(Json(document))
}

pub fn openapi_document(database: &Database, token_enabled: bool) -> Result<JsonValue> {
    let models = database.collection_models()?;
    let mut schemas = base_openapi_schemas();
    let mut collection_schemas = Map::new();
    for model in models {
        let component = collection_component_name(&model.name);
        let reference = format!("#/components/schemas/{component}");
        let schema = model
            .schema
            .unwrap_or_else(|| json!({ "type": "object", "additionalProperties": true }));
        schemas.insert(component, schema);
        collection_schemas.insert(model.name, JsonValue::String(reference.clone()));
    }

    let mut components = json!({ "schemas": schemas });
    if token_enabled {
        components["securitySchemes"] = json!({
            "bearerAuth": { "type": "http", "scheme": "bearer" }
        });
    }
    let mut document = json!({
        "openapi": "3.1.1",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "cr REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "HTTP access to the same audited Markdown database used by the cr CLI."
        },
        "paths": openapi_paths(),
        "components": components,
        "x-cr-collection-schemas": collection_schemas
    });
    if token_enabled {
        document["security"] = json!([{ "bearerAuth": [] }]);
    }
    Ok(document)
}

/// The static OpenAPI component schemas.
///
/// Split across two `json!` invocations only because one literal of this size
/// exceeds the macro recursion limit; the halves are concatenated and the
/// division carries no meaning.
fn base_openapi_schemas() -> Map<String, JsonValue> {
    let mut schemas: Map<String, JsonValue> = serde_json::from_value(json!({
        "FrontMatter": { "type": "object", "additionalProperties": true },
        "RecordSummary": {
            "type": "object",
            "required": ["path", "version", "front_matter"],
            "properties": {
                "path": { "type": "string" },
                "version": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "description": "SHA-256 of the bytes cr:record:v1\\0 followed by the exact stored Markdown bytes; the unquoted value carried by the strong ETag." },
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" }
            }
        },
        "Record": {
            "allOf": [
                { "$ref": "#/components/schemas/RecordSummary" },
                {
                    "type": "object",
                    "required": ["collection", "id", "markdown"],
                    "properties": {
                        "collection": { "type": "string" },
                        "id": { "type": "string" },
                        "markdown": { "type": "string" }
                    }
                }
            ]
        },
        "Pagination": {
            "type": "object",
            "required": ["limit", "offset", "returned", "total", "has_more", "next_offset", "previous_offset"],
            "properties": {
                "limit": { "type": "integer", "minimum": 1 },
                "offset": { "type": "integer", "minimum": 0 },
                "returned": { "type": "integer", "minimum": 0 },
                "total": { "type": ["integer", "null"], "minimum": 0 },
                "has_more": { "type": "boolean" },
                "next_offset": { "type": ["integer", "null"], "minimum": 0 },
                "previous_offset": { "type": ["integer", "null"], "minimum": 0 }
            }
        },
        "RecordPage": {
            "type": "object",
            "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "$ref": "#/components/schemas/RecordSummary" } },
                "pagination": { "$ref": "#/components/schemas/Pagination" }
            }
        },
        "CreateRecordRequest": {
            "type": "object",
            "required": ["id"],
            "additionalProperties": false,
            "properties": {
                "id": { "type": "string" },
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" },
                "markdown": { "type": "string", "default": "" }
            }
        },
        "PatchRecordRequest": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" },
                "remove": { "type": "array", "items": { "type": "string" } },
                "markdown": { "type": "string" }
            }
        },
        "ReplaceRecordRequest": {
            "type": "object",
            "additionalProperties": false,
            "required": ["front_matter", "markdown"],
            "properties": {
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" },
                "markdown": { "type": "string" }
            }
        },
        "Identity": {
            "type": "object", "required": ["actor", "principal", "impersonated_by"],
            "description": "The effective principal and attribution this request would record. In the local RBAC console, impersonated_by identifies the owner operating the selected perspective.",
            "properties": {
                "actor": { "type": "string" },
                "principal": { "type": "string" },
                "impersonated_by": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["principal", "display"],
                            "properties": {
                                "principal": { "type": "string" },
                                "display": { "type": "string" }
                            }
                        },
                        { "type": "null" }
                    ]
                },
                "agent": { "oneOf": [{ "$ref": "#/components/schemas/AuditAgent" }, { "type": "null" }] },
                "authorization": { "oneOf": [{ "$ref": "#/components/schemas/AuditAuthorization" }, { "type": "null" }] },
                "intent": { "oneOf": [{ "$ref": "#/components/schemas/AuditIntent" }, { "type": "null" }] }
            }
        },
        "AuditAgent": {
            "type": "object", "required": ["id", "detected_from"],
            "description": "Software that acted on the actor's behalf. Asserted, never verified.",
            "properties": {
                "id": { "type": "string" },
                "version": { "type": "string" },
                "model": { "type": "string" },
                "session": { "type": "string" },
                "turn": { "type": "string" },
                "detected_from": {
                    "enum": ["environment", "flag", "header", "config"],
                    "description": "How cr came to believe this. No value means verified."
                },
                "via": { "type": "array", "items": { "$ref": "#/components/schemas/AuditAgent" }, "description": "Delegation chain, nearest actor first." }
            }
        },
        "AuditAuthorization": {
            "type": "object", "required": ["mode"],
            "properties": {
                "mode": { "enum": ["direct", "interactive", "delegated", "autonomous", "unknown"] },
                "grant": { "type": "string" },
                "approved_by": { "type": "string" },
                "at": { "type": "string", "format": "date-time" },
                "approved_changes": { "type": "string", "description": "Digest of the change set that was previewed and approved. cr refuses a mutation whose change set hashes differently, and audit verify recomputes it from the stored changes. It commits to what was applied, not to who saw it." }
            }
        },
        "AuditIntentPart": {
            "type": "object", "required": ["author"],
            "properties": {
                "author": { "enum": ["human", "agent", "system"] },
                "text": { "type": "string" },
                "digest": { "type": "string" },
                "ref": { "type": "string" },
                "at": { "type": "string", "format": "date-time" }
            }
        },
        "AuditIntent": {
            "type": "object",
            "properties": {
                "request": { "$ref": "#/components/schemas/AuditIntentPart" },
                "rationale": { "$ref": "#/components/schemas/AuditIntentPart" }
            }
        },
        "CollectionModel": {
            "type": "object", "required": ["name"],
            "properties": {
                "name": { "type": "string" },
                "schema": { "type": "object", "additionalProperties": true }
            }
        },
        "CollectionPage": {
            "type": "object", "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "$ref": "#/components/schemas/CollectionModel" } },
                "pagination": { "$ref": "#/components/schemas/Pagination" }
            }
        },
        "FieldResponse": {
            "type": "object", "required": ["value"],
            "properties": { "value": true }
        },
        "LinkRequest": {
            "type": "object", "additionalProperties": false,
            "required": ["relation", "target_collection", "target_id"],
            "properties": {
                "relation": { "type": "string" },
                "target_collection": { "type": "string" },
                "target_id": { "type": "string" }
            }
        },
    }))
    .expect("static OpenAPI schemas are objects");
    let rest: Map<String, JsonValue> = serde_json::from_value(json!({
        "ChangePreview": {
            "type": "object",
            "required": ["preview", "action", "record", "changes", "digest"],
            "description": "A change set computed without writing it. Returned by any mutating operation with preview=true. `preview` is always true, so a client can tell a preview from a write even if the query parameter was lost in transit.",
            "properties": {
                "preview": { "const": true },
                "action": { "enum": ["baseline", "create", "update", "link", "delete"] },
                "record": { "type": "object" },
                "changes": { "type": "array", "items": { "type": "object" } },
                "before_hash": { "type": ["string", "null"] },
                "after_hash": { "type": ["string", "null"] },
                "digest": { "type": "string", "description": "sha256 over the canonical bytes of changes. Send back as X-CR-Approved-Changes." }
            }
        },
        "ChangePreviews": {
            "type": "array", "items": { "$ref": "#/components/schemas/ChangePreview" }
        },
        "DeleteResponse": {
            "type": "object", "required": ["deleted", "record"],
            "properties": {
                "deleted": { "const": true },
                "record": { "$ref": "#/components/schemas/Record" }
            }
        },
        "WorkingChange": {
            "type": "object",
            "required": ["status", "collection", "id", "path", "audited_hash", "current_hash"],
            "properties": {
                "status": { "enum": ["added", "modified", "deleted"] },
                "collection": { "type": "string" },
                "id": { "type": "string" },
                "path": { "type": "string" },
                "audited_hash": { "type": ["string", "null"] },
                "current_hash": { "type": ["string", "null"] }
            }
        },
        "WorkingChangePage": {
            "type": "object", "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "$ref": "#/components/schemas/WorkingChange" } },
                "pagination": { "$ref": "#/components/schemas/Pagination" }
            }
        },
        "CheckFinding": {
            "type": "object",
            "required": ["severity", "kind", "message"],
            "description": "One integrity problem. Records are named by collection and ID and never by filesystem path.",
            "properties": {
                "severity": { "enum": ["error", "warning"], "description": "warning marks a divergence cr save can still reconcile, which cr status also reports." },
                "kind": { "enum": [
                    "dangling_link", "malformed_relation", "schema_violation", "unusable_schema",
                    "invalid_record_name", "unreadable_record", "unaudited_record", "missing_record",
                    "record_content_mismatch", "audit_chain_broken", "approval_mismatch",
                    "interrupted_sync_run", "audit_anchor_mismatch", "audit_anchor_behind",
                    "audit_anchor_missing"
                ] },
                "collection": { "type": "string" },
                "id": { "type": "string" },
                "field": { "type": "string", "description": "Dotted front matter path, where the finding is about one field." },
                "target": { "type": "string", "description": "The collection/id a dangling relation pointed at." },
                "message": { "type": "string" }
            }
        },
        "CheckSummary": {
            "type": "object",
            "required": ["collections", "records", "audited_records", "errors", "warnings"],
            "properties": {
                "collections": { "type": "integer", "minimum": 0 },
                "records": { "type": "integer", "minimum": 0 },
                "audited_records": { "type": "integer", "minimum": 0 },
                "errors": { "type": "integer", "minimum": 0 },
                "warnings": { "type": "integer", "minimum": 0 }
            }
        },
        "CheckReport": {
            "type": "object", "required": ["data", "pagination", "summary"],
            "description": "Findings are paginated; the summary always covers the whole run.",
            "properties": {
                "data": { "type": "array", "items": { "$ref": "#/components/schemas/CheckFinding" } },
                "pagination": { "$ref": "#/components/schemas/Pagination" },
                "summary": { "$ref": "#/components/schemas/CheckSummary" },
                "collection": { "type": "string" }
            }
        },
        "SaveRequest": {
            "type": "object", "additionalProperties": false,
            "properties": {
                "records": { "type": "array", "items": { "type": "string" } },
                "all": { "type": "boolean", "default": false },
                "message": { "type": "string" }
            }
        },
        "AuditEntry": {
            "type": "object",
            "required": ["hash", "version", "sequence", "timestamp", "actor", "source", "action", "record", "changes", "before_hash", "after_hash", "previous_hash"],
            "properties": {
                "hash": { "type": "string", "description": "Hash of the exact stored audit payload. For encrypted collections, changes, snapshots, and idempotency results are logical plaintext projections while this hash still commits to stored ciphertext and cannot be recomputed from the response." },
                "version": { "type": "integer", "minimum": 1, "maximum": 3 },
                "sequence": { "type": "integer", "minimum": 1 },
                "timestamp": { "type": "string", "format": "date-time" },
                "actor": { "type": "string" },
                "source": { "enum": ["cli", "api", "filesystem", "sync"] },
                "action": { "enum": ["baseline", "create", "update", "link", "delete"] },
                "record": { "type": "object" },
                "changes": { "type": "array", "description": "Logical audit changes. Protected values are decrypted for authorized history reads; hash and authorization.approved_changes still commit to the stored ciphertext representation.", "items": { "type": "object" } },
                "after_snapshot": {
                    "type": "object",
                    "description": "Versioned exact Markdown witness. Protected content is decrypted in authorized history responses while the stored journal retains ciphertext.",
                    "required": ["version", "markdown"],
                    "properties": {
                        "version": { "const": 1 },
                        "markdown": { "type": "string" }
                    },
                    "additionalProperties": false
                },
                "before_hash": { "type": ["string", "null"] },
                "after_hash": { "type": ["string", "null"] },
                "previous_hash": { "type": ["string", "null"] },
                "agent": { "$ref": "#/components/schemas/AuditAgent" },
                "authorization": { "$ref": "#/components/schemas/AuditAuthorization" },
                "intent": { "$ref": "#/components/schemas/AuditIntent" },
                "idempotency": { "$ref": "#/components/schemas/AuditIdempotency" },
                "message": { "type": "string" }
            },
            "additionalProperties": true
        },
        "AuditIdempotency": {
            "type": "object",
            "required": ["principal", "operation", "key_hash", "request_hash", "result"],
            "description": "Durable retry identity committed in the same event as a successful single-record mutation. The caller's raw key is never stored.",
            "properties": {
                "principal": { "type": "string" },
                "operation": { "enum": ["create", "update", "patch", "replace", "link", "delete"] },
                "key_hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                "request_hash": { "type": "string", "pattern": "^hmac-sha256:[0-9a-f]{64}$", "description": "HMAC-SHA-256 of the canonical plaintext request, keyed by the raw retry key; the key itself is never stored." },
                "result": {
                    "type": "object",
                    "required": ["path", "version", "markdown"],
                    "properties": {
                        "path": { "type": "string" },
                        "version": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                        "markdown": { "type": "string" }
                    },
                    "additionalProperties": false
                }
            },
            "additionalProperties": false
        },
        "AuditEntries": {
            "type": "array", "items": { "$ref": "#/components/schemas/AuditEntry" }
        },
        "AuditPage": {
            "type": "object", "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "$ref": "#/components/schemas/AuditEntry" } },
                "pagination": { "$ref": "#/components/schemas/Pagination" }
            }
        },
        "AuditHead": {
            "type": "object", "required": ["sequence", "hash"],
            "properties": {
                "sequence": { "type": "integer", "minimum": 0 },
                "hash": { "type": ["string", "null"] }
            }
        },
        "AuditVerification": {
            "type": "object", "required": ["entries", "records_checked", "head", "anchor"],
            "properties": {
                "entries": { "type": "integer", "minimum": 0 },
                "records_checked": { "type": "integer", "minimum": 0 },
                "head": { "$ref": "#/components/schemas/AuditHead" },
                "anchor": { "$ref": "#/components/schemas/AnchorStatus" }
            }
        },
        "AnchorStatus": {
            "type": "object",
            "required": ["state"],
            "description": "How the anchor file at the database root relates to the journal head. A mismatch is not reported here: it fails the request with 409 anchor_mismatch.",
            "properties": {
                "state": { "enum": ["empty", "absent", "matched", "behind", "overridden"], "description": "behind means the anchor lags a still-agreeing journal, which is a reduced guarantee rather than altered history." },
                "sequence": { "type": "integer", "minimum": 1, "description": "The audit sequence the anchor attests to." },
                "head": { "type": "integer", "minimum": 1, "description": "The current head sequence, present when the anchor is behind." }
            }
        },
        "BaselineResponse": {
            "type": "object", "required": ["added"],
            "properties": { "added": { "type": "integer", "minimum": 0 } }
        },
        "Error": {
            "type": "object",
            "required": ["error"],
            "properties": {
                "error": {
                    "type": "object",
                    "required": ["code", "message", "request_id"],
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" },
                        "request_id": {
                            "type": "string",
                            "description": "Correlates this response with the server log entry that holds complete diagnostics"
                        }
                    }
                }
            }
        }
    }))
    .expect("static OpenAPI schemas are objects");
    schemas.extend(rest);
    schemas
}

fn openapi_paths() -> JsonValue {
    let actor = json!({
        "name": "X-CR-Actor",
        "in": "header",
        "required": false,
        "schema": { "type": "string" },
        "description": "Audit identity override for this request. Asserted, not authenticated."
    });
    let attribution_headers = [
        actor.clone(),
        json!({
            "name": "X-CR-Agent",
            "in": "header",
            "required": false,
            "schema": { "type": "string" },
            "description": "Software acting on the actor's behalf: 'none', a bare identifier such as claude-code, or a JSON agent object. Recorded as detected_from: header and authenticated by nothing."
        }),
        json!({
            "name": "X-CR-Authorization",
            "in": "header",
            "required": false,
            "schema": { "type": "string" },
            "description": "Approval this change was made under: a bare mode (direct, interactive, delegated, autonomous, unknown) or a JSON authorization object."
        }),
        json!({
            "name": "X-CR-Intent",
            "in": "header",
            "required": false,
            "schema": { "type": "string" },
            "description": "JSON intent object with a request, a rationale, or both. Header values are visible ASCII, so other characters must use JSON \\u escapes."
        }),
        json!({
            "name": "X-CR-Approved-Changes",
            "in": "header",
            "required": false,
            "schema": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
            "description": "Digest printed by a preview=true request. The mutation is refused with 409 approval_mismatch unless its change set hashes to exactly this, and the digest is recorded in authorization.approved_changes. Requires X-CR-Authorization to name an approval mode."
        }),
    ];
    let preview = json!({
        "name": "preview",
        "in": "query",
        "required": false,
        "schema": { "type": "boolean", "default": false },
        "description": "Compute the change set and its digest without writing anything, and return a ChangePreview with 200 instead of performing the mutation."
    });
    let if_match = json!({
        "name": "If-Match",
        "in": "header",
        "required": false,
        "schema": { "type": "string" },
        "description": "Strong ETag returned by a record read. When present, cr compares it with the exact current record bytes while holding the audit lock and returns 412 precondition_failed on a stale value."
    });
    let idempotency_key = json!({
        "name": "Idempotency-Key",
        "in": "header",
        "required": false,
        "schema": { "type": "string", "minLength": 16, "maxLength": 128, "pattern": "^[!-~]+$" },
        "description": "A caller-generated, high-entropy retry key for one effective principal, operation, and record. Successful single-record mutations are replayed with their original result and no extra audit event. Reusing a scoped key for different request semantics returns 409 idempotency_conflict. Preview requests and failed mutations do not consume the key."
    });
    let attribution_parameters = |mut path: Vec<JsonValue>| {
        path.extend(attribution_headers.iter().cloned());
        JsonValue::Array(path)
    };
    let mutation_parameters = |mut path: Vec<JsonValue>| {
        path.push(preview.clone());
        path.extend(attribution_headers.iter().cloned());
        JsonValue::Array(path)
    };
    let single_record_mutation_parameters = |mut path: Vec<JsonValue>| {
        path.push(preview.clone());
        path.push(idempotency_key.clone());
        path.extend(attribution_headers.iter().cloned());
        JsonValue::Array(path)
    };
    let conditional_mutation_parameters = |mut path: Vec<JsonValue>| {
        path.push(preview.clone());
        path.push(if_match.clone());
        path.push(idempotency_key.clone());
        path.extend(attribution_headers.iter().cloned());
        JsonValue::Array(path)
    };
    let replacement_parameters = |mut path: Vec<JsonValue>| {
        path.push(preview.clone());
        let mut required_if_match = if_match.clone();
        required_if_match["required"] = JsonValue::Bool(true);
        path.push(required_if_match);
        path.push(idempotency_key.clone());
        path.extend(attribution_headers.iter().cloned());
        JsonValue::Array(path)
    };
    let collection = json!({
        "name": "collection", "in": "path", "required": true,
        "schema": { "type": "string" }
    });
    let id = json!({
        "name": "id", "in": "path", "required": true,
        "schema": { "type": "string" }
    });
    let page_parameters = vec![
        json!({ "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "default": DEFAULT_PAGE_SIZE } }),
        json!({ "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0, "default": 0 } }),
    ];
    json!({
        "/health": {
            "get": {
                "operationId": "health",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Server is ready",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": { "status": { "const": "ok" } }
                                }
                            }
                        }
                    }
                }
            }
        },
        "/openapi.json": {
            "get": {
                "operationId": "getOpenApi",
                "responses": {
                    "200": {
                        "description": "Generated OpenAPI 3.1 document",
                        "content": { "application/json": { "schema": { "type": "object" } } }
                    },
                    "401": error_response(),
                    "500": error_response()
                }
            }
        },
        "/api/v1/identity": {
            "get": { "operationId": "getIdentity", "parameters": attribution_parameters(Vec::new()), "responses": ok("#/components/schemas/Identity") }
        },
        "/api/v1/collections": {
            "get": { "operationId": "listCollections", "parameters": page_parameters.clone(), "responses": ok("#/components/schemas/CollectionPage") }
        },
        "/api/v1/collections/{collection}/records": {
            "get": {
                "operationId": "listRecords",
                "parameters": [collection.clone(),
                    json!({ "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }),
                    json!({ "name": "where_expr", "in": "query", "description": "Typed expressions such as value>=10000, name contains Acme, or owner is-empty. Repeated expressions use AND.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }),
                    json!({ "name": "sort", "in": "query", "description": "Dotted front matter field or $id, $collection, or $path. Missing fields remain last.", "schema": { "type": "string" } }),
                    json!({ "name": "direction", "in": "query", "description": "Sort direction. Record ID remains the ascending deterministic tie-breaker.", "schema": { "type": "string", "enum": ["asc", "desc"], "default": "asc" } }),
                    json!({ "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1 } }),
                    json!({ "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0 } })],
                "responses": ok("#/components/schemas/RecordPage")
            },
            "post": {
                "operationId": "createRecord", "parameters": single_record_mutation_parameters(vec![collection.clone()]),
                "requestBody": json_body("#/components/schemas/CreateRecordRequest"),
                "responses": created_record_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview")
            }
        },
        "/api/v1/collections/{collection}/records/{id}": {
            "get": { "operationId": "getRecord", "parameters": [collection.clone(), id.clone()], "responses": record_ok("#/components/schemas/Record") },
            "put": {
                "operationId": "replaceRecord",
                "description": "Replace the complete front matter and Markdown document. If-Match is required so a stale whole-document editor cannot overwrite a newer change.",
                "parameters": replacement_parameters(vec![collection.clone(), id.clone()]),
                "requestBody": json_body("#/components/schemas/ReplaceRecordRequest"),
                "responses": replacement_record_ok_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview")
            },
            "patch": {
                "operationId": "patchRecord", "parameters": conditional_mutation_parameters(vec![collection.clone(), id.clone()]),
                "requestBody": json_body("#/components/schemas/PatchRecordRequest"),
                "responses": record_ok_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview")
            },
            "delete": { "operationId": "deleteRecord", "parameters": conditional_mutation_parameters(vec![collection.clone(), id.clone()]), "responses": conditional_ok_or_preview("#/components/schemas/DeleteResponse", "#/components/schemas/ChangePreview") }
        },
        "/api/v1/collections/{collection}/records/{id}/document": {
            "get": { "operationId": "getRecordDocument", "parameters": [collection.clone(), id.clone()], "responses": { "200": { "description": "Exact Markdown document", "headers": { "ETag": etag_response_header() }, "content": { "text/markdown": { "schema": { "type": "string" } } } }, "404": error_response() } }
        },
        "/api/v1/collections/{collection}/records/{id}/fields/{field}": {
            "get": { "operationId": "getRecordField", "parameters": [collection.clone(), id.clone(), json!({ "name": "field", "in": "path", "required": true, "schema": { "type": "string" } })], "responses": ok("#/components/schemas/FieldResponse") }
        },
        "/api/v1/collections/{collection}/records/{id}/links": {
            "post": { "operationId": "linkRecord", "parameters": conditional_mutation_parameters(vec![collection, id]), "requestBody": json_body("#/components/schemas/LinkRequest"), "responses": record_ok_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview") }
        },
        "/api/v1/search": {
            "get": { "operationId": "searchRecords", "parameters": [
                { "name": "q", "in": "query", "required": true, "schema": { "type": "string" } },
                { "name": "collection", "in": "query", "schema": { "type": "string" } },
                { "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "where_expr", "in": "query", "description": "Typed expressions such as value>=10000, name contains Acme, or owner is-empty. Repeated expressions use AND.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "sort", "in": "query", "description": "Dotted front matter field or $id, $collection, or $path. Missing fields remain last.", "schema": { "type": "string" } },
                { "name": "direction", "in": "query", "description": "Sort direction. Record ID remains the ascending deterministic tie-breaker.", "schema": { "type": "string", "enum": ["asc", "desc"], "default": "asc" } },
                { "name": "target", "in": "query", "schema": { "enum": ["document", "front_matter", "field", "body", "path"] } },
                { "name": "field", "in": "query", "schema": { "type": "string" } },
                { "name": "ignore_case", "in": "query", "schema": { "type": "boolean", "default": false } },
                { "name": "regex", "in": "query", "schema": { "type": "boolean", "default": false } },
                { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1 } },
                { "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0 } }
            ], "responses": ok("#/components/schemas/RecordPage") }
        },
        "/api/v1/status": { "get": { "operationId": "getStatus", "parameters": page_parameters, "responses": ok("#/components/schemas/WorkingChangePage") } },
        "/api/v1/check": { "get": { "operationId": "getCheckReport", "description": "Report every integrity problem in the database. Read-only, and 200 even when problems were found.", "parameters": [
            { "name": "collection", "in": "query", "description": "Check one collection instead of the whole database.", "schema": { "type": "string" } },
            { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1 } },
            { "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0 } }
        ], "responses": ok("#/components/schemas/CheckReport") } },
        "/api/v1/save": { "post": { "operationId": "saveDirectEdits", "parameters": mutation_parameters(Vec::new()), "requestBody": json_body("#/components/schemas/SaveRequest"), "responses": ok_or_preview("#/components/schemas/AuditEntries", "#/components/schemas/ChangePreviews") } },
        "/api/v1/audit/log": { "get": { "operationId": "getAuditLog", "parameters": [
            { "name": "agent", "in": "query", "description": "Only events whose acting agent, or any delegate in its chain, carries this identifier.", "schema": { "type": "string" } },
            { "name": "session", "in": "query", "description": "Only events whose acting agent, or any delegate in its chain, carries this session identifier.", "schema": { "type": "string" } },
            { "name": "collection", "in": "query", "schema": { "type": "string" } },
            { "name": "id", "in": "query", "schema": { "type": "string" } },
            { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1 } },
            { "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0 } }
        ], "responses": ok("#/components/schemas/AuditPage") } },
        "/api/v1/audit/head": { "get": { "operationId": "getAuditHead", "responses": ok("#/components/schemas/AuditHead") } },
        "/api/v1/audit/verify": { "get": { "operationId": "verifyAudit", "parameters": [
            { "name": "expected_head", "in": "query", "schema": { "type": "string" } }
        ], "responses": ok("#/components/schemas/AuditVerification") } },
        "/api/v1/audit/baseline": { "post": { "operationId": "baselineAudit", "responses": ok("#/components/schemas/BaselineResponse") } }
    })
}

fn ok(schema: &str) -> JsonValue {
    json!({
        "200": { "description": "Success", "content": { "application/json": { "schema": { "$ref": schema } } } },
        "400": error_response(), "401": error_response(), "404": error_response(),
        "409": error_response(), "413": error_response(), "422": error_response(),
        "500": error_response()
    })
}

fn etag_response_header() -> JsonValue {
    json!({
        "description": "Strong validator derived by hashing the cr:record:v1\\0 domain followed by the exact stored Markdown bytes",
        "schema": { "type": "string", "pattern": "^\"sha256:[0-9a-f]{64}\"$" }
    })
}

fn record_ok(schema: &str) -> JsonValue {
    let mut responses = ok(schema);
    responses["200"]["headers"] = json!({ "ETag": etag_response_header() });
    responses
}

/// Success responses for a mutating operation that also answers `preview=true`.
///
/// The preview response is a different shape from the write response, so both
/// are described rather than pretending one schema covers the operation.
fn ok_or_preview(schema: &str, preview: &str) -> JsonValue {
    let mut responses = ok(schema);
    responses["200"]["content"]["application/json"]["schema"] = json!({
        "oneOf": [{ "$ref": schema }, { "$ref": preview }]
    });
    responses["200"]["description"] =
        JsonValue::String("Success, or the computed change set when preview=true".to_owned());
    responses
}

fn conditional_ok_or_preview(schema: &str, preview: &str) -> JsonValue {
    let mut responses = ok_or_preview(schema, preview);
    responses["412"] = error_response();
    responses
}

fn record_ok_or_preview(schema: &str, preview: &str) -> JsonValue {
    let mut responses = conditional_ok_or_preview(schema, preview);
    responses["200"]["headers"] = json!({
        "ETag": {
            "description": "Strong record validator on an applied write; absent for preview=true",
            "schema": { "type": "string", "pattern": "^\"sha256:[0-9a-f]{64}\"$" }
        }
    });
    responses
}

fn replacement_record_ok_or_preview(schema: &str, preview: &str) -> JsonValue {
    let mut responses = record_ok_or_preview(schema, preview);
    responses["428"] = error_response();
    responses
}

fn created(schema: &str) -> JsonValue {
    let mut responses = ok(schema);
    if let Some(object) = responses.as_object_mut()
        && let Some(success) = object.remove("200")
    {
        object.insert("201".into(), success);
    }
    responses
}

/// A creation that answers `preview=true` with `200` and a change set.
fn created_record_or_preview(schema: &str, preview: &str) -> JsonValue {
    let mut responses = created(schema);
    responses["201"]["headers"] = json!({ "ETag": etag_response_header() });
    responses["200"] = json!({
        "description": "The computed change set, returned when preview=true",
        "content": { "application/json": { "schema": { "$ref": preview } } }
    });
    responses
}

fn error_response() -> JsonValue {
    json!({
        "description": "Error",
        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Error" } } }
    })
}

fn json_body(schema: &str) -> JsonValue {
    json!({ "required": true, "content": { "application/json": { "schema": { "$ref": schema } } } })
}

fn render_views_home(views: &[ViewDefinition], ui: Option<&UiContext>, csrf_token: &str) -> Markup {
    page_layout(
        "Database views",
        "/",
        views,
        html! {
            div class="cr-page-heading mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                div {
                    p class="cr-eyebrow" { "Workspace" }
                    h1 class="cr-title mt-1" { "Database views" }
                    p class="cr-lede mt-1 max-w-2xl" {
                        "Browse every collection or open a saved, filtered view. All changes use the same validated and audited database operations as the CLI and REST API."
                    }
                }
                span class="cr-pill" { (views.len()) " views" }
            }
            @if views.is_empty() {
                div class="cr-empty-state" {
                    h2 class="text-lg font-semibold text-slate-900" { "No collections yet" }
                    p class="mt-2 text-sm text-slate-600" {
                        "Create a record with the CLI, or add a saved view with "
                        code class="rounded bg-slate-100 px-1.5 py-1 text-xs" { "cr view create" }
                        "."
                    }
                }
            } @else {
                section class="cr-view-index" aria-label="Available database views" {
                    div class="cr-view-index-header" aria-hidden="true" {
                        span { "View" }
                        span { "Type" }
                        span { "Open" }
                    }
                    @for view in views {
                        a href=(format!("/{}", encode_segment(&view.name))) class="cr-view-row group" {
                            div class="min-w-0" {
                                h2 class="truncate text-[0.95rem] font-semibold text-slate-950" { (&view.title) }
                                p class="cr-path mt-1 truncate" { "records/" (&view.collection) }
                            }
                            div class="flex min-w-0 flex-wrap items-center gap-2" {
                                span class="cr-pill" {
                                    @if view.saved { "saved" } @else { "automatic" }
                                }
                                @if view.layout == ViewLayout::Kanban {
                                    span class="cr-pill cr-pill-accent" { "kanban" }
                                }
                                @if view.filters.is_empty() && view.where_expr.is_empty() && view.filter_groups.is_empty() {
                                    span class="text-xs text-slate-500" { "All records" }
                                } @else {
                                    @for filter in &view.filters {
                                        code class="cr-filter-tag" { (filter) }
                                    }
                                    @for expression in &view.where_expr {
                                        code class="cr-filter-tag" { (expression) }
                                    }
                                    @for group in &view.filter_groups {
                                        code class="cr-filter-tag" {
                                            (match group.match_mode { ViewPredicateMatch::All => "All: ", ViewPredicateMatch::Any => "Any: " })
                                            (group.expressions.join(" · "))
                                        }
                                    }
                                }
                            }
                            span class="cr-view-arrow" aria-hidden="true" { "→" }
                        }
                    }
                }
            }
        },
        ui,
        csrf_token,
    )
}

fn render_audit_view(
    page: &Page<AuditEntry>,
    query: &AuditViewQuery,
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let reset_url = "/audit";
    let first = if page.pagination.returned == 0 {
        0
    } else {
        page.pagination.offset + 1
    };
    let last = page.pagination.offset + page.pagination.returned;
    page_layout(
        "Audit log",
        "/audit",
        views,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-slate-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                span class="text-slate-900" { "Audit log" }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                div {
                    p class="cr-eyebrow" { "Tamper-evident journal" }
                    h1 class="cr-title mt-1" { "Global audit log" }
                    p class="cr-lede mt-1 max-w-2xl" {
                        "Every accepted record mutation, newest first. Expand an event to inspect its field-level changes."
                    }
                }
                a href="/api/v1/audit/log" class="cr-button" { "JSON API" span aria-hidden="true" { " ↗" } }
            }
            form method="get" action=(reset_url) class="cr-surface mb-4 grid gap-3 p-3 sm:grid-cols-[1fr_1fr_1fr_1fr_auto]" {
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-slate-600" { "Collection" }
                    input type="text" name="collection" value=(query.collection.as_deref().unwrap_or("")) placeholder="deals" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-slate-600" { "Record ID" }
                    input type="text" name="id" value=(query.id.as_deref().unwrap_or("")) placeholder="acme-renewal" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-slate-600" { "Agent" }
                    input type="text" name="agent" value=(query.agent.as_deref().unwrap_or("")) placeholder="claude-code" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-slate-600" { "Agent session" }
                    input type="text" name="session" value=(query.session.as_deref().unwrap_or("")) placeholder="6d1baa69" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                div class="flex items-end gap-2" {
                    button type="submit" class="cr-button cr-button-primary" { "Filter events" }
                    a href=(reset_url) class="cr-button" { "Reset" }
                }
            }
            (render_audit_entries(&page.data))
            div class="cr-surface mt-4 flex flex-col gap-3 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between" {
                p class="text-slate-600" { "Showing events " (first) "–" (last) " newest first" }
                div class="flex items-center gap-2" {
                    @if let Some(offset) = page.pagination.previous_offset {
                        a href=(audit_page_url(query, page.pagination.limit, offset)) class="cr-button" { "Previous" }
                    }
                    @if let Some(offset) = page.pagination.next_offset {
                        a href=(audit_page_url(query, page.pagination.limit, offset)) class="cr-button" { "Next" }
                    }
                }
            }
        },
        ui,
        csrf_token,
    )
}

fn render_audit_entries(entries: &[AuditEntry]) -> Markup {
    html! {
        div class="cr-audit-list" {
            @if entries.is_empty() {
                div class="p-10 text-center text-sm text-slate-500" {
                    "No audit events match this filter."
                }
            } @else {
                @for entry in entries {
                    article id=(format!("event-{}", entry.payload.sequence)) class="cr-audit-entry scroll-mt-20" {
                        div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between" {
                            div class="min-w-0" {
                                div class="flex flex-wrap items-center gap-2" {
                                    span class="cr-pill cr-pill-accent" { (entry.payload.action.to_string()) }
                                    span class="cr-data" { "#" (entry.payload.sequence) }
                                    span class="cr-pill" { (audit_source_label(&entry.payload.source)) }
                                }
                                a href=(audit_filter_url(&entry.payload.record.collection, &entry.payload.record.id)) class="mt-3 block truncate font-mono text-sm font-semibold text-slate-950 hover:text-blue-700" {
                                    (entry.payload.record.reference())
                                }
                                p class="mt-1 text-xs text-slate-500" {
                                    "by " span class="font-medium text-slate-700" { (&entry.payload.actor) }
                                    @if let Some(operator) = entry
                                        .payload
                                        .access
                                        .as_ref()
                                        .and_then(|access| access.impersonated_by.as_ref())
                                    {
                                        " · impersonated by " span class="font-medium text-slate-700" { (&operator.display) }
                                    }
                                    @if let Some(agent) = &entry.payload.agent {
                                        " · via " a href=(audit_agent_url(&agent.id)) class="font-medium text-slate-700 hover:text-blue-700" { (&agent.id) }
                                    }
                                    " · " time datetime=(&entry.payload.timestamp) { (&entry.payload.timestamp) }
                                }
                                @if let Some(agent) = &entry.payload.agent {
                                    (render_audit_agent(agent))
                                }
                                @if let Some(authorization) = &entry.payload.authorization {
                                    p class="mt-2 text-xs text-slate-500" {
                                        "Authorization "
                                        span class="font-medium text-slate-700" { (authorization.mode.label()) }
                                        @if let Some(grant) = &authorization.grant { " · grant " (grant) }
                                        @if let Some(approved_by) = &authorization.approved_by { " · approved by " (approved_by) }
                                        @if let Some(at) = &authorization.at { " · " (at) }
                                        @if let Some(approved) = &authorization.approved_changes {
                                            " · approved change set "
                                            span class="cr-data" title=(approved) { (short_hash(approved)) }
                                        }
                                    }
                                }
                                @if let Some(intent) = &entry.payload.intent {
                                    @if let Some(request) = &intent.request {
                                        (render_intent_part("Requested", request))
                                    }
                                    @if let Some(rationale) = &intent.rationale {
                                        (render_intent_part("Agent rationale", rationale))
                                    }
                                }
                                @if let Some(message) = &entry.payload.message {
                                    p class="mt-2 text-sm text-slate-600" { (message) }
                                }
                            }
                            span class="cr-data shrink-0" title=(&entry.hash) { (short_hash(&entry.hash)) }
                        }
                        details class="mt-4 border-t border-slate-100 pt-4" {
                            summary class="cursor-pointer text-sm font-semibold text-blue-700 hover:text-blue-900" {
                                (entry.payload.changes.len()) " field-level " @if entry.payload.changes.len() == 1 { "change" } @else { "changes" }
                            }
                            div class="mt-3 space-y-3" {
                                @for change in &entry.payload.changes {
                                    div class="rounded-lg border border-slate-200 bg-slate-50 p-3" {
                                        div class="flex flex-wrap items-center gap-2" {
                                            span class="rounded bg-slate-200 px-2 py-0.5 text-xs font-bold uppercase text-slate-700" { (audit_change_operation(change)) }
                                            code class="text-xs text-slate-700" { (audit_change_path(change)) }
                                        }
                                        div class="mt-3 grid gap-3 lg:grid-cols-2" {
                                            @if let Some(before) = audit_change_before(change) {
                                                div {
                                                    p class="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500" { "Before" }
                                                    pre class="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-red-100 bg-red-50 p-3 text-xs leading-5 text-red-950" { (json_preview(before)) }
                                                }
                                            }
                                            @if let Some(after) = audit_change_after(change) {
                                                div {
                                                    p class="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-500" { "After" }
                                                    pre class="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-emerald-100 bg-emerald-50 p-3 text-xs leading-5 text-emerald-950" { (json_preview(after)) }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn view_filter_fields(schema: Option<&JsonValue>, columns: &[String]) -> Vec<ViewFilterField> {
    let mut fields = schema
        .and_then(|schema| schema_form_fields(schema, &Mapping::new()))
        .unwrap_or_default()
        .into_iter()
        .map(|field| ViewFilterField {
            key: field.key,
            label: field.label,
            kind: field.kind,
        })
        .collect::<Vec<_>>();
    let mut known = fields
        .iter()
        .map(|field| field.key.clone())
        .collect::<BTreeSet<_>>();
    for column in columns {
        if known.insert(column.clone()) {
            fields.push(ViewFilterField {
                key: column.clone(),
                label: humanize_field_name(column),
                kind: SchemaFieldKind::Yaml,
            });
        }
    }
    fields
}

fn filter_kind_data(kind: &SchemaFieldKind) -> (&'static str, &'static str) {
    match kind {
        SchemaFieldKind::Select(_) => ("select", "text"),
        SchemaFieldKind::MultiSelect(_) => ("select", "text"),
        SchemaFieldKind::Boolean => ("select", "text"),
        SchemaFieldKind::Integer { .. } => ("input", "number"),
        SchemaFieldKind::Number { .. } => ("input", "number"),
        SchemaFieldKind::String { input_type, .. } => ("input", input_type),
        SchemaFieldKind::Yaml => ("input", "text"),
    }
}

fn filter_options_json(kind: &SchemaFieldKind) -> String {
    let values = match kind {
        SchemaFieldKind::Select(values) | SchemaFieldKind::MultiSelect(values) => values
            .iter()
            .map(|value| {
                json!({
                    "value": serialize_yaml_value(value),
                    "label": schema_value_label(value),
                })
            })
            .collect::<Vec<_>>(),
        SchemaFieldKind::Boolean => vec![
            json!({ "value": "true", "label": "True" }),
            json!({ "value": "false", "label": "False" }),
        ],
        _ => Vec::new(),
    };
    serde_json::to_string(&values).expect("filter options are JSON serializable")
}

fn filter_operator_options(kind: &SchemaFieldKind) -> Vec<ViewFilterOperator> {
    use ViewFilterOperator::{
        Contains, EndsWith, Eq, Gt, Gte, IsEmpty, IsNotEmpty, Lt, Lte, Ne, NotContains, StartsWith,
    };
    match kind {
        SchemaFieldKind::Select(_) | SchemaFieldKind::Boolean => {
            vec![Eq, Ne, IsEmpty, IsNotEmpty]
        }
        SchemaFieldKind::Integer { .. } | SchemaFieldKind::Number { .. } => {
            vec![Eq, Ne, Gt, Gte, Lt, Lte, IsEmpty, IsNotEmpty]
        }
        SchemaFieldKind::String { .. } => vec![
            Eq,
            Ne,
            Contains,
            NotContains,
            StartsWith,
            EndsWith,
            Gt,
            Gte,
            Lt,
            Lte,
            IsEmpty,
            IsNotEmpty,
        ],
        SchemaFieldKind::MultiSelect(_) => {
            vec![Contains, NotContains, IsEmpty, IsNotEmpty]
        }
        SchemaFieldKind::Yaml => vec![
            Eq,
            Ne,
            Contains,
            NotContains,
            StartsWith,
            EndsWith,
            Gt,
            Gte,
            Lt,
            Lte,
            IsEmpty,
            IsNotEmpty,
        ],
    }
}

fn filter_operators_json(kind: &SchemaFieldKind) -> String {
    let operators = filter_operator_options(kind)
        .into_iter()
        .map(|operator| json!({ "value": operator.as_str(), "label": operator.label() }))
        .collect::<Vec<_>>();
    serde_json::to_string(&operators).expect("filter operators are JSON serializable")
}

fn render_filter_operator_control(
    fields: &[ViewFilterField],
    index: usize,
    selected_field: &str,
    selected_operator: ViewFilterOperator,
) -> Markup {
    let mut operators = fields
        .iter()
        .find(|field| field.key == selected_field)
        .map(|field| filter_operator_options(&field.kind))
        .unwrap_or_else(|| filter_operator_options(&SchemaFieldKind::Yaml));
    if !operators.contains(&selected_operator) {
        operators.push(selected_operator);
    }
    html! {
        select name="filter_operator" data-filter-operator="true" aria-label=(format!("Filter operator {}", index + 1)) class="min-w-0 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 xl:col-span-3" {
            @for operator in operators {
                option value=(operator.as_str()) selected[operator == selected_operator] { (operator.label()) }
            }
        }
    }
}

fn render_filter_value_control(
    fields: &[ViewFilterField],
    index: usize,
    selected_field: &str,
    selected_operator: ViewFilterOperator,
    value: &str,
) -> Markup {
    if !selected_operator.requires_value() {
        return html! {
            input type="hidden" name="filter_value" data-filter-value="true" value="";
            span class="block px-3 py-2 text-sm text-slate-400" { "No value needed" }
        };
    }
    let definition = fields.iter().find(|field| field.key == selected_field);
    let aria_label = format!("Filter value {}", index + 1);
    match definition.map(|field| &field.kind) {
        Some(SchemaFieldKind::Select(options) | SchemaFieldKind::MultiSelect(options)) => {
            let known = options
                .iter()
                .any(|option| serialize_yaml_value(option) == value);
            html! {
                select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                    option value="" selected[value.is_empty()] { "Select a value…" }
                    @for option in options {
                        @let serialized = serialize_yaml_value(option);
                        option value=(serialized.clone()) selected[serialized == value] { (schema_value_label(option)) }
                    }
                    @if !value.is_empty() && !known {
                        option value=(value) selected { (value) " (custom)" }
                    }
                }
            }
        }
        Some(SchemaFieldKind::Boolean) => html! {
            select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                option value="" selected[value.is_empty()] { "Select a value…" }
                option value="true" selected[value == "true"] { "True" }
                option value="false" selected[value == "false"] { "False" }
            }
        },
        Some(SchemaFieldKind::Integer { .. }) => html! {
            input type="number" step="1" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact number" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        Some(SchemaFieldKind::Number { .. }) => html! {
            input type="number" step="any" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact number" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        Some(SchemaFieldKind::String { input_type, .. }) => html! {
            input type=(input_type) name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact value" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        _ => html! {
            input type="text" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Typed YAML value" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
        },
    }
}

fn render_filter_row(
    fields: &[ViewFilterField],
    index: usize,
    selected_field: &str,
    selected_operator: ViewFilterOperator,
    value: &str,
) -> Markup {
    let selected_known = fields.iter().any(|field| field.key == selected_field);
    html! {
        div data-filter-row="true" class="grid gap-2 rounded-xl border border-slate-200 bg-slate-50 p-3 md:grid-cols-2 xl:grid-cols-12 xl:items-center" {
            select name="filter_field" data-filter-field="true" aria-label=(format!("Filter field {}", index + 1)) class="min-w-0 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 xl:col-span-4" {
                option value="" selected[selected_field.is_empty()] data-filter-kind="input" data-filter-input-type="text" data-filter-options="[]" data-filter-operators=(filter_operators_json(&SchemaFieldKind::Yaml)) { "Choose a field…" }
                @for field in fields {
                    @let (kind, input_type) = filter_kind_data(&field.kind);
                    option value=(&field.key) selected[field.key == selected_field] data-filter-kind=(kind) data-filter-input-type=(input_type) data-filter-options=(filter_options_json(&field.kind)) data-filter-operators=(filter_operators_json(&field.kind)) { (&field.label) }
                }
                @if !selected_field.is_empty() && !selected_known {
                    option value=(selected_field) selected data-filter-kind="input" data-filter-input-type="text" data-filter-options="[]" data-filter-operators=(filter_operators_json(&SchemaFieldKind::Yaml)) { (selected_field) " (custom)" }
                }
            }
            (render_filter_operator_control(fields, index, selected_field, selected_operator))
            div data-filter-value-slot="true" class="min-w-0 md:col-span-2 xl:col-span-4" {
                (render_filter_value_control(fields, index, selected_field, selected_operator, value))
            }
            button type="button" data-remove-filter="true" aria-label=(format!("Remove filter {}", index + 1)) class="justify-self-start rounded-lg px-3 py-2 text-sm font-semibold text-slate-500 hover:bg-red-50 hover:text-red-700 md:col-span-2 xl:col-span-1 xl:justify-self-end" { "Remove" }
        }
    }
}

const FILTER_BUILDER_SCRIPT: &str = r#"(() => {
  const builder = document.querySelector('[data-filter-builder]');
  if (!builder) return;
  const disclosure = builder.querySelector('[data-filter-disclosure]');
  const list = builder.querySelector('[data-filter-list]');
  const template = builder.querySelector('template[data-filter-template]');
  const addButton = builder.querySelector('[data-add-filter]');
  const closeButton = builder.querySelector('[data-close-filter]');
  const maximum = Number(builder.dataset.maxFilters || '20');

  const closeDisclosure = () => {
    if (!disclosure) return;
    disclosure.open = false;
    disclosure.querySelector('summary')?.focus();
  };

  closeButton?.addEventListener('click', closeDisclosure);
  builder.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && disclosure?.open) closeDisclosure();
  });

  const reindex = () => {
    const rows = [...list.querySelectorAll('[data-filter-row]')];
    rows.forEach((row, index) => {
      row.querySelector('[data-filter-field]').setAttribute('aria-label', `Filter field ${index + 1}`);
      row.querySelector('[data-filter-operator]').setAttribute('aria-label', `Filter operator ${index + 1}`);
      row.querySelector('[data-filter-value]').setAttribute('aria-label', `Filter value ${index + 1}`);
      row.querySelector('[data-remove-filter]').setAttribute('aria-label', `Remove filter ${index + 1}`);
    });
    addButton.disabled = rows.length >= maximum;
  };

  const replaceValueControl = (row) => {
    const field = row.querySelector('[data-filter-field]');
    const option = field.selectedOptions[0];
    const operator = row.querySelector('[data-filter-operator]').value;
    const slot = row.querySelector('[data-filter-value-slot]');
    const kind = option.dataset.filterKind || 'input';
    let control;
    if (operator === 'is-empty' || operator === 'is-not-empty') {
      control = document.createElement('input');
      control.type = 'hidden';
      control.value = '';
      const hint = document.createElement('span');
      hint.className = 'block px-3 py-2 text-sm text-slate-400';
      hint.textContent = 'No value needed';
      control.name = 'filter_value';
      control.dataset.filterValue = 'true';
      slot.replaceChildren(control, hint);
      reindex();
      return;
    } else if (kind === 'select') {
      control = document.createElement('select');
      const blank = document.createElement('option');
      blank.value = '';
      blank.textContent = 'Select a value…';
      control.appendChild(blank);
      JSON.parse(option.dataset.filterOptions || '[]').forEach((item) => {
        const choice = document.createElement('option');
        choice.value = item.value;
        choice.textContent = item.label;
        control.appendChild(choice);
      });
    } else {
      control = document.createElement('input');
      control.type = option.dataset.filterInputType || 'text';
      if (control.type === 'number') control.step = 'any';
      control.placeholder = control.type === 'number' ? 'Exact number' : 'Exact value';
    }
    control.name = 'filter_value';
    control.dataset.filterValue = 'true';
    control.className = 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2';
    slot.replaceChildren(control);
    reindex();
  };

  const replaceOperatorControl = (row) => {
    const field = row.querySelector('[data-filter-field]');
    const selected = field.selectedOptions[0];
    const operator = row.querySelector('[data-filter-operator]');
    const previous = operator.value;
    const options = JSON.parse(selected.dataset.filterOperators || '[]');
    operator.replaceChildren(...options.map((item) => {
      const choice = document.createElement('option');
      choice.value = item.value;
      choice.textContent = item.label;
      return choice;
    }));
    if (options.some((item) => item.value === previous)) operator.value = previous;
    replaceValueControl(row);
  };

  const bindRow = (row) => {
    row.querySelector('[data-filter-field]').addEventListener('change', () => replaceOperatorControl(row));
    row.querySelector('[data-filter-operator]').addEventListener('change', () => replaceValueControl(row));
    row.querySelector('[data-remove-filter]').addEventListener('click', () => {
      const rows = list.querySelectorAll('[data-filter-row]');
      if (rows.length === 1) {
        row.querySelector('[data-filter-field]').value = '';
        row.querySelector('[data-filter-operator]').value = 'eq';
        replaceOperatorControl(row);
      } else {
        row.remove();
        reindex();
      }
    });
  };

  list.querySelectorAll('[data-filter-row]').forEach(bindRow);
  addButton.addEventListener('click', () => {
    if (list.querySelectorAll('[data-filter-row]').length >= maximum) return;
    const row = template.content.firstElementChild.cloneNode(true);
    list.appendChild(row);
    bindRow(row);
    reindex();
    row.querySelector('[data-filter-field]').focus();
  });
  reindex();
})();"#;

#[allow(clippy::too_many_arguments)]
fn render_view_records(
    view: &ViewDefinition,
    columns: &[String],
    available_columns: &[String],
    page: &Page<Record>,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    can_create: bool,
    can_manage_views: bool,
    updatable: &BTreeSet<String>,
) -> Markup {
    let new_url = format!("/{}/new", encode_segment(&view.name));
    let reset_url = format!("/{}", encode_segment(&view.name));
    let first = if page.pagination.returned == 0 {
        0
    } else {
        page.pagination.offset + 1
    };
    let last = page.pagination.offset + page.pagination.returned;
    let filter_fields = view_filter_fields(schema, available_columns);
    let mut filter_rows = query
        .filter_field
        .iter()
        .zip(&query.filter_value)
        .enumerate()
        .map(|(index, (field, value))| {
            (
                field.as_str(),
                query
                    .filter_operator
                    .get(index)
                    .copied()
                    .unwrap_or_default(),
                value.as_str(),
            )
        })
        .collect::<Vec<_>>();
    if filter_rows.is_empty() {
        filter_rows.push(("", ViewFilterOperator::default(), ""));
    }
    let active_filter_count = filter_rows
        .iter()
        .filter(|(field, _, value)| !field.is_empty() || !value.is_empty())
        .count();
    page_layout(
        &view.title,
        &format!("/{}", encode_segment(&view.name)),
        navigation,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-slate-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                span class="text-slate-900" { (&view.title) }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between" {
                div {
                    div class="flex flex-wrap items-center gap-2" {
                        h1 class="cr-title capitalize" { (&view.title) }
                        span class="cr-pill" {
                            @if view.saved { "saved view" } @else { "automatic view" }
                        }
                        @if view.layout == ViewLayout::Kanban {
                            span class="cr-pill cr-pill-accent" { "kanban" }
                        }
                        @if let Some(total) = page.pagination.total {
                            span class="cr-pill" { (total) " records" }
                        }
                    }
                    p class="cr-lede mt-1" {
                        "Collection " code class="cr-filter-tag" { (&view.collection) }
                    }
                    @if !view.filters.is_empty() || !view.where_expr.is_empty() || !view.filter_groups.is_empty() {
                        div class="mt-2 flex flex-wrap gap-1.5" {
                            @for filter in &view.filters {
                                code class="cr-filter-tag" { (filter) }
                            }
                            @for expression in &view.where_expr {
                                code class="cr-filter-tag" { (expression) }
                            }
                            @for group in &view.filter_groups {
                                code class="cr-filter-tag" {
                                    (match group.match_mode { ViewPredicateMatch::All => "All: ", ViewPredicateMatch::Any => "Any: " })
                                    (group.expressions.join(" · "))
                                }
                            }
                        }
                    }
                }
                div class="flex flex-wrap items-center gap-2" {
                    @if can_manage_views {
                        (render_save_view_control(
                            view,
                            query,
                            columns,
                            available_columns,
                            csrf_token,
                        ))
                    }
                    form method="get" action=(reset_url.clone()) data-filter-builder="true" data-max-filters=(MAX_VIEW_FILTERS) class="contents" {
                        div class="relative min-w-48 flex-1 sm:flex-none" {
                            label class="sr-only" { "Search records" }
                            input type="search" name="q" value=(query.q.as_deref().unwrap_or("")) aria-label="Search records" placeholder="Search records…" autocomplete="off" data-view-search="true" class="w-full border bg-white py-2 pl-3 pr-10 text-sm outline-none placeholder:text-slate-400 sm:w-56";
                            button type="submit" aria-label="Submit search" title="Search" class="absolute inset-y-1 right-1 inline-flex w-8 items-center justify-center rounded-md text-slate-400 hover:bg-slate-100 hover:text-blue-700" { "⌕" }
                        }
                        details class="relative" data-filter-disclosure="true" data-active-filters=(active_filter_count) {
                            summary class="cr-button cursor-pointer list-none gap-2" {
                                "Filter"
                                @if active_filter_count > 0 {
                                    span class="cr-pill cr-pill-accent" { (active_filter_count) }
                                }
                            }
                            div data-filter-panel="true" class="cr-popover cr-filter-popover z-30 space-y-4 overflow-y-auto p-4 sm:p-5" {
                                div {
                                    div class="mb-3 flex flex-wrap items-center justify-between gap-3" {
                                        div {
                                            div class="flex items-center gap-2" {
                                                h2 class="text-sm font-bold text-slate-900" { "Filters" }
                                                label {
                                                    span class="sr-only" { "Condition match mode" }
                                                    select name="filter_match" aria-label="Condition match mode" class="rounded-full border-0 bg-slate-100 py-1 pl-2.5 pr-8 text-xs font-semibold text-slate-600 outline-none ring-indigo-500 focus:ring-2" {
                                                        option value="all" selected[query.filter_match == ViewFilterMatch::All] { "All conditions match" }
                                                        option value="any" selected[query.filter_match == ViewFilterMatch::Any] { "Any condition matches" }
                                                    }
                                                }
                                            }
                                            p class="mt-1 text-xs text-slate-500" { "Field controls and allowed values come from the collection schema." }
                                        }
                                        div class="flex items-center gap-2" {
                                            button type="button" data-add-filter="true" class="cr-button disabled:cursor-not-allowed disabled:opacity-40" { "+ Add condition" }
                                            button type="button" data-close-filter="true" class="cr-button" { "Close" }
                                        }
                                    }
                                    div data-filter-list="true" class="space-y-2" {
                                        @for (index, (field, operator, value)) in filter_rows.iter().enumerate() {
                                            (render_filter_row(&filter_fields, index, field, *operator, value))
                                        }
                                    }
                                    template data-filter-template="true" {
                                        (render_filter_row(&filter_fields, 0, "", ViewFilterOperator::default(), ""))
                                    }
                                }
                                div class="border-t border-slate-100 pt-4" {
                                    details open[query_columns_custom(query)] {
                                        summary class="cursor-pointer list-none text-sm font-bold text-slate-900" {
                                            span class="inline-flex items-center gap-2" {
                                                "Columns"
                                                span class="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-600" { (columns.len()) " shown" }
                                            }
                                        }
                                        input type="hidden" name="columns" value="custom";
                                        p class="mt-1 text-xs text-slate-500" { "Choose the fields shown in the table or on Kanban cards. Select at least one." }
                                        div role="group" aria-label="Visible columns" class="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4" {
                                            @for column in available_columns {
                                                label class="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:border-indigo-300 hover:bg-indigo-50/40" {
                                                    input type="checkbox" name="column" value=(column) checked[columns.contains(column)] class="size-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500";
                                                    span class="truncate" title=(column) { (humanize_field_name(column)) }
                                                }
                                            }
                                        }
                                    }
                                }
                                div class="border-t border-slate-100 pt-4" {
                                    div class="mb-3" {
                                        h2 class="text-sm font-bold text-slate-900" { "Sorting" }
                                        p class="mt-1 text-xs text-slate-500" { "Missing values stay last; record ID breaks ties." }
                                    }
                                    div class="grid gap-3 sm:grid-cols-2" {
                                        label {
                                            span class="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Sort by" }
                                            select name="sort_field" aria-label="Sort by" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                                option value="" selected[view_sort_field(query).is_none()] { "Default (record ID)" }
                                                option value="$id" selected[view_sort_field(query) == Some("$id")] { "Record ID" }
                                                @for field in &filter_fields {
                                                    option value=(&field.key) selected[view_sort_field(query) == Some(field.key.as_str())] { (&field.label) }
                                                }
                                            }
                                        }
                                        label {
                                            span class="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Direction" }
                                            select name="sort_direction" aria-label="Sort direction" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                                option value="asc" selected[query.sort_direction == ViewSortDirection::Asc] { "Ascending" }
                                                option value="desc" selected[query.sort_direction == ViewSortDirection::Desc] { "Descending" }
                                            }
                                        }
                                    }
                                }
                                div class="flex flex-wrap items-center justify-end gap-2 border-t border-slate-100 pt-4" {
                                    a href=(reset_url.clone()) class="cr-button" { "Clear all" }
                                    button type="submit" class="cr-button cr-button-primary" { "Apply view" }
                                }
                            }
                        }
                    }
                    @if can_create {
                        a href=(new_url) class="cr-button cr-button-primary" {
                            "New record"
                        }
                    }
                }
            }
            @if let Some(notice) = query.notice.as_deref() {
                div role="status" class="mb-5 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800" { (notice) }
            }
            script { (PreEscaped(FILTER_BUILDER_SCRIPT)) }
            @if view.layout == ViewLayout::Kanban {
                (render_kanban_board(view, columns, page, query, schema, csrf_token, updatable))
            } @else {
            div class="cr-table-shell" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-slate-200 text-left text-sm" {
                        thead {
                            tr {
                                th scope="col" aria-sort=(sort_aria_state(query, "$id")) class="whitespace-nowrap px-4 py-3 font-semibold text-slate-700" {
                                    a href=(view_sort_url(view, query, "$id", page.pagination.limit)) aria-label=(sort_link_label(query, "record ID", "$id")) class="inline-flex items-center gap-1.5 hover:text-indigo-700" {
                                        "ID" span aria-hidden="true" class="text-slate-400" { (sort_indicator(query, "$id")) }
                                    }
                                }
                                @for column in columns {
                                    th scope="col" aria-sort=(sort_aria_state(query, column)) class="whitespace-nowrap px-4 py-3 font-semibold text-slate-700" {
                                        a href=(view_sort_url(view, query, column, page.pagination.limit)) aria-label=(sort_link_label(query, &humanize_field_name(column), column)) class="inline-flex items-center gap-1.5 hover:text-indigo-700" {
                                            (column) span aria-hidden="true" class="text-slate-400" { (sort_indicator(query, column)) }
                                        }
                                    }
                                }
                                th scope="col" class="px-4 py-3 text-right font-semibold text-slate-700" { "" }
                            }
                        }
                        tbody class="divide-y divide-slate-100" {
                            @if page.data.is_empty() {
                                tr { td colspan=(columns.len() + 2) class="px-4 py-12 text-center text-slate-500" { "No records match this view." } }
                            } @else {
                                @for record in &page.data {
                                    tr {
                                        td class="whitespace-nowrap px-4 py-3 font-mono text-xs font-semibold" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="text-slate-900 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        }
                                        @for column in columns {
                                            td class="max-w-sm px-4 py-3 text-slate-700" {
                                                a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="line-clamp-2 hover:text-indigo-700 hover:underline" { (record_value(record, column)) }
                                            }
                                        }
                                        td class="whitespace-nowrap px-4 py-3 text-right" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) aria-label=(format!("View {}", record.id)) title="Open record" class="inline-flex size-6 items-center justify-center rounded text-slate-400 hover:bg-slate-100 hover:text-indigo-700" {
                                                span class="sr-only" { "View" }
                                                span aria-hidden="true" { "→" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div class="flex flex-col gap-2 border-t border-slate-200 bg-slate-50 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between" {
                    p class="text-slate-600" {
                        "Showing " (first) "–" (last)
                        @if let Some(total) = page.pagination.total { " of " (total) }
                    }
                    div class="flex items-center gap-2" {
                        @if let Some(offset) = page.pagination.previous_offset {
                            a href=(view_page_url(view, query, page.pagination.limit, offset)) class="cr-button" { "Previous" }
                        }
                        @if let Some(offset) = page.pagination.next_offset {
                            a href=(view_page_url(view, query, page.pagination.limit, offset)) class="cr-button" { "Next" }
                        }
                    }
                }
            }
            }
        },
        ui,
        csrf_token,
    )
}

fn render_save_view_control(
    view: &ViewDefinition,
    query: &ViewQuery,
    columns: &[String],
    available_columns: &[String],
    csrf_token: &str,
) -> Markup {
    let action = format!("/{}/save-view", encode_segment(&view.name));
    html! {
        details class="relative" {
            summary class="cr-button cursor-pointer list-none" {
                "Save as view"
            }
            div class="cr-popover absolute right-0 z-20 mt-2 w-80 p-4" {
                form method="post" action=(action) class="space-y-3" {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    input type="hidden" name="filter_match" value=(match query.filter_match { ViewFilterMatch::All => "all", ViewFilterMatch::Any => "any" });
                    @for (index, (field, value)) in query.filter_field.iter().zip(&query.filter_value).enumerate() {
                        input type="hidden" name="filter_field" value=(field);
                        input type="hidden" name="filter_operator" value=(query.filter_operator.get(index).copied().unwrap_or_default().as_str());
                        input type="hidden" name="filter_value" value=(value);
                    }
                    @if let Some(field) = query.sort_field.as_deref() {
                        input type="hidden" name="sort_field" value=(field);
                    }
                    input type="hidden" name="sort_direction" value=(query.sort_direction.as_str());
                    @for column in columns {
                        input type="hidden" name="column" value=(column);
                    }
                    div {
                        h2 class="text-sm font-bold text-slate-900" { "Save current view" }
                        p class="mt-1 text-xs leading-5 text-slate-500" { "Preserves applied filters, all/any matching, layout, columns, and sorting. Search text remains shareable in the URL." }
                    }
                    label class="block" {
                        span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "View name" }
                        input required name="name" placeholder="enterprise-deals" autocomplete="off" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
                    }
                    label class="block" {
                        span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Title (optional)" }
                        input name="title" placeholder=(format!("{} copy", view.title)) autocomplete="off" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
                    }
                    div class="grid gap-3 sm:grid-cols-2" {
                        label class="block" {
                            span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Layout" }
                            select name="layout" aria-label="Layout" data-view-layout="true" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                option value="table" selected[view.layout == ViewLayout::Table] { "Table" }
                                option value="kanban" selected[view.layout == ViewLayout::Kanban] { "Kanban" }
                            }
                        }
                        label class="block" {
                            span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Group Kanban by" }
                            select name="group_by" aria-label="Group Kanban by" data-view-group-by="true" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-400" {
                                option value="" selected[view.group_by.is_none()] { "Choose a field…" }
                                @for column in available_columns {
                                    option value=(column) selected[view.group_by.as_deref() == Some(column.as_str())] { (humanize_field_name(column)) }
                                }
                            }
                        }
                    }
                    p class="text-xs leading-5 text-slate-500" { "Kanban uses the chosen front matter field as lanes; moving a card updates that field through the audited database path." }
                    button type="submit" class="cr-button cr-button-primary w-full" { "Save view" }
                }
            }
        }
        script { (PreEscaped(SAVE_VIEW_LAYOUT_SCRIPT)) }
    }
}

const SAVE_VIEW_LAYOUT_SCRIPT: &str = r#"(() => {
  document.querySelectorAll('[data-view-layout]').forEach((layout) => {
    const form = layout.closest('form');
    const groupBy = form && form.querySelector('[data-view-group-by]');
    if (!groupBy) return;
    const update = () => {
      const kanban = layout.value === 'kanban';
      groupBy.disabled = !kanban;
      groupBy.required = kanban;
      if (!kanban) groupBy.value = '';
    };
    layout.addEventListener('change', update);
    update();
  });
})();"#;

fn render_kanban_board(
    view: &ViewDefinition,
    columns: &[String],
    page: &Page<Record>,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
    updatable: &BTreeSet<String>,
) -> Markup {
    let group_by = view
        .group_by
        .as_deref()
        .expect("validated Kanban views have a group_by field");
    let lanes = kanban_lanes(&page.data, group_by, schema);
    let card_columns = columns
        .iter()
        .filter(|column| column.as_str() != group_by)
        .take(5)
        .collect::<Vec<_>>();
    let first = if page.pagination.returned == 0 {
        0
    } else {
        page.pagination.offset + 1
    };
    let last = page.pagination.offset + page.pagination.returned;

    html! {
        div class="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600" {
            p {
                "Kanban grouped by " code class="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-xs font-semibold text-slate-800" { (group_by) }
            }
            @if updatable.is_empty() {
                p { "This perspective can view cards but cannot move them." }
            } @else {
                p { "Drag permitted cards between lanes or use each card’s move control." }
            }
        }
        div class="overflow-x-auto pb-3" {
            div data-kanban-board="true" class="flex min-w-max items-start gap-3" {
                @for lane in &lanes {
                    section
                        data-kanban-lane="true"
                        data-kanban-target=(kanban_target_json(&lane.target))
                        data-kanban-csrf=(csrf_token)
                        class="cr-kanban-lane w-72 shrink-0 p-2.5 transition-colors"
                    {
                        div class="mb-2 flex items-center justify-between gap-3 px-1" {
                            h2 class="text-sm font-semibold text-slate-900" { (&lane.label) }
                            span class="cr-pill bg-white" { (lane.records.len()) }
                        }
                        div class="min-h-20 space-y-2" {
                            @if lane.records.is_empty() {
                                p class="rounded-xl border border-dashed border-slate-300 px-4 py-8 text-center text-xs text-slate-500" { "Drop cards here" }
                            }
                            @for record in &lane.records {
                                @let can_move = updatable.contains(&record.id);
                                article
                                    draggable=(if can_move { "true" } else { "false" })
                                    data-kanban-card=(if can_move { "true" } else { "false" })
                                    data-move-url=(kanban_move_url(view, &record.id))
                                    class=(if can_move { "cr-kanban-card cursor-grab p-3 active:cursor-grabbing" } else { "cr-kanban-card p-3" })
                                {
                                    div class="flex items-start justify-between gap-3" {
                                        a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="break-all font-mono text-sm font-bold text-slate-950 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        span aria-hidden="true" class="select-none text-slate-300" { "⠿" }
                                    }
                                    @if !card_columns.is_empty() {
                                        dl class="mt-2 space-y-1" {
                                            @for column in &card_columns {
                                                div {
                                                    dt class="text-[0.65rem] font-bold uppercase tracking-wide text-slate-400" { (column) }
                                                    dd class="mt-0.5 line-clamp-2 text-sm text-slate-700" { (record_value(record, column)) }
                                                }
                                            }
                                        }
                                    }
                                    @if can_move {
                                        details class="cr-kanban-move mt-3 border-t border-slate-100 pt-2" {
                                            summary class="cursor-pointer list-none" { "Move card…" }
                                            form method="post" action=(kanban_move_url(view, &record.id)) class="flex items-center gap-2" {
                                                input type="hidden" name="_csrf" value=(csrf_token);
                                                label class="min-w-0 flex-1" {
                                                    span class="sr-only" { "Move " (&record.id) " to" }
                                                    select name="target" aria-label=(format!("Move {} to", record.id)) class="w-full rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-xs outline-none ring-indigo-500 focus:ring-2" {
                                                        @for option_lane in &lanes {
                                                            @if option_lane.target == lane.target {
                                                                option value=(kanban_target_json(&option_lane.target)) selected { (&option_lane.label) }
                                                            } @else {
                                                                option value=(kanban_target_json(&option_lane.target)) { (&option_lane.label) }
                                                            }
                                                        }
                                                    }
                                                }
                                                button type="submit" class="cr-button cr-button-primary min-h-0 px-2.5 py-1.5 text-xs" { "Move" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        div class="cr-surface mt-1 flex flex-col gap-2 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between" {
            p class="text-slate-600" {
                "Showing " (first) "–" (last)
                @if let Some(total) = page.pagination.total { " of " (total) }
            }
            div class="flex items-center gap-2" {
                @if let Some(offset) = page.pagination.previous_offset {
                    a href=(view_page_url(view, query, page.pagination.limit, offset)) class="cr-button" { "Previous" }
                }
                @if let Some(offset) = page.pagination.next_offset {
                    a href=(view_page_url(view, query, page.pagination.limit, offset)) class="cr-button" { "Next" }
                }
            }
        }
        script { (PreEscaped(KANBAN_SCRIPT)) }
    }
}

const KANBAN_SCRIPT: &str = r#"(() => {
  const board = document.querySelector('[data-kanban-board]');
  if (!board) return;
  let draggedCard = null;

  board.querySelectorAll('[data-kanban-card="true"]').forEach((card) => {
    card.addEventListener('dragstart', () => {
      draggedCard = card;
      card.classList.add('opacity-50');
    });
    card.addEventListener('dragend', () => {
      draggedCard = null;
      card.classList.remove('opacity-50');
      board.querySelectorAll('[data-kanban-lane]').forEach((lane) => lane.classList.remove('ring-2', 'ring-blue-400'));
    });
  });

  board.querySelectorAll('[data-kanban-lane]').forEach((lane) => {
    lane.addEventListener('dragover', (event) => {
      event.preventDefault();
      lane.classList.add('ring-2', 'ring-blue-400');
    });
    lane.addEventListener('dragleave', () => lane.classList.remove('ring-2', 'ring-blue-400'));
    lane.addEventListener('drop', (event) => {
      event.preventDefault();
      if (!draggedCard) return;
      const form = document.createElement('form');
      form.method = 'post';
      form.action = draggedCard.dataset.moveUrl;
      const append = (name, value) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
      };
      append('_csrf', lane.dataset.kanbanCsrf);
      append('target', lane.dataset.kanbanTarget);
      document.body.appendChild(form);
      form.submit();
    });
  });
})();"#;

fn kanban_lanes<'a>(
    records: &'a [Record],
    group_by: &str,
    schema: Option<&JsonValue>,
) -> Vec<KanbanLane<'a>> {
    let mut lane_values = Vec::new();
    let mut known = BTreeSet::new();
    for value in kanban_schema_values(schema, group_by) {
        let serialized = serialize_yaml_value(&value);
        if known.insert(serialized.clone()) {
            lane_values.push((serialized, yaml_value(&value)));
        }
    }

    let mut observed = BTreeSet::new();
    let mut has_unassigned = false;
    for record in records {
        match record.field(group_by).ok().flatten() {
            Some(value) => {
                let serialized = serialize_yaml_value(value);
                if !known.contains(&serialized) {
                    observed.insert((serialized, yaml_value(value)));
                }
            }
            None => has_unassigned = true,
        }
    }
    lane_values.extend(observed);

    let mut lanes = lane_values
        .into_iter()
        .map(|(value, label)| KanbanLane {
            target: KanbanTarget::Value { value },
            label,
            records: Vec::new(),
        })
        .collect::<Vec<_>>();
    if has_unassigned || lanes.is_empty() {
        lanes.push(KanbanLane {
            target: KanbanTarget::Unset,
            label: "Unassigned".to_owned(),
            records: Vec::new(),
        });
    }

    for record in records {
        let target = match record.field(group_by).ok().flatten() {
            Some(value) => KanbanTarget::Value {
                value: serialize_yaml_value(value),
            },
            None => KanbanTarget::Unset,
        };
        if let Some(lane) = lanes.iter_mut().find(|lane| lane.target == target) {
            lane.records.push(record);
        }
    }
    lanes
}

fn kanban_schema_values(schema: Option<&JsonValue>, group_by: &str) -> Vec<YamlValue> {
    let Some(mut current) = schema else {
        return Vec::new();
    };
    for segment in group_by.split('.') {
        let Some(next) = current
            .get("properties")
            .and_then(JsonValue::as_object)
            .and_then(|properties| properties.get(segment))
        else {
            return Vec::new();
        };
        current = next;
    }
    current
        .get("enum")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect()
}

fn serialize_yaml_value(value: &YamlValue) -> String {
    yaml_serde::to_string(value)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "null".to_owned())
}

fn kanban_target_json(target: &KanbanTarget) -> String {
    serde_json::to_string(target).expect("Kanban target is JSON serializable")
}

fn kanban_move_url(view: &ViewDefinition, id: &str) -> String {
    format!(
        "/{}/records/{}/move",
        encode_segment(&view.name),
        encode_segment(id)
    )
}

fn collection_schema(database: &Database, collection: &str) -> Result<Option<JsonValue>> {
    Ok(database
        .collection_models()?
        .into_iter()
        .find(|model| model.name == collection)
        .and_then(|model| model.schema))
}

fn can_create_in_collection(database: &Database, collection: &str) -> Result<bool> {
    if database.access_allowed(
        AccessAction::Create,
        &AccessResource::collection(collection),
    )? {
        return Ok(true);
    }
    let Some(user) = database.current_user()? else {
        return Ok(false);
    };
    for grant in user.access {
        if matches!(
            &grant.resource,
            AccessResource::Record {
                collection: granted_collection,
                ..
            } if granted_collection == collection
        ) && database.access_allowed(AccessAction::Create, &grant.resource)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn schema_form_fields(schema: &JsonValue, attributes: &Mapping) -> Option<Vec<SchemaFormField>> {
    let properties = schema.get("properties")?.as_object()?;
    let required = schema
        .get("required")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .collect::<BTreeSet<_>>();
    let configured_order = schema
        .get("x-cr-ui")
        .and_then(|ui| ui.get("order"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .enumerate()
        .map(|(index, key)| (key.to_owned(), index))
        .collect::<BTreeMap<_, _>>();
    let mut fields = properties
        .iter()
        .map(|(key, definition)| SchemaFormField {
            key: key.clone(),
            label: definition
                .get("title")
                .and_then(JsonValue::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| humanize_field_name(key)),
            description: definition
                .get("description")
                .and_then(JsonValue::as_str)
                .map(str::to_owned),
            required: required.contains(key.as_str()),
            value: attributes.get(YamlValue::String(key.clone())).cloned(),
            kind: schema_field_kind(definition),
        })
        .collect::<Vec<_>>();
    fields.sort_by(|left, right| {
        let left_rank = configured_order
            .get(&left.key)
            .copied()
            .unwrap_or(usize::MAX);
        let right_rank = configured_order
            .get(&right.key)
            .copied()
            .unwrap_or(usize::MAX);
        left_rank
            .cmp(&right_rank)
            .then_with(|| right.required.cmp(&left.required))
            .then_with(|| left.label.cmp(&right.label))
    });
    Some(fields)
}

fn schema_field_kind(definition: &JsonValue) -> SchemaFieldKind {
    if let Some(values) = definition.get("enum").and_then(JsonValue::as_array) {
        return SchemaFieldKind::Select(json_values_as_yaml(values));
    }
    let field_type = definition.get("type").and_then(JsonValue::as_str);
    if field_type == Some("array") {
        if let Some(values) = definition
            .get("items")
            .and_then(|items| items.get("enum"))
            .and_then(JsonValue::as_array)
        {
            return SchemaFieldKind::MultiSelect(json_values_as_yaml(values));
        }
        return SchemaFieldKind::Yaml;
    }
    match field_type {
        Some("string") => SchemaFieldKind::String {
            input_type: match definition.get("format").and_then(JsonValue::as_str) {
                Some("email") => "email",
                Some("uri") | Some("url") => "url",
                Some("date") => "date",
                Some("time") => "time",
                Some("date-time") => "datetime-local",
                _ => "text",
            },
            min_length: definition
                .get("minLength")
                .and_then(JsonValue::as_u64)
                .and_then(|value| usize::try_from(value).ok()),
            max_length: definition
                .get("maxLength")
                .and_then(JsonValue::as_u64)
                .and_then(|value| usize::try_from(value).ok()),
        },
        Some("integer") => SchemaFieldKind::Integer {
            minimum: schema_number_constraint(definition, "minimum"),
            maximum: schema_number_constraint(definition, "maximum"),
        },
        Some("number") => SchemaFieldKind::Number {
            minimum: schema_number_constraint(definition, "minimum"),
            maximum: schema_number_constraint(definition, "maximum"),
        },
        Some("boolean") => SchemaFieldKind::Boolean,
        _ => SchemaFieldKind::Yaml,
    }
}

fn json_values_as_yaml(values: &[JsonValue]) -> Vec<YamlValue> {
    values
        .iter()
        .filter_map(|value| serde_json::from_value(value.clone()).ok())
        .collect()
}

fn schema_number_constraint(definition: &JsonValue, name: &str) -> Option<String> {
    definition.get(name).and_then(|value| match value {
        JsonValue::Number(_) => Some(value.to_string()),
        _ => None,
    })
}

fn humanize_field_name(name: &str) -> String {
    name.split(['_', '-', '.'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), characters.as_str()),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn schema_value_label(value: &YamlValue) -> String {
    match value {
        YamlValue::String(value) => humanize_field_name(value),
        _ => yaml_value(value),
    }
}

fn schema_field_type_label(kind: &SchemaFieldKind) -> &'static str {
    match kind {
        SchemaFieldKind::Select(_) => "Single select",
        SchemaFieldKind::MultiSelect(_) => "Multi-select",
        SchemaFieldKind::String { input_type, .. } => match *input_type {
            "email" => "Email",
            "url" => "URL",
            "date" => "Date",
            "time" => "Time",
            "datetime-local" => "Date & time",
            _ => "Text",
        },
        SchemaFieldKind::Integer { .. } => "Integer",
        SchemaFieldKind::Number { .. } => "Number",
        SchemaFieldKind::Boolean => "Boolean",
        SchemaFieldKind::Yaml => "Structured YAML",
    }
}

fn schema_field_is_wide(kind: &SchemaFieldKind) -> bool {
    matches!(
        kind,
        SchemaFieldKind::MultiSelect(_) | SchemaFieldKind::Yaml
    )
}

fn field_text_value(value: Option<&YamlValue>) -> String {
    match value {
        Some(YamlValue::String(value)) => value.clone(),
        Some(value) => serialize_yaml_value(value),
        None => String::new(),
    }
}

fn render_schema_field(field: &SchemaFormField) -> Markup {
    let name = format!("attribute.{}", field.key);
    let wide = schema_field_is_wide(&field.kind);
    let current = field.value.as_ref();
    html! {
        div class=(if wide { "cr-field p-4 sm:col-span-2" } else { "cr-field p-4" }) {
            div class="mb-2 flex items-start justify-between gap-3" {
                label for=(format!("field-{}", field.key)) class="text-sm font-semibold text-slate-900" {
                    (&field.label)
                    @if field.required {
                        span class="ml-1 text-red-500" aria-hidden="true" { "*" }
                    }
                }
                span class="shrink-0 rounded-md bg-white px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wide text-slate-500 shadow-sm" {
                    (schema_field_type_label(&field.kind))
                }
            }
            @if let Some(description) = &field.description {
                p class="mb-3 text-xs leading-5 text-slate-500" { (description) }
            }
            @match &field.kind {
                SchemaFieldKind::Select(options) => {
                    select id=(format!("field-{}", field.key)) name=(name) required[field.required] class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2" {
                        option value="" selected[current.is_none()] disabled[field.required] {
                            @if field.required { "Select a value…" } @else { "Not set" }
                        }
                        @for option in options {
                            option value=(serialize_yaml_value(option)) selected[current == Some(option)] { (schema_value_label(option)) }
                        }
                    }
                }
                SchemaFieldKind::MultiSelect(options) => {
                    div id=(format!("field-{}", field.key)) class="flex flex-wrap gap-2" {
                        @for option in options {
                            @let checked = match current {
                                Some(YamlValue::Sequence(values)) => values.contains(option),
                                _ => false,
                            };
                            label class="inline-flex cursor-pointer items-center gap-2 rounded-full border border-slate-300 bg-white px-3 py-2 text-sm text-slate-700 has-checked:border-indigo-500 has-checked:bg-indigo-50 has-checked:text-indigo-800" {
                                input type="checkbox" name=(name.clone()) value=(serialize_yaml_value(option)) checked[checked] class="size-4 accent-indigo-600";
                                (schema_value_label(option))
                            }
                        }
                    }
                }
                SchemaFieldKind::String { input_type, min_length, max_length } => {
                    input id=(format!("field-{}", field.key)) type=(input_type) name=(name) value=(field_text_value(current)) required[field.required] minlength=[*min_length] maxlength=[*max_length] autocomplete=(if *input_type == "email" { "email" } else { "off" }) class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Integer { minimum, maximum } => {
                    input id=(format!("field-{}", field.key)) type="number" step="1" name=(name) value=(field_text_value(current)) required[field.required] min=[minimum.as_deref()] max=[maximum.as_deref()] class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Number { minimum, maximum } => {
                    input id=(format!("field-{}", field.key)) type="number" step="any" name=(name) value=(field_text_value(current)) required[field.required] min=[minimum.as_deref()] max=[maximum.as_deref()] class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Boolean => {
                    select id=(format!("field-{}", field.key)) name=(name) required[field.required] class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2" {
                        option value="" selected[current.is_none()] disabled[field.required] {
                            @if field.required { "Choose true or false…" } @else { "Not set" }
                        }
                        option value="true" selected[current == Some(&YamlValue::Bool(true))] { "True" }
                        option value="false" selected[current == Some(&YamlValue::Bool(false))] { "False" }
                    }
                }
                SchemaFieldKind::Yaml => {
                    textarea id=(format!("field-{}", field.key)) name=(name) rows="5" spellcheck="false" required[field.required] placeholder="{}" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (current.map(serialize_yaml_value).unwrap_or_default()) }
                }
            }
        }
    }
}

fn additional_attributes(attributes: &Mapping, schema: &JsonValue) -> Mapping {
    let declared = schema
        .get("properties")
        .and_then(JsonValue::as_object)
        .map(|properties| {
            properties
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    attributes
        .iter()
        .filter(|(key, _)| match key {
            YamlValue::String(key) => !declared.contains(key.as_str()),
            _ => true,
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn schema_allows_additional_attributes(schema: &JsonValue) -> bool {
    schema.get("additionalProperties") != Some(&JsonValue::Bool(false))
}

#[allow(clippy::too_many_arguments)]
fn render_record_form(
    view: &ViewDefinition,
    record: Option<&Record>,
    audit_entries: &[AuditEntry],
    schema: Option<&JsonValue>,
    csrf_token: &str,
    error: Option<&str>,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    permissions: RecordPermissions,
) -> Markup {
    let editing = record.is_some();
    let title = record
        .map(|record| {
            if permissions.update {
                format!("Edit {}", record.id)
            } else {
                format!("View {}", record.id)
            }
        })
        .unwrap_or_else(|| format!("New {} record", view.collection));
    let action = record
        .map(|record| {
            format!(
                "/{}/records/{}",
                encode_segment(&view.name),
                encode_segment(&record.id)
            )
        })
        .unwrap_or_else(|| format!("/{}/records", encode_segment(&view.name)));
    let empty_attributes = Mapping::new();
    let attributes = record
        .map(|record| &record.attributes)
        .unwrap_or(&empty_attributes);
    let schema_fields = schema.and_then(|schema| schema_form_fields(schema, attributes));
    let structured = schema_fields.is_some();
    let schema_fields = schema_fields.unwrap_or_default();
    let front_matter = yaml_serde::to_string(attributes).unwrap_or_else(|_| "{}\n".to_owned());
    let additional = schema
        .map(|schema| additional_attributes(attributes, schema))
        .unwrap_or_default();
    let additional_yaml = yaml_serde::to_string(&additional).unwrap_or_else(|_| "{}\n".to_owned());
    let allows_additional = schema.is_some_and(schema_allows_additional_attributes);
    let markdown = record.map(|record| record.body.as_str()).unwrap_or("");
    let back = format!("/{}", encode_segment(&view.name));
    page_layout(
        &title,
        &back,
        navigation,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-slate-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                a href=(back.clone()) class="font-medium hover:text-blue-700" { (&view.title) }
                span aria-hidden="true" { "/" }
                span class="text-slate-900" { (&title) }
            }
            div class="mx-auto max-w-7xl" {
                div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                    h1 class="cr-title" { (&title) }
                    @if editing {
                        a href="#audit-history" class="cr-button cr-activity-jump" {
                            (audit_entries.len()) " audit " @if audit_entries.len() == 1 { "event" } @else { "events" } " ↓"
                        }
                    }
                }
                p class="cr-lede mt-1" {
                    @if editing && !permissions.update {
                        "This perspective has read-only access to the record."
                    } @else if structured {
                        "Edit typed fields generated from the collection schema. Saving validates the complete record and writes normal Markdown with YAML front matter."
                    } @else {
                        "This collection has no field schema yet, so front matter remains available as typed YAML."
                    }
                }
                @if let Some(error) = error {
                    div role="alert" class="mt-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" { (error) }
                }
                div class=(if editing { "cr-record-layout mt-5" } else { "mx-auto mt-5 max-w-5xl" }) {
                div class="cr-record-primary min-w-0" {
                form method="post" action=(action) class="space-y-4" {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    @if let Some(record) = record {
                        input type="hidden" name="_expected_record_hash" value=(&record.version);
                    }
                    @if structured {
                        input type="hidden" name="_form_mode" value="structured";
                    }
                    fieldset disabled[!permissions.update] class="contents disabled:opacity-80" {
                    section class="cr-form-section p-4 sm:p-5" {
                        div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" {
                            div {
                                h2 class="text-lg font-bold text-slate-950" { "Record details" }
                                p class="mt-1 text-sm text-slate-500" {
                                    @if structured { "Fields and controls follow this collection’s JSON Schema." } @else { "Front matter accepts any YAML mapping." }
                                }
                            }
                            @if structured {
                                span class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700" { "Schema-powered" }
                            }
                        }
                        @if !editing {
                            div class="mb-4 rounded-xl border border-indigo-100 bg-indigo-50/60 p-4" {
                                label for="record-id" class="mb-1.5 block text-sm font-semibold text-slate-900" { "Record ID " span class="text-red-500" aria-hidden="true" { "*" } }
                                input id="record-id" type="text" name="id" required pattern="[^/\\]+" placeholder="acme-renewal" aria-describedby="record-id-help" class="w-full rounded-lg border border-indigo-200 bg-white px-3 py-2.5 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                                span id="record-id-help" class="mt-1.5 block text-xs text-slate-500" { "Stable URL and filename identifier. It cannot be changed later." }
                            }
                        }
                        @if structured {
                            div class="grid gap-3 sm:grid-cols-2" {
                                @for field in &schema_fields {
                                    (render_schema_field(field))
                                }
                            }
                            @if allows_additional {
                                details class="mt-5 rounded-xl border border-dashed border-slate-300 bg-slate-50" open[!additional.is_empty()] {
                                    summary class="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-700 hover:text-indigo-700" { "+ Additional attributes" }
                                    div class="border-t border-slate-200 p-4" {
                                        p class="mb-2 text-xs leading-5 text-slate-500" { "Optional front matter not declared in the schema. Declared fields above cannot be overridden here." }
                                        textarea name="_additional_attributes" rows="5" spellcheck="false" class="w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (additional_yaml) }
                                    }
                                }
                            }
                        } @else {
                            label class="block" {
                                span class="mb-1.5 block text-sm font-semibold text-slate-800" { "Front matter" }
                                textarea name="front_matter" rows="14" spellcheck="false" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (front_matter) }
                            }
                        }
                    }
                    section class="cr-form-section p-4 sm:p-5" {
                        div class="mb-3 flex items-center justify-between gap-3" {
                            div {
                                h2 class="text-lg font-bold text-slate-950" { "Notes" }
                                p class="mt-1 text-sm text-slate-500" { "Long-form context stored as the Markdown body." }
                            }
                            span class="rounded-md bg-slate-100 px-2 py-1 font-mono text-xs font-semibold text-slate-500" { "Markdown" }
                        }
                        textarea name="markdown" aria-label="Markdown notes" rows="12" class="w-full rounded-lg border border-slate-300 px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (markdown) }
                    }
                    }
                    div class="cr-surface flex flex-wrap items-center justify-between gap-3 p-3" {
                        a href=(back.clone()) class="cr-button" { "Cancel" }
                        @if permissions.update {
                            button type="submit" class="cr-button cr-button-primary" {
                                @if editing { "Save changes" } @else { "Create record" }
                            }
                        } @else {
                            span class="cr-pill" { "Read-only perspective" }
                        }
                    }
                }
                }
                @if let Some(record) = record {
                    aside id="audit-history" class="cr-record-activity scroll-mt-20" {
                        div class="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" {
                            div {
                                h2 class="text-base font-bold text-slate-950" { "Activity" }
                                p class="mt-0.5 text-xs text-slate-500" { "Newest accepted changes" }
                            }
                            a href=(audit_filter_url(&view.collection, &record.id)) class="text-xs font-semibold text-indigo-700 hover:text-indigo-900" { "All activity" span aria-hidden="true" { " →" } }
                        }
                        (render_audit_entries(audit_entries))
                    @if permissions.delete {
                        form method="post" action=(format!("/{}/records/{}/delete", encode_segment(&view.name), encode_segment(&record.id))) onsubmit="return window.confirm('Delete this record? This cannot be undone from the web app.');" class="cr-record-danger rounded-lg border border-red-200 bg-red-50 p-4" {
                            input type="hidden" name="_csrf" value=(csrf_token);
                            input type="hidden" name="_expected_record_hash" value=(&record.version);
                            div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                                div {
                                    h2 class="font-semibold text-red-900" { "Delete this record" }
                                    p class="mt-1 text-sm text-red-700" { "The previous document remains represented in the tamper-evident audit log." }
                                }
                                button type="submit" class="rounded-lg border border-red-300 bg-white px-4 py-2 text-sm font-semibold text-red-700 hover:bg-red-100" { "Delete record" }
                            }
                        }
                    }
                    }
                }
                }
            }
        },
        ui,
        csrf_token,
    )
}

const GLOBAL_STYLES: &str = r#"
:root {
  --cr-canvas: #ffffff;
  --cr-sidebar: #f7f7f5;
  --cr-sidebar-hover: #eeeeeb;
  --cr-surface: #ffffff;
  --cr-surface-subtle: #fafaf9;
  --cr-ink: #242424;
  --cr-muted: #787774;
  --cr-line: #e8e8e6;
  --cr-line-strong: #d8d8d5;
  --cr-accent: #5e6ad2;
  --cr-accent-hover: #4f5abf;
  --cr-accent-soft: #f0f1fb;
  --cr-danger: #b91c1c;
  --cr-radius: 8px;
  --cr-sidebar-width: 232px;
  --cr-shadow-popover: 0 18px 44px rgb(36 36 36 / 0.14), 0 2px 8px rgb(36 36 36 / 0.07);
}

* { box-sizing: border-box; }

html {
  background: var(--cr-canvas);
  color-scheme: light;
  scroll-behavior: smooth;
}

.cr-app {
  background: var(--cr-canvas);
  color: var(--cr-ink);
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  font-feature-settings: "cv02", "cv03", "cv04", "cv11";
}

.cr-app a,
.cr-app button,
.cr-app input,
.cr-app select,
.cr-app textarea,
.cr-app summary {
  touch-action: manipulation;
}

.cr-app :focus-visible {
  outline: 2px solid var(--cr-accent);
  outline-offset: 2px;
}

.cr-skip-link {
  position: fixed;
  top: 8px;
  left: 8px;
  z-index: 100;
  transform: translateY(-150%);
  border-radius: 6px;
  background: var(--cr-ink);
  color: white;
  padding: 8px 12px;
  font-size: 0.875rem;
  font-weight: 600;
  transition: transform 120ms ease-out;
}

.cr-skip-link:focus { transform: translateY(0); }

.cr-shell {
  display: grid;
  grid-template-columns: var(--cr-sidebar-width) minmax(0, 1fr);
  min-height: 100vh;
}

.cr-workspace { min-width: 0; background: var(--cr-canvas); }

.cr-sidebar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  height: 100vh;
  min-width: 0;
  flex-direction: column;
  border-right: 1px solid var(--cr-line);
  background: var(--cr-sidebar);
  color: #5f5e5b;
}

.cr-sidebar-brand {
  display: flex;
  height: 52px;
  flex: 0 0 auto;
  align-items: center;
  justify-content: space-between;
  padding: 0 12px;
}

.cr-wordmark {
  display: inline-flex;
  height: 32px;
  gap: 8px;
  align-items: center;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  color: var(--cr-ink);
  font-size: 0.9rem;
  font-weight: 700;
  letter-spacing: -0.04em;
}

.cr-wordmark-mark {
  display: inline-grid;
  width: 24px;
  height: 24px;
  place-items: center;
  border: 1px solid #d1d1ce;
  border-radius: 6px;
  background: white;
  box-shadow: 0 1px 1px rgb(36 36 36 / 0.04);
  font-size: 0.78rem;
}

.cr-local-badge {
  border: 1px solid var(--cr-line-strong);
  border-radius: 999px;
  color: #8b8a87;
  padding: 2px 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.62rem;
  line-height: 1.3;
}

.cr-sidebar-nav {
  min-height: 0;
  flex: 1 1 auto;
  overflow-y: auto;
  padding: 4px 8px 16px;
  scrollbar-width: thin;
}

.cr-sidebar-label {
  margin: 17px 8px 5px;
  color: #9a9996;
  font-size: 0.68rem;
  font-weight: 650;
  letter-spacing: 0.015em;
}

.cr-sidebar-link {
  position: relative;
  display: flex;
  min-width: 0;
  min-height: 30px;
  align-items: center;
  gap: 8px;
  border-radius: 5px;
  color: #5f5e5b;
  padding: 5px 8px;
  font-size: 0.79rem;
  font-weight: 520;
  line-height: 1.25;
  transition: background-color 90ms ease-out, color 90ms ease-out;
}

.cr-sidebar-link:hover { background: var(--cr-sidebar-hover); color: var(--cr-ink); }
.cr-sidebar-link.is-active { background: #e8e8e4; color: var(--cr-ink); font-weight: 620; }

.cr-nav-glyph {
  display: inline-flex;
  width: 16px;
  flex: 0 0 16px;
  align-items: center;
  justify-content: center;
  color: #8b8a87;
  font-size: 0.72rem;
}

.cr-nav-glyph-collection,
.cr-nav-glyph-view,
.cr-nav-glyph-kanban {
  width: 13px;
  height: 13px;
  flex-basis: 13px;
  border: 1px solid #aaa9a5;
  border-radius: 3px;
}

.cr-nav-glyph-collection::after { content: ""; width: 5px; border-top: 1px solid #aaa9a5; border-bottom: 1px solid #aaa9a5; height: 4px; }
.cr-nav-glyph-view::after { content: ""; width: 7px; border-top: 1px solid #aaa9a5; }
.cr-nav-glyph-kanban::after { content: ""; width: 7px; height: 7px; border-left: 2px solid #aaa9a5; border-right: 2px solid #aaa9a5; }

.cr-external { margin-left: auto; color: #aaa9a5; font-size: 0.7rem; }

.cr-sidebar-utility {
  flex: 0 0 auto;
  border-top: 1px solid var(--cr-line);
  padding: 8px;
}

.cr-sidebar-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 8px 2px;
  color: #aaa9a5;
  font-size: 0.62rem;
}

.cr-mobile-header { display: none; }

.cr-nav-link {
  border-radius: 6px;
  color: #52525b;
  padding: 6px 8px;
  font-size: 0.825rem;
  font-weight: 550;
  transition: background-color 120ms ease-out, color 120ms ease-out;
}

.cr-nav-link:hover { background: #f4f4f5; color: var(--cr-ink); }

.cr-perspective { display: grid; gap: 5px; margin-top: 8px; border-top: 1px solid var(--cr-line); padding: 10px 8px 2px; }

.cr-perspective-label { color: #8b8a87; font-size: 0.65rem; font-weight: 650; }

.cr-perspective select {
  width: 100%;
  min-height: 30px;
  padding: 4px 28px 4px 8px;
  font-size: 0.72rem;
  font-weight: 600;
}

.cr-perspective-banner {
  border-bottom: 1px solid #bfdbfe;
  background: #eff6ff;
  color: #1e3a8a;
}

.cr-main { min-height: 100vh; }

.cr-eyebrow {
  color: var(--cr-accent);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.72rem;
  font-weight: 650;
  letter-spacing: 0.04em;
}

.cr-title {
  color: var(--cr-ink);
  font-size: clamp(1.5rem, 2vw, 1.8rem);
  font-weight: 670;
  letter-spacing: -0.028em;
  line-height: 1.12;
  text-wrap: balance;
}

.cr-lede {
  color: #52525b;
  font-size: 0.82rem;
  line-height: 1.45;
  text-wrap: pretty;
}

.cr-button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--cr-line-strong);
  border-radius: 7px;
  background: var(--cr-surface);
  color: #3f3f46;
  padding: 6px 10px;
  font-size: 0.77rem;
  font-weight: 600;
  line-height: 1;
  white-space: nowrap;
  transition: border-color 120ms ease-out, background-color 120ms ease-out, color 120ms ease-out, transform 80ms ease-out;
}

.cr-button > span[aria-hidden="true"] { margin-left: 0.2em; }

.cr-button:hover { border-color: #a1a1aa; background: #fafafa; color: var(--cr-ink); }
.cr-button:active { transform: translateY(1px); }

.cr-button-primary {
  border-color: var(--cr-ink);
  background: var(--cr-ink);
  color: white;
}

.cr-button-primary:hover { border-color: #27272a; background: #27272a; color: white; }

.cr-empty-state {
  border: 1px dashed var(--cr-line-strong);
  border-radius: var(--cr-radius);
  background: var(--cr-surface);
  padding: 40px 24px;
  text-align: center;
}

.cr-view-index {
  overflow: hidden;
  border: 1px solid var(--cr-line);
  border-radius: var(--cr-radius);
  background: var(--cr-surface);
}

.cr-view-index-header,
.cr-view-row {
  display: grid;
  grid-template-columns: minmax(220px, 0.9fr) minmax(0, 1.7fr) 32px;
  align-items: center;
  column-gap: 24px;
}

.cr-view-index-header {
  border-bottom: 1px solid var(--cr-line);
  background: var(--cr-surface-subtle);
  color: #71717a;
  padding: 9px 16px;
  font-size: 0.68rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.cr-view-row {
  min-height: 54px;
  border-bottom: 1px solid var(--cr-line);
  padding: 9px 14px;
  transition: background-color 120ms ease-out;
}

.cr-view-row:last-child { border-bottom: 0; }
.cr-view-row:hover { background: #fafafa; }
.cr-view-row:hover h2 { color: var(--cr-accent); }

.cr-view-arrow {
  color: #a1a1aa;
  font-size: 1rem;
  text-align: right;
  transition: color 120ms ease-out, transform 120ms ease-out;
}

.cr-view-row:hover .cr-view-arrow { color: var(--cr-accent); transform: translateX(2px); }

.cr-path,
.cr-data {
  color: var(--cr-muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
}

.cr-pill,
.cr-filter-tag {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--cr-line);
  border-radius: 999px;
  background: #fafafa;
  color: #52525b;
  padding: 3px 7px;
  font-size: 0.68rem;
  font-weight: 600;
  line-height: 1.2;
}

.cr-pill-accent { border-color: #bfdbfe; background: var(--cr-accent-soft); color: #1d4ed8; }

.cr-filter-tag {
  border-radius: 5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 500;
}

.cr-surface {
  border: 1px solid var(--cr-line);
  border-radius: var(--cr-radius);
  background: var(--cr-surface);
  box-shadow: none;
}

.cr-app input:not([type="checkbox"]):not([type="radio"]),
.cr-app select,
.cr-app textarea {
  border-color: var(--cr-line-strong);
  border-radius: 7px;
  background-color: white;
  color: var(--cr-ink);
}

.cr-app input:not([type="checkbox"]):not([type="radio"]):hover,
.cr-app select:hover,
.cr-app textarea:hover { border-color: #a1a1aa; }

.cr-app input:not([type="checkbox"]):not([type="radio"]):focus,
.cr-app select:focus,
.cr-app textarea:focus { border-color: var(--cr-accent); box-shadow: 0 0 0 3px rgb(37 99 235 / 0.12); }

.cr-table-shell { overflow: hidden; border: 1px solid var(--cr-line); border-radius: var(--cr-radius); background: white; }
.cr-table-shell table { font-variant-numeric: tabular-nums; }
.cr-table-shell thead { background: var(--cr-surface-subtle); }
.cr-table-shell th { padding: 8px 12px !important; color: #666561 !important; font-size: 0.72rem; font-weight: 620 !important; }
.cr-table-shell td { padding: 8px 12px !important; font-size: 0.79rem; }
.cr-table-shell tbody tr { transition: background-color 100ms ease-out; }
.cr-table-shell tbody tr:hover { background: #f8f8f6; }

.cr-popover {
  border: 1px solid var(--cr-line);
  border-radius: var(--cr-radius);
  background: white;
  box-shadow: var(--cr-shadow-popover);
}

.cr-filter-popover {
  position: fixed;
  top: 60px;
  right: max(16px, env(safe-area-inset-right));
  width: min(42rem, calc(100vw - 32px));
  max-height: calc(100vh - 88px);
  overscroll-behavior: contain;
}

.cr-audit-list { overflow: hidden; border: 1px solid var(--cr-line); border-radius: var(--cr-radius); background: white; }
.cr-audit-entry { border-bottom: 1px solid var(--cr-line); background: white; padding: 13px 14px; }
.cr-audit-entry:last-child { border-bottom: 0; }
.cr-audit-entry:target { background: var(--cr-accent-soft); }

.cr-kanban-lane {
  border: 1px solid var(--cr-line);
  border-radius: var(--cr-radius);
  background: #f6f6f4;
  box-shadow: none;
}

.cr-kanban-card {
  border: 1px solid var(--cr-line-strong);
  border-radius: 8px;
  background: white;
  box-shadow: 0 1px 2px rgb(36 36 36 / 0.04);
  transition: border-color 120ms ease-out, box-shadow 120ms ease-out, transform 80ms ease-out;
}

.cr-kanban-card:hover { border-color: #b6b5b2; box-shadow: 0 3px 8px rgb(36 36 36 / 0.07); }
.cr-kanban-card:active { transform: rotate(0.25deg); }
.cr-kanban-card dl > div { display: grid; grid-template-columns: minmax(64px, 0.42fr) minmax(0, 1fr); align-items: baseline; gap: 8px; }
.cr-kanban-card dl dt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cr-kanban-card dl dd { margin-top: 0 !important; min-width: 0; }
.cr-kanban-move summary { color: #6f6e6b; font-size: 0.72rem; font-weight: 620; }
.cr-kanban-move[open] summary { margin-bottom: 8px; }

.cr-form-section,
.cr-field {
  border: 1px solid var(--cr-line);
  border-radius: var(--cr-radius);
  background: white;
  box-shadow: none;
}

.cr-field { background: var(--cr-surface-subtle); }

.cr-record-layout { display: grid; grid-template-columns: minmax(0, 1fr) 350px; align-items: start; gap: 18px; }
.cr-record-layout .cr-field { padding: 14px !important; }
.cr-record-activity { position: sticky; top: 20px; min-width: 0; max-height: calc(100vh - 40px); overflow-y: auto; padding: 2px; scrollbar-width: thin; }
.cr-record-activity .cr-audit-entry { padding: 11px; }
.cr-record-activity .cr-audit-entry > div { gap: 8px; }
.cr-record-danger { margin-top: 12px; }
.cr-record-danger p { font-size: 0.75rem !important; line-height: 1.4; }

@media (min-width: 1200px) {
  .cr-activity-jump { display: none; }
}

@media (max-width: 1199px) {
  .cr-record-layout { display: block; }
  .cr-record-activity { position: static; max-height: none; margin-top: 28px; overflow: visible; }
}

@media (max-width: 899px) {
  .cr-shell { display: block; }
  .cr-sidebar { display: none; }
  .cr-mobile-header {
    position: sticky;
    top: 0;
    z-index: 40;
    display: block;
    border-bottom: 1px solid var(--cr-line);
    background: rgb(255 255 255 / 0.96);
    backdrop-filter: blur(14px);
  }
  .cr-mobile-topbar { display: flex; min-height: 46px; align-items: center; justify-content: space-between; gap: 12px; padding: 6px 16px; }
  .cr-mobile-utilities { display: flex; align-items: center; gap: 2px; }
  .cr-mobile-view-strip { display: flex; gap: 4px; overflow-x: auto; border-top: 1px solid #f1f1ef; padding: 5px 12px 6px; scrollbar-width: none; }
  .cr-mobile-view-strip::-webkit-scrollbar { display: none; }
  .cr-mobile-view-strip a { flex: 0 0 auto; border-radius: 5px; color: #6f6e6b; padding: 4px 7px; font-size: 0.72rem; font-weight: 550; }
  .cr-mobile-view-strip a:hover,
  .cr-mobile-view-strip a.is-active { background: #f0f0ed; color: var(--cr-ink); }
  .cr-mobile-header .cr-perspective { display: flex; align-items: center; gap: 6px; margin: 0; border: 0; padding: 0; }
  .cr-mobile-header .cr-perspective-label { display: none; }
  .cr-mobile-header .cr-perspective select { width: auto; max-width: 210px; }
  .cr-main { min-height: calc(100vh - 82px); }
  .cr-filter-popover { top: 94px; }
}

@media (max-width: 640px) {
  .cr-view-index-header { display: none; }
  .cr-view-row { grid-template-columns: minmax(0, 1fr) 24px; gap: 10px; }
  .cr-view-row > :nth-child(2) { grid-column: 1; }
  .cr-view-arrow { grid-column: 2; grid-row: 1 / span 2; }
  .cr-title { font-size: 1.45rem; }
  .cr-mobile-header .cr-perspective select { max-width: 155px; }
}

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  .cr-app *, .cr-app *::before, .cr-app *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
}
"#;

fn perspective_control(ui: &UiContext, csrf_token: &str, id: &str) -> Markup {
    html! {
        form method="post" action="/perspective" class="cr-perspective" {
            input type="hidden" name="_csrf" value=(csrf_token);
            label for=(id) class="cr-perspective-label" { "Viewing as" }
            select id=(id) name="principal" aria-label="View as user" onchange="this.form.submit()" {
                @for user in &ui.users {
                    option value=(&user.id) selected[user.id == ui.selected] {
                        (&user.name) " — " (&user.role)
                        @if user.status == UserStatus::Disabled { " (disabled)" }
                    }
                }
            }
            noscript { button type="submit" class="cr-button" { "View" } }
        }
    }
}

fn sidebar_navigation(
    current_path: &str,
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    html! {
        aside class="cr-sidebar" aria-label="Workspace navigation" {
            div class="cr-sidebar-brand" {
                a href="/" class="cr-wordmark" translate="no" aria-label="cr home" {
                    span aria-hidden="true" class="cr-wordmark-mark" { "c" }
                    span { "cr" }
                }
                span class="cr-local-badge" { "local" }
            }
            nav aria-label="Primary" class="cr-sidebar-nav" {
                a href="/" class=(if current_path == "/" { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == "/").then_some("page")] {
                    span class="cr-nav-glyph" aria-hidden="true" { "⌂" }
                    span { "All views" }
                }
                @if views.iter().any(|view| !view.saved) {
                    p class="cr-sidebar-label" { "Collections" }
                    @for view in views.iter().filter(|view| !view.saved) {
                        @let path = format!("/{}", encode_segment(&view.name));
                        a href=(&path) class=(if current_path == path { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == path).then_some("page")] title=(&view.title) {
                            span class="cr-nav-glyph cr-nav-glyph-collection" aria-hidden="true" { "" }
                            span class="truncate" { (&view.title) }
                        }
                    }
                }
                @if views.iter().any(|view| view.saved) {
                    p class="cr-sidebar-label" { "Saved views" }
                    @for view in views.iter().filter(|view| view.saved) {
                        @let path = format!("/{}", encode_segment(&view.name));
                        a href=(&path) class=(if current_path == path { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == path).then_some("page")] title=(&view.title) {
                            span class=(if view.layout == ViewLayout::Kanban { "cr-nav-glyph cr-nav-glyph-kanban" } else { "cr-nav-glyph cr-nav-glyph-view" }) aria-hidden="true" { "" }
                            span class="truncate" { (&view.title) }
                        }
                    }
                }
            }
            div class="cr-sidebar-utility" {
                nav aria-label="Utilities" {
                    @if ui.is_none_or(|ui| ui.can_view_global_audit) {
                        a href="/audit" class=(if current_path == "/audit" { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == "/audit").then_some("page")] {
                            span class="cr-nav-glyph" aria-hidden="true" { "↺" }
                            span { "Audit log" }
                        }
                    }
                    a href="/openapi.json" class="cr-sidebar-link" {
                        span class="cr-nav-glyph" aria-hidden="true" { "{}" }
                        span { "OpenAPI" }
                        span class="cr-external" aria-hidden="true" { "↗" }
                    }
                }
                @if let Some(ui) = ui {
                    (perspective_control(ui, csrf_token, "cr-perspective-sidebar"))
                }
                div class="cr-sidebar-meta" {
                    span { "Markdown database" }
                    code { "cr serve" }
                }
            }
        }
    }
}

fn mobile_navigation(
    current_path: &str,
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    html! {
        header class="cr-mobile-header" {
            div class="cr-mobile-topbar" {
                a href="/" class="cr-wordmark" translate="no" aria-label="cr home" {
                    span aria-hidden="true" class="cr-wordmark-mark" { "c" }
                    span { "cr" }
                }
                @if let Some(ui) = ui {
                    (perspective_control(ui, csrf_token, "cr-perspective-mobile"))
                } @else {
                    div class="cr-mobile-utilities" {
                        a href="/audit" class="cr-nav-link" { "Audit" }
                        a href="/openapi.json" class="cr-nav-link" { "API" }
                    }
                }
            }
            nav aria-label="Views" class="cr-mobile-view-strip" {
                a href="/" class=(if current_path == "/" { "is-active" } else { "" }) { "All views" }
                @for view in views {
                    @let path = format!("/{}", encode_segment(&view.name));
                    a href=(&path) class=(if current_path == path { "is-active" } else { "" }) { (&view.title) }
                }
                @if ui.is_none_or(|ui| ui.can_view_global_audit) {
                    a href="/audit" class=(if current_path == "/audit" { "is-active" } else { "" }) { "Audit" }
                }
                @if ui.is_some() {
                    a href="/openapi.json" { "API" }
                }
            }
        }
    }
}

fn page_layout(
    title: &str,
    current_path: &str,
    views: &[ViewDefinition],
    content: Markup,
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" class="h-full" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light";
                meta name="theme-color" content="#ffffff";
                meta name="robots" content="noindex, nofollow";
                link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='1' y='1' width='30' height='30' rx='7' fill='%23fff' stroke='%23d4d4d0'/%3E%3Cpath d='M20.5 20.2c-1.1 1-2.4 1.5-4 1.5-3.5 0-6-2.4-6-5.8s2.5-5.8 6-5.8c1.6 0 3 .5 4 1.5l-1.7 2a3.2 3.2 0 0 0-2.2-.8c-1.8 0-3 1.2-3 3.1s1.2 3.1 3 3.1c.9 0 1.6-.3 2.2-.8l1.7 2z' fill='%23242424'/%3E%3C/svg%3E";
                title { (title) " · cr" }
                script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4" {}
                style { (PreEscaped(GLOBAL_STYLES)) }
            }
            body class="cr-app min-h-full antialiased" data-design-system="cr-workspace" {
                a href="#main-content" class="cr-skip-link" { "Skip to content" }
                div class="cr-shell" {
                    (sidebar_navigation(current_path, views, ui, csrf_token))
                    div class="cr-workspace" {
                        (mobile_navigation(current_path, views, ui, csrf_token))
                        @if let Some(ui) = ui {
                            @if ui.selected != ui.operator.principal {
                                div role="status" class="cr-perspective-banner" {
                                    div class="flex w-full flex-wrap items-center justify-between gap-2 px-4 py-2 text-xs sm:px-6" {
                                        span {
                                            "Viewing as " strong { (&ui.selected_name) }
                                            " (" code class="font-mono" { (&ui.selected) } ")"
                                            @if ui.selected_status == UserStatus::Disabled { " · disabled" }
                                        }
                                        span { "Impersonated by " (&ui.operator.display) }
                                    }
                                }
                            }
                        }
                        main id="main-content" class="cr-main w-full px-4 py-5 sm:px-6 sm:py-6 xl:px-8" tabindex="-1" { (content) }
                    }
                }
            }
        }
    }
}

fn view_available_columns(
    view: &ViewDefinition,
    records: &[Record],
    schema: Option<&JsonValue>,
) -> Vec<String> {
    let mut columns = Vec::new();
    let mut known = BTreeSet::new();
    for column in &view.columns {
        if known.insert(column.clone()) {
            columns.push(column.clone());
        }
    }

    let mut additional = BTreeSet::new();
    if let Some(properties) = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(JsonValue::as_object)
    {
        additional.extend(properties.keys().cloned());
    }
    for record in records {
        additional.extend(record.attributes.keys().filter_map(|key| match key {
            YamlValue::String(key) => Some(key.clone()),
            _ => None,
        }));
    }
    columns.extend(
        additional
            .into_iter()
            .filter(|column| known.insert(column.clone())),
    );
    columns
}

fn selected_view_columns(
    view: &ViewDefinition,
    query: &ViewQuery,
    available: &[String],
) -> ApiResult<Vec<String>> {
    if !query_columns_custom(query) {
        return Ok(if view.columns.is_empty() {
            available.iter().take(12).cloned().collect()
        } else {
            view.columns.clone()
        });
    }
    if query.column.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_columns",
            "select at least one visible column",
        ));
    }
    if query.column.len() > MAX_VIEW_COLUMNS {
        return Err(ApiError::bad_request(
            "invalid_columns",
            format!("a view can show at most {MAX_VIEW_COLUMNS} columns"),
        ));
    }

    let available = available
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut known = BTreeSet::new();
    for column in &query.column {
        if !known.insert(column.as_str()) {
            return Err(ApiError::bad_request(
                "invalid_columns",
                format!("column '{column}' cannot be selected more than once"),
            ));
        }
        if !available.contains(column.as_str()) {
            return Err(ApiError::bad_request(
                "invalid_columns",
                format!("column '{column}' is not available in this view"),
            ));
        }
    }
    Ok(query.column.clone())
}

fn query_columns_custom(query: &ViewQuery) -> bool {
    query.columns == ViewColumnsMode::Custom || !query.column.is_empty()
}

fn record_value(record: &Record, column: &str) -> String {
    record
        .field(column)
        .ok()
        .flatten()
        .map(yaml_value)
        .unwrap_or_else(|| "—".to_owned())
}

fn yaml_value(value: &YamlValue) -> String {
    match value {
        YamlValue::String(value) => value.clone(),
        _ => yaml_serde::to_string(value)
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|_| "<unprintable>".to_owned()),
    }
}

fn audit_source_label(source: &AuditSource) -> &'static str {
    match source {
        AuditSource::Cli => "CLI",
        AuditSource::Api => "web/API",
        AuditSource::Filesystem => "filesystem",
        AuditSource::Sync => "sync",
    }
}

fn audit_change_operation(change: &AuditChange) -> &'static str {
    match change {
        AuditChange::Add { .. } => "add",
        AuditChange::Remove { .. } => "remove",
        AuditChange::Replace { .. } => "replace",
    }
}

fn audit_change_path(change: &AuditChange) -> &str {
    let path = change.path();
    if path.is_empty() {
        "complete record"
    } else {
        path
    }
}

fn audit_change_before(change: &AuditChange) -> Option<&JsonValue> {
    match change {
        AuditChange::Remove { before, .. } | AuditChange::Replace { before, .. } => Some(before),
        AuditChange::Add { .. } => None,
    }
}

fn audit_change_after(change: &AuditChange) -> Option<&JsonValue> {
    match change {
        AuditChange::Add { after, .. } | AuditChange::Replace { after, .. } => Some(after),
        AuditChange::Remove { .. } => None,
    }
}

fn json_preview(value: &JsonValue) -> String {
    const MAX_CHARS: usize = 2_000;
    let rendered = serde_json::to_string_pretty(value).unwrap_or_else(|_| "<unprintable>".into());
    let mut characters = rendered.chars();
    let preview: String = characters.by_ref().take(MAX_CHARS).collect();
    if characters.next().is_some() {
        format!("{preview}\n…")
    } else {
        preview
    }
}

fn short_hash(hash: &str) -> String {
    hash.chars().take(20).collect()
}

/// One agent line, including the delegation chain behind it.
fn render_audit_agent(agent: &AuditAgent) -> Markup {
    let chain: Vec<&AuditAgent> = agent.via.iter().flatten().collect();
    html! {
        p class="mt-2 text-xs text-slate-500" {
            "Agent " span class="font-medium text-slate-700" { (&agent.id) }
            @if let Some(version) = &agent.version { " " (version) }
            @if let Some(model) = &agent.model { " · model " (model) }
            @if let Some(session) = &agent.session {
                " · session " a href=(audit_session_url(session)) class="hover:text-blue-700" { (session) }
            }
            @if let Some(turn) = &agent.turn { " · turn " (turn) }
            @for delegate in &chain { " · via " (&delegate.id) }
            " · asserted, detected from " (agent.detected_from.label())
        }
    }
}

/// One intent half, bounded for display. The complete text stays in the event.
fn render_intent_part(label: &str, part: &AuditIntentPart) -> Markup {
    html! {
        p class="mt-2 text-sm text-slate-600" {
            span class="text-xs font-semibold uppercase tracking-wide text-slate-500" { (label) }
            " (" (part.author.label()) ") "
            @if let Some(text) = &part.text { (text_preview(text)) }
            @else if let Some(digest) = &part.digest { "text not retained; digest " (digest) }
        }
    }
}

/// Bound one attribution string for a page without losing it from the journal.
fn text_preview(value: &str) -> String {
    const MAX_CHARS: usize = 400;
    let mut characters = value.chars();
    let preview: String = characters.by_ref().take(MAX_CHARS).collect();
    let preview = preview.replace(['\n', '\r'], " ");
    if characters.next().is_some() {
        format!("{preview} …")
    } else {
        preview
    }
}

fn audit_agent_url(agent: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("agent", agent);
    format!("/audit?{}", serializer.finish())
}

fn audit_session_url(session: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("session", session);
    format!("/audit?{}", serializer.finish())
}

fn audit_filter_url(collection: &str, id: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("collection", collection);
    serializer.append_pair("id", id);
    format!("/audit?{}", serializer.finish())
}

fn audit_page_url(query: &AuditViewQuery, limit: usize, offset: usize) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    if let Some(collection) = query
        .collection
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        serializer.append_pair("collection", collection);
    }
    if let Some(id) = query.id.as_deref().filter(|value| !value.trim().is_empty()) {
        serializer.append_pair("id", id);
    }
    if let Some(agent) = query
        .agent
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        serializer.append_pair("agent", agent);
    }
    if let Some(session) = query
        .session
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        serializer.append_pair("session", session);
    }
    serializer.append_pair("limit", &limit.to_string());
    serializer.append_pair("offset", &offset.to_string());
    format!("/audit?{}", serializer.finish())
}

fn view_filter_expressions(query: &ViewQuery) -> ApiResult<Vec<FilterExpression>> {
    if query.filter_field.len() != query.filter_value.len() {
        return Err(ApiError::bad_request(
            "invalid_filter",
            "each filter_field must have one matching filter_value",
        ));
    }
    if !query.filter_operator.is_empty() && query.filter_field.len() != query.filter_operator.len()
    {
        return Err(ApiError::bad_request(
            "invalid_filter",
            "each filter_field must have one matching filter_operator",
        ));
    }
    if query.filter_field.len() > MAX_VIEW_FILTERS {
        return Err(ApiError::bad_request(
            "invalid_filter",
            format!("a view can apply at most {MAX_VIEW_FILTERS} filters"),
        ));
    }
    query
        .filter_field
        .iter()
        .zip(&query.filter_value)
        .enumerate()
        .filter_map(|(index, (field, value))| {
            if field.is_empty() && value.is_empty() {
                None
            } else if field.is_empty() {
                Some(Err(ApiError::bad_request(
                    "invalid_filter",
                    "filter_field cannot be empty when filter_value is provided",
                )))
            } else {
                let operator = query
                    .filter_operator
                    .get(index)
                    .copied()
                    .unwrap_or_default();
                Some(
                    FilterExpression::new(field, operator.into(), value)
                        .map_err(ApiError::from_domain),
                )
            }
        })
        .collect()
}

fn save_view_filter_group(form: &HtmlSaveViewForm) -> ApiResult<Option<ViewFilterGroup>> {
    let query = ViewQuery {
        filter_match: form.filter_match,
        filter_field: form.filter_field.clone(),
        filter_operator: form.filter_operator.clone(),
        filter_value: form.filter_value.clone(),
        ..ViewQuery::default()
    };
    view_filter_expressions(&query)?;

    let mut expressions = Vec::new();
    for (index, (field, value)) in form.filter_field.iter().zip(&form.filter_value).enumerate() {
        if field.is_empty() && value.is_empty() {
            continue;
        }
        let operator = form.filter_operator.get(index).copied().unwrap_or_default();
        let expression = if operator.requires_value() {
            format!(
                "{}{}{}",
                field.trim(),
                operator.expression_token(),
                value.trim()
            )
        } else {
            format!("{}{}", field.trim(), operator.expression_token())
        };
        FilterExpression::from_str(&expression).map_err(ApiError::from_domain)?;
        expressions.push(expression);
    }

    if expressions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ViewFilterGroup {
            match_mode: match form.filter_match {
                ViewFilterMatch::All => ViewPredicateMatch::All,
                ViewFilterMatch::Any => ViewPredicateMatch::Any,
            },
            expressions,
        }))
    }
}

fn view_sort_field(query: &ViewQuery) -> Option<&str> {
    query
        .sort_field
        .as_deref()
        .map(str::trim)
        .filter(|field| !field.is_empty())
}

fn sort_view_records(records: &mut [Record], query: &ViewQuery) -> ApiResult<()> {
    let Some(field) = view_sort_field(query) else {
        return Ok(());
    };
    sort_records_by_field(records, field, query.sort_direction.into())
        .map_err(ApiError::from_domain)
}

fn view_page_url(view: &ViewDefinition, query: &ViewQuery, limit: usize, offset: usize) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    if let Some(q) = query.q.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("q", q);
    }
    serializer.append_pair(
        "filter_match",
        match query.filter_match {
            ViewFilterMatch::All => "all",
            ViewFilterMatch::Any => "any",
        },
    );
    for (index, (field, value)) in query
        .filter_field
        .iter()
        .zip(&query.filter_value)
        .enumerate()
    {
        serializer.append_pair("filter_field", field);
        serializer.append_pair(
            "filter_operator",
            query
                .filter_operator
                .get(index)
                .copied()
                .unwrap_or_default()
                .as_str(),
        );
        serializer.append_pair("filter_value", value);
    }
    if let Some(field) = query.sort_field.as_deref() {
        serializer.append_pair("sort_field", field.trim());
        if !field.trim().is_empty() {
            serializer.append_pair("sort_direction", query.sort_direction.as_str());
        }
    }
    if query_columns_custom(query) {
        serializer.append_pair("columns", "custom");
        for column in &query.column {
            serializer.append_pair("column", column);
        }
    }
    serializer.append_pair("limit", &limit.to_string());
    serializer.append_pair("offset", &offset.to_string());
    format!("/{}?{}", encode_segment(&view.name), serializer.finish())
}

fn view_sort_url(view: &ViewDefinition, query: &ViewQuery, field: &str, limit: usize) -> String {
    let mut next = query.clone();
    next.sort_direction = if view_sort_field(query) == Some(field)
        && query.sort_direction == ViewSortDirection::Asc
    {
        ViewSortDirection::Desc
    } else {
        ViewSortDirection::Asc
    };
    next.sort_field = Some(field.to_owned());
    view_page_url(view, &next, limit, 0)
}

fn sort_indicator(query: &ViewQuery, field: &str) -> &'static str {
    if view_sort_field(query) != Some(field) {
        "↕"
    } else if query.sort_direction == ViewSortDirection::Asc {
        "↑"
    } else {
        "↓"
    }
}

fn sort_aria_state(query: &ViewQuery, field: &str) -> &'static str {
    if view_sort_field(query) != Some(field) {
        "none"
    } else if query.sort_direction == ViewSortDirection::Asc {
        "ascending"
    } else {
        "descending"
    }
}

fn sort_link_label(query: &ViewQuery, label: &str, field: &str) -> String {
    let direction = if view_sort_field(query) == Some(field)
        && query.sort_direction == ViewSortDirection::Asc
    {
        "descending"
    } else {
        "ascending"
    };
    format!("Sort by {label} {direction}")
}

fn parse_document_form(raw: &[u8]) -> ApiResult<HtmlDocumentForm> {
    let mut csrf = None;
    let mut expected_record_hash = None;
    let mut id = None;
    let mut front_matter = None;
    let mut markdown = None;
    let mut mode = None;
    let mut additional_attributes = None;
    let mut fields: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, value) in form_urlencoded::parse(raw) {
        let name = name.into_owned();
        let value = value.into_owned();
        match name.as_str() {
            "_csrf" => set_form_value(&mut csrf, value, "_csrf")?,
            "_expected_record_hash" => {
                set_form_value(&mut expected_record_hash, value, "_expected_record_hash")?
            }
            "id" => set_form_value(&mut id, value, "id")?,
            "front_matter" => set_form_value(&mut front_matter, value, "front_matter")?,
            "markdown" => set_form_value(&mut markdown, value, "markdown")?,
            "_form_mode" => set_form_value(&mut mode, value, "_form_mode")?,
            "_additional_attributes" => {
                set_form_value(&mut additional_attributes, value, "_additional_attributes")?
            }
            _ => {
                let Some(field) = name.strip_prefix("attribute.") else {
                    return Err(ApiError::bad_request(
                        "invalid_form",
                        format!("unknown form field '{name}'"),
                    ));
                };
                if field.is_empty() {
                    return Err(ApiError::bad_request(
                        "invalid_form",
                        "attribute field name cannot be empty",
                    ));
                }
                fields.entry(field.to_owned()).or_default().push(value);
            }
        }
    }

    let structured = match mode.as_deref() {
        Some("structured") => true,
        Some(other) => {
            return Err(ApiError::bad_request(
                "invalid_form",
                format!("unsupported form mode '{other}'"),
            ));
        }
        None => false,
    };
    if structured && front_matter.is_some() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "structured fields and raw front matter cannot be submitted together",
        ));
    }
    if !structured && front_matter.is_none() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "front_matter is required when structured fields are not used",
        ));
    }

    Ok(HtmlDocumentForm {
        csrf: csrf.ok_or_else(|| ApiError::bad_request("invalid_form", "_csrf is required"))?,
        expected_record_hash,
        id,
        front_matter,
        markdown: markdown
            .ok_or_else(|| ApiError::bad_request("invalid_form", "markdown is required"))?,
        structured,
        additional_attributes: additional_attributes.unwrap_or_else(|| "{}".to_owned()),
        fields,
    })
}

fn set_form_value(destination: &mut Option<String>, value: String, name: &str) -> ApiResult<()> {
    if destination.replace(value).is_some() {
        Err(ApiError::bad_request(
            "invalid_form",
            format!("form field '{name}' cannot be repeated"),
        ))
    } else {
        Ok(())
    }
}

fn document_form_attributes(
    form: &HtmlDocumentForm,
    schema: Option<&JsonValue>,
) -> ApiResult<Mapping> {
    if !form.structured {
        return parse_front_matter(
            form.front_matter
                .as_deref()
                .expect("raw forms have front matter"),
        );
    }
    let schema = schema.ok_or_else(|| {
        ApiError::bad_request(
            "invalid_form",
            "structured fields require a collection schema",
        )
    })?;
    parse_structured_attributes(form, schema)
}

fn parse_structured_attributes(form: &HtmlDocumentForm, schema: &JsonValue) -> ApiResult<Mapping> {
    let properties = schema
        .get("properties")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            ApiError::bad_request(
                "invalid_form",
                "structured fields require schema properties",
            )
        })?;
    for field in form.fields.keys() {
        if !properties.contains_key(field) {
            return Err(ApiError::bad_request(
                "invalid_form",
                format!("attribute '{field}' is not declared by the collection schema"),
            ));
        }
    }

    let mut attributes = parse_front_matter(&form.additional_attributes)?;
    for key in attributes.keys() {
        if let YamlValue::String(key) = key
            && properties.contains_key(key)
        {
            return Err(ApiError::bad_request(
                "invalid_form",
                format!("declared attribute '{key}' cannot be overridden in additional YAML"),
            ));
        }
    }
    if !schema_allows_additional_attributes(schema) && !attributes.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "this collection schema does not allow additional attributes",
        ));
    }

    let required = schema
        .get("required")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .collect::<BTreeSet<_>>();
    for (key, definition) in properties {
        let values = form.fields.get(key).map(Vec::as_slice).unwrap_or(&[]);
        if let Some(value) =
            parse_schema_form_value(key, definition, required.contains(key.as_str()), values)?
        {
            attributes.insert(YamlValue::String(key.clone()), value);
        }
    }
    Ok(attributes)
}

fn parse_schema_form_value(
    key: &str,
    definition: &JsonValue,
    required: bool,
    values: &[String],
) -> ApiResult<Option<YamlValue>> {
    let kind = schema_field_kind(definition);
    match kind {
        SchemaFieldKind::MultiSelect(options) => {
            let mut selected = Vec::new();
            for raw in values.iter().filter(|value| !value.is_empty()) {
                let value = parse_form_yaml_value(key, raw)?;
                if !options.contains(&value) {
                    return Err(ApiError::bad_request(
                        "invalid_form",
                        format!("attribute '{key}' contains a value outside its allowed options"),
                    ));
                }
                if !selected.contains(&value) {
                    selected.push(value);
                }
            }
            if selected.is_empty() && !required {
                Ok(None)
            } else {
                Ok(Some(YamlValue::Sequence(selected)))
            }
        }
        SchemaFieldKind::Select(options) => {
            let Some(raw) = single_schema_form_value(key, values)? else {
                return Ok(None);
            };
            if raw.is_empty() {
                return Ok(None);
            }
            let value = parse_form_yaml_value(key, raw)?;
            if !options.contains(&value) {
                return Err(ApiError::bad_request(
                    "invalid_form",
                    format!("attribute '{key}' is outside its allowed options"),
                ));
            }
            Ok(Some(value))
        }
        SchemaFieldKind::String { .. } => {
            let Some(raw) = single_schema_form_value(key, values)? else {
                return Ok(None);
            };
            if raw.is_empty() && !required {
                Ok(None)
            } else {
                Ok(Some(YamlValue::String(raw.to_owned())))
            }
        }
        SchemaFieldKind::Integer { .. }
        | SchemaFieldKind::Number { .. }
        | SchemaFieldKind::Boolean => {
            let Some(raw) = single_schema_form_value(key, values)? else {
                return Ok(None);
            };
            if raw.is_empty() {
                Ok(None)
            } else {
                Ok(Some(parse_form_yaml_value(key, raw)?))
            }
        }
        SchemaFieldKind::Yaml => {
            let Some(raw) = single_schema_form_value(key, values)? else {
                return Ok(None);
            };
            if raw.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(parse_form_yaml_value(key, raw)?))
            }
        }
    }
}

fn single_schema_form_value<'a>(key: &str, values: &'a [String]) -> ApiResult<Option<&'a str>> {
    match values {
        [] => Ok(None),
        [value] => Ok(Some(value)),
        _ => Err(ApiError::bad_request(
            "invalid_form",
            format!("attribute '{key}' cannot be repeated"),
        )),
    }
}

fn parse_form_yaml_value(key: &str, raw: &str) -> ApiResult<YamlValue> {
    yaml_serde::from_str(raw).map_err(|error| {
        ApiError::bad_request(
            "invalid_form",
            format!("attribute '{key}' is not valid typed YAML: {error}"),
        )
    })
}

fn notice_url(view: &str, notice: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("notice", notice);
    format!("/{}?{}", encode_segment(view), serializer.finish())
}

fn parse_html_form<T: DeserializeOwned>(raw: &[u8]) -> ApiResult<T> {
    serde_html_form::from_bytes(raw)
        .map_err(|error| ApiError::bad_request("invalid_form", error.to_string()))
}

fn parse_front_matter(serialized: &str) -> ApiResult<Mapping> {
    if serialized.trim().is_empty() {
        return Ok(Mapping::new());
    }
    yaml_serde::from_str(serialized).map_err(|error| {
        ApiError::bad_request(
            "invalid_front_matter",
            format!("front matter is not a YAML object: {error}"),
        )
    })
}

fn verify_csrf(state: &AppState, provided: &str) -> ApiResult<()> {
    if provided == state.csrf_token.as_ref() {
        Ok(())
    } else {
        Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid_csrf_token",
            "reload the form and try again",
        ))
    }
}

fn random_token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| anyhow!("could not generate form security token: {error}"))?;
    Ok(hexadecimal(&bytes))
}

/// A short correlation ID. Unlike a security token this may never fail, so a
/// process-wide counter covers the rare case where the system source does not
/// answer; diagnostics still correlate within one server run.
fn random_id() -> String {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        static FALLBACK: AtomicU64 = AtomicU64::new(0);
        bytes = FALLBACK.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    }
    hexadecimal(&bytes)
}

fn hexadecimal(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn see_other(location: &str) -> ApiResult<Response> {
    let location = HeaderValue::from_str(location)
        .map_err(|error| ApiError::bad_request("invalid_location", error.to_string()))?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

fn html_result(result: ApiResult<Markup>) -> Response {
    match result {
        Ok(markup) => html_response(StatusCode::OK, markup),
        Err(error) => html_error(error),
    }
}

fn html_error(error: ApiError) -> Response {
    let error = error.publish();
    let status = error.status;
    let markup = page_layout(
        "Error",
        "",
        &[],
        html! {
            div class="mx-auto max-w-2xl rounded-2xl border border-red-200 bg-white p-8 shadow-sm" {
                p class="text-sm font-semibold uppercase tracking-wide text-red-600" { (status.as_u16()) " " (status.canonical_reason().unwrap_or("Error")) }
                h1 class="mt-2 text-2xl font-bold text-slate-950" { "Request could not be completed" }
                p class="mt-3 text-sm text-slate-700" { (error.message) }
                p class="mt-3 text-xs text-slate-500" { "Request ID " (error.request_id) }
                a href="/" class="mt-6 inline-flex rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700" { "Back to views" }
            }
        },
        None,
        "",
    );
    html_response(status, markup)
}

fn html_response(status: StatusCode, markup: Markup) -> Response {
    let mut response = (status, Html(markup.into_string())).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "route_not_found", "route not found")
}

async fn method_not_allowed() -> ApiError {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "method not allowed for this route",
    )
}

fn request_database(state: &AppState, headers: &HeaderMap) -> ApiResult<Database> {
    let mut database = state.database.clone();
    if let Some(actor) = headers.get(ACTOR_HEADER) {
        let actor = actor.to_str().map_err(|_| {
            ApiError::bad_request("invalid_actor", "X-CR-Actor must be valid UTF-8")
        })?;
        database = database.with_actor(actor).map_err(ApiError::from_domain)?;
    }
    if state.access_controlled {
        let principal =
            perspective_principal(headers)?.unwrap_or_else(|| database.principal().to_owned());
        database = database
            .impersonate_verified(&principal)
            .map_err(ApiError::from_domain)?;
    }
    let agent = attribution_header(headers, AGENT_HEADER, "X-CR-Agent", "invalid_agent")?;
    let authorization = attribution_header(
        headers,
        AUTHORIZATION_ATTRIBUTION_HEADER,
        "X-CR-Authorization",
        "invalid_authorization",
    )?;
    let intent = attribution_header(headers, INTENT_HEADER, "X-CR-Intent", "invalid_intent")?;
    let approved_changes = attribution_header(
        headers,
        APPROVED_CHANGES_HEADER,
        "X-CR-Approved-Changes",
        "invalid_approved_changes",
    )?;
    if agent.is_none() && authorization.is_none() && intent.is_none() && approved_changes.is_none()
    {
        return Ok(database);
    }
    let mut attribution = database.attribution().clone();
    attribution
        .apply(
            &AttributionOverrides {
                agent,
                authorization,
                intent,
                approved_changes,
                ..AttributionOverrides::default()
            },
            AgentEvidence::Header,
        )
        .map_err(ApiError::from_domain)?;
    Ok(database.with_attribution(attribution))
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    header: &str,
    name: &str,
    code: &'static str,
) -> ApiResult<Option<&'a str>> {
    let mut values = headers.get_all(header).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ApiError::bad_request(
            code,
            format!("{name} may appear only once"),
        ));
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| ApiError::bad_request(code, format!("{name} must be visible ASCII")))
}

fn perspective_principal(headers: &HeaderMap) -> ApiResult<Option<String>> {
    let mut selected = None;
    for header in headers.get_all(header::COOKIE) {
        let header = header.to_str().map_err(|_| {
            ApiError::bad_request("invalid_cookie", "Cookie must be valid visible text")
        })?;
        for cookie in header.split(';').map(str::trim) {
            let Some(value) = cookie.strip_prefix(&format!("{PERSPECTIVE_COOKIE}=")) else {
                continue;
            };
            if selected.is_some() {
                return Err(ApiError::bad_request(
                    "invalid_cookie",
                    "the perspective cookie may appear only once",
                ));
            }
            let principal = percent_decode_str(value)
                .decode_utf8()
                .map_err(|_| {
                    ApiError::bad_request(
                        "invalid_cookie",
                        "the perspective cookie is not valid UTF-8",
                    )
                })?
                .into_owned();
            selected = Some(principal);
        }
    }
    Ok(selected)
}

async fn ui_context(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<UiContext>> {
    if !state.access_controlled {
        return Ok(None);
    }
    let selected =
        perspective_principal(headers)?.unwrap_or_else(|| state.database.principal().to_owned());
    let database = state.database.clone();
    tokio::task::spawn_blocking(move || {
        let users = database.users()?;
        let selected_user = users
            .iter()
            .find(|(id, _)| id == &selected)
            .map(|(_, user)| user)
            .ok_or_else(|| DomainError::record_not_found("users", &selected))?;
        let selected_name = selected_user.name.clone();
        let selected_status = selected_user.status;
        let selected_database = database.impersonate_verified(&selected)?;
        let can_view_global_audit =
            selected_database.owner_access_allowed(&AccessResource::Database)?;
        let users = users
            .into_iter()
            .map(|(id, user)| UiUser {
                id,
                name: user.name,
                role: user_role_summary(&user.access),
                status: user.status,
            })
            .collect();
        Ok(UiContext {
            operator: AccessIdentity {
                principal: database.principal().to_owned(),
                display: database.actor().to_owned(),
            },
            selected,
            selected_name,
            selected_status,
            can_view_global_audit,
            users,
        })
    })
    .await
    .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
    .map(Some)
    .map_err(ApiError::from_domain)
}

fn user_role_summary(grants: &[crate::AccessGrant]) -> String {
    if let Some(grant) = grants
        .iter()
        .find(|grant| grant.resource == AccessResource::Database)
    {
        return grant.role.to_string();
    }
    let roles = grants
        .iter()
        .map(|grant| grant.role.to_string())
        .collect::<BTreeSet<_>>();
    if roles.is_empty() {
        "no access".to_owned()
    } else {
        let roles = roles.into_iter().collect::<Vec<_>>().join(" + ");
        format!("{roles} · scoped")
    }
}

/// Read one attribution header.
///
/// HTTP header values are visible ASCII, so non-ASCII intent text must arrive
/// as JSON `\uXXXX` escapes. The rejection says so without naming anything
/// internal.
fn attribution_header<'a>(
    headers: &'a HeaderMap,
    header: &str,
    name: &str,
    code: &'static str,
) -> ApiResult<Option<&'a str>> {
    headers
        .get(header)
        .map(|value| {
            value.to_str().map_err(|_| {
                ApiError::bad_request(
                    code,
                    format!(
                        "{name} must be visible ASCII; encode other characters as JSON \\u escapes"
                    ),
                )
            })
        })
        .transpose()
}

/// Parse the strong validators from an HTTP `If-Match` precondition.
///
/// Weak validators are syntactically accepted but can never satisfy
/// `If-Match`, whose comparison is strong. Multiple field lines and comma
/// lists have the same meaning. The database receives the parsed condition and
/// performs the actual comparison while holding the audit lock.
fn if_match(headers: &HeaderMap, required: bool) -> ApiResult<Option<RecordPrecondition>> {
    let mut present = false;
    let mut wildcards = 0;
    let mut entity_tag = false;
    let mut versions = Vec::new();
    for value in headers.get_all(header::IF_MATCH) {
        present = true;
        let parsed = parse_if_match_field(value.as_bytes())?;
        wildcards += parsed.wildcards;
        entity_tag |= parsed.entity_tag;
        versions.extend(parsed.versions);
    }
    if !present {
        return if required {
            Err(ApiError::new(
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                "this whole-record replacement requires If-Match",
            ))
        } else {
            Ok(None)
        };
    }
    if wildcards > 0 {
        if wildcards != 1 || entity_tag {
            return Err(ApiError::bad_request(
                "invalid_if_match",
                "If-Match '*' must be the only field value",
            ));
        }
        return Ok(Some(RecordPrecondition::any_current()));
    }
    RecordPrecondition::versions(versions)
        .map(Some)
        .map_err(ApiError::from_domain)
}

struct ParsedIfMatchField {
    wildcards: usize,
    entity_tag: bool,
    versions: Vec<String>,
}

/// Parse one `If-Match` field value without interpreting opaque entity-tags.
///
/// A comma is legal inside an entity-tag, and tags issued by another server
/// are still syntactically valid. Only strong tags in cr's version format are
/// passed to the domain layer; every other valid tag simply cannot match.
fn parse_if_match_field(value: &[u8]) -> ApiResult<ParsedIfMatchField> {
    let mut offset = 0;
    let mut wildcards = 0;
    let mut entity_tag = false;
    let mut versions = Vec::new();
    let mut parsed_items = 0;

    loop {
        while value
            .get(offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            offset += 1;
        }
        if offset == value.len() {
            if parsed_items == 0 {
                return Err(ApiError::bad_request(
                    "invalid_if_match",
                    "If-Match must contain an entity tag",
                ));
            }
            break;
        }

        if value[offset] == b'*' {
            wildcards += 1;
            offset += 1;
        } else {
            let weak = value.get(offset..offset + 2) == Some(b"W/");
            if weak {
                offset += 2;
            }
            if value.get(offset) != Some(&b'"') {
                return Err(ApiError::bad_request(
                    "invalid_if_match",
                    "If-Match entity tags must be quoted",
                ));
            }
            offset += 1;
            let opaque_start = offset;
            while value.get(offset).is_some_and(|byte| *byte != b'"') {
                let byte = value[offset];
                if byte != 0x21 && !(0x23..=0x7e).contains(&byte) && byte < 0x80 {
                    return Err(ApiError::bad_request(
                        "invalid_if_match",
                        "If-Match contains an invalid entity tag",
                    ));
                }
                offset += 1;
            }
            if value.get(offset) != Some(&b'"') {
                return Err(ApiError::bad_request(
                    "invalid_if_match",
                    "If-Match contains an unterminated entity tag",
                ));
            }
            let opaque = &value[opaque_start..offset];
            offset += 1;
            entity_tag = true;
            if !weak
                && let Ok(version) = std::str::from_utf8(opaque)
                && RecordPrecondition::version(version.to_owned()).is_ok()
            {
                versions.push(version.to_owned());
            }
        }
        parsed_items += 1;

        while value
            .get(offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            offset += 1;
        }
        if offset == value.len() {
            break;
        }
        if value[offset] != b',' {
            return Err(ApiError::bad_request(
                "invalid_if_match",
                "If-Match entity tags must be separated by commas",
            ));
        }
        offset += 1;
        let next = value[offset..]
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .map(|next| offset + next);
        if next.is_none() || value[next.expect("checked above")] == b',' {
            return Err(ApiError::bad_request(
                "invalid_if_match",
                "If-Match contains an empty entity tag",
            ));
        }
    }

    Ok(ParsedIfMatchField {
        wildcards,
        entity_tag,
        versions,
    })
}

fn entity_tag(version: &str) -> ApiResult<HeaderValue> {
    HeaderValue::from_str(&format!("\"{version}\""))
        .map_err(|error| ApiError::internal(anyhow!(error).context("could not build record ETag")))
}

fn api_record_response(status: StatusCode, record: Record) -> ApiResult<Response> {
    let etag = entity_tag(&record.version)?;
    let mut response = (status, Json(ApiRecord::try_from(record)?)).into_response();
    response.headers_mut().insert(header::ETAG, etag);
    Ok(response)
}

async fn run_database<T, F>(state: &AppState, headers: &HeaderMap, operation: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T> + Send + 'static,
{
    let database = request_database(state, headers)?;
    tokio::task::spawn_blocking(move || operation(&database))
        .await
        .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
        .map_err(ApiError::from_domain)
}

async fn run_idempotent_database<T, F>(
    state: &AppState,
    headers: &HeaderMap,
    operation: F,
) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T> + Send + 'static,
{
    let mut database = request_database(state, headers)?;
    if let Some(key) = single_header(
        headers,
        IDEMPOTENCY_HEADER,
        "Idempotency-Key",
        "invalid_idempotency_key",
    )? {
        database = database
            .with_idempotency_key(key)
            .map_err(ApiError::from_domain)?;
    }
    tokio::task::spawn_blocking(move || operation(&database))
        .await
        .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
        .map_err(ApiError::from_domain)
}

fn json_payload<T>(payload: std::result::Result<Json<T>, JsonRejection>) -> ApiResult<Json<T>> {
    payload.map_err(|error| {
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                error.body_text(),
            )
        } else {
            ApiError::bad_request("invalid_json", error.body_text())
        }
    })
}

fn parse_query<T: DeserializeOwned>(raw: Option<String>) -> ApiResult<T> {
    serde_html_form::from_str(raw.as_deref().unwrap_or_default())
        .map_err(|error| ApiError::bad_request("invalid_query", error.to_string()))
}

fn parse_filters(filters: Vec<String>) -> ApiResult<Vec<Assignment>> {
    filters
        .into_iter()
        .map(|filter| filter.parse().map_err(ApiError::from_domain))
        .collect()
}

fn parse_filter_expressions(expressions: Vec<String>) -> ApiResult<Vec<FilterExpression>> {
    expressions
        .into_iter()
        .map(|expression| expression.parse().map_err(ApiError::from_domain))
        .collect()
}

fn search_target(
    target: Option<SearchTargetParameter>,
    field: Option<String>,
) -> ApiResult<SearchTarget> {
    match (target, field) {
        (None, None) | (Some(SearchTargetParameter::Document), None) => Ok(SearchTarget::Document),
        (None, Some(field)) | (Some(SearchTargetParameter::Field), Some(field)) => {
            Ok(SearchTarget::Field(field))
        }
        (Some(SearchTargetParameter::FrontMatter), None) => Ok(SearchTarget::FrontMatter),
        (Some(SearchTargetParameter::Body), None) => Ok(SearchTarget::Body),
        (Some(SearchTargetParameter::Path), None) => Ok(SearchTarget::Path),
        (Some(SearchTargetParameter::Field), None) => {
            Err(ApiError::unprocessable("target=field requires field"))
        }
        (_, Some(_)) => Err(ApiError::unprocessable(
            "field can only be used with target=field",
        )),
    }
}

#[derive(Clone, Copy)]
struct PageBounds {
    limit: usize,
    offset: usize,
}

fn page_bounds(
    limit: Option<usize>,
    offset: Option<usize>,
    max_page_size: usize,
) -> ApiResult<PageBounds> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_SIZE.min(max_page_size));
    let offset = offset.unwrap_or(0);
    if limit == 0 {
        return Err(ApiError::unprocessable("limit must be greater than zero"));
    }
    if limit > max_page_size {
        return Err(ApiError::unprocessable(format!(
            "limit cannot exceed {max_page_size}"
        )));
    }
    if offset > MAX_PAGE_OFFSET {
        return Err(ApiError::unprocessable(format!(
            "offset cannot exceed {MAX_PAGE_OFFSET}"
        )));
    }
    Ok(PageBounds { limit, offset })
}

fn paginate<T>(items: Vec<T>, bounds: PageBounds) -> Page<T> {
    let total = items.len();
    let data: Vec<_> = items
        .into_iter()
        .skip(bounds.offset)
        .take(bounds.limit)
        .collect();
    let returned = data.len();
    let end = bounds.offset.saturating_add(returned);
    let has_more = end < total;
    Page {
        data,
        pagination: Pagination {
            limit: bounds.limit,
            offset: bounds.offset,
            returned,
            total: Some(total),
            has_more,
            next_offset: has_more.then_some(end),
            previous_offset: (bounds.offset > 0)
                .then_some(bounds.offset.saturating_sub(bounds.limit)),
        },
    }
}

fn paginate_unknown_total<T>(items: Vec<T>, bounds: PageBounds) -> Page<T> {
    let has_more = items.len() > bounds.offset.saturating_add(bounds.limit);
    let data: Vec<_> = items
        .into_iter()
        .skip(bounds.offset)
        .take(bounds.limit)
        .collect();
    let returned = data.len();
    Page {
        data,
        pagination: Pagination {
            limit: bounds.limit,
            offset: bounds.offset,
            returned,
            total: None,
            has_more,
            next_offset: has_more.then_some(bounds.offset.saturating_add(returned)),
            previous_offset: (bounds.offset > 0)
                .then_some(bounds.offset.saturating_sub(bounds.limit)),
        },
    }
}

impl<T> Page<T> {
    fn try_map<U>(self, mut convert: impl FnMut(T) -> ApiResult<U>) -> ApiResult<Page<U>> {
        Ok(Page {
            data: self
                .data
                .into_iter()
                .map(&mut convert)
                .collect::<ApiResult<Vec<_>>>()?,
            pagination: self.pagination,
        })
    }
}

fn json_front_matter(attributes: Mapping) -> ApiResult<JsonValue> {
    serde_json::to_value(attributes).map_err(|error| {
        ApiError::unprocessable(format!(
            "front matter cannot be represented as a JSON object: {error}"
        ))
    })
}

fn display_path(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

fn encode_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn collection_component_name(collection: &str) -> String {
    let digest = Sha256::digest(collection.as_bytes());
    let suffix: String = digest[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let readable: String = collection
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    format!("Collection_{readable}_{suffix}_FrontMatter")
}

#[cfg(test)]
mod tests {
    use super::{ApiError, INTERNAL_MESSAGE};
    use crate::DomainError;
    use anyhow::anyhow;
    use axum::http::StatusCode;

    /// A leaky diagnostic chain of the shape the domain layer actually
    /// produces, used to prove that none of it reaches a caller.
    fn leaky_cause() -> anyhow::Error {
        anyhow!(
            "could not read record /private/db/records/people/ada.md: No such file or directory (os error 2)"
        )
    }

    #[test]
    fn every_domain_classification_maps_to_a_stable_status_and_code() {
        let cases = [
            (
                DomainError::NotFound("record people/ada does not exist".to_owned()),
                StatusCode::NOT_FOUND,
                "not_found",
            ),
            (
                DomainError::AlreadyExists("record people/ada already exists".to_owned()),
                StatusCode::CONFLICT,
                "already_exists",
            ),
            (
                DomainError::Conflict("record people/ada has unsaved changes".to_owned()),
                StatusCode::CONFLICT,
                "conflict",
            ),
            (
                DomainError::PreconditionFailed(
                    "record people/ada changed since the expected version".to_owned(),
                ),
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
            ),
            (
                DomainError::IdempotencyConflict(
                    "idempotency key was already used for a different request".to_owned(),
                ),
                StatusCode::CONFLICT,
                "idempotency_conflict",
            ),
            (
                DomainError::Forbidden("principal cannot read record people/ada".to_owned()),
                StatusCode::FORBIDDEN,
                "forbidden",
            ),
            (
                DomainError::Invalid("field path cannot be empty".to_owned()),
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_failed",
            ),
            (
                DomainError::AuditIntegrity(
                    "audit replay is inconsistent at sequence 2".to_owned(),
                ),
                StatusCode::CONFLICT,
                "audit_integrity_failed",
            ),
        ];

        for (domain, status, code) in cases {
            let expected = domain.message().to_owned();
            let error = ApiError::from_domain(leaky_cause().context(domain));
            assert_eq!(error.status, status);
            assert_eq!(error.code, code);
            assert_eq!(error.message, expected);

            let published = error.publish();
            assert_eq!(published.message, expected);
            assert!(!published.request_id.is_empty());
        }
    }

    #[test]
    fn unclassified_failures_become_redacted_internal_errors() {
        let error = ApiError::from_domain(leaky_cause());
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "internal_error");

        let published = error.publish();
        assert_eq!(published.message, INTERNAL_MESSAGE);
        assert!(!published.request_id.is_empty());
        assert!(!published.message.contains("/private/db"));
        assert!(!published.message.contains("os error"));
    }
}
