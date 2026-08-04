use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, RawForm, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, Request, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use maud::{html, Markup, PreEscaped, DOCTYPE};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use yaml_serde::{Mapping, Value as YamlValue};

use crate::{
    audit::AuditChange, sort_records_by_field, Assignment, AuditEntry, AuditSource,
    CollectionModel, Database, FilterExpression, FilterOperator, Record, SearchQuery, SearchTarget,
    SortDirection, ViewDefinition, ViewFilterGroup, ViewLayout, ViewPredicateMatch,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const DEFAULT_MAX_PAGE_SIZE: usize = 200;
const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE_OFFSET: usize = 1_000_000;
const MAX_VIEW_FILTERS: usize = 20;
const ACTOR_HEADER: &str = "x-cr-actor";
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
    max_page_size: usize,
    api_token: Option<Arc<str>>,
    csrf_token: Arc<str>,
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
    front_matter: JsonValue,
    markdown: String,
}

#[derive(Debug, Serialize)]
struct ApiRecordSummary {
    path: String,
    front_matter: JsonValue,
}

impl TryFrom<Record> for ApiRecord {
    type Error = ApiError;

    fn try_from(record: Record) -> ApiResult<Self> {
        Ok(Self {
            collection: record.collection,
            id: record.id,
            path: display_path(&record.path),
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
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
    limit: Option<usize>,
    offset: Option<usize>,
    notice: Option<String>,
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
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug)]
struct HtmlDocumentForm {
    csrf: String,
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
}

type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct ErrorEnvelope {
    error: ErrorDetail,
}

#[derive(Debug, Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
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

    fn from_database(error: anyhow::Error) -> Self {
        let message = format!("{error:#}");
        let lower = message.to_lowercase();
        if lower.contains("already exists") || lower.contains("file exists") {
            Self::new(StatusCode::CONFLICT, "already_exists", message)
        } else if lower.contains("does not exist")
            || lower.contains("no such file or directory")
            || lower.contains("has no audit history")
        {
            Self::new(StatusCode::NOT_FOUND, "not_found", message)
        } else if lower.contains("unsaved")
            || lower.contains("audited hash")
            || lower.contains("differs from")
            || lower.contains("concurrent")
        {
            Self::new(StatusCode::CONFLICT, "conflict", message)
        } else if lower.contains("schema")
            || lower.contains("expected")
            || lower.contains("must ")
            || lower.contains("cannot ")
            || lower.contains("provide ")
            || lower.contains("field '")
            || lower.contains("field path")
            || lower.contains("path component")
            || lower.contains("regular expression")
        {
            Self::unprocessable(message)
        } else {
            Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorDetail {
                    code: self.code,
                    message: self.message,
                },
            }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"cr\""),
            );
        }
        response
    }
}

pub fn router(database: Database, config: ServerConfig) -> Result<Router> {
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
        max_page_size: config.max_page_size,
        api_token: config.api_token.map(Arc::from),
        csrf_token: Arc::from(random_token()?),
    };
    let protected = Router::new()
        .route("/openapi.json", get(openapi))
        .route("/", get(views_home))
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
                    get(get_record).patch(patch_record).delete(delete_record),
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

async fn authorize(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    let Some(token) = &state.api_token else {
        return next.run(request).await;
    };
    let authorized = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == token.as_ref());
    if authorized {
        next.run(request).await
    } else {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "provide a valid Bearer token",
        )
        .into_response()
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn views_home(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result: ApiResult<Markup> = async {
        let views = run_database(&state, &headers, Database::views).await?;
        Ok(render_views_home(&views))
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
            database.audit_recent(requested, collection.as_deref(), id.as_deref())
        })
        .await?;
        let page = paginate_unknown_total(entries, bounds);
        Ok(render_audit_view(&page, &query))
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
        let (view, mut records, schema) = run_database(&state, &headers, move |database| {
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
                    let search = SearchQuery::new(pattern, SearchTarget::Document, false, true)?;
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
            Ok((view, records, schema))
        })
        .await?;

        if query.sort_field.is_none() {
            query.sort_field = view.sort_by.clone();
            query.sort_direction = match view.sort_direction {
                SortDirection::Asc => ViewSortDirection::Asc,
                SortDirection::Desc => ViewSortDirection::Desc,
            };
        }

        let columns = view_columns(&view, &records, schema.as_ref());
        sort_view_records(&mut records, &query)?;
        let bounds = page_bounds(
            query
                .limit
                .or(Some(view.page_size.min(state.max_page_size))),
            query.offset,
            state.max_page_size,
        )?;
        let page = paginate(records, bounds);
        Ok(render_view_records(
            &view,
            &columns,
            &page,
            &query,
            schema.as_ref(),
            &state.csrf_token,
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
            database.create_view_with_options(
                &name,
                title.as_deref(),
                &source.collection,
                source.filters.clone(),
                source.where_expr.clone(),
                filter_groups,
                source.columns.clone(),
                source.page_size,
                source.layout,
                source.group_by.clone(),
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
        let (view, schema) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let schema = collection_schema(database, &view.collection)?;
            Ok((view, schema))
        })
        .await?;
        Ok(render_record_form(
            &view,
            None,
            &[],
            schema.as_ref(),
            &state.csrf_token,
            None,
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
        let (view, record, audit_entries, schema) =
            run_database(&state, &headers, move |database| {
                let view = database.view(&requested_view)?;
                let record = database.get(&view.collection, &requested_id)?;
                let audit_entries = database.audit_recent(
                    DEFAULT_PAGE_SIZE,
                    Some(&view.collection),
                    Some(&requested_id),
                )?;
                let schema = collection_schema(database, &view.collection)?;
                Ok((view, record, audit_entries, schema))
            })
            .await?;
        Ok(render_record_form(
            &view,
            Some(&record),
            &audit_entries,
            schema.as_ref(),
            &state.csrf_token,
            None,
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
        run_database(&state, &headers, move |database| {
            database.replace(&collection, &id, attributes, &markdown)
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
                bail!(
                    "cannot move a card through view '{}' because it does not use the kanban layout",
                    view.name
                );
            }
            let group_by = view
                .group_by
                .as_deref()
                .context("kanban view is missing group_by")?;
            let record = database.get(&view.collection, &id)?;
            match target {
                KanbanTarget::Value { value } => {
                    let target_value: YamlValue = yaml_serde::from_str(&value)
                        .with_context(|| format!("kanban target '{value}' is not valid YAML"))?;
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
        let requested_view = view_name.clone();
        run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            database.delete(&view.collection, &id)
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
    Ok(Json(IdentityResponse {
        actor: database.actor().to_owned(),
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
) -> ApiResult<Json<ApiRecord>> {
    let record = run_database(&state, &headers, move |database| {
        database.get(&collection, &id)
    })
    .await?;
    Ok(Json(record.try_into()?))
}

async fn get_document(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let document = run_database(&state, &headers, move |database| {
        database.read_raw(&collection, &id)
    })
    .await?;
    Ok((
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        document,
    )
        .into_response())
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
            .with_context(|| format!("field '{field}' does not exist"))?;
        serde_json::to_value(value).context("field cannot be represented as JSON")
    })
    .await?;
    Ok(Json(json!({ "value": value })))
}

async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    payload: std::result::Result<Json<CreateRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let Json(payload) = json_payload(payload)?;
    let id = payload.id.clone();
    let location = format!(
        "/api/v1/collections/{}/records/{}",
        encode_segment(&collection),
        encode_segment(&id)
    );
    let record = run_database(&state, &headers, move |database| {
        database.create_record(
            &collection,
            &payload.id,
            payload.front_matter,
            &payload.markdown,
        )
    })
    .await?;
    let mut response = (StatusCode::CREATED, Json(ApiRecord::try_from(record)?)).into_response();
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
    payload: std::result::Result<Json<PatchRecordRequest>, JsonRejection>,
) -> ApiResult<Json<ApiRecord>> {
    let Json(payload) = json_payload(payload)?;
    let record = run_database(&state, &headers, move |database| {
        database.patch(
            &collection,
            &id,
            &payload.front_matter,
            &payload.remove,
            payload.markdown.as_deref(),
        )
    })
    .await?;
    Ok(Json(record.try_into()?))
}

async fn delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
) -> ApiResult<Json<DeleteResponse>> {
    let record = run_database(&state, &headers, move |database| {
        database.delete(&collection, &id)
    })
    .await?;
    Ok(Json(DeleteResponse {
        deleted: true,
        record: record.try_into()?,
    }))
}

async fn link_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    payload: std::result::Result<Json<LinkRequest>, JsonRejection>,
) -> ApiResult<Json<ApiRecord>> {
    let Json(payload) = json_payload(payload)?;
    let record = run_database(&state, &headers, move |database| {
        database.link(
            &collection,
            &id,
            &payload.relation,
            &payload.target_collection,
            &payload.target_id,
        )
    })
    .await?;
    Ok(Json(record.try_into()?))
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
    .map_err(ApiError::from_database)?;
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

async fn save(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: std::result::Result<Json<SaveRequest>, JsonRejection>,
) -> ApiResult<Json<Vec<crate::AuditEntry>>> {
    let Json(payload) = json_payload(payload)?;
    let entries = run_database(&state, &headers, move |database| {
        database.save(&payload.records, payload.all, payload.message.as_deref())
    })
    .await?;
    Ok(Json(entries))
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
            parameters.collection.as_deref(),
            parameters.id.as_deref(),
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

fn base_openapi_schemas() -> Map<String, JsonValue> {
    serde_json::from_value(json!({
        "FrontMatter": { "type": "object", "additionalProperties": true },
        "RecordSummary": {
            "type": "object",
            "required": ["path", "front_matter"],
            "properties": {
                "path": { "type": "string" },
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
        "Identity": {
            "type": "object", "required": ["actor"],
            "properties": { "actor": { "type": "string" } }
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
            "required": ["hash", "sequence", "timestamp", "actor", "source", "action", "record", "changes"],
            "properties": {
                "hash": { "type": "string" },
                "sequence": { "type": "integer", "minimum": 1 },
                "timestamp": { "type": "string", "format": "date-time" },
                "actor": { "type": "string" },
                "source": { "enum": ["cli", "api", "filesystem", "sync"] },
                "action": { "enum": ["baseline", "create", "update", "link", "delete"] },
                "record": { "type": "object" },
                "changes": { "type": "array", "items": { "type": "object" } }
            },
            "additionalProperties": true
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
            "type": "object", "required": ["entries", "records_checked", "head"],
            "properties": {
                "entries": { "type": "integer", "minimum": 0 },
                "records_checked": { "type": "integer", "minimum": 0 },
                "head": { "$ref": "#/components/schemas/AuditHead" }
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
                    "required": ["code", "message"],
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" }
                    }
                }
            }
        }
    }))
    .expect("static OpenAPI schemas are objects")
}

fn openapi_paths() -> JsonValue {
    let actor = json!({
        "name": "X-CR-Actor",
        "in": "header",
        "required": false,
        "schema": { "type": "string" },
        "description": "Audit identity override for this request."
    });
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
            "get": { "operationId": "getIdentity", "responses": ok("#/components/schemas/Identity") }
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
                "operationId": "createRecord", "parameters": [collection.clone(), actor.clone()],
                "requestBody": json_body("#/components/schemas/CreateRecordRequest"),
                "responses": created("#/components/schemas/Record")
            }
        },
        "/api/v1/collections/{collection}/records/{id}": {
            "get": { "operationId": "getRecord", "parameters": [collection.clone(), id.clone()], "responses": ok("#/components/schemas/Record") },
            "patch": {
                "operationId": "patchRecord", "parameters": [collection.clone(), id.clone(), actor.clone()],
                "requestBody": json_body("#/components/schemas/PatchRecordRequest"),
                "responses": ok("#/components/schemas/Record")
            },
            "delete": { "operationId": "deleteRecord", "parameters": [collection.clone(), id.clone(), actor.clone()], "responses": ok("#/components/schemas/DeleteResponse") }
        },
        "/api/v1/collections/{collection}/records/{id}/document": {
            "get": { "operationId": "getRecordDocument", "parameters": [collection.clone(), id.clone()], "responses": { "200": { "description": "Exact Markdown document", "content": { "text/markdown": { "schema": { "type": "string" } } } }, "404": error_response() } }
        },
        "/api/v1/collections/{collection}/records/{id}/fields/{field}": {
            "get": { "operationId": "getRecordField", "parameters": [collection.clone(), id.clone(), json!({ "name": "field", "in": "path", "required": true, "schema": { "type": "string" } })], "responses": ok("#/components/schemas/FieldResponse") }
        },
        "/api/v1/collections/{collection}/records/{id}/links": {
            "post": { "operationId": "linkRecord", "parameters": [collection, id, actor], "requestBody": json_body("#/components/schemas/LinkRequest"), "responses": ok("#/components/schemas/Record") }
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
        "/api/v1/save": { "post": { "operationId": "saveDirectEdits", "requestBody": json_body("#/components/schemas/SaveRequest"), "responses": ok("#/components/schemas/AuditEntries") } },
        "/api/v1/audit/log": { "get": { "operationId": "getAuditLog", "parameters": [
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
        "409": error_response(), "413": error_response(), "422": error_response(), "500": error_response()
    })
}

fn created(schema: &str) -> JsonValue {
    let mut responses = ok(schema);
    if let Some(object) = responses.as_object_mut() {
        if let Some(success) = object.remove("200") {
            object.insert("201".into(), success);
        }
    }
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

fn render_views_home(views: &[ViewDefinition]) -> Markup {
    page_layout(
        "Database views",
        html! {
            div class="mb-10 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between" {
                div {
                    p class="text-sm font-semibold uppercase tracking-[0.2em] text-indigo-600" { "cr database" }
                    h1 class="mt-2 text-3xl font-bold tracking-tight text-slate-950" { "Database views" }
                    p class="mt-2 max-w-2xl text-sm text-slate-600" {
                        "Browse every collection or open a saved, filtered view. All changes use the same validated and audited database operations as the CLI and REST API."
                    }
                }
                div class="flex items-center gap-4" {
                    a href="/audit" class="text-sm font-semibold text-indigo-700 hover:text-indigo-900" { "Audit log" }
                    a href="/openapi.json" class="text-sm font-semibold text-indigo-700 hover:text-indigo-900" { "OpenAPI ↗" }
                }
            }
            @if views.is_empty() {
                div class="rounded-2xl border border-dashed border-slate-300 bg-white p-10 text-center shadow-sm" {
                    h2 class="text-lg font-semibold text-slate-900" { "No collections yet" }
                    p class="mt-2 text-sm text-slate-600" {
                        "Create a record with the CLI, or add a saved view with "
                        code class="rounded bg-slate-100 px-1.5 py-1 text-xs" { "cr view create" }
                        "."
                    }
                }
            } @else {
                div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3" {
                    @for view in views {
                        a href=(format!("/{}", encode_segment(&view.name))) class="group rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition hover:-translate-y-0.5 hover:border-indigo-300 hover:shadow-md" {
                            div class="flex items-start justify-between gap-4" {
                                div {
                                    h2 class="text-lg font-semibold capitalize text-slate-950 group-hover:text-indigo-700" { (&view.title) }
                                    p class="mt-1 font-mono text-xs text-slate-500" { (&view.collection) }
                                }
                                span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600" {
                                    @if view.saved { "saved" } @else { "automatic" }
                                }
                                @if view.layout == ViewLayout::Kanban {
                                    span class="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700" { "kanban" }
                                }
                            }
                            @if view.filters.is_empty() && view.where_expr.is_empty() && view.filter_groups.is_empty() {
                                p class="mt-5 text-sm text-slate-500" { "All records" }
                            } @else {
                                div class="mt-5 flex flex-wrap gap-2" {
                                    @for filter in &view.filters {
                                        span class="rounded-lg bg-indigo-50 px-2 py-1 font-mono text-xs text-indigo-700" { (filter) }
                                    }
                                    @for expression in &view.where_expr {
                                        span class="rounded-lg bg-violet-50 px-2 py-1 font-mono text-xs text-violet-700" { (expression) }
                                    }
                                    @for group in &view.filter_groups {
                                        span class="rounded-lg bg-fuchsia-50 px-2 py-1 font-mono text-xs text-fuchsia-700" {
                                            (match group.match_mode { ViewPredicateMatch::All => "All: ", ViewPredicateMatch::Any => "Any: " })
                                            (group.expressions.join(" · "))
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

fn render_audit_view(page: &Page<AuditEntry>, query: &AuditViewQuery) -> Markup {
    let reset_url = "/audit";
    let first = if page.pagination.returned == 0 {
        0
    } else {
        page.pagination.offset + 1
    };
    let last = page.pagination.offset + page.pagination.returned;
    page_layout(
        "Audit log",
        html! {
            nav class="mb-6 flex items-center gap-2 text-sm text-slate-500" {
                a href="/" class="font-medium hover:text-indigo-700" { "Views" }
                span { "/" }
                span class="text-slate-900" { "Audit log" }
            }
            div class="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between" {
                div {
                    p class="text-sm font-semibold uppercase tracking-[0.2em] text-indigo-600" { "Tamper-evident journal" }
                    h1 class="mt-2 text-3xl font-bold tracking-tight text-slate-950" { "Global audit log" }
                    p class="mt-2 max-w-2xl text-sm text-slate-600" {
                        "Every accepted record mutation, newest first. Expand an event to inspect its field-level changes."
                    }
                }
                a href="/api/v1/audit/log" class="text-sm font-semibold text-indigo-700 hover:text-indigo-900" { "JSON API ↗" }
            }
            form method="get" action=(reset_url) class="mb-6 grid gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-[1fr_1fr_auto]" {
                label class="block" {
                    span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Collection" }
                    input type="text" name="collection" value=(query.collection.as_deref().unwrap_or("")) placeholder="deals" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Record ID" }
                    input type="text" name="id" value=(query.id.as_deref().unwrap_or("")) placeholder="acme-renewal" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                div class="flex items-end gap-2" {
                    button type="submit" class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700" { "Filter" }
                    a href=(reset_url) class="rounded-lg px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100" { "Reset" }
                }
            }
            (render_audit_entries(&page.data))
            div class="mt-4 flex flex-col gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between" {
                p class="text-slate-600" { "Showing events " (first) "–" (last) " newest first" }
                div class="flex items-center gap-2" {
                    @if let Some(offset) = page.pagination.previous_offset {
                        a href=(audit_page_url(query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Previous" }
                    }
                    @if let Some(offset) = page.pagination.next_offset {
                        a href=(audit_page_url(query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Next" }
                    }
                }
            }
        },
    )
}

fn render_audit_entries(entries: &[AuditEntry]) -> Markup {
    html! {
        div class="space-y-3" {
            @if entries.is_empty() {
                div class="rounded-2xl border border-dashed border-slate-300 bg-white p-10 text-center text-sm text-slate-500 shadow-sm" {
                    "No audit events match this filter."
                }
            } @else {
                @for entry in entries {
                    article id=(format!("event-{}", entry.payload.sequence)) class="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm" {
                        div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between" {
                            div class="min-w-0" {
                                div class="flex flex-wrap items-center gap-2" {
                                    span class="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-bold uppercase tracking-wide text-indigo-700" { (entry.payload.action.to_string()) }
                                    span class="font-mono text-xs text-slate-500" { "#" (entry.payload.sequence) }
                                    span class="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600" { (audit_source_label(&entry.payload.source)) }
                                }
                                a href=(audit_filter_url(&entry.payload.record.collection, &entry.payload.record.id)) class="mt-3 block truncate font-mono text-sm font-semibold text-slate-950 hover:text-indigo-700" {
                                    (entry.payload.record.reference())
                                }
                                p class="mt-1 text-xs text-slate-500" {
                                    "by " span class="font-medium text-slate-700" { (&entry.payload.actor) }
                                    " · " time datetime=(&entry.payload.timestamp) { (&entry.payload.timestamp) }
                                }
                                @if let Some(message) = &entry.payload.message {
                                    p class="mt-2 text-sm text-slate-600" { (message) }
                                }
                            }
                            span class="shrink-0 font-mono text-xs text-slate-400" { (short_hash(&entry.hash)) }
                        }
                        details class="mt-4 border-t border-slate-100 pt-4" {
                            summary class="cursor-pointer text-sm font-semibold text-indigo-700 hover:text-indigo-900" {
                                (entry.payload.changes.len()) " field-level " @if entry.payload.changes.len() == 1 { "change" } @else { "changes" }
                            }
                            div class="mt-3 space-y-3" {
                                @for change in &entry.payload.changes {
                                    div class="rounded-xl bg-slate-50 p-3" {
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
  const list = builder.querySelector('[data-filter-list]');
  const template = builder.querySelector('template[data-filter-template]');
  const addButton = builder.querySelector('[data-add-filter]');
  const maximum = Number(builder.dataset.maxFilters || '20');

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

fn render_view_records(
    view: &ViewDefinition,
    columns: &[String],
    page: &Page<Record>,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
) -> Markup {
    let new_url = format!("/{}/new", encode_segment(&view.name));
    let reset_url = format!("/{}", encode_segment(&view.name));
    let first = if page.pagination.returned == 0 {
        0
    } else {
        page.pagination.offset + 1
    };
    let last = page.pagination.offset + page.pagination.returned;
    let filter_fields = view_filter_fields(schema, columns);
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
    page_layout(
        &view.title,
        html! {
            nav class="mb-6 flex items-center gap-2 text-sm text-slate-500" {
                a href="/" class="font-medium hover:text-indigo-700" { "Views" }
                span { "/" }
                span class="text-slate-900" { (&view.title) }
            }
            div class="mb-6 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between" {
                div {
                    div class="flex flex-wrap items-center gap-3" {
                        h1 class="text-3xl font-bold capitalize tracking-tight text-slate-950" { (&view.title) }
                        span class="rounded-full bg-slate-200 px-2.5 py-1 text-xs font-medium text-slate-700" {
                            @if view.saved { "saved view" } @else { "automatic view" }
                        }
                        @if view.layout == ViewLayout::Kanban {
                            span class="rounded-full bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700" { "kanban" }
                        }
                    }
                    p class="mt-2 text-sm text-slate-600" {
                        "Collection " code class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-xs" { (&view.collection) }
                    }
                    @if !view.filters.is_empty() || !view.where_expr.is_empty() || !view.filter_groups.is_empty() {
                        div class="mt-3 flex flex-wrap gap-2" {
                            @for filter in &view.filters {
                                span class="rounded-lg bg-indigo-50 px-2 py-1 font-mono text-xs text-indigo-700" { (filter) }
                            }
                            @for expression in &view.where_expr {
                                span class="rounded-lg bg-violet-50 px-2 py-1 font-mono text-xs text-violet-700" { (expression) }
                            }
                            @for group in &view.filter_groups {
                                span class="rounded-lg bg-fuchsia-50 px-2 py-1 font-mono text-xs text-fuchsia-700" {
                                    (match group.match_mode { ViewPredicateMatch::All => "All: ", ViewPredicateMatch::Any => "Any: " })
                                    (group.expressions.join(" · "))
                                }
                            }
                        }
                    }
                }
                div class="flex flex-wrap items-center gap-2" {
                    (render_save_view_control(view, query, csrf_token))
                    a href=(new_url) class="inline-flex items-center justify-center rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700" {
                        "+ New record"
                    }
                }
            }
            @if let Some(notice) = query.notice.as_deref() {
                div role="status" class="mb-5 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800" { (notice) }
            }
            form method="get" action=(reset_url.clone()) data-filter-builder="true" data-max-filters=(MAX_VIEW_FILTERS) class="mb-5 space-y-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5" {
                label class="block" {
                    span class="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Search records" }
                    input type="search" name="q" value=(query.q.as_deref().unwrap_or("")) placeholder="Search paths, front matter, and Markdown…" class="w-full rounded-lg border border-slate-300 px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                div class="border-t border-slate-100 pt-4" {
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
                        button type="button" data-add-filter="true" class="rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:border-indigo-300 hover:text-indigo-700 disabled:cursor-not-allowed disabled:opacity-40" { "+ Add condition" }
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
                    a href=(reset_url) class="rounded-lg px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100" { "Clear all" }
                    button type="submit" class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700" { "Apply view" }
                }
            }
            script { (PreEscaped(FILTER_BUILDER_SCRIPT)) }
            @if view.layout == ViewLayout::Kanban {
                (render_kanban_board(view, columns, page, query, schema, csrf_token))
            } @else {
            div class="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-slate-200 text-left text-sm" {
                        thead class="bg-slate-50" {
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
                                    tr class="hover:bg-slate-50/80" {
                                        td class="whitespace-nowrap px-4 py-3 font-mono text-xs font-semibold" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="text-slate-900 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        }
                                        @for column in columns {
                                            td class="max-w-sm px-4 py-3 text-slate-700" {
                                                a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="line-clamp-2 hover:text-indigo-700 hover:underline" { (record_value(record, column)) }
                                            }
                                        }
                                        td class="whitespace-nowrap px-4 py-3 text-right" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="font-semibold text-indigo-700 hover:text-indigo-900" { "View" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                div class="flex flex-col gap-3 border-t border-slate-200 bg-slate-50 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between" {
                    p class="text-slate-600" {
                        "Showing " (first) "–" (last)
                        @if let Some(total) = page.pagination.total { " of " (total) }
                    }
                    div class="flex items-center gap-2" {
                        @if let Some(offset) = page.pagination.previous_offset {
                            a href=(view_page_url(view, query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Previous" }
                        }
                        @if let Some(offset) = page.pagination.next_offset {
                            a href=(view_page_url(view, query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Next" }
                        }
                    }
                }
            }
            }
        },
    )
}

fn render_save_view_control(view: &ViewDefinition, query: &ViewQuery, csrf_token: &str) -> Markup {
    let action = format!("/{}/save-view", encode_segment(&view.name));
    html! {
        details class="relative" {
            summary class="cursor-pointer list-none rounded-xl border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm hover:border-indigo-300 hover:text-indigo-700" {
                "Save as view"
            }
            div class="absolute right-0 z-20 mt-2 w-80 rounded-2xl border border-slate-200 bg-white p-4 shadow-xl" {
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
                    button type="submit" class="w-full rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white hover:bg-indigo-700" { "Save view" }
                }
            }
        }
    }
}

fn render_kanban_board(
    view: &ViewDefinition,
    columns: &[String],
    page: &Page<Record>,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
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
        div class="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm text-slate-600" {
            p {
                "Kanban grouped by " code class="rounded bg-slate-200 px-1.5 py-0.5 font-mono text-xs font-semibold text-slate-800" { (group_by) }
            }
            p { "Drag cards between lanes or use each card’s move control." }
        }
        div class="overflow-x-auto pb-3" {
            div data-kanban-board="true" class="flex min-w-max items-start gap-4" {
                @for lane in &lanes {
                    section
                        data-kanban-lane="true"
                        data-kanban-target=(kanban_target_json(&lane.target))
                        data-kanban-csrf=(csrf_token)
                        class="w-80 shrink-0 rounded-2xl border border-slate-200 bg-slate-200/70 p-3 transition-colors"
                    {
                        div class="mb-3 flex items-center justify-between gap-3 px-1" {
                            h2 class="font-semibold text-slate-900" { (&lane.label) }
                            span class="rounded-full bg-white px-2 py-0.5 text-xs font-bold text-slate-600 shadow-sm" { (lane.records.len()) }
                        }
                        div class="min-h-24 space-y-3" {
                            @if lane.records.is_empty() {
                                p class="rounded-xl border border-dashed border-slate-300 px-4 py-8 text-center text-xs text-slate-500" { "Drop cards here" }
                            }
                            @for record in &lane.records {
                                article
                                    draggable="true"
                                    data-kanban-card="true"
                                    data-move-url=(kanban_move_url(view, &record.id))
                                    class="cursor-grab rounded-xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-indigo-300 hover:shadow active:cursor-grabbing"
                                {
                                    div class="flex items-start justify-between gap-3" {
                                        a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="break-all font-mono text-sm font-bold text-slate-950 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        span aria-hidden="true" class="select-none text-slate-300" { "⠿" }
                                    }
                                    @if !card_columns.is_empty() {
                                        dl class="mt-3 space-y-2" {
                                            @for column in &card_columns {
                                                div {
                                                    dt class="text-[0.65rem] font-bold uppercase tracking-wide text-slate-400" { (column) }
                                                    dd class="mt-0.5 line-clamp-2 text-sm text-slate-700" { (record_value(record, column)) }
                                                }
                                            }
                                        }
                                    }
                                    form method="post" action=(kanban_move_url(view, &record.id)) class="mt-4 flex items-center gap-2 border-t border-slate-100 pt-3" {
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
                                        button type="submit" class="rounded-lg bg-slate-900 px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-700" { "Move" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        div class="mt-2 flex flex-col gap-3 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm shadow-sm sm:flex-row sm:items-center sm:justify-between" {
            p class="text-slate-600" {
                "Showing " (first) "–" (last)
                @if let Some(total) = page.pagination.total { " of " (total) }
            }
            div class="flex items-center gap-2" {
                @if let Some(offset) = page.pagination.previous_offset {
                    a href=(view_page_url(view, query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Previous" }
                }
                @if let Some(offset) = page.pagination.next_offset {
                    a href=(view_page_url(view, query, page.pagination.limit, offset)) class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 font-medium text-slate-700 hover:bg-slate-100" { "Next" }
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

  board.querySelectorAll('[data-kanban-card]').forEach((card) => {
    card.addEventListener('dragstart', () => {
      draggedCard = card;
      card.classList.add('opacity-50');
    });
    card.addEventListener('dragend', () => {
      draggedCard = null;
      card.classList.remove('opacity-50');
      board.querySelectorAll('[data-kanban-lane]').forEach((lane) => lane.classList.remove('ring-2', 'ring-indigo-400'));
    });
  });

  board.querySelectorAll('[data-kanban-lane]').forEach((lane) => {
    lane.addEventListener('dragover', (event) => {
      event.preventDefault();
      lane.classList.add('ring-2', 'ring-indigo-400');
    });
    lane.addEventListener('dragleave', () => lane.classList.remove('ring-2', 'ring-indigo-400'));
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
        div class=(if wide { "rounded-xl border border-slate-200 bg-slate-50 p-4 sm:col-span-2" } else { "rounded-xl border border-slate-200 bg-slate-50 p-4" }) {
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

fn render_record_form(
    view: &ViewDefinition,
    record: Option<&Record>,
    audit_entries: &[AuditEntry],
    schema: Option<&JsonValue>,
    csrf_token: &str,
    error: Option<&str>,
) -> Markup {
    let editing = record.is_some();
    let title = record
        .map(|record| format!("Edit {}", record.id))
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
        html! {
            nav class="mb-6 flex items-center gap-2 text-sm text-slate-500" {
                a href="/" class="font-medium hover:text-indigo-700" { "Views" }
                span { "/" }
                a href=(back.clone()) class="font-medium hover:text-indigo-700" { (&view.title) }
                span { "/" }
                span class="text-slate-900" { (&title) }
            }
            div class="mx-auto max-w-5xl" {
                div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                    h1 class="text-3xl font-bold tracking-tight text-slate-950" { (&title) }
                    @if editing {
                        a href="#audit-history" class="inline-flex items-center rounded-lg bg-indigo-50 px-3 py-2 text-sm font-semibold text-indigo-700 hover:bg-indigo-100" {
                            (audit_entries.len()) " audit " @if audit_entries.len() == 1 { "event" } @else { "events" } " ↓"
                        }
                    }
                }
                p class="mt-2 text-sm text-slate-600" {
                    @if structured {
                        "Edit typed fields generated from the collection schema. Saving validates the complete record and writes normal Markdown with YAML front matter."
                    } @else {
                        "This collection has no field schema yet, so front matter remains available as typed YAML."
                    }
                }
                @if let Some(error) = error {
                    div role="alert" class="mt-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" { (error) }
                }
                form method="post" action=(action) class="mt-6 space-y-6" {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    @if structured {
                        input type="hidden" name="_form_mode" value="structured";
                    }
                    section class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm" {
                        div class="mb-5 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" {
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
                            div class="grid gap-4 sm:grid-cols-2" {
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
                    section class="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm" {
                        div class="mb-3 flex items-center justify-between gap-3" {
                            div {
                                h2 class="text-lg font-bold text-slate-950" { "Notes" }
                                p class="mt-1 text-sm text-slate-500" { "Long-form context stored as the Markdown body." }
                            }
                            span class="rounded-md bg-slate-100 px-2 py-1 font-mono text-xs font-semibold text-slate-500" { "Markdown" }
                        }
                        textarea name="markdown" aria-label="Markdown notes" rows="12" class="w-full rounded-lg border border-slate-300 px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (markdown) }
                    }
                    div class="sticky bottom-4 z-10 flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur" {
                        a href=(back.clone()) class="rounded-lg px-3 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100" { "Cancel" }
                        button type="submit" class="rounded-xl bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700" {
                            @if editing { "Save changes" } @else { "Create record" }
                        }
                    }
                }
                @if let Some(record) = record {
                    section id="audit-history" class="mt-6 scroll-mt-6 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm" {
                        div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" {
                            div {
                                h2 class="text-xl font-bold text-slate-950" { "Audit history" }
                                p class="mt-1 text-sm text-slate-600" { "Newest accepted changes to this record, with actor and source attribution." }
                            }
                            a href=(audit_filter_url(&view.collection, &record.id)) class="text-sm font-semibold text-indigo-700 hover:text-indigo-900" { "View complete history →" }
                        }
                        (render_audit_entries(audit_entries))
                    }
                    form method="post" action=(format!("/{}/records/{}/delete", encode_segment(&view.name), encode_segment(&record.id))) class="mt-6 rounded-2xl border border-red-200 bg-red-50 p-5" {
                        input type="hidden" name="_csrf" value=(csrf_token);
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
        },
    )
}

fn page_layout(title: &str, content: Markup) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" class="h-full bg-slate-100" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta name="color-scheme" content="light";
                title { (title) " · cr" }
                script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4" {}
            }
            body class="min-h-full text-slate-900 antialiased" {
                header class="border-b border-slate-200 bg-white" {
                    div class="mx-auto flex w-full max-w-7xl items-center justify-between px-4 py-3 sm:px-6 lg:px-8" {
                        a href="/" class="font-bold tracking-tight text-slate-950 hover:text-indigo-700" { "cr" }
                        nav aria-label="Primary" class="flex items-center gap-4 text-sm font-semibold" {
                            a href="/" class="text-slate-600 hover:text-indigo-700" { "Views" }
                            a href="/audit" class="text-slate-600 hover:text-indigo-700" { "Audit log" }
                            a href="/openapi.json" class="text-slate-600 hover:text-indigo-700" { "OpenAPI" }
                        }
                    }
                }
                main class="mx-auto w-full max-w-7xl px-4 py-8 sm:px-6 lg:px-8" { (content) }
                footer class="mx-auto w-full max-w-7xl px-4 pb-8 text-xs text-slate-500 sm:px-6 lg:px-8" {
                    "Server-rendered by cr · records remain Markdown with YAML front matter"
                }
            }
        }
    }
}

fn view_columns(
    view: &ViewDefinition,
    records: &[Record],
    schema: Option<&JsonValue>,
) -> Vec<String> {
    if !view.columns.is_empty() {
        return view.columns.clone();
    }
    let mut columns = BTreeSet::new();
    if let Some(properties) = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(JsonValue::as_object)
    {
        columns.extend(properties.keys().cloned());
    }
    for record in records {
        columns.extend(record.attributes.keys().filter_map(|key| match key {
            YamlValue::String(key) => Some(key.clone()),
            _ => None,
        }));
    }
    columns.into_iter().take(12).collect()
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
                        .map_err(ApiError::from_database),
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
        FilterExpression::from_str(&expression).map_err(ApiError::from_database)?;
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
        .map_err(ApiError::from_database)
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
            ))
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
        if let YamlValue::String(key) = key {
            if properties.contains_key(key) {
                return Err(ApiError::bad_request(
                    "invalid_form",
                    format!("declared attribute '{key}' cannot be overridden in additional YAML"),
                ));
            }
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
        .map_err(|error| anyhow::anyhow!("could not generate form security token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
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
    let status = error.status;
    let markup = page_layout(
        "Error",
        html! {
            div class="mx-auto max-w-2xl rounded-2xl border border-red-200 bg-white p-8 shadow-sm" {
                p class="text-sm font-semibold uppercase tracking-wide text-red-600" { (status.as_u16()) " " (status.canonical_reason().unwrap_or("Error")) }
                h1 class="mt-2 text-2xl font-bold text-slate-950" { "Request could not be completed" }
                p class="mt-3 text-sm text-slate-700" { (error.message) }
                a href="/" class="mt-6 inline-flex rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700" { "Back to views" }
            }
        },
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
    let database = state.database.clone();
    let Some(actor) = headers.get(ACTOR_HEADER) else {
        return Ok(database);
    };
    let actor = actor
        .to_str()
        .map_err(|_| ApiError::bad_request("invalid_actor", "X-CR-Actor must be valid UTF-8"))?;
    database.with_actor(actor).map_err(ApiError::from_database)
}

async fn run_database<T, F>(state: &AppState, headers: &HeaderMap, operation: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce(&Database) -> Result<T> + Send + 'static,
{
    let database = request_database(state, headers)?;
    tokio::task::spawn_blocking(move || operation(&database))
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("database task failed: {error}"),
            )
        })?
        .map_err(ApiError::from_database)
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
        .map(|filter| filter.parse().map_err(ApiError::from_database))
        .collect()
}

fn parse_filter_expressions(expressions: Vec<String>) -> ApiResult<Vec<FilterExpression>> {
    expressions
        .into_iter()
        .map(|expression| expression.parse().map_err(ApiError::from_database))
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
