use std::{collections::BTreeSet, io::Write, net::SocketAddr, str::FromStr, sync::Arc};

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
    audit::AuditChange, Assignment, AuditEntry, AuditSource, CollectionModel, Database, Record,
    SearchQuery, SearchTarget, ViewDefinition, ViewLayout,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const DEFAULT_MAX_PAGE_SIZE: usize = 200;
const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE_OFFSET: usize = 1_000_000;
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
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ViewQuery {
    q: Option<String>,
    filter_field: Option<String>,
    filter_value: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    notice: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditViewQuery {
    collection: Option<String>,
    id: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlDocumentForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    id: Option<String>,
    front_matter: String,
    markdown: String,
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
        if lower.contains("already exists") {
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
        let query: ViewQuery = parse_query(raw)?;
        let ad_hoc_filter = match (&query.filter_field, &query.filter_value) {
            (None, None) => None,
            (Some(field), Some(value)) if field.is_empty() && value.is_empty() => None,
            (Some(field), Some(_)) if field.is_empty() => {
                return Err(ApiError::bad_request(
                    "invalid_filter",
                    "filter_field cannot be empty when filter_value is provided",
                ))
            }
            (Some(field), Some(value)) => Some(format!("{field}={value}")),
            _ => {
                return Err(ApiError::bad_request(
                    "invalid_filter",
                    "filter_field and filter_value must be provided together",
                ))
            }
        };
        let query_for_database = query.clone();
        let requested_view = view_name.clone();
        let (view, records, schema) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let mut filters = view
                .filters
                .iter()
                .map(|filter| Assignment::from_str(filter))
                .collect::<Result<Vec<_>>>()?;
            if let Some(filter) = ad_hoc_filter {
                filters.push(Assignment::from_str(&filter)?);
            }
            let records = match query_for_database.q.as_deref().filter(|q| !q.is_empty()) {
                Some(pattern) => {
                    let search = SearchQuery::new(pattern, SearchTarget::Document, false, true)?;
                    database.search(Some(&view.collection), &filters, &search)?
                }
                None => database.list(&view.collection, &filters)?,
            };
            let schema = database
                .collection_models()?
                .into_iter()
                .find(|model| model.name == view.collection)
                .and_then(|model| model.schema);
            Ok((view, records, schema))
        })
        .await?;

        let columns = view_columns(&view, &records, schema.as_ref());
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

async fn new_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(view_name): Path<String>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let requested_view = view_name.clone();
        let view = run_database(&state, &headers, move |database| {
            database.view(&requested_view)
        })
        .await?;
        Ok(render_record_form(
            &view,
            None,
            &[],
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
        let (view, record, audit_entries) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let record = database.get(&view.collection, &requested_id)?;
            let audit_entries = database.audit_recent(
                DEFAULT_PAGE_SIZE,
                Some(&view.collection),
                Some(&requested_id),
            )?;
            Ok((view, record, audit_entries))
        })
        .await?;
        Ok(render_record_form(
            &view,
            Some(&record),
            &audit_entries,
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
        let form: HtmlDocumentForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let id = form
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ApiError::bad_request("invalid_form", "record ID cannot be empty"))?;
        let attributes = parse_front_matter(&form.front_matter)?;
        let requested_view = view_name.clone();
        let id = id.to_owned();
        run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            database.create_record(&view.collection, &id, attributes, &form.markdown)
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
        let form: HtmlDocumentForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        if form.id.is_some() {
            return Err(ApiError::bad_request(
                "invalid_form",
                "record ID cannot be changed",
            ));
        }
        let attributes = parse_front_matter(&form.front_matter)?;
        let requested_view = view_name.clone();
        run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            database.replace(&view.collection, &id, attributes, &form.markdown)
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
    let records = run_database(&state, &headers, move |database| {
        database.list(&collection, &filters)
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
        database.search(collection.as_deref(), &filters, &query)
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
                            @if view.filters.is_empty() {
                                p class="mt-5 text-sm text-slate-500" { "All records" }
                            } @else {
                                div class="mt-5 flex flex-wrap gap-2" {
                                    @for filter in &view.filters {
                                        span class="rounded-lg bg-indigo-50 px-2 py-1 font-mono text-xs text-indigo-700" { (filter) }
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
                    @if !view.filters.is_empty() {
                        div class="mt-3 flex flex-wrap gap-2" {
                            @for filter in &view.filters {
                                span class="rounded-lg bg-indigo-50 px-2 py-1 font-mono text-xs text-indigo-700" { (filter) }
                            }
                        }
                    }
                }
                a href=(new_url) class="inline-flex items-center justify-center rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700" {
                    "+ New record"
                }
            }
            @if let Some(notice) = query.notice.as_deref() {
                div role="status" class="mb-5 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800" { (notice) }
            }
            form method="get" action=(reset_url.clone()) class="mb-5 grid gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm lg:grid-cols-[2fr_1fr_1fr_auto]" {
                label class="block" {
                    span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Search" }
                    input type="search" name="q" value=(query.q.as_deref().unwrap_or("")) placeholder="Path, front matter, or Markdown" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "Exact field" }
                    input type="text" name="filter_field" value=(query.filter_field.as_deref().unwrap_or("")) placeholder="status" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-slate-500" { "YAML value" }
                    input type="text" name="filter_value" value=(query.filter_value.as_deref().unwrap_or("")) placeholder="open" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                div class="flex items-end gap-2" {
                    button type="submit" class="rounded-lg bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-700" { "Apply" }
                    a href=(reset_url) class="rounded-lg px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100" { "Reset" }
                }
            }
            @if view.layout == ViewLayout::Kanban {
                (render_kanban_board(view, columns, page, query, schema, csrf_token))
            } @else {
            div class="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-slate-200 text-left text-sm" {
                        thead class="bg-slate-50" {
                            tr {
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-slate-700" { "ID" }
                                @for column in columns {
                                    th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-slate-700" { (column) }
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

fn render_record_form(
    view: &ViewDefinition,
    record: Option<&Record>,
    audit_entries: &[AuditEntry],
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
    let front_matter = record
        .map(|record| yaml_serde::to_string(&record.attributes).unwrap_or_default())
        .unwrap_or_else(|| "{}\n".to_owned());
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
            div class="mx-auto max-w-4xl" {
                div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                    h1 class="text-3xl font-bold tracking-tight text-slate-950" { (&title) }
                    @if editing {
                        a href="#audit-history" class="inline-flex items-center rounded-lg bg-indigo-50 px-3 py-2 text-sm font-semibold text-indigo-700 hover:bg-indigo-100" {
                            (audit_entries.len()) " audit " @if audit_entries.len() == 1 { "event" } @else { "events" } " ↓"
                        }
                    }
                }
                p class="mt-2 text-sm text-slate-600" { "YAML values retain their types. Saving validates the complete front matter against the collection schema." }
                @if let Some(error) = error {
                    div role="alert" class="mt-5 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" { (error) }
                }
                form method="post" action=(action) class="mt-6 space-y-5 rounded-2xl border border-slate-200 bg-white p-6 shadow-sm" {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    @if !editing {
                        label class="block" {
                            span class="mb-1.5 block text-sm font-semibold text-slate-800" { "Record ID" }
                            input type="text" name="id" required pattern="[^/\\]+" placeholder="acme-renewal" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                        }
                    }
                    label class="block" {
                        span class="mb-1.5 block text-sm font-semibold text-slate-800" { "Front matter" }
                        textarea name="front_matter" rows="14" spellcheck="false" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (front_matter) }
                    }
                    label class="block" {
                        span class="mb-1.5 block text-sm font-semibold text-slate-800" { "Markdown" }
                        textarea name="markdown" rows="12" class="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (markdown) }
                    }
                    div class="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-5" {
                        a href=(back.clone()) class="rounded-lg px-3 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-100" { "Cancel" }
                        button type="submit" class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700" {
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

fn view_page_url(view: &ViewDefinition, query: &ViewQuery, limit: usize, offset: usize) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    if let Some(q) = query.q.as_deref().filter(|value| !value.is_empty()) {
        serializer.append_pair("q", q);
    }
    if let (Some(field), Some(value)) = (&query.filter_field, &query.filter_value) {
        serializer.append_pair("filter_field", field);
        serializer.append_pair("filter_value", value);
    }
    serializer.append_pair("limit", &limit.to_string());
    serializer.append_pair("offset", &offset.to_string());
    format!("/{}?{}", encode_segment(&view.name), serializer.finish())
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
