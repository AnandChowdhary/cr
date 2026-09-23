use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path as FilePath, PathBuf},
    str::FromStr,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::SystemTime,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result, anyhow, bail};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, RawForm, RawQuery, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use percent_encoding::{
    AsciiSet, CONTROLS, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value as JsonValue, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use yaml_serde::{Mapping, Value as YamlValue};

use crate::{
    AccessAction, AccessIdentity, AccessResource, AgentEvidence, Aggregation, Assignment,
    Attribution, AttributionOverrides, AuditAgent, AuditAuthorization, AuditEntry, AuditFilter,
    AuditIntent, AuditIntentPart, AuditSource, Backlink, COLLECTION_ACCESS_EXTENSION, CheckScope,
    CheckSummary, CollectionModel, CollectionPresentation, Database, DomainError, Filter,
    FilterExpression, FilterOperator, Finding, MAX_TRAVERSAL_DEPTH, Projection,
    RECORD_ACCESS_FIELD, Record, RecordActivity, RecordPrecondition, SchemaReview, SchemaViolation,
    SearchQuery, SearchTarget, SortDirection, USERS_COLLECTION, User, UserKind, UserStatus,
    ViewDefinition, ViewFilterGroup, ViewLayout, ViewPredicateMatch, audit::AuditChange,
    sort_by_record_field, sort_records_by_field,
};

const DEFAULT_PAGE_SIZE: usize = 50;
const DEFAULT_MAX_PAGE_SIZE: usize = 200;
const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PAGE_OFFSET: usize = 1_000_000;
const MAX_VIEW_FILTERS: usize = 20;
const MAX_VIEW_COLUMNS: usize = 50;
/// A browser page is for inspection, not bulk file transfer. Bounding previews
/// keeps a click on a log or disk image from turning into an enormous HTML
/// response while still making ordinary source and configuration files useful.
const MAX_FILE_PREVIEW_BYTES: usize = 1024 * 1024;
const MAX_BINARY_PREVIEW_BYTES: usize = 4 * 1024;
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

/// One pinned location, resolved for the sidebar.
#[derive(Clone, Debug)]
struct UiPin {
    /// The stored spelling, which is what unpinning submits back.
    stored: String,
    label: String,
    /// The absolute location, shown as the link's tooltip.
    location: String,
    /// The browse URL. Built from the canonical location when the pin
    /// resolves, because that is what the browse page addresses itself by, so
    /// the link and the page agree on which sidebar entry is active.
    href: String,
    canonical: Option<PathBuf>,
    kind: UiPinKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiPinKind {
    Directory,
    File,
    /// Pinned, but nothing is there now. Still listed: a log directory that
    /// has not been created yet, or a mount that is down, is exactly when the
    /// owner needs to see that the pin exists.
    Missing,
}

#[derive(Clone, Debug)]
struct UiContext {
    operator: AccessIdentity,
    selected: String,
    selected_name: String,
    selected_status: UserStatus,
    can_view_global_audit: bool,
    /// Whether this perspective may read the reserved `users` collection, and
    /// therefore whether the internal navigation section is offered at all.
    can_read_users: bool,
    /// Whole-filesystem access is deliberately narrower than policy access:
    /// only a database owner may use the browser, and the route is absent when
    /// RBAC is disabled because there is then no authenticated administrator.
    can_browse_files: bool,
    /// Pinned filesystem locations, loaded only for a perspective that may
    /// browse files.
    pins: Vec<UiPin>,
    /// Why the pins could not be loaded — a hand-edited `.cr/pins.yaml` that no
    /// longer parses, say. The sidebar says so instead of every page failing,
    /// because a typo in a navigation preference must not lock the owner out
    /// of the UI they would use to see it.
    pins_error: Option<String>,
    users: Vec<UiUser>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserEntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

impl BrowserEntryKind {
    fn label(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }

    fn icon(self) -> &'static str {
        match self {
            Self::Directory => DIRECTORY_ICON,
            Self::File => FILE_ICON,
            Self::Symlink => SYMLINK_ICON,
            Self::Other => OTHER_FILE_ICON,
        }
    }

    fn sort_rank(self) -> u8 {
        match self {
            Self::Directory => 0,
            Self::File => 1,
            Self::Symlink => 2,
            Self::Other => 3,
        }
    }
}

#[derive(Debug)]
struct BrowserEntry {
    name: String,
    href: Option<String>,
    kind: BrowserEntryKind,
    size: Option<u64>,
    /// Birth time, which not every filesystem records.
    created: Option<SystemTime>,
    modified: Option<SystemTime>,
}

/// A directory-listing column the reader can order by.
///
/// Type is not one of them: directories are always listed first, then files,
/// then everything else, so ordering by type could only ever reproduce the
/// grouping every listing already has.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum BrowseSortField {
    Name,
    Size,
    Created,
    Updated,
}

impl BrowseSortField {
    fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Size => "size",
            Self::Created => "created",
            Self::Updated => "updated",
        }
    }
}

/// How a directory listing is ordered within its kind groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BrowseSort {
    field: BrowseSortField,
    direction: ViewSortDirection,
}

impl BrowseSort {
    /// Newest first, the order a view table opens in, and for the same reason:
    /// a directory is read to answer "what changed?" at least as often as
    /// "what is here?".
    const DEFAULT: Self = Self {
        field: BrowseSortField::Created,
        direction: ViewSortDirection::Desc,
    };

    fn requested(query: &BrowseQuery) -> Self {
        match (query.sort_field, query.sort_direction) {
            (None, None) => Self::DEFAULT,
            (field, direction) => Self {
                field: field.unwrap_or(Self::DEFAULT.field),
                direction: direction.unwrap_or_default(),
            },
        }
    }

    /// `href`, a browse link, carrying this order along.
    ///
    /// The default order adds nothing, so a link to a directory in the default
    /// order is its canonical address — the one a pin stores and the sidebar
    /// compares against.
    fn carry(self, href: &str) -> String {
        if self == Self::DEFAULT {
            return href.to_owned();
        }
        let separator = if href.contains('?') { '&' } else { '?' };
        let direction = match self.direction {
            ViewSortDirection::Asc => "asc",
            ViewSortDirection::Desc => "desc",
        };
        format!(
            "{href}{separator}sort_field={}&sort_direction={direction}",
            self.field.as_str()
        )
    }

    /// The order a column heading switches to: that column ascending, or
    /// descending when it already is ascending — the rule view tables use.
    fn toggled(self, field: BrowseSortField) -> Self {
        let direction = if self.field == field && self.direction == ViewSortDirection::Asc {
            ViewSortDirection::Desc
        } else {
            ViewSortDirection::Asc
        };
        Self { field, direction }
    }

    fn indicator(self, field: BrowseSortField) -> &'static str {
        match (self.field == field, self.direction) {
            (false, _) => "↕",
            (true, ViewSortDirection::Asc) => "↑",
            (true, ViewSortDirection::Desc) => "↓",
        }
    }

    fn aria_state(self, field: BrowseSortField) -> &'static str {
        match (self.field == field, self.direction) {
            (false, _) => "none",
            (true, ViewSortDirection::Asc) => "ascending",
            (true, ViewSortDirection::Desc) => "descending",
        }
    }

    /// Directories, then files, then links and the rest; within each group
    /// this order, with values a filesystem does not record last in either
    /// direction and the name as the deterministic tie-breaker.
    fn apply(self, entries: &mut [BrowserEntry]) {
        fn present_first<T: Ord>(
            left: Option<T>,
            right: Option<T>,
            direction: ViewSortDirection,
        ) -> std::cmp::Ordering {
            match (left, right) {
                (Some(left), Some(right)) => match direction {
                    ViewSortDirection::Asc => left.cmp(&right),
                    ViewSortDirection::Desc => right.cmp(&left),
                },
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        }
        let by_name = |left: &BrowserEntry, right: &BrowserEntry| {
            left.name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.name.cmp(&right.name))
        };
        entries.sort_by(|left, right| {
            let chosen = match self.field {
                BrowseSortField::Name => match self.direction {
                    ViewSortDirection::Asc => by_name(left, right),
                    ViewSortDirection::Desc => by_name(right, left),
                },
                BrowseSortField::Size => present_first(left.size, right.size, self.direction),
                BrowseSortField::Created => {
                    present_first(left.created, right.created, self.direction)
                }
                BrowseSortField::Updated => {
                    present_first(left.modified, right.modified, self.direction)
                }
            };
            left.kind
                .sort_rank()
                .cmp(&right.kind.sort_rank())
                .then(chosen)
                .then_with(|| by_name(left, right))
        });
    }
}

#[derive(Debug)]
struct BrowserCrumb {
    label: String,
    href: String,
}

#[derive(Debug)]
enum BrowserFileContents {
    Text(String),
    Binary(String),
}

#[derive(Debug)]
struct BrowserFile {
    contents: BrowserFileContents,
    bytes_shown: usize,
    total_bytes: u64,
    truncated: bool,
}

#[derive(Debug)]
enum BrowserItem {
    Directory(Vec<BrowserEntry>),
    File(BrowserFile),
    Other,
}

#[derive(Debug)]
struct BrowserPage {
    location: PathBuf,
    parent: Option<PathBuf>,
    crumbs: Vec<BrowserCrumb>,
    item: BrowserItem,
}

/// A document that explains its directory — a README, or an agent skill's
/// `SKILL.md` — previewed beneath the listing the way a code host shows a
/// README.
///
/// The preview is the same bounded, escaped `BrowserFile` that opening the
/// file produces, so a document is never read or rendered by a looser rule
/// than the file itself. One that cannot be previewed keeps its public error
/// message rather than failing the listing: the directory is what was asked
/// for, and it is still readable.
#[derive(Debug)]
struct BrowserDocument {
    /// The element id the section renders with, so `#readme` and `#skill` are
    /// stable links to the section itself.
    anchor: &'static str,
    name: String,
    href: Option<String>,
    preview: Result<BrowserFile, String>,
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

/// One record that links to another, with the relations holding the reference.
#[derive(Debug, Serialize)]
struct ApiBacklink {
    collection: String,
    id: String,
    path: String,
    version: String,
    relations: Vec<String>,
    front_matter: JsonValue,
}

impl TryFrom<Backlink> for ApiBacklink {
    type Error = ApiError;

    fn try_from(backlink: Backlink) -> ApiResult<Self> {
        let record = backlink.record;
        Ok(Self {
            collection: record.collection,
            id: record.id,
            path: display_path(&record.path),
            version: record.version,
            relations: backlink.relations,
            front_matter: json_front_matter(record.attributes)?,
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
struct SchemaChangeQuery {
    #[serde(default)]
    preview: bool,
    #[serde(default)]
    allow_violations: bool,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PageQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowseQuery {
    path: Option<String>,
    sort_field: Option<BrowseSortField>,
    sort_direction: Option<ViewSortDirection>,
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
struct BacklinkQuery {
    from: Option<String>,
    relation: Option<String>,
    #[serde(default, rename = "where")]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    filter: Option<String>,
    #[serde(default)]
    select: Vec<String>,
    sort: Option<String>,
    #[serde(default)]
    direction: SortDirectionParameter,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraverseQuery {
    #[serde(default)]
    relation: Vec<String>,
    depth: Option<usize>,
    #[serde(default)]
    expand: bool,
    #[serde(default)]
    select: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CountQuery {
    #[serde(default, rename = "where")]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    filter: Option<String>,
    by: Option<String>,
    #[serde(default)]
    sum: Vec<String>,
    #[serde(default)]
    avg: Vec<String>,
    #[serde(default)]
    min: Vec<String>,
    #[serde(default)]
    max: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRecordQuery {
    #[serde(default)]
    select: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default, rename = "where")]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    filter: Option<String>,
    #[serde(default)]
    select: Vec<String>,
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
    /// The record this page continues after, and the one it ends before.
    ///
    /// Views open newest-first, where an offset is the wrong address: creating
    /// a record shifts every later row down one, so a reader paging by offset
    /// sees a row twice. Naming the record a page continues from survives
    /// concurrent writes. `offset` remains accepted so links shared before
    /// cursors existed still resolve.
    after: Option<String>,
    before: Option<String>,
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

/// A view definition's own predicates, parsed once.
///
/// This is the part of "which records does this view show" that the definition
/// decides, before a search or an ad hoc filter narrows it further, and the view
/// page and the view index both ask it so that the count beside a view on the
/// index is the count on the view.
#[derive(Debug)]
struct ViewPredicates {
    /// Equalities, which the database can apply while it lists.
    assignments: Vec<Assignment>,
    expressions: Vec<FilterExpression>,
    groups: Vec<(ViewPredicateMatch, Vec<FilterExpression>)>,
}

impl ViewPredicates {
    fn parse(view: &ViewDefinition) -> Result<Self> {
        let expressions = |expressions: &[String]| {
            expressions
                .iter()
                .map(|expression| FilterExpression::from_str(expression))
                .collect::<Result<Vec<_>>>()
        };
        Ok(Self {
            assignments: view
                .filters
                .iter()
                .map(|filter| Assignment::from_str(filter))
                .collect::<Result<Vec<_>>>()?,
            expressions: expressions(&view.where_expr)?,
            groups: view
                .filter_groups
                .iter()
                .map(|group| Ok((group.match_mode, expressions(&group.expressions)?)))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn matches(&self, attributes: &Mapping) -> bool {
        self.assignments
            .iter()
            .all(|assignment| assignment.matches(attributes))
            && self
                .expressions
                .iter()
                .all(|expression| expression.matches(attributes))
            && self.groups.iter().all(|(match_mode, expressions)| {
                saved_filter_group_matches(*match_mode, expressions, attributes)
            })
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

/// What the view index is asked for.
///
/// Unknown parameters are ignored rather than refused, unlike on the other
/// pages: this is the page a server's address opens, and a stray parameter on a
/// bookmark must not turn it into an error.
#[derive(Clone, Debug, Default, Deserialize)]
struct ViewsHomeQuery {
    #[serde(default)]
    summary: ViewIndexSummary,
}

/// Whether the view index document counts the records itself.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ViewIndexSummary {
    /// The rows at once, and their numbers when the page asks for the region.
    #[default]
    Deferred,
    /// The numbers in the document, for a reader whose browser will not ask.
    Inline,
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

/// One submitted record form, exactly as the browser sent it.
///
/// Every text field is the submitted string and not a value parsed out of it,
/// which is what lets a refused submission be answered with the user's own text:
/// re-rendering a reparsed round trip would quietly normalise `1.50` to `1.5`,
/// reorder a YAML mapping, and drop a comment somebody wrote in the front matter.
#[derive(Clone, Debug)]
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
    /// What the browser sent for this field, verbatim, when the form is being
    /// re-rendered after a refusal; `None` on a first render, which is the only
    /// time `value` is what the controls should show. A field with no submitted
    /// values is `Some(empty)` rather than `None`: a checkbox group with nothing
    /// ticked sends nothing, and coming back with the stored list ticked again
    /// would silently undo what the user did.
    submitted: Option<Vec<String>>,
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
struct HtmlPinForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    path: String,
    /// The browse location to return to, which is not always `path`: unpinning
    /// submits the stored spelling, which may be relative to the database.
    from: String,
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
    filter: Option<String>,
    #[serde(default)]
    select: Vec<String>,
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
    /// The submitted field this failure is about, when it is about one.
    ///
    /// Only the HTML form re-render reads it, to show the message beside the
    /// control the value was typed into instead of only at the top of the page.
    /// It is a hint about presentation and never about classification: `status`
    /// and `code` decide the answer, and a failure that names no field is
    /// answered exactly as it was before this field existed. The JSON envelope
    /// deliberately ignores it — giving the API a field-level error shape is a
    /// contract of its own, not a side effect of improving a form.
    field: Option<String>,
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
            field: None,
        }
    }

    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// Record which submitted field this failure is about. Called where the
    /// field is known — the parser that rejected a value, or the one route that
    /// can tell a taken record ID from any other conflict — because that is the
    /// only place that knows, and nothing downstream can work it back out of a
    /// sentence.
    fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
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
            field: None,
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
            field: None,
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
    // Every request is derived from this one database, so they all resume the
    // same verified journal rather than each re-hashing it from the first
    // event. The startup check below is the walk that fills it.
    let database = database.with_journal_cache();
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
        // Static before dynamic: these are internal read-only pages, not views
        // served by the `/{view}` route.
        .route("/users", get(users_view))
        .route("/browse", get(browse_view))
        .route("/browse/pin", post(pin_location_form))
        .route("/browse/unpin", post(unpin_location_form))
        .route("/{view}", get(view_records))
        .route("/{view}/save-view", post(save_view_form))
        .route("/{view}/new", get(new_record_form))
        .route("/{view}/records", post(create_record_form))
        .route(
            "/{view}/records/{id}",
            get(edit_record_form).post(update_record_form),
        )
        .route("/{view}/records/{id}/move", post(move_kanban_card))
        // One path, both methods: `GET` renders the confirmation and `POST`
        // performs the deletion, which keeps the destructive request's contract
        // exactly as it was while making the question that precedes it something
        // the server asks rather than something a script does.
        .route(
            "/{view}/records/{id}/delete",
            get(confirm_delete_record).post(delete_record_form),
        )
        .nest(
            "/api/v1",
            Router::new()
                .route("/identity", get(identity))
                .route("/collections", get(collections))
                .route("/collections/{collection}/count", get(count_records))
                .route(
                    "/collections/{collection}/schema",
                    get(get_schema).put(put_schema).delete(delete_schema),
                )
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
                .route(
                    "/collections/{collection}/records/{id}/links/{relation}/{target_collection}/{target_id}",
                    delete(unlink_record),
                )
                .route(
                    "/collections/{collection}/records/{id}/backlinks",
                    get(list_backlinks),
                )
                .route(
                    "/collections/{collection}/records/{id}/traverse",
                    get(traverse_record),
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
        // Outside the authorization layer, for the same reason `/health` is: it
        // carries no database data, only bytes that are already in the binary
        // any caller is talking to. It also cannot be inside it. A browser
        // cannot attach a bearer header to a `<script src>`, so with
        // `CR_API_TOKEN` set an authenticated asset route would leave every
        // page requesting a script it is not allowed to fetch.
        .route("/static/{file}", get(static_asset))
        .merge(protected)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(DefaultBodyLimit::max(config.max_body_bytes))
        .layer(middleware::from_fn(request_context))
        .with_state(state))
}

pub async fn serve(database: Database, config: ServerConfig) -> Result<()> {
    let bind = config.bind;
    // Given here rather than left to `router`, so the warm-up below fills the
    // cache every request will read.
    let database = database.with_journal_cache();
    let journal = database.clone();
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
    // Verify the journal now, while nobody is waiting for it, so the first
    // page finds it verified instead of walking it. A request that arrives
    // sooner waits on this walk rather than starting its own. A failure is
    // left to the request that needs the journal, which walks it again and
    // reports why, exactly as it would have without this.
    tokio::task::spawn_blocking(move || {
        let _ = journal.audit().record_states();
    });
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
        // Appended rather than inserted: an HTML answer has already named the
        // headers its representation depends on (see `HTML_VARY`), and an
        // `insert` here would delete that list on its way past. A response
        // whose body depends on a header no cache was told about is a
        // cache-poisoning bug, and this layer sees every route, so it is the
        // one place where clobbering would be silent.
        vary_on(response.headers_mut(), "Cookie");
    }
    response
}

/// Declare that a response body depends on the named request header, without
/// disturbing the names something else already declared.
///
/// `Vary` is a list, two layers have entries in it — `html_response` names the
/// htmx headers that choose between a document and a fragment, the
/// authorization layer above names `Cookie` when a perspective can change what
/// a principal may see — and neither runs knowing whether the other did. The
/// membership test is what keeps the append idempotent: `HeaderMap::append`
/// would otherwise emit `Vary: Cookie` twice for an HTML answer under access
/// control, which is legal and useless.
fn vary_on(headers: &mut HeaderMap, name: &'static str) {
    let listed = headers.get_all(header::VARY).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|listed| listed.trim().eq_ignore_ascii_case(name))
        })
    });
    if !listed {
        headers.append(header::VARY, HeaderValue::from_static(name));
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

/// The UI's progressive-enhancement script, compiled into the binary.
///
/// It used to be three string constants emitted as `<script>` blocks in the
/// body of every page that needed them, which meant the browser re-parsed them
/// on every navigation, no page could ever declare `script-src 'self'`, and
/// the JavaScript sat in a Rust file where no editor or linter understood it.
/// Embedding keeps the single-binary, no-build-step, works-offline property
/// that ruled out a CDN in the first place.
const UI_SCRIPT: &str = include_str!("static/cr.js");

/// The asset's served file name, derived from the bytes it serves.
///
/// A digest rather than a version number because a number is a promise a
/// future edit has to remember to keep: with a content hash, changing the
/// script changes its URL, which is what makes the year-long `immutable`
/// cache below safe to promise. Eight bytes is far more than enough to
/// distinguish the handful of revisions a cache will ever hold at once.
static UI_SCRIPT_NAME: LazyLock<String> =
    LazyLock::new(|| format!("cr-{}.js", hexadecimal(&Sha256::digest(UI_SCRIPT)[..8])));

/// The absolute path rendered pages link, as `/static/cr-<digest>.js`.
static UI_SCRIPT_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/{}", UI_SCRIPT_NAME.as_str()));

/// htmx, vendored into the binary rather than fetched from a CDN.
///
/// These are the bytes of `dist/htmx.min.js` from the published `htmx.org`
/// 2.0.10 npm tarball — byte for byte what
/// `unpkg.com/htmx.org@2.0.10/dist/htmx.min.js` serves — with a SHA-256 of
/// `71ea67185bfa8c98c39d31717c6fce5d852370fcdfd129db4543774d3145c0de`. The
/// digest is written down because 50 KiB of minified JavaScript is not
/// something a reviewer can read in a diff, while "these are exactly the bytes
/// upstream published" is something they can check in one command. It is not
/// only a comment: the served URL below embeds that digest's first eight bytes
/// and `tests/static_assets_http.rs` asserts the whole name, so re-pinning htmx
/// is necessarily a deliberate commit that updates a failing assertion rather
/// than a silent file swap.
///
/// htmx is 0BSD, whose entire grant is "Permission to use, copy, modify, and/or
/// distribute this software for any purpose with or without fee is hereby
/// granted" followed by a warranty disclaimer. It attaches no condition at all:
/// no notice to reproduce, no attribution to carry, nothing this binary or its
/// output has to say in order to redistribute the file. That is also why the
/// minified file has no license header to preserve — upstream ships it without
/// one. The upstream text is committed beside it as
/// `src/static/htmx-2.0.10.LICENSE.txt` regardless, because a vendored
/// dependency whose terms a reader has to leave the tree to find is worse than
/// one they can read in place.
const HTMX_SCRIPT: &str = include_str!("static/htmx-2.0.10.min.js");

/// The vendored release, carried in the served name so the version a page is
/// running is legible in a browser's network panel without hashing anything.
const HTMX_VERSION: &str = "2.0.10";

/// `htmx-<version>-<digest>.min.js`, content addressed like `cr-<digest>.js`.
///
/// The version alone could not carry the `immutable` promise below: a
/// re-published or locally patched 2.0.10 would keep the name and leave caches
/// on the old bytes for a year. The version is in the name for humans, the
/// digest for correctness.
static HTMX_SCRIPT_NAME: LazyLock<String> = LazyLock::new(|| {
    format!(
        "htmx-{HTMX_VERSION}-{}.min.js",
        hexadecimal(&Sha256::digest(HTMX_SCRIPT)[..8])
    )
});

/// The absolute path rendered pages link, as
/// `/static/htmx-<version>-<digest>.min.js`.
static HTMX_SCRIPT_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/{}", HTMX_SCRIPT_NAME.as_str()));

/// The Tailwind utilities the markup uses, compiled ahead of time and committed.
///
/// These pages used to load Tailwind's Play CDN, a script that fetched itself
/// from jsDelivr on every page, compiled CSS in the browser and injected it,
/// which Tailwind documents as development-only: the UI needed the network,
/// rendered unstyled until the script had run, and could not be given a
/// content security policy that did not trust a third-party origin. This file
/// is the same utilities compiled by the Tailwind CLI from
/// `src/static/tailwind.input.css`, which says how to regenerate it; CI fails
/// if the committed bytes are not what that produces. Tailwind is MIT
/// licensed, and its text is committed beside the file as
/// `src/static/tailwindcss-4.3.3.LICENSE.txt`.
const TAILWIND_STYLESHEET: &str = include_str!("static/tailwind.css");

/// `tailwind-<digest>.css`, content addressed like `cr-<digest>.js`.
static TAILWIND_STYLESHEET_NAME: LazyLock<String> = LazyLock::new(|| {
    format!(
        "tailwind-{}.css",
        hexadecimal(&Sha256::digest(TAILWIND_STYLESHEET)[..8])
    )
});

/// The absolute path rendered pages link, as `/static/tailwind-<digest>.css`.
static TAILWIND_STYLESHEET_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/{}", TAILWIND_STYLESHEET_NAME.as_str()));

/// `hx-boost="false"`: the value that hands one element back to the browser's
/// own navigation, spelled as a constant so the reasons for using it are
/// written down once rather than repeated at every call site.
///
/// Two kinds of element carry it. The first is a link to a representation that
/// is not an HTML page — `/openapi.json` in the sidebar and both mobile navs,
/// and the JSON-API buttons on `/users` and `/audit`. Boosting those would swap
/// a JSON document into the page body as text, whereas they exist to leave the
/// UI for a raw representation, which is exactly what the `↗` beside them
/// promises.
///
/// The second is a mutating form whose two possible answers are not yet shapes
/// htmx can act on. A boosted form needs both: a success it can turn into a
/// navigation, and a refusal it can show. The record create and edit form now
/// has both — `204` with `HX-Location` (see `mutation_redirect`) and the
/// re-rendered form itself (see `reject_record_form`) — and is therefore boosted
/// like the rest of the page. The remaining three keep the attribute, each for a
/// reason of its own:
///
/// * The **delete** form — now the one on the confirmation page, not a form on
///   the record page — answers a refusal with a rendered error document. A
///   version that no longer matches is a `412`, and htmx will not swap a failed
///   `POST`, so boosting it would turn a lost race into a button that visibly
///   does nothing. This is the save-as-view reason below, and it replaces the
///   older one: the form used to stay native because its confirmation was an
///   `onsubmit` handler that htmx's submit listener does not consult, so a boost
///   would have deleted a record after a declined confirmation. That handler is
///   gone. The confirmation is a page the server renders, which is asked of a
///   browser with no JavaScript too; see `delete_confirmation_url`.
/// * The **save-as-view** form answers a refusal — a name already taken, a
///   Kanban layout with no grouping field — with a rendered error page, which is
///   a whole document and not a form. Boosting it would turn those refusals into
///   a button that visibly does nothing. It is a different form with different
///   fields, so giving it this phase's treatment is its own change rather than a
///   side effect of this one.
/// * The **Kanban move** form has no fields to preserve and its drag-and-drop
///   equivalent in `cr.js` submits a form it builds itself with `form.submit()`,
///   which fires no submit event and so is never boosted. Leaving the rendered
///   form native keeps both ways of moving a card behaving identically. The board
///   *is* `VIEW_TABLE_REGION` and a page turn on a Kanban view already swaps it,
///   so the region is not what is missing: a move is a `POST`, and the answer to
///   a successful one is a redirect (`mutation_redirect`), not the region. Making
///   a move swap the board means giving the mutation a second success shape that
///   returns markup, and only the rendered form could use it — the drop would
///   still reload the page, which is the asymmetry this attribute exists to
///   prevent. It waits for the drag to go through htmx too.
///
/// The **perspective** form is the one case where the attribute is belt and
/// braces rather than load bearing: its `<select>` calls `form.submit()`, which
/// fires no submit event, so htmx would never see it regardless. It is marked
/// anyway so that the opt-out is a decision on the page rather than an accident
/// of how that one control happens to submit.
const UNBOOSTED: &str = "false";

/// Serve one of the embedded UI assets.
///
/// The match is over names we compiled in, not a lookup rooted at a directory:
/// this route performs no filesystem access at all, so `/static/../Cargo.toml`
/// and every other traversal shape has nothing to traverse. That is deliberate
/// rather than incidental. `src/paths.rs` goes to considerable trouble to walk
/// database-relative paths component by component with `O_NOFOLLOW`, and a
/// static route that joined a request-supplied name onto a directory would
/// reintroduce exactly the class of bug that walk exists to prevent.
///
/// The content type is per asset, because one of them is a stylesheet. The
/// cache lifetime is shared and never has to move into the match, because
/// every name here is derived from the bytes it names.
async fn static_asset(Path(file): Path<String>) -> Response {
    const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
    let (content, content_type) = match file.as_str() {
        name if name == UI_SCRIPT_NAME.as_str() => (UI_SCRIPT, JAVASCRIPT),
        name if name == HTMX_SCRIPT_NAME.as_str() => (HTMX_SCRIPT, JAVASCRIPT),
        name if name == TAILWIND_STYLESHEET_NAME.as_str() => {
            (TAILWIND_STYLESHEET, "text/css; charset=utf-8")
        }
        _ => return not_found().await.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        content,
    )
        .into_response()
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

async fn views_home(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let query: ViewsHomeQuery = parse_query(raw)?;
        let representation = Representation::requested(&headers);
        // Counting reads every record of every collection, which is not a
        // reason to keep the names of the views from a reader who came to pick
        // one. So the document is sent without the numbers unless it was asked
        // for them, and the region is only ever requested to fill them in, so
        // asking for it is asking for them.
        let summarize =
            query.summary == ViewIndexSummary::Inline || representation.wants(VIEW_INDEX_REGION);
        let (views, index) = run_database(&state, &headers, move |database| {
            let views = database.views()?;
            let index = if summarize {
                ViewIndex::summarize(database, &views)?
            } else {
                ViewIndex::titles(database)?
            };
            Ok((views, index))
        })
        .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_views_home(
            &representation,
            &views,
            &index,
            ui.as_ref(),
            &state.csrf_token,
        ))
    }
    .await;
    html_result(result)
}

/// What the view index says about one view: how many records it shows this
/// perspective, and when the most recently changed of them last changed.
#[derive(Debug, Default)]
struct ViewSummary {
    /// `None` when the collection could not be read.
    records: Option<usize>,
    /// `None` when no matching record has audit history this perspective may
    /// read, or when the journal could not be read.
    updated_at: Option<String>,
}

impl ViewSummary {
    fn of<'a>(
        records: impl IntoIterator<Item = &'a str>,
        activity: Option<&BTreeMap<String, RecordActivity>>,
    ) -> Self {
        let mut count = 0;
        let mut newest: Option<&RecordActivity> = None;
        for id in records {
            count += 1;
            if let Some(record) = activity.and_then(|activity| activity.get(id))
                && newest.is_none_or(|newest| record.updated_sequence > newest.updated_sequence)
            {
                newest = Some(record);
            }
        }
        Self {
            records: Some(count),
            updated_at: newest.map(|record| record.updated_at.clone()),
        }
    }
}

/// Everything the view index shows beyond the view definitions themselves.
#[derive(Debug)]
struct ViewIndex {
    /// What each collection is called, for the saved views that narrow it.
    collection_titles: BTreeMap<String, String>,
    /// `None` in the document a browser is sent first, which leaves the
    /// numbers to a request for `VIEW_INDEX_REGION`.
    summary: Option<IndexSummary>,
}

/// The numbers in the view index, which are the part that reads every record.
#[derive(Debug)]
struct IndexSummary {
    /// One per view, by position.
    views: Vec<ViewSummary>,
    users: ViewSummary,
    /// Records across the collections the views read, each collection counted
    /// once however many views narrow it; `None` when one could not be read.
    records: Option<usize>,
}

impl ViewIndex {
    /// The index without its numbers, which costs what the sidebar costs.
    fn titles(database: &Database) -> Result<Self> {
        let collection_titles = database
            .collection_models()?
            .into_iter()
            .map(|model| {
                let title =
                    CollectionPresentation::from_schema(model.schema.as_ref()).title(&model.name);
                (model.name, title)
            })
            .collect();
        Ok(Self {
            collection_titles,
            summary: None,
        })
    }

    /// Each collection is read once however many views share it, and the
    /// journal is walked at most once for all of them. Neither failure is the
    /// index's to report: a collection that cannot be read or a journal that
    /// does not verify leaves a dash where its numbers would be, and opening
    /// the view says why. The index is how a reader gets to that explanation,
    /// so it must not be what breaks.
    fn summarize(database: &Database, views: &[ViewDefinition]) -> Result<Self> {
        let mut index = Self::titles(database)?;
        let activity = database.collections_activity().unwrap_or_default();
        let mut listings: BTreeMap<&str, Option<Vec<Record>>> = BTreeMap::new();
        // Shared across collections, as `search` shares it: a plaintext listing
        // replays the whole journal, and one replay per collection made this
        // page cost collections times history.
        let mut audited_states = None;
        let summaries = views
            .iter()
            .map(|view| {
                let records = listings.entry(view.collection.as_str()).or_insert_with(|| {
                    database
                        .list_with_audited_cache(&view.collection, &[], &mut audited_states)
                        .ok()
                });
                let (Some(records), Ok(predicates)) =
                    (records.as_ref(), ViewPredicates::parse(view))
                else {
                    return ViewSummary::default();
                };
                ViewSummary::of(
                    records
                        .iter()
                        .filter(|record| predicates.matches(&record.attributes))
                        .map(|record| record.id.as_str()),
                    activity.get(&view.collection),
                )
            })
            .collect();
        let users = database
            .users()
            .map(|users| {
                ViewSummary::of(
                    users.iter().map(|(id, _)| id.as_str()),
                    activity.get(USERS_COLLECTION),
                )
            })
            .unwrap_or_default();
        index.summary = Some(IndexSummary {
            views: summaries,
            users,
            records: listings
                .values()
                .map(|records| records.as_ref().map(Vec::len))
                .sum(),
        });
        Ok(index)
    }
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
            &Representation::requested(&headers),
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

/// The read-only page for the reserved `users` collection.
///
/// `users` is CR's own access-control registry rather than application data, so
/// it is deliberately absent from the collection views `/{view}` serves. It is
/// still worth seeing: this page lists the registry for any perspective allowed
/// to read access policy, and offers no mutation at all. Editing a principal or
/// its grants stays with `cr access` and the REST API, which enforce the
/// reserved-field rules the browser forms cannot express.
async fn users_view(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let result: ApiResult<Markup> = async {
        let (users, navigation) = run_database(&state, &headers, |database| {
            let users = database.users()?;
            let navigation = database.views()?;
            Ok((users, navigation))
        })
        .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_users_view(
            &Representation::requested(&headers),
            &users,
            &navigation,
            ui.as_ref(),
            &state.csrf_token,
        ))
    }
    .await;
    html_result(result)
}

/// Owner-only, read-only inspection of the filesystem visible to this process.
///
/// The database root is the landing point, but the parent entry is intentional:
/// an owner can navigate to `/` and inspect files outside the database. This is
/// an administrative fallback, not a database-relative sandbox. Only regular
/// files are opened and previews are bounded so devices, pipes, and very large
/// files cannot turn one GET into an unbounded response.
async fn browse_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        if !state.access_controlled {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "route_not_found",
                "route not found",
            ));
        }
        let query: BrowseQuery = parse_query(raw)?;
        let (start, navigation) = run_database(&state, &headers, |database| {
            if !database.owner_access_allowed(&AccessResource::Database)? {
                return Err(DomainError::Forbidden(
                    "principal cannot browse server files".to_owned(),
                )
                .into());
            }
            let start = database.root().to_path_buf();
            let navigation = database.views()?;
            Ok((start, navigation))
        })
        .await?;
        let sort = BrowseSort::requested(&query);
        let requested = query.path;
        let page = tokio::task::spawn_blocking(move || {
            browse_filesystem(&start, requested.as_deref(), sort)
        })
        .await
        .map_err(|error| {
            ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
        })??;
        let mut documents = Vec::new();
        if let BrowserItem::Directory(entries) = &page.item {
            for (anchor, entry) in directory_documents(entries) {
                let path = page.location.join(&entry.name);
                let preview = tokio::task::spawn_blocking(move || browse_file(&path))
                    .await
                    .map_err(|error| {
                        ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
                    })?;
                documents.push(BrowserDocument {
                    anchor,
                    name: entry.name.clone(),
                    href: entry.href.clone(),
                    // Published here rather than on the blocking worker:
                    // publishing logs the full chain under this request's ID,
                    // and that ID only exists on the request's own task. The
                    // page shows the public message alone.
                    preview: preview.map_err(|error| error.publish().message),
                });
            }
        }
        let ui = ui_context(&state, &headers).await?;
        Ok(render_browse_view(
            &Representation::requested(&headers),
            &page,
            sort,
            &documents,
            &navigation,
            ui.as_ref(),
            &state.csrf_token,
        ))
    }
    .await;
    html_result(result)
}

async fn pin_location_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawForm(raw): RawForm,
) -> Response {
    change_pin(state, headers, raw, |database, path| {
        database.pin(path, None).map(|_| ())
    })
    .await
}

async fn unpin_location_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawForm(raw): RawForm,
) -> Response {
    // Unpinning something already unpinned is not an error here: the form is
    // native, so a double click submits twice, and the second has nothing left
    // to do. The CLI, where a typo is the likelier cause, does refuse it.
    change_pin(state, headers, raw, |database, path| {
        database.unpin(path).map(|_| ())
    })
    .await
}

/// Apply one pin change from the browser and return to the page it came from.
///
/// The return address is only ever a browse URL built from an absolute path,
/// so a crafted `from` cannot turn this into a redirect off the browser.
async fn change_pin(
    state: AppState,
    headers: HeaderMap,
    raw: axum::body::Bytes,
    change: fn(&Database, &str) -> Result<()>,
) -> Response {
    let result: ApiResult<Response> = async {
        if !state.access_controlled {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "route_not_found",
                "route not found",
            ));
        }
        let form: HtmlPinForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        if !FilePath::new(&form.from).is_absolute() {
            return Err(ApiError::bad_request(
                "invalid_browse_path",
                "filesystem browser paths must be absolute",
            ));
        }
        let back = browse_url(&form.from);
        let path = form.path;
        run_database(&state, &headers, move |database| change(database, &path)).await?;
        see_other(&back)
    }
    .await;
    result.unwrap_or_else(html_error)
}

fn browse_filesystem(
    start: &FilePath,
    requested: Option<&str>,
    sort: BrowseSort,
) -> ApiResult<BrowserPage> {
    let candidate = match requested.filter(|value| !value.is_empty()) {
        Some(path) => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err(ApiError::bad_request(
                    "invalid_browse_path",
                    "filesystem browser paths must be absolute",
                ));
            }
            path
        }
        None => start.to_path_buf(),
    };
    let location = std::fs::canonicalize(&candidate).map_err(|error| {
        browse_io_error(error, "could not resolve the requested filesystem location")
    })?;
    let metadata = std::fs::metadata(&location).map_err(|error| {
        browse_io_error(error, "could not inspect the requested filesystem location")
    })?;
    let parent = location
        .parent()
        .filter(|parent| *parent != location)
        .map(FilePath::to_path_buf);
    let crumbs = browse_crumbs(&location);
    let item = if metadata.is_dir() {
        let mut entries = browse_directory(&location)?;
        sort.apply(&mut entries);
        BrowserItem::Directory(entries)
    } else if metadata.is_file() {
        BrowserItem::File(browse_file(&location)?)
    } else {
        BrowserItem::Other
    };
    Ok(BrowserPage {
        location,
        parent,
        crumbs,
        item,
    })
}

fn browse_directory(path: &FilePath) -> ApiResult<Vec<BrowserEntry>> {
    let directory = std::fs::read_dir(path)
        .map_err(|error| browse_io_error(error, "could not read the requested directory"))?;
    let mut entries = Vec::new();
    for entry in directory {
        let entry = entry.map_err(|error| {
            browse_io_error(error, "could not read an entry in the requested directory")
        })?;
        let file_type = entry.file_type().map_err(|error| {
            browse_io_error(
                error,
                "could not inspect an entry in the requested directory",
            )
        })?;
        let kind = if file_type.is_dir() {
            BrowserEntryKind::Directory
        } else if file_type.is_file() {
            BrowserEntryKind::File
        } else if file_type.is_symlink() {
            BrowserEntryKind::Symlink
        } else {
            BrowserEntryKind::Other
        };
        // The entry's own metadata, not its target's: a link's times are the
        // link's, as its kind is.
        let metadata = entry.metadata().ok();
        let size = metadata
            .as_ref()
            .filter(|_| kind == BrowserEntryKind::File)
            .map(std::fs::Metadata::len);
        let entry_path = entry.path();
        entries.push(BrowserEntry {
            name: entry.file_name().to_string_lossy().into_owned(),
            href: entry_path.to_str().map(browse_url),
            kind,
            size,
            created: metadata
                .as_ref()
                .and_then(|metadata| metadata.created().ok()),
            modified: metadata
                .as_ref()
                .and_then(|metadata| metadata.modified().ok()),
        });
    }
    Ok(entries)
}

/// README names in the order a code host prefers them when several exist.
///
/// Matching ignores case, as on GitHub, so `readme.md` and `README.MD` both
/// qualify. Markdown comes first because it is what a README almost always is;
/// the plain-text and extensionless forms follow because older projects and
/// tool directories still ship them.
const README_NAMES: [&str; 4] = ["readme.md", "readme.markdown", "readme.txt", "readme"];

/// The file that defines an agent skill, and so explains its directory the way
/// a README explains a project. Matched without case like a README.
const SKILL_NAME: &str = "skill.md";

/// The documents to preview beneath a directory listing: its README, then its
/// `SKILL.md`, each only if present.
///
/// Both rather than one, because they answer different readers. A skill
/// directory commonly carries a `SKILL.md` for the agent and a README for the
/// person maintaining it, and hiding either would make the other look like the
/// whole story.
///
/// Only regular files qualify. A symbolic link named `README.md` is listed as a
/// link and left alone: previews open with `O_NOFOLLOW`, so it would fail, and
/// following it silently would show a file from somewhere the listing does not
/// say.
fn directory_documents(entries: &[BrowserEntry]) -> Vec<(&'static str, &BrowserEntry)> {
    let regular = |name: &str| {
        entries.iter().find(|entry| {
            entry.kind == BrowserEntryKind::File && entry.name.eq_ignore_ascii_case(name)
        })
    };
    let readme = README_NAMES.iter().find_map(|name| regular(name));
    let skill = regular(SKILL_NAME);
    readme
        .map(|entry| ("readme", entry))
        .into_iter()
        .chain(skill.map(|entry| ("skill", entry)))
        .collect()
}

fn browse_file(path: &FilePath) -> ApiResult<BrowserFile> {
    let mut file = open_browser_file(path)
        .map_err(|error| browse_io_error(error, "could not open the requested file"))?;
    let metadata = file
        .metadata()
        .map_err(|error| browse_io_error(error, "could not inspect the requested file"))?;
    if !metadata.is_file() {
        return Err(ApiError::unprocessable(
            "the requested filesystem location is not a regular file",
        ));
    }

    let mut bytes = Vec::with_capacity(MAX_FILE_PREVIEW_BYTES.saturating_add(1));
    (&mut file)
        .take(MAX_FILE_PREVIEW_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| browse_io_error(error, "could not read the requested file"))?;
    let read_bytes = bytes.len();
    let mut truncated = read_bytes > MAX_FILE_PREVIEW_BYTES;
    bytes.truncate(MAX_FILE_PREVIEW_BYTES);
    let total_bytes = metadata.len().max(read_bytes as u64);

    if let Some((text, bytes_shown)) = text_file_preview(&bytes, truncated) {
        truncated |= bytes_shown < bytes.len();
        return Ok(BrowserFile {
            contents: BrowserFileContents::Text(text),
            bytes_shown,
            total_bytes,
            truncated,
        });
    }

    let binary_bytes = bytes.len().min(MAX_BINARY_PREVIEW_BYTES);
    truncated |= binary_bytes < bytes.len();
    Ok(BrowserFile {
        contents: BrowserFileContents::Binary(hex_preview(&bytes[..binary_bytes])),
        bytes_shown: binary_bytes,
        total_bytes,
        truncated,
    })
}

/// Open a preview without letting a FIFO block a server worker indefinitely or
/// a last-moment symlink replacement redirect the checked path. Regular files
/// ignore `O_NONBLOCK`; special files are rejected after `fstat` above.
fn open_browser_file(path: &FilePath) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    options.open(path)
}

/// A preview cut through the middle of its last UTF-8 character is still text.
/// Other invalid UTF-8 and NUL bytes are treated as binary.
fn text_file_preview(bytes: &[u8], truncated: bool) -> Option<(String, usize)> {
    if bytes.contains(&0) {
        return None;
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => Some((text.to_owned(), bytes.len())),
        Err(error) if truncated && error.error_len().is_none() => {
            let valid = error.valid_up_to();
            std::str::from_utf8(&bytes[..valid])
                .ok()
                .map(|text| (text.to_owned(), valid))
        }
        Err(_) => None,
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    let mut preview = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        preview.push_str(&format!("{:08x}  ", line * 16));
        for index in 0..16 {
            if let Some(byte) = chunk.get(index) {
                preview.push_str(&format!("{byte:02x} "));
            } else {
                preview.push_str("   ");
            }
            if index == 7 {
                preview.push(' ');
            }
        }
        preview.push_str(" |");
        for byte in chunk {
            preview.push(if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            });
        }
        preview.push_str("|\n");
    }
    preview
}

fn browse_crumbs(path: &FilePath) -> Vec<BrowserCrumb> {
    let mut ancestors = path
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect::<Vec<_>>();
    ancestors.reverse();
    ancestors
        .into_iter()
        .filter_map(|ancestor| {
            let encoded = ancestor.to_str().map(browse_url)?;
            let label = ancestor
                .file_name()
                .map_or_else(|| "root".to_owned(), |name| name.to_string_lossy().into());
            Some(BrowserCrumb {
                label,
                href: encoded,
            })
        })
        .collect()
}

fn browse_io_error(error: io::Error, context: &'static str) -> ApiError {
    let kind = error.kind();
    let detail = anyhow!(error).context(context);
    match kind {
        io::ErrorKind::NotFound => ApiError {
            status: StatusCode::NOT_FOUND,
            code: "filesystem_not_found",
            message: "the requested filesystem location does not exist".to_owned(),
            detail: Some(detail),
            field: None,
        },
        io::ErrorKind::PermissionDenied => ApiError {
            status: StatusCode::FORBIDDEN,
            code: "filesystem_permission_denied",
            message: "the CR server process cannot read this filesystem location".to_owned(),
            detail: Some(detail),
            field: None,
        },
        _ => ApiError::internal(detail),
    }
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
        let (
            view,
            mut records,
            activity,
            schema,
            navigation,
            can_create,
            can_manage_views,
            updatable,
        ) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let predicates = ViewPredicates::parse(&view)?;
            let mut records = match query_for_database.q.as_deref().filter(|q| !q.is_empty()) {
                Some(pattern) => {
                    let search = SearchQuery::new(pattern, SearchTarget::Document, false, true)?;
                    database.search(Some(&view.collection), &predicates.assignments, &search)?
                }
                None => database.list(&view.collection, &predicates.assignments)?,
            };
            records.retain(|record| {
                predicates.matches(&record.attributes)
                    && query_for_database
                        .filter_match
                        .matches(&ad_hoc_filters, &record.attributes)
            });
            // One verified journal walk per page: the created and updated
            // columns are derived from history, and the sort default reads
            // them, so this is not optional work the renderer can skip.
            let activity = database.record_activity(&view.collection)?;
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
                activity,
                schema,
                navigation,
                can_create,
                can_manage_views,
                updatable,
            ))
        })
        .await?;

        if query.sort_field.is_none() {
            match view.sort_by.clone() {
                Some(field) => {
                    query.sort_field = Some(field);
                    query.sort_direction = match view.sort_direction {
                        SortDirection::Asc => ViewSortDirection::Asc,
                        SortDirection::Desc => ViewSortDirection::Desc,
                    };
                }
                // Newest first. Making the default explicit in the query keeps
                // the header indicator, the sort control, and every generated
                // link agreeing about what the page is actually ordered by.
                None => {
                    query.sort_field = Some(DEFAULT_VIEW_SORT_FIELD.to_owned());
                    query.sort_direction = ViewSortDirection::Desc;
                }
            }
        }

        let available_columns = view_available_columns(&view, &records, schema.as_ref());
        let columns = selected_view_columns(&view, &query, &available_columns)?;
        sort_view_records(&mut records, &query, &activity)?;
        let bounds = page_bounds(
            query
                .limit
                .or(Some(view.page_size.min(state.max_page_size))),
            query.offset,
            state.max_page_size,
        )?;
        let page = paginate_view(records, bounds.limit, view_position(&query, bounds.offset));
        let ui = ui_context(&state, &headers).await?;
        Ok(render_view_records(
            &Representation::requested(&headers),
            &view,
            &columns,
            &available_columns,
            &page,
            &activity,
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
            &Representation::requested(&headers),
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
            &Representation::requested(&headers),
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
    // A body that is not the form this server rendered — a field it never emits,
    // one it emits twice, no `markdown` at all — is a broken or tampering client
    // rather than somebody's typing, and there is nothing to preserve because
    // nothing in it says what was typed. Every refusal after this point is
    // answered with the form itself.
    let form = match parse_document_form(&raw) {
        Ok(form) => form,
        Err(error) => return html_error(error),
    };
    let submitted = form.clone();
    let result: ApiResult<Response> = async {
        verify_csrf(&state, &form.csrf)?;
        let id = form
            .id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ApiError::bad_request("invalid_form", "record ID cannot be empty")
                    .with_field(ID_CONTROL)
            })?
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
        .await
        .map_err(taken_record_id)?;
        mutation_redirect(
            &Representation::requested(&headers),
            &notice_url(&view_name, "Record created"),
        )
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => {
            reject_record_form(&state, &headers, &view_name, None, submitted, error).await
        }
    }
}

/// A creation refused because that identity is taken is about the record ID, the
/// one field on a create form no collection schema describes. The classification
/// is the stable domain code, never the message text.
fn taken_record_id(error: ApiError) -> ApiError {
    if error.code == DomainError::AlreadyExists(String::new()).code() {
        return error.with_field(ID_CONTROL);
    }
    error
}

async fn update_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    let form = match parse_document_form(&raw) {
        Ok(form) => form,
        Err(error) => return html_error(error),
    };
    let submitted = form.clone();
    let record_id = id.clone();
    let result: ApiResult<Response> = async {
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
        mutation_redirect(
            &Representation::requested(&headers),
            &notice_url(&view_name, "Record updated"),
        )
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => {
            reject_record_form(
                &state,
                &headers,
                &view_name,
                Some(&record_id),
                submitted,
                error,
            )
            .await
        }
    }
}

/// Everything a re-rendered record form needs that the submission itself does
/// not carry, read in one pass so a refusal costs one trip to the database.
struct RecordFormContext {
    view: ViewDefinition,
    record: Option<Record>,
    audit_entries: Vec<AuditEntry>,
    schema: Option<JsonValue>,
    navigation: Vec<ViewDefinition>,
    permissions: RecordPermissions,
    violations: Vec<SchemaViolation>,
    ui: Option<UiContext>,
}

/// Answer a refused submission with the form the user is still looking at.
///
/// The point of the phase: a rejected write used to become the generic error
/// page, which meant navigating back to recover — and browsers do not reliably
/// restore a `<textarea>` full of typed YAML, so "navigate back" often meant
/// "type it again". The same values come back instead, escaped, in the controls
/// they were typed into, with the reason at the top and, where the schema locates
/// it, beside the field it is about.
///
/// The status is the status of the refusal, not a fixed one: `422` for a schema
/// violation, `412` for a record that changed underneath the form, `409` for an
/// identity already taken, `400` for YAML that does not parse. Each is what the
/// API answers for the same failure, and a browser without JavaScript sees the
/// same page and the same status a plain `POST` has always received — only with
/// the form filled in.
async fn reject_record_form(
    state: &AppState,
    headers: &HeaderMap,
    view_name: &str,
    id: Option<&str>,
    submitted: HtmlDocumentForm,
    error: ApiError,
) -> Response {
    // An internal failure is not a rejected form: nothing that was typed is
    // wrong, the message is deliberately generic, and the very data a form needs
    // to re-render may be what could not be read. That keeps the error page.
    if error.status.is_server_error() {
        return html_error(error);
    }
    let error_field = error.field.clone();
    let requested_view = view_name.to_owned();
    let requested_id = id.map(str::to_owned);
    let form = submitted.clone();
    let loaded: ApiResult<RecordFormContext> = async {
        let context = run_database(state, headers, move |database| {
            let view = database.view(&requested_view)?;
            let schema = collection_schema(database, &view.collection)?;
            let navigation = database.views()?;
            let (record, audit_entries, permissions) = match &requested_id {
                Some(id) => {
                    let record = database.get(&view.collection, id)?;
                    let audit_entries = database.audit_recent(
                        DEFAULT_PAGE_SIZE,
                        AuditFilter::record(&view.collection, id),
                    )?;
                    let resource = AccessResource::record(&view.collection, &record.id);
                    let permissions = RecordPermissions {
                        update: database.access_allowed(AccessAction::Update, &resource)?,
                        delete: database.access_allowed(AccessAction::Delete, &resource)?,
                    };
                    (Some(record), audit_entries, permissions)
                }
                // A refused creation renders the same form a refused edit does,
                // so it answers the same question about permission: a principal
                // who may not create here gets their text back in a form they
                // cannot submit, rather than a button that will refuse again.
                None => (
                    None,
                    Vec::new(),
                    RecordPermissions {
                        update: can_create_in_collection(database, &view.collection)?,
                        delete: false,
                    },
                ),
            };
            // Field-level diagnostics explain a refusal that already has a
            // message, so an explanation that cannot be produced is simply
            // absent: deriving the attributes again is how the schema is asked
            // which field each violation is about, and if that derivation is
            // itself what failed, the failure already names its own field.
            let violations = document_form_attributes(&form, schema.as_ref())
                .ok()
                .and_then(|attributes| {
                    database
                        .schema_violations(&view.collection, &attributes)
                        .ok()
                })
                .unwrap_or_default();
            Ok((
                view,
                record,
                audit_entries,
                schema,
                navigation,
                permissions,
                violations,
            ))
        })
        .await?;
        let (view, record, audit_entries, schema, navigation, permissions, violations) = context;
        Ok(RecordFormContext {
            view,
            record,
            audit_entries,
            schema,
            navigation,
            permissions,
            violations,
            ui: ui_context(state, headers).await?,
        })
    }
    .await;
    let context = match loaded {
        Ok(context) => context,
        Err(secondary) => {
            // The form cannot be re-rendered, so answer with the failure that
            // refused the write rather than the one that refused to describe it.
            // `publish` is what writes the second failure to the log, under its
            // own request ID, so it is not lost by being answered with the first.
            secondary.publish();
            return html_error(error);
        }
    };
    let published = error.publish();
    let fields = record_form_diagnostics(
        &submitted,
        context.schema.as_ref(),
        &published,
        error_field.as_deref(),
        &context.violations,
    );
    let status = published.status;
    let rejection = RecordFormRejection {
        error: published,
        fields,
        submitted,
    };
    let markup = render_record_form(
        &Representation::requested(headers),
        &context.view,
        context.record.as_ref(),
        &context.audit_entries,
        context.schema.as_ref(),
        &state.csrf_token,
        Some(&rejection),
        &context.navigation,
        context.ui.as_ref(),
        context.permissions,
    );
    rejected_form_response(status, markup)
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

/// Ask before deleting, on the server.
///
/// The `GET` half of the delete path; `delete_confirmation_url` explains why the
/// confirmation is a page. It reads the record for two reasons beyond rendering
/// its id: a record that does not exist must answer `404` rather than offering
/// to delete nothing, and the form needs the record's current version so the
/// `POST` can refuse a deletion of something that changed in between.
///
/// It checks the delete permission itself rather than trusting that the reader
/// arrived from a page that rendered the link. A principal who may read a record
/// but not delete it can type this URL, and answering it with a confirmation
/// page whose only possible outcome is `403` would be a worse answer than the
/// `403` itself.
async fn confirm_delete_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((view_name, id)): Path<(String, String)>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let requested_view = view_name.clone();
        let requested_id = id.clone();
        let (view, record, navigation) = run_database(&state, &headers, move |database| {
            let view = database.view(&requested_view)?;
            let record = database.get(&view.collection, &requested_id)?;
            let resource = AccessResource::record(&view.collection, &record.id);
            if !database.access_allowed(AccessAction::Delete, &resource)? {
                return Err(DomainError::Forbidden(format!(
                    "principal cannot delete record:{}/{}",
                    view.collection, record.id
                ))
                .into());
            }
            let navigation = database.views()?;
            Ok((view, record, navigation))
        })
        .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_delete_confirmation(
            &Representation::requested(&headers),
            &view,
            &record,
            &navigation,
            ui.as_ref(),
            &state.csrf_token,
        ))
    }
    .await;
    html_result(result)
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

async fn get_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
) -> ApiResult<Json<JsonValue>> {
    let schema = run_database(&state, &headers, move |database| {
        database.schema(&collection)?.ok_or_else(|| {
            DomainError::NotFound(format!("collection '{collection}' has no schema")).into()
        })
    })
    .await?;
    Ok(Json(schema))
}

/// Install a collection schema, or with `preview=true` only review it.
async fn put_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<JsonValue>, JsonRejection>,
) -> ApiResult<Json<SchemaReview>> {
    let query: SchemaChangeQuery = parse_query(raw)?;
    let Json(proposed) = json_payload(payload)?;
    let review = run_database(&state, &headers, move |database| {
        if query.preview {
            database.review_schema(&collection, &proposed)
        } else {
            database.set_schema(&collection, &proposed, query.allow_violations)
        }
    })
    .await?;
    Ok(Json(review))
}

async fn delete_schema(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
) -> ApiResult<Json<JsonValue>> {
    let removed = run_database(&state, &headers, move |database| {
        database.remove_schema(&collection)
    })
    .await?;
    Ok(Json(json!({ "removed": removed })))
}

async fn list_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: ListQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let filter = parse_filter(query.filter)?;
    let projection = parse_projection(&query.select)?;
    let sort = query.sort;
    let direction = query.direction.into();
    let records = run_database(&state, &headers, move |database| {
        let mut records = database.list(&collection, &filters)?;
        records.retain(|record| {
            expressions
                .iter()
                .all(|expression| expression.matches(&record.attributes))
                && filter.as_ref().is_none_or(|filter| filter.matches(record))
        });
        if let Some(field) = sort {
            sort_records_by_field(&mut records, &field, direction)?;
        }
        Ok(records)
    })
    .await?;
    record_page_response(paginate(records, bounds), projection.as_ref())
}

/// Count a collection's records, optionally per value of a field, with sums,
/// averages, minimums, and maximums.
async fn count_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(collection): Path<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<JsonValue>> {
    let query: CountQuery = parse_query(raw)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let filter = parse_filter(query.filter)?;
    let aggregation = Aggregation::new(
        query.by.as_deref(),
        &query.sum,
        &query.avg,
        &query.min,
        &query.max,
    )
    .map_err(ApiError::from_domain)?;
    let summary = run_database(&state, &headers, move |database| {
        let mut records = database.list(&collection, &filters)?;
        records.retain(|record| {
            expressions
                .iter()
                .all(|expression| expression.matches(&record.attributes))
                && filter.as_ref().is_none_or(|filter| filter.matches(record))
        });
        aggregation.run(&records).json()
    })
    .await?;
    Ok(Json(summary))
}

async fn get_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: GetRecordQuery = parse_query(raw)?;
    let projection = parse_projection(&query.select)?;
    let record = run_database(&state, &headers, move |database| {
        database.get(&collection, &id)
    })
    .await?;
    match projection {
        Some(projection) => {
            let etag = entity_tag(&record.version)?;
            let object = projection.object(&record).map_err(ApiError::from_domain)?;
            let mut response = Json(object).into_response();
            response.headers_mut().insert(header::ETAG, etag);
            Ok(response)
        }
        None => api_record_response(StatusCode::OK, record),
    }
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

/// List the records that link to one record, which need not exist.
async fn list_backlinks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: BacklinkQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let filter = parse_filter(query.filter)?;
    let projection = parse_projection(&query.select)?;
    let (from, relation, sort) = (query.from, query.relation, query.sort);
    let direction = query.direction.into();
    let backlinks = run_database(&state, &headers, move |database| {
        let mut backlinks = database.backlinks(
            &collection,
            &id,
            from.as_deref(),
            relation.as_deref(),
            &filters,
        )?;
        backlinks.retain(|backlink| {
            expressions
                .iter()
                .all(|expression| expression.matches(&backlink.record.attributes))
                && filter
                    .as_ref()
                    .is_none_or(|filter| filter.matches(&backlink.record))
        });
        if let Some(field) = sort {
            sort_by_record_field(
                &mut backlinks,
                |backlink| &backlink.record,
                &field,
                direction,
            )?;
        }
        Ok(backlinks)
    })
    .await?;
    let page = paginate(backlinks, bounds);
    Ok(match projection {
        Some(projection) => Json(page.try_map(|backlink| {
            projection
                .object(&backlink.record)
                .map_err(ApiError::from_domain)
        })?)
        .into_response(),
        None => Json(page.try_map(ApiBacklink::try_from)?).into_response(),
    })
}

/// Follow relations outward from one record.
async fn traverse_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id)): Path<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Json<JsonValue>> {
    let query: TraverseQuery = parse_query(raw)?;
    let projection = parse_projection(&query.select)?;
    let rendered = run_database(&state, &headers, move |database| {
        let traversal =
            database.traverse(&collection, &id, &query.relation, query.depth.unwrap_or(1))?;
        if query.expand {
            traversal.tree_json(projection.as_ref())
        } else {
            traversal.graph_json(projection.as_ref())
        }
    })
    .await?;
    Ok(Json(rendered))
}

/// Remove one relation reference. Every part of the reference is a path
/// component, so it needs no request body, which a `DELETE` should not carry.
async fn unlink_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id, relation, target_collection, target_id)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let precondition = if_match(&headers, false)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_unlink_conditionally(
                &collection,
                &id,
                &relation,
                &target_collection,
                &target_id,
                precondition.as_ref(),
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.unlink_conditionally(
            &collection,
            &id,
            &relation,
            &target_collection,
            &target_id,
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
) -> ApiResult<Response> {
    let parameters: SearchParameters = parse_query(raw)?;
    let bounds = page_bounds(parameters.limit, parameters.offset, state.max_page_size)?;
    let filters = parse_filters(parameters.filters)?;
    let expressions = parse_filter_expressions(parameters.where_expr)?;
    let filter = parse_filter(parameters.filter)?;
    let projection = parse_projection(&parameters.select)?;
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
                && filter.as_ref().is_none_or(|filter| filter.matches(record))
        });
        if let Some(field) = sort {
            sort_records_by_field(&mut records, &field, direction)?;
        }
        Ok(records)
    })
    .await?;
    record_page_response(paginate(records, bounds), projection.as_ref())
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
        "TraversalNode": {
            "type": "object",
            "required": ["collection", "id", "status"],
            "properties": {
                "collection": { "type": "string" },
                "id": { "type": "string" },
                "status": { "enum": ["found", "missing", "forbidden", "unreadable"] },
                "depth": { "type": "integer", "minimum": 0 },
                "path": { "type": "string" },
                "version": { "type": "string" },
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" },
                "fields": { "$ref": "#/components/schemas/ProjectedRecord" },
                "seen": { "type": "boolean", "description": "In an expanded tree, a reference to a record already expanded elsewhere." },
                "links": { "type": "object", "additionalProperties": { "type": "array", "items": { "$ref": "#/components/schemas/TraversalNode" } } }
            }
        },
        "Traversal": {
            "description": "A flat graph of nodes and edges, or with expand=true one nested TraversalNode for the start with depth and truncated beside it.",
            "type": "object",
            "properties": {
                "root": { "type": "string" },
                "depth": { "type": "integer" },
                "truncated": { "type": "boolean" },
                "nodes": { "type": "array", "items": { "$ref": "#/components/schemas/TraversalNode" } },
                "edges": { "type": "array", "items": {
                    "type": "object",
                    "required": ["from", "relation", "to"],
                    "properties": { "from": { "type": "string" }, "relation": { "type": "string" }, "to": { "type": "string" } }
                } }
            }
        },
        "Backlink": {
            "type": "object",
            "required": ["collection", "id", "path", "version", "relations", "front_matter"],
            "description": "A record that links to the requested record, with the relations holding the reference.",
            "properties": {
                "collection": { "type": "string" },
                "id": { "type": "string" },
                "path": { "type": "string" },
                "version": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                "relations": { "type": "array", "items": { "type": "string" } },
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" }
            }
        },
        "BacklinkPage": {
            "type": "object",
            "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "anyOf": [{ "$ref": "#/components/schemas/Backlink" }, { "$ref": "#/components/schemas/ProjectedRecord" }] } },
                "pagination": { "$ref": "#/components/schemas/Pagination" }
            }
        },
        "RecordPage": {
            "type": "object",
            "required": ["data", "pagination"],
            "properties": {
                "data": { "type": "array", "items": { "anyOf": [{ "$ref": "#/components/schemas/RecordSummary" }, { "$ref": "#/components/schemas/ProjectedRecord" }] } },
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
        "ProjectedRecord": {
            "description": "The fields a select parameter asked for, keyed by selector as written. A field the record does not have is left out.",
            "type": "object",
            "additionalProperties": true
        },
        "RecordOrProjection": {
            "anyOf": [{ "$ref": "#/components/schemas/Record" }, { "$ref": "#/components/schemas/ProjectedRecord" }]
        },
        "JsonSchema": {
            "description": "A Draft 2020-12 JSON Schema, which may carry cr's x-cr-* annotations.",
            "type": ["object", "boolean"]
        },
        "SchemaReview": {
            "type": "object",
            "required": ["collection", "changed", "applied", "records", "violations"],
            "properties": {
                "collection": { "type": "string" },
                "changed": { "type": "boolean", "description": "Whether the proposed schema differs from the installed one." },
                "applied": { "type": "boolean", "description": "Whether it was written." },
                "records": { "type": "integer", "description": "Existing records judged against it." },
                "violations": { "type": "array", "items": {
                    "type": "object",
                    "required": ["id", "message"],
                    "properties": {
                        "id": { "type": "string" },
                        "field": { "type": "string" },
                        "message": { "type": "string" }
                    }
                } }
            }
        },
        "SchemaRemoval": {
            "type": "object",
            "required": ["removed"],
            "properties": { "removed": { "type": "boolean" } }
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
        "CountMetrics": {
            "type": "object",
            "required": ["count"],
            "properties": {
                "count": { "type": "integer", "minimum": 0 },
                "sum": { "type": "object", "additionalProperties": { "type": "number" } },
                "avg": { "type": "object", "additionalProperties": { "type": ["number", "null"] } },
                "min": { "type": "object", "additionalProperties": true },
                "max": { "type": "object", "additionalProperties": true }
            }
        },
        "CountSummary": {
            "allOf": [
                { "$ref": "#/components/schemas/CountMetrics" },
                {
                    "type": "object",
                    "properties": {
                        "by": { "type": "string" },
                        "groups": { "type": "array", "items": {
                            "allOf": [
                                { "$ref": "#/components/schemas/CountMetrics" },
                                { "type": "object", "properties": { "value": {}, "missing": { "type": "boolean", "const": true } } }
                            ]
                        } }
                    }
                }
            ]
        },
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
                    "dangling_link", "malformed_relation", "schema_violation",
                    "invalid_access_metadata", "unusable_schema",
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
        "/api/v1/collections/{collection}/count": {
            "get": { "operationId": "countRecords", "description": "Count records, optionally once per distinct value of a field, with sums and averages of numeric fields and minimums and maximums ordered as sort orders them. Never returns record bodies.", "parameters": [
                collection.clone(),
                { "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "where_expr", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "filter", "in": "query", "schema": { "type": "string" } },
                { "name": "by", "in": "query", "description": "Group by this dotted field; records without it form the last group, marked missing.", "schema": { "type": "string" } },
                { "name": "sum", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "avg", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "min", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "max", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }
            ], "responses": ok("#/components/schemas/CountSummary") }
        },
        "/api/v1/collections/{collection}/schema": {
            "get": { "operationId": "getCollectionSchema", "description": "The JSON Schema the collection's records are judged against. users answers with its built-in schema.", "parameters": [collection.clone()], "responses": ok("#/components/schemas/JsonSchema") },
            "put": { "operationId": "setCollectionSchema", "description": "Install a JSON Schema after judging every existing record against it. Refused when a record does not satisfy it unless allow_violations=true, and when it would change which values are encrypted or whether records are creator-owned. With preview=true, only review it.", "parameters": [
                collection.clone(),
                { "name": "preview", "in": "query", "schema": { "type": "boolean", "default": false } },
                { "name": "allow_violations", "in": "query", "schema": { "type": "boolean", "default": false } }
            ], "requestBody": json_body("#/components/schemas/JsonSchema"), "responses": ok("#/components/schemas/SchemaReview") },
            "delete": { "operationId": "removeCollectionSchema", "description": "Remove the schema, making the collection schemaless. Refused while it declares encrypted storage or creator-owned records.", "parameters": [collection.clone()], "responses": ok("#/components/schemas/SchemaRemoval") }
        },
        "/api/v1/collections/{collection}/records": {
            "get": {
                "operationId": "listRecords",
                "parameters": [collection.clone(),
                    json!({ "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }),
                    json!({ "name": "where_expr", "in": "query", "description": "Typed expressions such as value>=10000, name contains Acme, or owner is-empty. Repeated expressions use AND.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }),
                    json!({ "name": "filter", "in": "query", "description": "A filter with AND, OR, NOT, parentheses, comparisons, contains, starts-with, ends-with, in [...], exists, is null, and is-empty, such as stage in [open, won] AND (value >= 10000 OR owner is null). Combined with the other filters by AND.", "schema": { "type": "string" } }),
                    json!({ "name": "select", "in": "query", "description": "Return only these fields: dotted front matter paths, or $id, $collection, $path, $version, and $body. Comma-separated or repeated. Each result is then a flat object keyed by the selectors, without the fields a record does not have.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }),
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
            "get": { "operationId": "getRecord", "parameters": [collection.clone(), id.clone(), { "name": "select", "in": "query", "description": "Return only these fields: dotted front matter paths, or $id, $collection, $path, $version, and $body. Comma-separated or repeated. Each result is then a flat object keyed by the selectors, without the fields a record does not have.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }], "responses": record_ok("#/components/schemas/RecordOrProjection") },
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
            "post": { "operationId": "linkRecord", "parameters": conditional_mutation_parameters(vec![collection.clone(), id.clone()]), "requestBody": json_body("#/components/schemas/LinkRequest"), "responses": record_ok_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview") }
        },
        "/api/v1/collections/{collection}/records/{id}/backlinks": {
            "get": { "operationId": "listBacklinks", "description": "List readable records whose relations refer to this record. The record does not have to exist.", "parameters": [
                collection.clone(),
                id.clone(),
                { "name": "from", "in": "query", "description": "Only records in this collection.", "schema": { "type": "string" } },
                { "name": "relation", "in": "query", "description": "Only references held in this relation.", "schema": { "type": "string" } },
                { "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "where_expr", "in": "query", "description": "Typed expressions on the source record. Repeated expressions use AND.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "filter", "in": "query", "description": "A filter with AND, OR, NOT, parentheses, comparisons, contains, starts-with, ends-with, in [...], exists, is null, and is-empty, such as stage in [open, won] AND (value >= 10000 OR owner is null). Combined with the other filters by AND.", "schema": { "type": "string" } },
                { "name": "select", "in": "query", "description": "Return only these fields: dotted front matter paths, or $id, $collection, $path, $version, and $body. Comma-separated or repeated. Each result is then a flat object keyed by the selectors, without the fields a record does not have.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "sort", "in": "query", "description": "Dotted front matter field or $id, $collection, or $path. Missing fields remain last.", "schema": { "type": "string" } },
                { "name": "direction", "in": "query", "schema": { "type": "string", "enum": ["asc", "desc"], "default": "asc" } },
                { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1 } },
                { "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0 } }
            ], "responses": ok("#/components/schemas/BacklinkPage") }
        },
        "/api/v1/collections/{collection}/records/{id}/traverse": {
            "get": { "operationId": "traverseRecord", "description": "Follow relations outward from a record, breadth first. Each record is visited once, a missing or unreadable target is reported and not followed, and at most 1000 records are visited.", "parameters": [
                collection.clone(),
                id.clone(),
                { "name": "relation", "in": "query", "description": "Follow only these relations. By default every relation is followed.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "depth", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": MAX_TRAVERSAL_DEPTH, "default": 1 } },
                { "name": "expand", "in": "query", "description": "Nest each record's linked records under it instead of returning a flat graph.", "schema": { "type": "boolean", "default": false } },
                { "name": "select", "in": "query", "description": "Give each record only these fields, under fields, instead of its path, version, and front matter.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true }
            ], "responses": ok("#/components/schemas/Traversal") }
        },
        "/api/v1/collections/{collection}/records/{id}/links/{relation}/{target_collection}/{target_id}": {
            "delete": { "operationId": "unlinkRecord", "description": "Remove every reference to target_collection/target_id from the named relation. Removing a reference that is not there changes nothing, and the target does not have to exist.", "parameters": conditional_mutation_parameters(vec![
                collection,
                id,
                json!({ "name": "relation", "in": "path", "required": true, "schema": { "type": "string" } }),
                json!({ "name": "target_collection", "in": "path", "required": true, "schema": { "type": "string" } }),
                json!({ "name": "target_id", "in": "path", "required": true, "schema": { "type": "string" } })
            ]), "responses": record_ok_or_preview("#/components/schemas/Record", "#/components/schemas/ChangePreview") }
        },
        "/api/v1/search": {
            "get": { "operationId": "searchRecords", "parameters": [
                { "name": "q", "in": "query", "required": true, "schema": { "type": "string" } },
                { "name": "collection", "in": "query", "schema": { "type": "string" } },
                { "name": "where", "in": "query", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "where_expr", "in": "query", "description": "Typed expressions such as value>=10000, name contains Acme, or owner is-empty. Repeated expressions use AND.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
                { "name": "filter", "in": "query", "description": "A filter with AND, OR, NOT, parentheses, comparisons, contains, starts-with, ends-with, in [...], exists, is null, and is-empty, such as stage in [open, won] AND (value >= 10000 OR owner is null). Combined with the other filters by AND.", "schema": { "type": "string" } },
                { "name": "select", "in": "query", "description": "Return only these fields: dotted front matter paths, or $id, $collection, $path, $version, and $body. Comma-separated or repeated. Each result is then a flat object keyed by the selectors, without the fields a record does not have.", "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true },
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

fn render_views_home(
    representation: &Representation,
    views: &[ViewDefinition],
    index: &ViewIndex,
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let internal = ui.is_some_and(|ui| ui.can_read_users);
    let deferred = index.summary.is_none() && (!views.is_empty() || internal);
    let region = view_index_region(views, index, ui, deferred);
    // The answer smaller than the page: the rows with their numbers, and the
    // heading's total beside them as an out-of-band patch, rendered by the
    // function the heading itself calls so the two cannot disagree.
    if representation.wants(VIEW_INDEX_REGION) {
        return fragment(
            "Database views",
            html! {
                (region)
                (view_index_total(views, index, OutOfBand::Yes))
            },
        );
    }
    page_or_content(
        representation,
        "Database views",
        "/",
        views,
        html! {
            div class="cr-page-heading mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between" {
                div {
                    p class="cr-eyebrow" { "Workspace" }
                    h1 class="cr-title mt-1" { "Database views" }
                    p class="cr-lede mt-1 max-w-2xl" {
                        "Every collection and saved view. Changes use the same validated, audited operations as the CLI and REST API."
                    }
                }
                div class="flex flex-wrap gap-1.5" {
                    span class="cr-pill" { (views.len()) " views" }
                    (view_index_total(views, index, OutOfBand::No))
                    @if deferred {
                        // Nothing will ask for the region without a script, so
                        // offer the document that has the numbers in it.
                        noscript {
                            a href=(VIEW_INDEX_SUMMARY_URL) class="cr-pill" { "Count records" }
                        }
                    }
                }
            }
            @if views.is_empty() {
                div class="cr-empty-state" {
                    h2 class="text-lg font-semibold text-gray-900" { "No collections yet" }
                    p class="mt-2 text-sm text-gray-600" {
                        "Create a record with the CLI, or add a saved view with "
                        code class="rounded bg-gray-100 px-1.5 py-1 text-xs" { "cr view create" }
                        "."
                    }
                }
            }
            (region)
        },
        ui,
        csrf_token,
    )
}

/// Every row of the view index, and so every number in it.
///
/// `deferred` renders the rows with placeholders where the numbers go, and asks
/// for this same region with them filled in as soon as htmx has processed it.
/// The answer replaces the region whole, and carries no trigger of its own.
fn view_index_region(
    views: &[ViewDefinition],
    index: &ViewIndex,
    ui: Option<&UiContext>,
    deferred: bool,
) -> Markup {
    let summaries = match &index.summary {
        Some(summary) => summary.views.iter().map(Some).collect::<Vec<_>>(),
        None => vec![None; views.len()],
    };
    let users = index.summary.as_ref().map(|summary| &summary.users);
    html! {
        div id=(VIEW_INDEX_REGION)
            aria-busy=[deferred.then_some("true")]
            hx-get=[deferred.then_some(VIEW_INDEX_SUMMARY_URL)]
            hx-trigger=[deferred.then_some("load")]
            hx-swap=[deferred.then_some("outerHTML")]
        {
            @if !views.is_empty() {
                section class="cr-view-index" aria-label="Available database views" {
                    (view_index_header("View"))
                    @for (view, summary) in navigation_order_with(views, &summaries) {
                        a href=(format!("/{}", encode_segment(&view.name))) class="cr-view-row group" {
                            div class="cr-view-name" {
                                span class="cr-view-icon" aria-hidden="true" { (view_icon(view)) }
                                h2 class="truncate" { (&view.title) }
                                @if view.saved {
                                    span class="cr-view-source" {
                                        (index.collection_titles.get(&view.collection).map_or(view.collection.as_str(), String::as_str))
                                    }
                                }
                            }
                            (view_index_numbers(*summary))
                            div class="cr-view-kind" {
                                span class="cr-pill" {
                                    @if view.saved { "saved" } @else { "automatic" }
                                }
                                @if view.layout == ViewLayout::Kanban {
                                    span class="cr-pill cr-pill-accent" { "kanban" }
                                }
                                @if view.filters.is_empty() && view.where_expr.is_empty() && view.filter_groups.is_empty() {
                                    span class="text-xs text-gray-500" { "All records" }
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
            @if ui.is_some_and(|ui| ui.can_read_users) {
                section class="cr-view-index mt-5" aria-label="Internal records" {
                    (view_index_header("Internal"))
                    a href="/users" class="cr-view-row group" {
                        div class="cr-view-name" {
                            span class="cr-view-icon" aria-hidden="true" { (USERS_ICON) }
                            h2 class="truncate" { "Users" }
                        }
                        (view_index_numbers(users))
                        div class="cr-view-kind" {
                            span class="cr-pill" { "access control" }
                            span class="cr-pill cr-pill-warn" { "read-only" }
                            span class="text-xs text-gray-500" { "Registered principals and their grants" }
                        }
                        span class="cr-view-arrow" aria-hidden="true" { "→" }
                    }
                    @if ui.is_some_and(|ui| ui.can_browse_files) {
                        a href="/browse" class="cr-view-row group" {
                            div class="cr-view-name" {
                                span class="cr-view-icon" aria-hidden="true" { (ALL_FILES_ICON) }
                                h2 class="truncate" { "Browse" }
                            }
                            span {}
                            span {}
                            div class="cr-view-kind" {
                                span class="cr-pill" { "owner only" }
                                span class="cr-pill cr-pill-warn" { "read-only" }
                                span class="text-xs text-gray-500" { "Files visible to the server process" }
                            }
                            span class="cr-view-arrow" aria-hidden="true" { "→" }
                        }
                    }
                }
            }
        }
    }
}

/// The heading's total-records pill.
///
/// Rendered even when there is no total to show, empty and hidden, because it
/// is also where the index region's out-of-band copy lands, and htmx drops a
/// patch whose target is not on the page.
fn view_index_total(views: &[ViewDefinition], index: &ViewIndex, out_of_band: OutOfBand) -> Markup {
    let total = index
        .summary
        .as_ref()
        .and_then(|summary| summary.records)
        .filter(|_| !views.is_empty());
    html! {
        @match total {
            Some(total) => span id=(VIEW_INDEX_TOTAL_ID) class="cr-pill" hx-swap-oob=[out_of_band.attribute()] {
                (count_noun(total, "record", "records"))
            },
            // No `cr-pill`: its `display` would override `hidden`.
            None => span id=(VIEW_INDEX_TOTAL_ID) hidden hx-swap-oob=[out_of_band.attribute()] {},
        }
    }
}

fn view_index_header(first: &str) -> Markup {
    html! {
        div class="cr-view-index-header" aria-hidden="true" {
            span { (first) }
            span class="text-right" { "Records" }
            span { "Updated" }
            span { "Type" }
            span {}
        }
    }
}

/// The record count and last change of one index row, or placeholders for them
/// while the region is still being counted.
///
/// The column headings are hidden from assistive technology — each row is one
/// link, read as one phrase — so the units a heading would have supplied are in
/// the row itself, visible only where the headings are not. A placeholder is
/// hidden too: the region's `aria-busy` is what says the numbers are coming.
fn view_index_numbers(summary: Option<&ViewSummary>) -> Markup {
    let Some(summary) = summary else {
        return html! {
            span class="cr-view-count" {
                span class="text-gray-400" aria-hidden="true" { "…" }
            }
            span class="cr-view-updated" {}
        };
    };
    html! {
        span class="cr-view-count" {
            @match summary.records {
                Some(records) => {
                    (records)
                    span class="cr-view-unit" { " " (if records == 1 { "record" } else { "records" }) }
                }
                None => span class="text-gray-400" { "—" },
            }
        }
        span class="cr-view-updated" {
            @if summary.updated_at.is_some() {
                span class="cr-view-unit" { "updated " }
            }
            (render_timestamp(summary.updated_at.as_deref()))
        }
    }
}

fn count_noun(count: usize, singular: &str, plural: &str) -> String {
    format!("{count} {}", if count == 1 { singular } else { plural })
}

/// The icon a collection shows until its schema names another.
const DEFAULT_COLLECTION_ICON: &str = "🗃️";
const HOME_ICON: &str = "🏠";
const USERS_ICON: &str = "👥";
const ALL_FILES_ICON: &str = "🗂️";
const DIRECTORY_ICON: &str = "📁";
const FILE_ICON: &str = "📄";
const SYMLINK_ICON: &str = "🔗";
const OTHER_FILE_ICON: &str = "⚙️";
/// A pinned location that does not exist cannot say whether it would be a
/// directory or a file.
const MISSING_PIN_ICON: &str = "📍";
const AUDIT_ICON: &str = "📜";
const OPENAPI_ICON: &str = "🔌";

/// The order every list of views is shown in: saved views, then collections,
/// each by the name a reader sees rather than the one in the URL, since a label
/// need not sort where its directory does.
fn navigation_order(views: &[ViewDefinition]) -> impl Iterator<Item = &ViewDefinition> {
    navigation_order_with(views, views).map(|(view, _)| view)
}

/// [`navigation_order`] for views paired, by position, with what was computed
/// for each.
fn navigation_order_with<'a, T>(
    views: &'a [ViewDefinition],
    paired: &'a [T],
) -> impl Iterator<Item = (&'a ViewDefinition, &'a T)> {
    let mut ordered = views.iter().zip(paired).collect::<Vec<_>>();
    ordered.sort_by_cached_key(|(view, _)| {
        (
            !view.saved,
            view.title.to_lowercase(),
            view.title.clone(),
            view.name.clone(),
        )
    });
    ordered.into_iter()
}

fn view_icon(view: &ViewDefinition) -> &str {
    view.icon.as_deref().unwrap_or(DEFAULT_COLLECTION_ICON)
}

fn render_users_view(
    representation: &Representation,
    users: &[(String, User)],
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    // Profile metadata is optional and usually absent, so the column only
    // appears when some principal actually carries it.
    let show_profile = users.iter().any(|(_, user)| !user.profile.is_empty());
    let columns = if show_profile { 7 } else { 6 };
    page_or_content(
        representation,
        "Users",
        "/users",
        views,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                span class="text-gray-900" { "Users" }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                div {
                    p class="cr-eyebrow" { "Internal record" }
                    h1 class="cr-title mt-1" { "Users" }
                    p class="cr-lede mt-1 max-w-2xl" {
                        "Every principal registered in the reserved "
                        code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { "users" }
                        " collection. CR owns this collection's schema and history, so the web UI keeps it read-only: register a principal, change a role, or disable an identity with "
                        code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { "cr access" }
                        " or the REST API."
                    }
                }
                div class="flex flex-wrap items-center gap-2" {
                    span class="cr-pill" { (users.len()) " principals" }
                    span class="cr-pill cr-pill-warn" { "read-only" }
                    a href="/api/v1/collections/users/records" hx-boost=(UNBOOSTED) class="cr-button" { "JSON API" span aria-hidden="true" { " ↗" } }
                }
            }
            div class="cr-table-shell" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-gray-200 text-left text-sm" {
                        thead {
                            tr {
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Principal" }
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Name" }
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Email" }
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Kind" }
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Status" }
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Access" }
                                @if show_profile {
                                    th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Profile" }
                                }
                            }
                        }
                        tbody class="divide-y divide-gray-100" {
                            @if users.is_empty() {
                                tr {
                                    td colspan=(columns) class="px-4 py-12 text-center text-gray-500" {
                                        "This database has no registered principals. Run "
                                        code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { "cr access init" }
                                        " to bootstrap access control."
                                    }
                                }
                            } @else {
                                @for (id, user) in users {
                                    tr {
                                        td class="whitespace-nowrap px-4 py-3 font-mono text-xs font-semibold text-gray-900" { (id) }
                                        td class="px-4 py-3 text-gray-700" { (&user.name) }
                                        td class="px-4 py-3 text-gray-700" { (user.email.as_deref().unwrap_or("—")) }
                                        td class="whitespace-nowrap px-4 py-3 text-gray-700" { (user_kind_label(user.kind)) }
                                        td class="whitespace-nowrap px-4 py-3" {
                                            @if user.status == UserStatus::Disabled {
                                                span class="cr-pill cr-pill-warn" { "disabled" }
                                            } @else {
                                                span class="cr-pill" { "active" }
                                            }
                                        }
                                        td class="px-4 py-3" {
                                            @if user.access.is_empty() {
                                                span class="text-gray-500" { "no access" }
                                            } @else {
                                                div class="flex flex-wrap gap-1.5" {
                                                    @for grant in &user.access {
                                                        span class="cr-pill" title=(format!("{} at {}", grant.role, grant.resource)) {
                                                            (grant.role) " · " (grant.resource)
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        @if show_profile {
                                            td class="px-4 py-3 text-gray-700" {
                                                @if user.profile.is_empty() {
                                                    "—"
                                                } @else {
                                                    ul class="cr-data space-y-0.5" {
                                                        @for (key, value) in &user.profile {
                                                            li { span class="font-semibold" { (yaml_value(key)) } ": " (yaml_value(value)) }
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
                div class="border-t border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600" {
                    "Records live in "
                    code { "records/users/" }
                    " and every change to them is audited like any other record."
                }
            }
        },
        ui,
        csrf_token,
    )
}

fn render_browse_view(
    representation: &Representation,
    page: &BrowserPage,
    sort: BrowseSort,
    documents: &[BrowserDocument],
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let location = page.location.to_string_lossy();
    // The page addresses itself by its canonical location, which is how a
    // pin's link is built too, so the sidebar can tell which entry this is.
    let current_path = page
        .location
        .to_str()
        .map_or_else(|| "/browse".to_owned(), browse_url);
    let pinned = ui.and_then(|ui| {
        ui.pins
            .iter()
            .find(|pin| pin.canonical.as_deref() == Some(page.location.as_path()))
    });
    page_or_content(
        representation,
        "Browse files",
        &current_path,
        views,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex min-w-0 flex-wrap items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                a href=(sort.carry("/browse")) class="font-medium hover:text-blue-700" { "Browse" }
                @for crumb in &page.crumbs {
                    span aria-hidden="true" { "/" }
                    a href=(sort.carry(&crumb.href)) class="max-w-48 truncate font-mono hover:text-blue-700" { (&crumb.label) }
                }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between" {
                div class="min-w-0" {
                    p class="cr-eyebrow" { "Internal · owner only" }
                    h1 class="cr-title mt-1" { "Filesystem browser" }
                    p class="cr-lede mt-1 max-w-3xl" {
                        "Read-only access to files visible to the CR server process. Browsing starts at the database root; use "
                        code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { ".." }
                        " to move toward the filesystem root."
                    }
                    p class="cr-path mt-3 break-all" { (&location) }
                }
                div class="flex shrink-0 flex-wrap items-center gap-2" {
                    span class="cr-pill cr-pill-warn" { "read-only" }
                    @if let Some(here) = page.location.to_str() {
                        (render_pin_control(here, pinned, csrf_token))
                    }
                    a href=(sort.carry("/browse")) class="cr-button" { "Database root" }
                    @if let Some(parent) = &page.parent {
                        a href=(sort.carry(&browse_url(parent.to_string_lossy().as_ref()))) class="cr-button" { "Up" }
                    }
                }
            }
            @match &page.item {
                BrowserItem::Directory(entries) => {
                    div class="cr-table-shell" {
                        div class="overflow-x-auto" {
                            table class="min-w-full divide-y divide-gray-200 text-left text-sm" {
                                thead {
                                    tr {
                                        (browse_sort_heading(page, sort, BrowseSortField::Name, "Name", ""))
                                        (browse_sort_heading(page, sort, BrowseSortField::Created, "Created", ""))
                                        (browse_sort_heading(page, sort, BrowseSortField::Updated, "Updated", ""))
                                        th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "Type" }
                                        (browse_sort_heading(page, sort, BrowseSortField::Size, "Size", "text-right"))
                                        th scope="col" class="w-14 px-4 py-3" { span class="sr-only" { "Open" } }
                                    }
                                }
                                tbody class="divide-y divide-gray-100" {
                                    @if let Some(parent) = &page.parent {
                                        @let href = sort.carry(&browse_url(parent.to_string_lossy().as_ref()));
                                        tr {
                                            td class="px-4 py-3" {
                                                a href=(&href) class="font-mono font-semibold text-gray-900 hover:text-blue-700" {
                                                    span class="cr-file-icon" aria-hidden="true" { (DIRECTORY_ICON) }
                                                    ".."
                                                }
                                            }
                                            td {}
                                            td {}
                                            td class="px-4 py-3" { span class="cr-pill" { "parent" } }
                                            td class="px-4 py-3 text-right text-gray-400" { "—" }
                                            td class="px-4 py-3 text-right" { a href=(&href) aria-label="Open parent directory" class="font-semibold text-blue-700 hover:text-blue-900" { "→" } }
                                        }
                                    }
                                    @if entries.is_empty() && page.parent.is_none() {
                                        tr {
                                            td colspan="6" class="px-4 py-12 text-center text-gray-500" { "This directory is empty." }
                                        }
                                    } @else {
                                        @for entry in entries {
                                            @let href = entry.href.as_deref().map(|href| sort.carry(href));
                                            tr {
                                                td class="px-4 py-3" {
                                                    @if let Some(href) = &href {
                                                        a href=(href) class="font-mono font-semibold text-gray-900 hover:text-blue-700" {
                                                            span class="cr-file-icon" aria-hidden="true" { (entry.kind.icon()) }
                                                            (&entry.name)
                                                        }
                                                    } @else {
                                                        span class="font-mono text-gray-500" title="This name is not valid UTF-8 and cannot be put in a browser URL" {
                                                            span class="cr-file-icon" aria-hidden="true" { (entry.kind.icon()) }
                                                            (&entry.name)
                                                        }
                                                    }
                                                }
                                                td class="whitespace-nowrap px-4 py-3" {
                                                    (render_timestamp(entry.created.and_then(format_system_time).as_deref()))
                                                }
                                                td class="whitespace-nowrap px-4 py-3" {
                                                    (render_timestamp(entry.modified.and_then(format_system_time).as_deref()))
                                                }
                                                td class="px-4 py-3" { span class="cr-pill" { (entry.kind.label()) } }
                                                td class="whitespace-nowrap px-4 py-3 text-right cr-data" {
                                                    @if let Some(size) = entry.size { (format_file_size(size)) } @else { "—" }
                                                }
                                                td class="px-4 py-3 text-right" {
                                                    @if let Some(href) = &href {
                                                        a href=(href) aria-label=(format!("Open {}", entry.name)) class="font-semibold text-blue-700 hover:text-blue-900" { "→" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        div class="border-t border-gray-200 bg-gray-50 px-3 py-2 text-xs text-gray-600" {
                            (entries.len()) " entries · directories first · hidden files included"
                        }
                    }
                    @for document in documents {
                        section id=(document.anchor) aria-label=(&document.name) class="mt-6" {
                            @match &document.preview {
                                Ok(file) => {
                                    (render_file_preview(file, Some((&document.name, document.href.as_deref()))))
                                }
                                Err(message) => {
                                    div class="cr-table-shell px-4 py-3 text-sm text-gray-600" {
                                        span class="font-mono font-semibold text-gray-900" { (&document.name) }
                                        " could not be previewed: " (message)
                                    }
                                }
                            }
                        }
                    }
                }
                BrowserItem::File(file) => {
                    (render_file_preview(file, None))
                }
                BrowserItem::Other => {
                    div class="cr-empty-state" {
                        h2 class="text-lg font-semibold text-gray-900" { "Preview unavailable" }
                        p class="mt-2 text-sm text-gray-600" {
                            "This location is not a regular file or directory. Devices, sockets, and named pipes are never opened by the browser."
                        }
                    }
                }
            }
        },
        ui,
        csrf_token,
    )
}

/// Pin or unpin the location a browse page shows.
///
/// Unpinning submits the pin's stored spelling rather than this page's
/// location. A pin written through a symbolic link resolves to this page, but
/// only its own spelling names it in `.cr/pins.yaml`.
///
/// Both forms stay native (`UNBOOSTED`): a refusal — a stale token, the pin
/// limit — answers with an error document, which htmx will not swap into a
/// failed `POST`, the same reason the save-as-view form is native.
fn render_pin_control(here: &str, pinned: Option<&UiPin>, csrf_token: &str) -> Markup {
    html! {
        @match pinned {
            Some(pin) => {
                form method="post" action="/browse/unpin" hx-boost=(UNBOOSTED) {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    input type="hidden" name="path" value=(&pin.stored);
                    input type="hidden" name="from" value=(here);
                    button type="submit" class="cr-button" title="Remove this location from the sidebar" { "Unpin" }
                }
            }
            None => {
                form method="post" action="/browse/pin" hx-boost=(UNBOOSTED) {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    input type="hidden" name="path" value=(here);
                    input type="hidden" name="from" value=(here);
                    button type="submit" class="cr-button" title="Add this location to the sidebar" { "Pin to sidebar" }
                }
            }
        }
    }
}

/// One bounded file preview: the panel an opened file gets, and the panel a
/// directory's README or `SKILL.md` gets beneath its listing.
///
/// A directory document passes its name and link so the header says which
/// file is being shown and opens it on its own, as a code host's README header
/// does; an opened file already names itself in the breadcrumb and path above.
///
/// Text wraps; hexadecimal does not. A long line of prose or configuration is
/// read rather than scrolled to, and a minified file or a URL with no spaces
/// still breaks instead of pushing the panel wider than the page. A hex dump is
/// the opposite case: its value is in the aligned offset, byte, and character
/// columns, which wrapping would scramble, so it keeps horizontal scrolling.
fn render_file_preview(file: &BrowserFile, document: Option<(&str, Option<&str>)>) -> Markup {
    let (contents, class) = match &file.contents {
        BrowserFileContents::Text(contents) => (contents, "cr-file-preview cr-file-preview-wrap"),
        BrowserFileContents::Binary(contents) => (contents, "cr-file-preview"),
    };
    html! {
        div class="cr-table-shell overflow-hidden" {
            div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-600" {
                div class="flex flex-wrap items-center gap-2" {
                    @if let Some((name, href)) = document {
                        @if let Some(href) = href {
                            a href=(href) class="font-mono text-sm font-semibold text-gray-900 hover:text-blue-700" { (name) }
                        } @else {
                            span class="font-mono text-sm font-semibold text-gray-900" { (name) }
                        }
                    }
                    @match &file.contents {
                        BrowserFileContents::Text(_) => { span class="cr-pill" { "text preview" } }
                        BrowserFileContents::Binary(_) => { span class="cr-pill" { "binary · hex preview" } }
                    }
                    span { (format_file_size(file.total_bytes)) }
                }
                span {
                    "Showing " (format_file_size(file.bytes_shown as u64))
                    @if file.truncated { " · preview truncated" }
                }
            }
            pre class=(class) tabindex="0" {
                code { (contents) }
            }
        }
    }
}

/// A sortable directory-listing heading, in the same shape as a view table's.
///
/// A directory whose path is not UTF-8 cannot be put in a URL, so it gets its
/// headings as plain text in the order it was listed in.
fn browse_sort_heading(
    page: &BrowserPage,
    sort: BrowseSort,
    field: BrowseSortField,
    heading: &str,
    align: &str,
) -> Markup {
    let next = sort.toggled(field);
    let spoken_direction = match next.direction {
        ViewSortDirection::Asc => "ascending",
        ViewSortDirection::Desc => "descending",
    };
    html! {
        th scope="col" aria-sort=(sort.aria_state(field)) class=(format!("whitespace-nowrap px-4 py-3 font-semibold text-gray-700 {align}")) {
            @if let Some(location) = page.location.to_str() {
                a href=(next.carry(&browse_url(location))) aria-label=(format!("Sort by {} {spoken_direction}", heading.to_lowercase())) class="inline-flex items-center gap-1.5 hover:text-indigo-700" {
                    (heading) span aria-hidden="true" class="text-gray-400" { (sort.indicator(field)) }
                }
            } @else {
                (heading)
            }
        }
    }
}

/// A filesystem time in the audit journal's format, so one renderer shows both.
///
/// `None` for a time RFC 3339 cannot write — a timestamp any process may set
/// can be set to the year 30000, and a listing must not fail over it.
fn format_system_time(time: SystemTime) -> Option<String> {
    let nanoseconds = match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).ok()?,
        Err(before) => -i128::try_from(before.duration().as_nanos()).ok()?,
    };
    OffsetDateTime::from_unix_timestamp_nanos(nanoseconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn format_file_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GiB", 1024 * 1024 * 1024),
        ("MiB", 1024 * 1024),
        ("KiB", 1024),
        ("B", 1),
    ];
    for (unit, divisor) in UNITS {
        if bytes >= divisor || divisor == 1 {
            if divisor == 1 {
                return format!("{bytes} B");
            }
            return format!("{:.1} {unit}", bytes as f64 / divisor as f64);
        }
    }
    unreachable!("the byte unit table always contains bytes")
}

/// The label for a principal kind. `UserKind` has no `Display`: its serialized
/// form belongs to the on-disk schema, not to the UI.
fn user_kind_label(kind: UserKind) -> &'static str {
    match kind {
        UserKind::Human => "human",
        UserKind::Service => "service",
    }
}

fn render_audit_view(
    representation: &Representation,
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
    page_or_content(
        representation,
        "Audit log",
        "/audit",
        views,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                span class="text-gray-900" { "Audit log" }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                div {
                    p class="cr-eyebrow" { "Tamper-evident journal" }
                    h1 class="cr-title mt-1" { "Global audit log" }
                    p class="cr-lede mt-1 max-w-2xl" {
                        "Every accepted record mutation, newest first. Expand an event to inspect its field-level changes."
                    }
                }
                a href="/api/v1/audit/log" hx-boost=(UNBOOSTED) class="cr-button" { "JSON API" span aria-hidden="true" { " ↗" } }
            }
            form method="get" action=(reset_url) class="cr-surface mb-4 grid gap-3 p-3 sm:grid-cols-[1fr_1fr_1fr_1fr_auto]" {
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-gray-600" { "Collection" }
                    input type="text" name="collection" value=(query.collection.as_deref().unwrap_or("")) placeholder="deals" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-gray-600" { "Record ID" }
                    input type="text" name="id" value=(query.id.as_deref().unwrap_or("")) placeholder="acme-renewal" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-gray-600" { "Agent" }
                    input type="text" name="agent" value=(query.agent.as_deref().unwrap_or("")) placeholder="claude-code" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                label class="block" {
                    span class="mb-1 block text-xs font-semibold text-gray-600" { "Agent session" }
                    input type="text" name="session" value=(query.session.as_deref().unwrap_or("")) placeholder="6d1baa69" autocomplete="off" spellcheck="false" class="w-full border px-3 py-2 font-mono text-sm outline-none";
                }
                div class="flex items-end gap-2" {
                    button type="submit" class="cr-button cr-button-primary" { "Filter events" }
                    a href=(reset_url) class="cr-button" { "Reset" }
                }
            }
            (render_audit_entries(&page.data))
            div class="cr-surface mt-4 flex flex-col gap-3 px-4 py-3 text-sm sm:flex-row sm:items-center sm:justify-between" {
                p class="text-gray-600" { "Showing events " (first) "–" (last) " newest first" }
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
                div class="p-10 text-center text-sm text-gray-500" {
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
                                a href=(audit_filter_url(&entry.payload.record.collection, &entry.payload.record.id)) class="mt-3 block truncate font-mono text-sm font-semibold text-gray-900 hover:text-blue-700" {
                                    (entry.payload.record.reference())
                                }
                                p class="mt-1 text-xs text-gray-500" {
                                    "by " span class="font-medium text-gray-700" { (&entry.payload.actor) }
                                    @if let Some(operator) = entry
                                        .payload
                                        .access
                                        .as_ref()
                                        .and_then(|access| access.impersonated_by.as_ref())
                                    {
                                        " · impersonated by " span class="font-medium text-gray-700" { (&operator.display) }
                                    }
                                    @if let Some(agent) = &entry.payload.agent {
                                        " · via " a href=(audit_agent_url(&agent.id)) class="font-medium text-gray-700 hover:text-blue-700" { (&agent.id) }
                                    }
                                    " · " time datetime=(&entry.payload.timestamp) { (&entry.payload.timestamp) }
                                }
                                @if let Some(agent) = &entry.payload.agent {
                                    (render_audit_agent(agent))
                                }
                                @if let Some(authorization) = &entry.payload.authorization {
                                    p class="mt-2 text-xs text-gray-500" {
                                        "Authorization "
                                        span class="font-medium text-gray-700" { (authorization.mode.label()) }
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
                                    p class="mt-2 text-sm text-gray-600" { (message) }
                                }
                            }
                            span class="cr-data shrink-0" title=(&entry.hash) { (short_hash(&entry.hash)) }
                        }
                        details class="mt-4 border-t border-gray-100 pt-4" {
                            summary class="cursor-pointer text-sm font-semibold text-blue-700 hover:text-blue-900" {
                                (entry.payload.changes.len()) " field-level " @if entry.payload.changes.len() == 1 { "change" } @else { "changes" }
                            }
                            div class="mt-3 space-y-3" {
                                @for change in &entry.payload.changes {
                                    div class="rounded-lg border border-gray-200 bg-gray-50 p-3" {
                                        div class="flex flex-wrap items-center gap-2" {
                                            span class="rounded bg-gray-200 px-2 py-0.5 text-xs font-bold uppercase text-gray-700" { (audit_change_operation(change)) }
                                            code class="text-xs text-gray-700" { (audit_change_path(change)) }
                                        }
                                        div class="mt-3 grid gap-3 lg:grid-cols-2" {
                                            @if let Some(before) = audit_change_before(change) {
                                                div {
                                                    p class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500" { "Before" }
                                                    pre class="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-red-100 bg-red-50 p-3 text-xs leading-5 text-red-950" { (json_preview(before)) }
                                                }
                                            }
                                            @if let Some(after) = audit_change_after(change) {
                                                div {
                                                    p class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500" { "After" }
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
        select name="filter_operator" data-filter-operator="true" aria-label=(format!("Filter operator {}", index + 1)) class="min-w-0 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 xl:col-span-3" {
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
            span class="block px-3 py-2 text-sm text-gray-400" { "No value needed" }
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
                select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
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
            select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                option value="" selected[value.is_empty()] { "Select a value…" }
                option value="true" selected[value == "true"] { "True" }
                option value="false" selected[value == "false"] { "False" }
            }
        },
        Some(SchemaFieldKind::Integer { .. }) => html! {
            input type="number" step="1" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact number" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        Some(SchemaFieldKind::Number { .. }) => html! {
            input type="number" step="any" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact number" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        Some(SchemaFieldKind::String { input_type, .. }) => html! {
            input type=(input_type) name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Exact value" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
        },
        _ => html! {
            input type="text" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Typed YAML value" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
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
        div data-filter-row="true" class="grid gap-2 rounded-xl border border-gray-200 bg-gray-50 p-3 md:grid-cols-2 xl:grid-cols-12 xl:items-center" {
            select name="filter_field" data-filter-field="true" aria-label=(format!("Filter field {}", index + 1)) class="min-w-0 w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 xl:col-span-4" {
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
            button type="button" data-remove-filter="true" aria-label=(format!("Remove filter {}", index + 1)) class="justify-self-start rounded-lg px-3 py-2 text-sm font-semibold text-gray-500 hover:bg-red-50 hover:text-red-700 md:col-span-2 xl:col-span-1 xl:justify-self-end" { "Remove" }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn render_view_records(
    representation: &Representation,
    view: &ViewDefinition,
    columns: &[String],
    available_columns: &[String],
    page: &ViewPage,
    activity: &BTreeMap<String, RecordActivity>,
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
    let results = view_results(
        view, columns, page, activity, query, schema, csrf_token, updatable,
    );
    // The one route that can answer with something smaller than its content.
    // It comes first because it is the narrower answer: everything below builds
    // the heading, the search box and the filter panel, none of which the
    // request asked for.
    //
    // Three elements travel with the region, marked `hx-swap-oob` so htmx
    // applies each to the element of the same id already on the page and then
    // drops it from the content it swaps. Two are the whole of the heading that
    // depends on the results — the record count and the badge counting applied
    // filters — and they are rendered here by the same functions the heading
    // below calls, with the attribute as their only difference, so neither can
    // start disagreeing with the page it patches.
    //
    // The third is the announcement, and it is last because it is not part of
    // the page's appearance at all: it is the sentence a reader who cannot see
    // the table is told about the swap that just happened, sent into the live
    // region the shell rendered. It patches that region's *contents* rather than
    // replacing it, for the reason `view_results_announcement` explains.
    if representation.wants(VIEW_TABLE_REGION) {
        return fragment(
            &view.title,
            html! {
                (results)
                (view_record_count(page.total, OutOfBand::Yes))
                (view_filter_summary(active_filter_count, OutOfBand::Yes))
                (view_results_announcement(page))
            },
        );
    }
    page_or_content(
        representation,
        &view.title,
        &format!("/{}", encode_segment(&view.name)),
        navigation,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                span class="text-gray-900" { (&view.title) }
            }
            div class="cr-page-heading mb-4 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between" {
                div {
                    div class="flex flex-wrap items-center gap-2" {
                        span class="cr-title-icon" aria-hidden="true" { (view_icon(view)) }
                        h1 class="cr-title" { (&view.title) }
                        span class="cr-pill" {
                            @if view.saved { "saved view" } @else { "automatic view" }
                        }
                        @if view.layout == ViewLayout::Kanban {
                            span class="cr-pill cr-pill-accent" { "kanban" }
                        }
                        (view_record_count(page.total, OutOfBand::No))
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
                    // One form, two submit buttons, and both of them only change
                    // which records are listed: the magnifying glass beside the
                    // search box and "Apply view" at the bottom of the filter
                    // panel. Targeting the results region is what keeps the
                    // panel open across an apply — it is not re-rendered, so the
                    // browser never has a reason to close it or to forget what
                    // was typed into it.
                    //
                    // It stays an ordinary `method="get"` form with an `action`,
                    // so with JavaScript off, or before the deferred script has
                    // run, the same click navigates to the same URL and gets the
                    // same records inside a whole page. `hx-push-url="true"`
                    // makes the enhanced path end on that URL too, which is the
                    // property that keeps every filtered, sorted and searched
                    // state shareable: what the reader copies out of the address
                    // bar is what a stranger with no JavaScript would be served.
                    form method="get" action=(reset_url.clone())
                        hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_IN_PLACE) hx-push-url="true"
                        data-filter-builder="true" data-max-filters=(MAX_VIEW_FILTERS) class="contents" {
                        div class="relative min-w-48 flex-1 sm:flex-none" {
                            label class="sr-only" { "Search records" }
                            input type="search" name="q" value=(query.q.as_deref().unwrap_or("")) aria-label="Search records" placeholder="Search records…" autocomplete="off" data-view-search="true" class="w-full border bg-white py-2 pl-3 pr-10 text-sm outline-none placeholder:text-gray-400 sm:w-56";
                            button type="submit" aria-label="Submit search" title="Search" class="absolute inset-y-1 right-1 inline-flex w-8 items-center justify-center rounded-md text-gray-400 hover:bg-gray-100 hover:text-blue-700" { "⌕" }
                        }
                        details class="relative" data-filter-disclosure="true" {
                            (view_filter_summary(active_filter_count, OutOfBand::No))
                            div data-filter-panel="true" class="cr-popover cr-filter-popover z-30 space-y-4 overflow-y-auto p-4 sm:p-5" {
                                div {
                                    div class="mb-3 flex flex-wrap items-center justify-between gap-3" {
                                        div {
                                            div class="flex items-center gap-2" {
                                                h2 class="text-sm font-bold text-gray-900" { "Filters" }
                                                label {
                                                    span class="sr-only" { "Condition match mode" }
                                                    select name="filter_match" aria-label="Condition match mode" class="rounded-full border-0 bg-gray-100 py-1 pl-2.5 pr-8 text-xs font-semibold text-gray-600 outline-none ring-indigo-500 focus:ring-2" {
                                                        option value="all" selected[query.filter_match == ViewFilterMatch::All] { "All conditions match" }
                                                        option value="any" selected[query.filter_match == ViewFilterMatch::Any] { "Any condition matches" }
                                                    }
                                                }
                                            }
                                            p class="mt-1 text-xs text-gray-500" { "Field controls and allowed values come from the collection schema." }
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
                                div class="border-t border-gray-100 pt-4" {
                                    details open[query_columns_custom(query)] {
                                        summary class="cursor-pointer list-none text-sm font-bold text-gray-900" {
                                            span class="inline-flex items-center gap-2" {
                                                "Columns"
                                                span class="rounded-full bg-gray-100 px-2 py-0.5 text-xs font-semibold text-gray-600" { (columns.len()) " shown" }
                                            }
                                        }
                                        input type="hidden" name="columns" value="custom";
                                        p class="mt-1 text-xs text-gray-500" { "Choose the fields shown in the table or on Kanban cards. Select at least one." }
                                        div role="group" aria-label="Visible columns" class="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4" {
                                            @for column in available_columns {
                                                label class="flex items-center gap-2 rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 hover:border-indigo-300 hover:bg-indigo-50/40" {
                                                    input type="checkbox" name="column" value=(column) checked[columns.contains(column)] class="size-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500";
                                                    span class="truncate" title=(column) { (humanize_field_name(column)) }
                                                }
                                            }
                                        }
                                    }
                                }
                                div class="border-t border-gray-100 pt-4" {
                                    div class="mb-3" {
                                        h2 class="text-sm font-bold text-gray-900" { "Sorting" }
                                        p class="mt-1 text-xs text-gray-500" { "Newest first by default. Missing values stay last; record ID breaks ties." }
                                    }
                                    div class="grid gap-3 sm:grid-cols-2" {
                                        label {
                                            span class="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "Sort by" }
                                            select name="sort_field" aria-label="Sort by" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                                option value="" selected[view_sort_field(query).is_none()] { "None (record ID order)" }
                                                option value="$created_at" selected[view_sort_field(query) == Some("$created_at")] { "Created (default)" }
                                                option value="$updated_at" selected[view_sort_field(query) == Some("$updated_at")] { "Updated" }
                                                option value="$id" selected[view_sort_field(query) == Some("$id")] { "Record ID" }
                                                @for field in &filter_fields {
                                                    option value=(&field.key) selected[view_sort_field(query) == Some(field.key.as_str())] { (&field.label) }
                                                }
                                            }
                                        }
                                        label {
                                            span class="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "Direction" }
                                            select name="sort_direction" aria-label="Sort direction" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                                option value="asc" selected[query.sort_direction == ViewSortDirection::Asc] { "Ascending" }
                                                option value="desc" selected[query.sort_direction == ViewSortDirection::Desc] { "Descending" }
                                            }
                                        }
                                    }
                                }
                                div class="flex flex-wrap items-center justify-end gap-2 border-t border-gray-100 pt-4" {
                                    // "Clear all" is the one control in this
                                    // panel that is deliberately *not* a
                                    // targeted swap. It goes to the view's bare
                                    // URL, and the conditions it clears are the
                                    // rendered contents of the panel beside it:
                                    // swapping only the results would leave the
                                    // reader looking at the filters they just
                                    // discarded, still typed in, above rows that
                                    // no longer reflect them. A whole page is the
                                    // correct answer for the one action whose
                                    // point is that the panel should be empty.
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
            // The banner a successful mutation redirects to, carrying the
            // notice in the query string. It is plain markup and deliberately
            // not a live region of its own: it arrives *with* the page, which is
            // the one case a live region does not reliably announce, and a
            // second `role="status"` on the page would mean two candidates for
            // one announcement. `cr.js` copies this text into `ANNOUNCE_REGION`
            // a beat after the page settles, which is a mutation of a region
            // that was already being watched. With JavaScript off nothing is
            // announced and nothing needs to be: the reader has just been
            // navigated to a new document and this is the first thing in it.
            @if let Some(notice) = query.notice.as_deref() {
                div data-notice="true" class="mb-5 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800" { (notice) }
            }
            (results)
        },
        ui,
        csrf_token,
    )
}

/// Every sortable column heading of a table view, left to right, as
/// `(query field, heading text, spoken name)`.
///
/// The three differ, which is why they are all here: the record id column is
/// headed `ID` and read out as "record ID", an audit column is headed `Created`
/// and read out as "created", and a view's own column is headed by its raw front
/// matter key — which is what a reader correlating the table with a record file
/// needs to see — while being read out humanized.
fn sortable_headings(columns: &[String]) -> Vec<(&str, String, String)> {
    std::iter::once(("$id", "ID".to_owned(), "record ID".to_owned()))
        .chain(
            ACTIVITY_COLUMNS
                .iter()
                .map(|(field, label)| (*field, humanize_field_name(label), (*label).to_owned())),
        )
        .chain(
            columns
                .iter()
                .map(|column| (column.as_str(), column.clone(), humanize_field_name(column))),
        )
        .collect()
}

/// The DOM id of the sort link in the *n*th column heading.
///
/// It exists so that focus survives the swap. htmx restores focus after a swap by
/// looking up the id of the element that had it, and replacing the results region
/// destroys the header cell the reader just activated: without an id a keyboard or
/// screen reader user is returned to the top of the document by every re-sort,
/// which is worse than the full page load this replaces rather than better. With
/// one they stay on the column they are sorting and hear its label — which the
/// same swap has just updated from "sort by name ascending" to "sort by name
/// descending" — read out again.
///
/// The position rather than the field name, because a field here is a front matter
/// key and may be any string a YAML mapping key may be, including one that
/// collides with another heading's. The position is unique by construction and it
/// is stable across exactly the swaps that need it: re-sorting, paging, filtering
/// and searching all leave the column set alone.
fn sort_link_id(index: usize) -> String {
    format!("cr-sort-{index}")
}

/// The cursor links, shared by the table's pager and the Kanban board's.
///
/// One function because the two layouts render the same three links with the same
/// ids and the same swap, and a second copy is how one of them would end up
/// reloading the page after the other stopped. The ids are here for the reason
/// `sort_link_id` explains: "Next" is inside the region it replaces, so htmx needs
/// a name to put focus back on.
fn view_pager_links(view: &ViewDefinition, query: &ViewQuery, page: &ViewPage) -> Markup {
    html! {
        div class="flex items-center gap-2" {
            @if page.records.is_empty() && page.start > 0 {
                a id="cr-page-first" href=(view_page_url(view, query, page.limit, ViewPosition::Start)) class="cr-button"
                    hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" { "First page" }
            }
            @if let Some(cursor) = page.previous.as_deref() {
                a id="cr-page-previous" href=(view_page_url(view, query, page.limit, ViewPosition::Before(cursor))) rel="prev" class="cr-button"
                    hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" { "Previous" }
            }
            @if let Some(cursor) = page.next.as_deref() {
                a id="cr-page-next" href=(view_page_url(view, query, page.limit, ViewPosition::After(cursor))) rel="next" class="cr-button"
                    hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" { "Next" }
            }
        }
    }
}

/// Whether an element is being rendered into the page it belongs to, or beside a
/// fragment as a patch for the copy already on the page.
///
/// A boolean would read as `view_record_count(total, true)` at the call site,
/// where `true` says nothing about which of the two an answer is sending. It
/// matters which: an `hx-swap-oob` attribute in a *document* would be acted on
/// the next time a boosted navigation swapped that document into the body — htmx
/// would patch the element into place and then remove it from the incoming
/// markup, so the page would arrive with the element missing.
#[derive(Copy, Clone)]
enum OutOfBand {
    Yes,
    No,
}

impl OutOfBand {
    /// The `hx-swap-oob` attribute value, or nothing at all.
    ///
    /// `hx-swap-oob="true"` means "replace the element with this id, wherever it
    /// is". Maud omits an attribute given `None`, so the document and the patch
    /// come out of one renderer differing by exactly this attribute, which is
    /// what `tests/targeted_swap_http.rs` asserts by stripping it and comparing.
    fn attribute(self) -> Option<&'static str> {
        match self {
            Self::Yes => Some("true"),
            Self::No => None,
        }
    }
}

/// The heading's "*n* records" pill.
///
/// Lives outside the results region and is changed by every filter and search
/// that hits it, which is why it is a function: the heading renders it and a
/// results fragment sends it again as an out-of-band patch, and two copies of
/// `page.total` in two `html!` blocks is how a count starts disagreeing with the
/// pager six inches below it.
fn view_record_count(total: usize, out_of_band: OutOfBand) -> Markup {
    html! {
        span id=(VIEW_COUNT_ID) class="cr-pill" hx-swap-oob=[out_of_band.attribute()] { (total) " records" }
    }
}

/// The one-based positions of the first and last record on this page.
///
/// Both pager footers and the announcement below state the same range, and they
/// are three renderings of one fact rather than three calculations of it. An
/// empty page is `(0, page.start)` — "showing 0 of 33" after a filter emptied
/// the page the reader was on — which is the arithmetic the table footer has
/// always printed, kept here so the sentence a screen reader hears and the
/// sentence on screen cannot disagree.
fn page_range(page: &ViewPage) -> (usize, usize) {
    let first = if page.records.is_empty() {
        0
    } else {
        page.start + 1
    };
    (first, page.start + page.records.len())
}

/// What a reader who cannot see the table is told after a page turn, a re-sort,
/// a search or a filter apply.
///
/// One sentence, and the same sentence for all four, because it states the fact
/// every one of them changes: which records are on screen now. The alternative —
/// a message per control, "sorted by name descending", "2 filters applied" —
/// says what was *asked for*, which the reader already knows, having just asked;
/// and for sorting and filtering it would also duplicate what htmx's focus
/// restoration already reads out, since the sort link's own label is re-rendered
/// by the same swap and the reader is returned to it.
///
/// "1 to 10" rather than the footer's "1–10": an en dash is read out
/// inconsistently — as a pause, as "dash", or as nothing — and this string
/// exists only to be spoken.
fn view_results_summary(page: &ViewPage) -> String {
    let (first, last) = page_range(page);
    if page.records.is_empty() {
        if page.total == 0 {
            "No records match".to_owned()
        } else {
            format!("No records on this page, {} in total", page.total)
        }
    } else {
        format!("Showing records {first} to {last} of {}", page.total)
    }
}

/// The results announcement as the third out-of-band passenger of a results
/// swap.
///
/// `hx-swap-oob="innerHTML"` rather than the `"true"` the other two use, and the
/// difference is the entire reason this is a separate function. `"true"` means
/// *replace the element*, which is right for the count pill and the filter
/// summary and would be wrong here: an assistive technology announces a live
/// region because it is watching that element, and replacing the node it was
/// watching with an identical one carrying text is how a region ends up silent.
/// Swapping the region's contents leaves the node — and the watcher on it — in
/// place, which is also why `ANNOUNCE_REGION` is rendered by the shell rather
/// than travelling with any fragment.
///
/// It is sent only with a fragment. A whole document must not carry it for the
/// reason `OutOfBand` gives — a boosted navigation would apply the patch and
/// then deliver the page — and it would be wrong even if htmx ignored it, since
/// arriving on a page is not a change to announce.
fn view_results_announcement(page: &ViewPage) -> Markup {
    html! {
        div id=(ANNOUNCE_REGION) hx-swap-oob="innerHTML" { (view_results_summary(page)) }
    }
}

/// The filter disclosure's summary: the word "Filter", and a badge counting the
/// conditions the current URL applies.
///
/// The `<details>` element around it is what the reader opens, and a targeted
/// apply leaves it strictly alone — that is the point of the phase. Its summary
/// is the exception, because it reports a number the apply just changed, and it
/// can be replaced without disturbing either the open state or the controls
/// inside. `data-active-filters` moved here from the `<details>` for that reason:
/// it states the same count, so it has to live on the element that gets it right.
fn view_filter_summary(active: usize, out_of_band: OutOfBand) -> Markup {
    html! {
        summary id=(VIEW_FILTER_SUMMARY_ID) data-active-filters=(active) class="cr-button cursor-pointer list-none gap-2" hx-swap-oob=[out_of_band.attribute()] {
            "Filter"
            @if active > 0 {
                span class="cr-pill cr-pill-accent" { (active) }
            }
        }
    }
}

/// The region of a view page that a page turn, a re-sort, a filter or a search
/// replaces, and the only part of the page any of them change.
///
/// Split out of `render_view_records` so that one URL can answer with either
/// the whole page or just this, from the same data and the same markup. The
/// pagination, sort, filter and search controls are what ask for it, and the
/// filter panel surviving an apply falls out of not re-rendering it: the panel is
/// the same DOM nodes before and after, so the browser has no occasion to close
/// the disclosure or to forget what was typed into it.
///
/// The fragment carries its own root element, id and all, which is what lets a
/// swap be `outerHTML`: the response is the element it replaces rather than a
/// bag of children whose container the client has to already have right. The
/// root is a wrapper rather than the table shell itself because a Kanban view's
/// results are two sibling elements — the grouping caption and the board — and
/// the id has to name the same region in both layouts.
#[allow(clippy::too_many_arguments)]
fn view_results(
    view: &ViewDefinition,
    columns: &[String],
    page: &ViewPage,
    activity: &BTreeMap<String, RecordActivity>,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
    updatable: &BTreeSet<String>,
) -> Markup {
    let (first, last) = page_range(page);
    html! {
        div id=(VIEW_TABLE_REGION) {
            @if view.layout == ViewLayout::Kanban {
                (render_kanban_board(view, columns, page, query, schema, csrf_token, updatable))
            } @else {
            div class="cr-table-shell" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-gray-200 text-left text-sm" {
                        thead {
                            tr {
                                // One loop over the three kinds of sortable
                                // heading — the record id, the two audit
                                // timestamps and the view's own columns — rather
                                // than three near-identical blocks, because every
                                // one of them now needs its position for
                                // `sort_link_id` and a position is only
                                // meaningful across the whole row.
                                @for (index, (field, heading, spoken)) in sortable_headings(columns).iter().enumerate() {
                                    th scope="col" aria-sort=(sort_aria_state(query, field)) class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" {
                                        a id=(sort_link_id(index)) href=(view_sort_url(view, query, field, page.limit)) aria-label=(sort_link_label(query, spoken, field)) class="inline-flex items-center gap-1.5 hover:text-indigo-700"
                                            hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" {
                                            (heading) span aria-hidden="true" class="text-gray-400" { (sort_indicator(query, field)) }
                                        }
                                    }
                                }
                                th scope="col" class="px-4 py-3 text-right font-semibold text-gray-700" { "" }
                            }
                        }
                        tbody class="divide-y divide-gray-100" {
                            @if page.records.is_empty() {
                                tr { td colspan=(columns.len() + ACTIVITY_COLUMNS.len() + 2) class="px-4 py-12 text-center text-gray-500" { "No records match this view." } }
                            } @else {
                                @for record in &page.records {
                                    @let record_activity = activity.get(&record.id);
                                    tr {
                                        td class="whitespace-nowrap px-4 py-3 font-mono text-xs font-semibold" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="text-gray-900 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        }
                                        td class="whitespace-nowrap px-4 py-3" {
                                            (render_timestamp(record_activity.map(|activity| activity.created_at.as_str())))
                                        }
                                        td class="whitespace-nowrap px-4 py-3" {
                                            (render_timestamp(record_activity.map(|activity| activity.updated_at.as_str())))
                                        }
                                        @for column in columns {
                                            td class="max-w-sm px-4 py-3 text-gray-700" {
                                                a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="line-clamp-2 hover:text-indigo-700 hover:underline" { (record_value(record, column)) }
                                            }
                                        }
                                        td class="whitespace-nowrap px-4 py-3 text-right" {
                                            a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) aria-label=(format!("View {}", record.id)) title="Open record" class="inline-flex size-6 items-center justify-center rounded text-gray-400 hover:bg-gray-100 hover:text-indigo-700" {
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
                div class="flex flex-col gap-2 border-t border-gray-200 bg-gray-50 px-3 py-2 text-xs sm:flex-row sm:items-center sm:justify-between" {
                    p class="text-gray-600" {
                        "Showing " (first) "–" (last) " of " (page.total)
                    }
                    (view_pager_links(view, query, page))
                }
            }
            }
        }
    }
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
                form method="post" action=(action) hx-boost=(UNBOOSTED) class="space-y-3" {
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
                        h2 class="text-sm font-bold text-gray-900" { "Save current view" }
                        p class="mt-1 text-xs leading-5 text-gray-500" { "Preserves applied filters, all/any matching, layout, columns, and sorting. Search text remains shareable in the URL." }
                    }
                    label class="block" {
                        span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "View name" }
                        input required name="name" placeholder="enterprise-deals" autocomplete="off" class="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
                    }
                    label class="block" {
                        span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "Title (optional)" }
                        input name="title" placeholder=(format!("{} copy", view.title)) autocomplete="off" class="w-full rounded-lg border border-gray-300 px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2";
                    }
                    div class="grid gap-3 sm:grid-cols-2" {
                        label class="block" {
                            span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "Layout" }
                            select name="layout" aria-label="Layout" data-view-layout="true" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2" {
                                option value="table" selected[view.layout == ViewLayout::Table] { "Table" }
                                option value="kanban" selected[view.layout == ViewLayout::Kanban] { "Kanban" }
                            }
                        }
                        label class="block" {
                            span class="mb-1 block text-xs font-semibold uppercase tracking-wide text-gray-500" { "Group Kanban by" }
                            select name="group_by" aria-label="Group Kanban by" data-view-group-by="true" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-400" {
                                option value="" selected[view.group_by.is_none()] { "Choose a field…" }
                                @for column in available_columns {
                                    option value=(column) selected[view.group_by.as_deref() == Some(column.as_str())] { (humanize_field_name(column)) }
                                }
                            }
                        }
                    }
                    p class="text-xs leading-5 text-gray-500" { "Kanban uses the chosen front matter field as lanes; moving a card updates that field through the audited database path." }
                    button type="submit" class="cr-button cr-button-primary w-full" { "Save view" }
                }
            }
        }
    }
}

fn render_kanban_board(
    view: &ViewDefinition,
    columns: &[String],
    page: &ViewPage,
    query: &ViewQuery,
    schema: Option<&JsonValue>,
    csrf_token: &str,
    updatable: &BTreeSet<String>,
) -> Markup {
    let group_by = view
        .group_by
        .as_deref()
        .expect("validated Kanban views have a group_by field");
    let lanes = kanban_lanes(&page.records, group_by, schema);
    let card_columns = columns
        .iter()
        .filter(|column| column.as_str() != group_by)
        .take(5)
        .collect::<Vec<_>>();
    let (first, last) = page_range(page);

    html! {
        div class="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-gray-600" {
            p {
                "Kanban grouped by " code class="rounded bg-gray-200 px-1.5 py-0.5 font-mono text-xs font-semibold text-gray-900" { (group_by) }
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
                        class="cr-kanban-lane w-72 shrink-0 p-2.5"
                    {
                        div class="mb-2 flex items-center justify-between gap-3 px-1" {
                            h2 class="text-sm font-semibold text-gray-900" { (&lane.label) }
                            span class="cr-pill bg-white" { (lane.records.len()) }
                        }
                        div class="min-h-20 space-y-2" {
                            @if lane.records.is_empty() {
                                p class="rounded-xl border border-dashed border-gray-300 px-4 py-8 text-center text-xs text-gray-500" { "Drop cards here" }
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
                                        a href=(format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id))) class="break-all font-mono text-sm font-bold text-gray-900 hover:text-indigo-700 hover:underline" { (&record.id) }
                                        span aria-hidden="true" class="select-none text-gray-300" { "⠿" }
                                    }
                                    @if !card_columns.is_empty() {
                                        dl class="mt-2 space-y-1" {
                                            @for column in &card_columns {
                                                div {
                                                    dt class="text-[0.65rem] font-bold uppercase tracking-wide text-gray-400" { (column) }
                                                    dd class="mt-0.5 line-clamp-2 text-sm text-gray-700" { (record_value(record, column)) }
                                                }
                                            }
                                        }
                                    }
                                    @if can_move {
                                        details class="cr-kanban-move mt-3 border-t border-gray-100 pt-2" {
                                            summary class="cursor-pointer list-none" { "Move card…" }
                                            form method="post" action=(kanban_move_url(view, &record.id)) hx-boost=(UNBOOSTED) class="flex items-center gap-2" {
                                                input type="hidden" name="_csrf" value=(csrf_token);
                                                label class="min-w-0 flex-1" {
                                                    span class="sr-only" { "Move " (&record.id) " to" }
                                                    select name="target" aria-label=(format!("Move {} to", record.id)) class="w-full rounded-lg border border-gray-300 bg-white px-2 py-1.5 text-xs outline-none ring-indigo-500 focus:ring-2" {
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
            p class="text-gray-600" {
                "Showing " (first) "–" (last) " of " (page.total)
            }
            (view_pager_links(view, query, page))
        }
    }
}

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
            submitted: None,
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

/// What a single-valued control shows: the submitted text when this is a
/// re-render, and otherwise the stored value written out for display.
fn field_control_text(field: &SchemaFormField) -> String {
    match &field.submitted {
        Some(values) => values.first().cloned().unwrap_or_default(),
        None => field_text_value(field.value.as_ref()),
    }
}

/// The same, for the structured-YAML textarea, whose stored rendering is YAML
/// rather than a bare string.
fn field_yaml_text(field: &SchemaFormField) -> String {
    match &field.submitted {
        Some(values) => values.first().cloned().unwrap_or_default(),
        None => field
            .value
            .as_ref()
            .map(serialize_yaml_value)
            .unwrap_or_default(),
    }
}

/// Whether a select or checkbox option is the one the form shows as chosen.
///
/// A re-render compares the option's submitted text, because that is the only
/// thing the browser sent back and the submitted text is what the user chose. A
/// first render compares the stored value, so an enum of numbers or tagged
/// values keeps matching by value rather than by however YAML printed it.
fn option_is_chosen(field: &SchemaFormField, option: &YamlValue) -> bool {
    if let Some(values) = &field.submitted {
        return values
            .iter()
            .any(|value| *value == serialize_yaml_value(option));
    }
    match (&field.kind, &field.value) {
        (SchemaFieldKind::MultiSelect(_), Some(YamlValue::Sequence(values))) => {
            values.contains(option)
        }
        (SchemaFieldKind::MultiSelect(_), _) => false,
        (_, value) => value.as_ref() == Some(option),
    }
}

/// Whether the form shows this field as having no value, which selects the blank
/// option of a `<select>`. A submitted field is unset when the browser sent
/// nothing for it or sent only the blank option's empty value.
fn field_is_unset(field: &SchemaFormField) -> bool {
    match &field.submitted {
        Some(values) => values.iter().all(|value| value.is_empty()),
        None => field.value.is_none(),
    }
}

fn render_schema_field(field: &SchemaFormField, diagnostics: &[String]) -> Markup {
    let name = format!("attribute.{}", field.key);
    let wide = schema_field_is_wide(&field.kind);
    let unset = field_is_unset(field);
    // Maud writes an attribute with a `[…]` value only when the option is
    // `Some`, so a field nothing was said about carries no `aria-invalid` at all
    // rather than carrying `aria-invalid="false"`.
    let invalid = (!diagnostics.is_empty()).then_some("true");
    let field_class = if diagnostics.is_empty() {
        if wide {
            "cr-field p-4 sm:col-span-2"
        } else {
            "cr-field p-4"
        }
    } else if wide {
        "cr-field cr-field-invalid p-4 sm:col-span-2"
    } else {
        "cr-field cr-field-invalid p-4"
    };
    html! {
        div class=(field_class) {
            div class="mb-2 flex items-start justify-between gap-3" {
                label for=(format!("field-{}", field.key)) class="text-sm font-semibold text-gray-900" {
                    (&field.label)
                    @if field.required {
                        span class="ml-1 text-red-500" aria-hidden="true" { "*" }
                    }
                }
                span class="shrink-0 rounded-md bg-white px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wide text-gray-500 shadow-sm" {
                    (schema_field_type_label(&field.kind))
                }
            }
            @if let Some(description) = &field.description {
                p class="mb-3 text-xs leading-5 text-gray-500" { (description) }
            }
            (render_field_diagnostics(diagnostics))
            @match &field.kind {
                SchemaFieldKind::Select(options) => {
                    select id=(format!("field-{}", field.key)) name=(name) required[field.required] aria-invalid=[invalid] class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2" {
                        option value="" selected[unset] disabled[field.required] {
                            @if field.required { "Select a value…" } @else { "Not set" }
                        }
                        @for option in options {
                            option value=(serialize_yaml_value(option)) selected[option_is_chosen(field, option)] { (schema_value_label(option)) }
                        }
                    }
                }
                SchemaFieldKind::MultiSelect(options) => {
                    div id=(format!("field-{}", field.key)) class="flex flex-wrap gap-2" {
                        @for option in options {
                            label class="inline-flex cursor-pointer items-center gap-2 rounded-full border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 has-checked:border-indigo-500 has-checked:bg-indigo-50 has-checked:text-indigo-800" {
                                input type="checkbox" name=(name.clone()) value=(serialize_yaml_value(option)) checked[option_is_chosen(field, option)] aria-invalid=[invalid] class="size-4 accent-indigo-600";
                                (schema_value_label(option))
                            }
                        }
                    }
                }
                SchemaFieldKind::String { input_type, min_length, max_length } => {
                    input id=(format!("field-{}", field.key)) type=(input_type) name=(name) value=(field_control_text(field)) required[field.required] minlength=[*min_length] maxlength=[*max_length] aria-invalid=[invalid] autocomplete=(if *input_type == "email" { "email" } else { "off" }) class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Integer { minimum, maximum } => {
                    input id=(format!("field-{}", field.key)) type="number" step="1" name=(name) value=(field_control_text(field)) required[field.required] min=[minimum.as_deref()] max=[maximum.as_deref()] aria-invalid=[invalid] class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Number { minimum, maximum } => {
                    input id=(format!("field-{}", field.key)) type="number" step="any" name=(name) value=(field_control_text(field)) required[field.required] min=[minimum.as_deref()] max=[maximum.as_deref()] aria-invalid=[invalid] class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2";
                }
                SchemaFieldKind::Boolean => {
                    select id=(format!("field-{}", field.key)) name=(name) required[field.required] aria-invalid=[invalid] class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 text-sm outline-none ring-indigo-500 focus:ring-2" {
                        option value="" selected[unset] disabled[field.required] {
                            @if field.required { "Choose true or false…" } @else { "Not set" }
                        }
                        option value="true" selected[option_is_chosen(field, &YamlValue::Bool(true))] { "True" }
                        option value="false" selected[option_is_chosen(field, &YamlValue::Bool(false))] { "False" }
                    }
                }
                SchemaFieldKind::Yaml => {
                    textarea id=(format!("field-{}", field.key)) name=(name) rows="5" spellcheck="false" required[field.required] aria-invalid=[invalid] placeholder="{}" class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (field_yaml_text(field)) }
                }
            }
        }
    }
}

/// The diagnostics about one control, rendered where that control is.
///
/// `role="alert"` rather than plain text: after an htmx swap there is no page
/// load to announce, so the region a screen reader is told about has to be the
/// markup itself. Empty diagnostics render nothing at all, so every caller can
/// place this unconditionally.
fn render_field_diagnostics(diagnostics: &[String]) -> Markup {
    html! {
        @if !diagnostics.is_empty() {
            ul role="alert" class="mb-2 space-y-1 text-xs font-semibold text-red-700" {
                @for message in diagnostics {
                    li { (message) }
                }
            }
        }
    }
}

fn additional_attributes(attributes: &Mapping, schema: &JsonValue) -> Mapping {
    let record_owned = schema.get(COLLECTION_ACCESS_EXTENSION).is_some();
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
            YamlValue::String(key) => {
                (!record_owned || key != RECORD_ACCESS_FIELD) && !declared.contains(key.as_str())
            }
            _ => true,
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn schema_allows_additional_attributes(schema: &JsonValue) -> bool {
    schema.get("additionalProperties") != Some(&JsonValue::Bool(false))
}

/// The names of the three controls a collection schema cannot describe, used as
/// diagnostic keys beside the schema's own property names.
///
/// They are the form field names the browser submits, so one map covers both
/// kinds of control and a diagnostic about the record ID cannot collide with one
/// about a schema property called `id` — a property is only ever looked up on a
/// structured form, where the ID input is not rendered at all.
const ID_CONTROL: &str = "id";
const FRONT_MATTER_CONTROL: &str = "front_matter";
const ADDITIONAL_ATTRIBUTES_CONTROL: &str = "_additional_attributes";

/// A submission the server refused, ready to be rendered back as the form.
struct RecordFormRejection {
    /// The refusal after logging and redaction. It carries the message a caller
    /// may see and the request ID that message was logged under, which is the
    /// same boundary the error page goes through: a form is not a reason to
    /// disclose anything an error page would not.
    error: PublicError,
    /// Diagnostics by the control they belong to. Absent for a refusal the
    /// schema does not locate in a field, which is then only shown at the top of
    /// the form.
    fields: BTreeMap<String, Vec<String>>,
    /// Exactly what the browser sent.
    submitted: HtmlDocumentForm,
}

/// The diagnostics about one control, or nothing when this is not a re-render.
fn form_diagnostics<'a>(rejection: Option<&'a RecordFormRejection>, control: &str) -> &'a [String] {
    rejection
        .and_then(|rejection| rejection.fields.get(control))
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The first line of the alert on a refused form, which says what happened to
/// the record rather than repeating the reason underneath it.
fn rejected_form_headline(editing: bool) -> &'static str {
    if editing {
        "This record was not saved."
    } else {
        "This record was not created."
    }
}

/// Decide where each diagnostic belongs on the form.
///
/// A diagnostic is worth more beside the control the value was typed into than
/// at the top of a long form, but only if it lands on the right one. The mapping
/// is therefore explicit: a violation about a property the structured form
/// renders goes to that property's control; one about `profile.team` goes to the
/// `profile` control, keeping the full path in its text, because that is the box
/// the value was typed into; and anything the form does not render a control for
/// — an attribute the schema does not declare, or a schema-shaped name on a form
/// that has no schema — goes to whichever free-text box carries it, which is the
/// whole point of that box existing.
///
/// A violation the schema locates in the record as a whole is deliberately left
/// where it is: it is already in the message at the top of the form, and putting
/// it beside an arbitrary control would be a guess dressed up as a diagnosis.
fn record_form_diagnostics(
    submitted: &HtmlDocumentForm,
    schema: Option<&JsonValue>,
    error: &PublicError,
    error_field: Option<&str>,
    violations: &[SchemaViolation],
) -> BTreeMap<String, Vec<String>> {
    let declared = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(JsonValue::as_object)
        .map(|properties| properties.keys().cloned().collect::<BTreeSet<_>>())
        .unwrap_or_default();
    // Where anything the form renders no control for ends up.
    let overflow = if submitted.structured {
        ADDITIONAL_ATTRIBUTES_CONTROL
    } else {
        FRONT_MATTER_CONTROL
    };
    let control_for = |field: &str| -> String {
        let root = field.split('.').next().unwrap_or(field);
        if submitted.structured && declared.contains(root) {
            return root.to_owned();
        }
        if matches!(
            root,
            ID_CONTROL | FRONT_MATTER_CONTROL | ADDITIONAL_ATTRIBUTES_CONTROL
        ) {
            return root.to_owned();
        }
        overflow.to_owned()
    };

    let mut diagnostics: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for violation in violations {
        let Some(field) = &violation.field else {
            continue;
        };
        let control = control_for(field);
        let message = if control == *field {
            violation.message.clone()
        } else {
            // A nested path keeps naming itself, so a diagnostic on a YAML box
            // says which key inside it is meant.
            format!("{field}: {}", violation.message)
        };
        diagnostics.entry(control).or_default().push(message);
    }
    if let Some(field) = error_field {
        diagnostics
            .entry(control_for(field))
            .or_default()
            .push(error.message.clone());
    }
    diagnostics
}

#[allow(clippy::too_many_arguments)]
fn render_record_form(
    representation: &Representation,
    view: &ViewDefinition,
    record: Option<&Record>,
    audit_entries: &[AuditEntry],
    schema: Option<&JsonValue>,
    csrf_token: &str,
    rejection: Option<&RecordFormRejection>,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    permissions: RecordPermissions,
) -> Markup {
    let editing = record.is_some();
    let submitted = rejection.map(|rejection| &rejection.submitted);
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
    let mut schema_fields = schema_fields.unwrap_or_default();
    // Every value below is the submitted text when there is one, and the stored
    // record's otherwise. The two are overlaid here rather than inside each
    // control so that "show what was typed" is one decision per field group
    // instead of a judgement call repeated a dozen times in the markup — and so
    // that the text is the submitted string throughout: re-serializing what the
    // server parsed would answer a rejected `1.50` with `1.5` and a rejected
    // YAML mapping with its keys reordered.
    if let Some(submitted) = submitted.filter(|submitted| submitted.structured) {
        for field in &mut schema_fields {
            field.submitted = Some(
                submitted
                    .fields
                    .get(&field.key)
                    .cloned()
                    .unwrap_or_default(),
            );
        }
    }
    let front_matter = submitted
        .and_then(|submitted| submitted.front_matter.clone())
        .unwrap_or_else(|| yaml_serde::to_string(attributes).unwrap_or_else(|_| "{}\n".to_owned()));
    let additional = schema
        .map(|schema| additional_attributes(attributes, schema))
        .unwrap_or_default();
    let additional_yaml = submitted
        .filter(|submitted| submitted.structured)
        .map(|submitted| submitted.additional_attributes.clone())
        .unwrap_or_else(|| {
            yaml_serde::to_string(&additional).unwrap_or_else(|_| "{}\n".to_owned())
        });
    let additional_diagnostics = form_diagnostics(rejection, ADDITIONAL_ATTRIBUTES_CONTROL);
    let allows_additional = schema.is_some_and(schema_allows_additional_attributes);
    // A collapsed disclosure would hide a diagnostic about what is inside it, and
    // hide the YAML the reader is being asked to correct.
    let additional_open = (!additional_yaml.trim().is_empty() && additional_yaml.trim() != "{}")
        || !additional_diagnostics.is_empty();
    let markdown = submitted
        .map(|submitted| submitted.markdown.as_str())
        .unwrap_or_else(|| record.map(|record| record.body.as_str()).unwrap_or(""));
    let record_id = submitted
        .and_then(|submitted| submitted.id.clone())
        .unwrap_or_default();
    // A refused submission keeps the version it was submitted with, not the
    // record's current one. For every refusal but a stale version they are the
    // same string, and where they differ that difference is the refusal: handing
    // back the current version would turn "somebody else changed this record"
    // into a form that silently overwrites their change on the next click.
    let expected_version = submitted
        .and_then(|submitted| submitted.expected_record_hash.clone())
        .or_else(|| record.map(|record| record.version.clone()));
    let back = format!("/{}", encode_segment(&view.name));
    // The form is rendered on its own first because it is a region in its own
    // right: a refused submission is answered with exactly this element, rooted
    // at the `id` the request named, and the document below embeds the very same
    // markup. One rendering, two envelopes, as everywhere else in the seam.
    let form_region = html! {
        form id=(RECORD_FORM_REGION) method="post" action=(action)
            // The form posts through htmx and is answered with either `204` and
            // an `HX-Location` or its own markup again, so it is boosted like
            // the rest of the page. `hx-target` points at the form itself, which
            // both narrows the answer — the breadcrumb, the heading and the
            // record's activity beside it are not re-rendered — and puts this
            // region's name in `HX-Target`, which is how the server knows a
            // fragment is wanted. `hx-disabled-elt` covers the gap that makes a
            // double click dangerous here: an HTML form post deliberately sits
            // outside the `Idempotency-Key` contract the JSON API offers, so two
            // submissions really are two writes, and disabling the button for
            // the life of the request is what stops the second one.
            hx-target="this" hx-swap="outerHTML" hx-disabled-elt="find button[type=submit]"
            class="space-y-4" {
            input type="hidden" name="_csrf" value=(csrf_token);
            @if let Some(version) = &expected_version {
                input type="hidden" name="_expected_record_hash" value=(version);
            }
            @if structured {
                input type="hidden" name="_form_mode" value="structured";
            }
            @if let Some(rejection) = rejection {
                div role="alert" class="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" {
                    p class="font-semibold" { (rejected_form_headline(editing)) }
                    p class="mt-1 whitespace-pre-line" { (&rejection.error.message) }
                    p class="mt-2 text-xs text-red-700" {
                        "Nothing was written and no audit event was recorded. The values below are exactly what you submitted. Request ID " (&rejection.error.request_id)
                    }
                }
            }
            fieldset disabled[!permissions.update] class="contents disabled:opacity-80" {
            section class="cr-form-section p-4 sm:p-5" {
                div class="mb-4 flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between" {
                    div {
                        h2 class="text-lg font-bold text-gray-900" { "Record details" }
                        p class="mt-1 text-sm text-gray-500" {
                            @if structured { "Fields and controls follow this collection’s JSON Schema." } @else { "Front matter accepts any YAML mapping." }
                        }
                    }
                    @if structured {
                        span class="rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700" { "Schema-powered" }
                    }
                }
                @if !editing {
                    div class="mb-4 rounded-xl border border-indigo-100 bg-indigo-50/60 p-4" {
                        label for="record-id" class="mb-1.5 block text-sm font-semibold text-gray-900" { "Record ID " span class="text-red-500" aria-hidden="true" { "*" } }
                        (render_field_diagnostics(form_diagnostics(rejection, ID_CONTROL)))
                        // Both characters are escaped, so the rendered attribute
                        // is `[^\/\\]+`. `pattern` is compiled with the
                        // Unicode-sets semantics current browsers apply, which
                        // require `/` inside a character class to be escaped;
                        // the previous `[^/\]+` failed to compile, so the
                        // browser logged a syntax error on every submission and
                        // ignored an attribute whose whole purpose is to refuse
                        // `/` and `\` in a record ID. The server refuses those
                        // characters regardless — this is the hint, not the rule.
                        input id="record-id" type="text" name="id" value=(record_id) required pattern="[^\\/\\\\]+" placeholder="acme-renewal" aria-describedby="record-id-help" aria-invalid=[(!form_diagnostics(rejection, ID_CONTROL).is_empty()).then_some("true")] class="w-full rounded-lg border border-indigo-200 bg-white px-3 py-2.5 font-mono text-sm outline-none ring-indigo-500 focus:ring-2";
                        span id="record-id-help" class="mt-1.5 block text-xs text-gray-500" { "Stable URL and filename identifier. It cannot be changed later." }
                    }
                }
                @if structured {
                    div class="grid gap-3 sm:grid-cols-2" {
                        @for field in &schema_fields {
                            (render_schema_field(field, form_diagnostics(rejection, &field.key)))
                        }
                    }
                    @if allows_additional {
                        details class="mt-5 rounded-xl border border-dashed border-gray-300 bg-gray-50" open[additional_open] {
                            summary class="cursor-pointer px-4 py-3 text-sm font-semibold text-gray-700 hover:text-indigo-700" { "+ Additional attributes" }
                            div class="border-t border-gray-200 p-4" {
                                p class="mb-2 text-xs leading-5 text-gray-500" { "Optional front matter not declared in the schema. Declared fields above cannot be overridden here." }
                                (render_field_diagnostics(additional_diagnostics))
                                textarea name="_additional_attributes" rows="5" spellcheck="false" aria-invalid=[(!additional_diagnostics.is_empty()).then_some("true")] class="w-full rounded-lg border border-gray-300 bg-white px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (additional_yaml) }
                            }
                        }
                    }
                } @else {
                    label class="block" {
                        span class="mb-1.5 block text-sm font-semibold text-gray-900" { "Front matter" }
                        (render_field_diagnostics(form_diagnostics(rejection, FRONT_MATTER_CONTROL)))
                        textarea name="front_matter" rows="14" spellcheck="false" aria-invalid=[(!form_diagnostics(rejection, FRONT_MATTER_CONTROL).is_empty()).then_some("true")] class="w-full rounded-lg border border-gray-300 px-3 py-2 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (front_matter) }
                    }
                }
            }
            section class="cr-form-section p-4 sm:p-5" {
                div class="mb-3 flex items-center justify-between gap-3" {
                    div {
                        h2 class="text-lg font-bold text-gray-900" { "Notes" }
                        p class="mt-1 text-sm text-gray-500" { "Long-form context stored as the Markdown body." }
                    }
                    span class="rounded-md bg-gray-100 px-2 py-1 font-mono text-xs font-semibold text-gray-500" { "Markdown" }
                }
                textarea name="markdown" aria-label="Markdown notes" rows="12" class="w-full rounded-lg border border-gray-300 px-3 py-2.5 font-mono text-sm leading-6 outline-none ring-indigo-500 focus:ring-2" { (markdown) }
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
    };
    // The one fragment that is deliberately not wrapped by `fragment`. A refused
    // submission does not move the reader anywhere — `rejected_form_response`
    // sends `HX-Push-Url: false` precisely so the address bar stays on the form
    // they are still looking at — so there is no new state for a title to name,
    // and sending one anyway would make this answer stop being byte for byte the
    // form the document contains, which is what `tests/record_form_http.rs`
    // holds it to.
    if representation.wants(RECORD_FORM_REGION) {
        return form_region;
    }
    page_or_content(
        representation,
        &title,
        &back,
        navigation,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                a href=(back.clone()) class="font-medium hover:text-blue-700" { (&view.title) }
                span aria-hidden="true" { "/" }
                span class="text-gray-900" { (&title) }
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
                div class=(if editing { "cr-record-layout mt-5" } else { "mx-auto mt-5 max-w-5xl" }) {
                div class="cr-record-primary min-w-0" {
                (form_region)
                }
                @if let Some(record) = record {
                    aside id="audit-history" class="cr-record-activity scroll-mt-20" {
                        div class="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between" {
                            div {
                                h2 class="text-base font-bold text-gray-900" { "Activity" }
                                p class="mt-0.5 text-xs text-gray-500" { "Newest accepted changes" }
                            }
                            a href=(audit_filter_url(&view.collection, &record.id)) class="text-xs font-semibold text-indigo-700 hover:text-indigo-900" { "All activity" span aria-hidden="true" { " →" } }
                        }
                        (render_audit_entries(audit_entries))
                    // A link to the confirmation page, not a form that deletes.
                    // See `delete_confirmation_url` for why the confirmation is
                    // a page rather than a dialog; the consequence here is that
                    // this element cannot write anything, so it needs no CSRF
                    // token, no version, and no handler to guard it.
                    @if permissions.delete {
                        div class="cr-record-danger rounded-lg border border-red-200 bg-red-50 p-4" {
                            div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between" {
                                div {
                                    h2 class="font-semibold text-red-900" { "Delete this record" }
                                    p class="mt-1 text-sm text-red-700" { "You will be asked to confirm. The previous document remains represented in the tamper-evident audit log." }
                                }
                                a href=(delete_confirmation_url(view, record)) class="rounded-lg border border-red-300 bg-white px-4 py-2 text-sm font-semibold text-red-700 hover:bg-red-100" { "Delete record…" }
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

/// The URL of a record's delete confirmation, which is the same path its
/// deletion is posted to.
///
/// One path, two methods: `GET` asks the question and `POST` performs the write,
/// which is the ordinary HTML shape for a destructive action and the reason this
/// needed no second route. The `POST` contract is byte for byte the one it has
/// always had — the same fields, the same statuses, the same audit event — so
/// every existing test of it is still a test of it.
///
/// **Why a page and not a dialog.** The button used to be a form whose
/// `onsubmit` called `window.confirm`, and that guard is worth less than it
/// looks: an inline handler needs JavaScript, so a browser with JavaScript
/// switched off — the configuration the whole HTTP suite stands in for — already
/// deleted the record on the first click with nothing asked. Replacing the
/// handler with htmx's `hx-confirm` would have kept exactly that hole, because
/// `hx-confirm` is also JavaScript; it would merely have moved which script was
/// missing. A confirmation the server renders is asked of everyone, needs
/// nothing to be running, and is the one shape of this that a test can assert.
///
/// It is also better where the dialog worked. `window.confirm` can say one
/// sentence with no markup; the page names the record, shows which view it is
/// being deleted from, says what survives in the audit log, and offers Cancel as
/// a real link rather than a button in a modal a screen reader has to be handed.
/// And it costs no more clicks than the dialog did: one to ask, one to confirm,
/// exactly as before.
///
/// The version the form carries is read when this page is rendered rather than
/// when the record page was, which narrows the window in which a record can
/// change between being read and being deleted — the `POST` still refuses with
/// `412` if it changes inside that window.
fn delete_confirmation_url(view: &ViewDefinition, record: &Record) -> String {
    format!(
        "/{}/records/{}/delete",
        encode_segment(&view.name),
        encode_segment(&record.id)
    )
}

/// The confirmation page: what is about to be deleted, and the two ways out.
///
/// A whole page rather than a region, and it takes a `Representation` for the
/// same reason every other renderer does — a boosted click on "Delete record…"
/// swaps it into `<body>` like any other navigation, and asks for a document
/// because a boost names no target.
fn render_delete_confirmation(
    representation: &Representation,
    view: &ViewDefinition,
    record: &Record,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let back = format!("/{}", encode_segment(&view.name));
    let record_url = format!(
        "/{}/records/{}",
        encode_segment(&view.name),
        encode_segment(&record.id)
    );
    page_or_content(
        representation,
        &format!("Delete {}", record.id),
        &back,
        navigation,
        html! {
            nav aria-label="Breadcrumb" class="mb-3 flex items-center gap-2 text-xs text-gray-500" {
                a href="/" class="font-medium hover:text-blue-700" { "Views" }
                span aria-hidden="true" { "/" }
                a href=(&back) class="font-medium hover:text-blue-700" { (&view.title) }
                span aria-hidden="true" { "/" }
                a href=(&record_url) class="font-medium hover:text-blue-700" { (&record.id) }
                span aria-hidden="true" { "/" }
                span class="text-gray-900" { "Delete" }
            }
            div class="mx-auto max-w-2xl" {
                div class="cr-record-danger rounded-xl border border-red-200 bg-red-50 p-6" {
                    h1 class="cr-title text-red-900" { "Delete this record?" }
                    p class="mt-2 text-sm text-red-800" {
                        "You are about to delete "
                        code class="cr-filter-tag" { (&record.id) }
                        " from collection "
                        code class="cr-filter-tag" { (&view.collection) }
                        "."
                    }
                    p class="mt-2 text-sm text-red-700" {
                        "This cannot be undone from the web app. The document's previous contents remain represented in the tamper-evident audit log, and "
                        code class="cr-filter-tag" { "cr" }
                        " records who deleted it."
                    }
                    // The form does the writing, so it carries the token and the
                    // version; the page that linked here carries neither. It
                    // stays native for the reason `UNBOOSTED` gives: a refusal
                    // here is a rendered error document, which htmx will not
                    // swap into a boosted `POST`, so boosting it would turn a
                    // stale version into a button that visibly does nothing.
                    form method="post" action=(delete_confirmation_url(view, record)) hx-boost=(UNBOOSTED) class="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center" {
                        input type="hidden" name="_csrf" value=(csrf_token);
                        input type="hidden" name="_expected_record_hash" value=(&record.version);
                        button type="submit" class="rounded-lg border border-red-300 bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800" { "Delete record" }
                        // A link rather than a second button, because cancelling
                        // is a navigation back to the record and must not be
                        // able to submit the form it sits inside.
                        a href=(&record_url) class="cr-button" { "Cancel" }
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
  /* The grey scale, and every neutral in the UI. The rules below use these
     steps directly, and `src/static/tailwind.input.css` makes them the `gray`
     and `white` utilities the markup uses, so `text-gray-500` and
     `var(--cr-gray-500)` are one colour. 0 is the page and every surface on
     it, 50 to 300 are fills and lines, and 400 to 900 are text. */
  --cr-gray-0: #ffffff;
  --cr-gray-50: #f7f7f5;
  --cr-gray-100: #efefec;
  --cr-gray-200: #e6e6e3;
  --cr-gray-300: #d5d5d1;
  --cr-gray-400: #a3a29e;
  --cr-gray-500: #72716d;
  --cr-gray-600: #5b5a57;
  --cr-gray-700: #464543;
  --cr-gray-900: #242424;

  --cr-accent: #5e6ad2;
  --cr-accent-hover: #4f5abf;
  --cr-accent-soft: #f0f1fb;
  --cr-focus-halo: rgb(37 99 235 / 0.12);
  --cr-danger: #b91c1c;
  --cr-info-line: #bfdbfe;
  --cr-info-soft: #eff6ff;
  --cr-info-ink: #1e3a8a;
  --cr-info-strong: #1d4ed8;
  --cr-warn-line: #fcd34d;
  --cr-warn-soft: #fffbeb;
  --cr-warn-ink: #92400e;
  --cr-invalid-line: #fca5a5;
  --cr-invalid-soft: #fef2f2;

  --cr-radius: 8px;
  --cr-emoji: "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif;
  --cr-sidebar-width: 232px;
  --cr-shadow-popover: 0 18px 44px rgb(36 36 36 / 0.14), 0 2px 8px rgb(36 36 36 / 0.07);
}

/* Dark mode follows the operating system; there is no switch of its own.
   `color-scheme` on `html` tells the browser both schemes are supported, which
   is what darkens scrollbars, date pickers and select menus, and this block
   swaps the palette when the system asks for dark. Every colour the rules
   below use is a token above, so no rule has a dark variant to keep in step;
   the only literals left are a card's faint shadows, which a dark canvas
   simply swallows.

   The grey scale runs the other way here, 0 the darkest step and 900 the
   lightest, and because the `gray` and `white` utilities are these same
   properties that one flip recolours the markup's greys too: `text-white` on
   a `bg-gray-900` button is still the opposite of its fill. The markup's
   other hues are Tailwind's own, which v4 resolves through `--color-*`
   properties declared inside a cascade layer. A declaration outside any
   layer beats every declaration inside one, so redefining them here recolours
   every use at once, including the ones `cr.js` adds. Each is mapped the same
   way round — a 50 becomes the darkest tint and a 950 the lightest ink — so
   `bg-red-50 text-red-900` is still a quiet panel with legible text; the 500s
   are the middle of their scales and keep their value. A colour a utility
   reads with no dark value here would stay light on a dark page, which
   `tests/stylesheet_http.rs` refuses. */
@media (prefers-color-scheme: dark) {
  :root {
    --cr-gray-0: #191919;
    --cr-gray-50: #1f1f1f;
    --cr-gray-100: #272726;
    --cr-gray-200: #30302f;
    --cr-gray-300: #3f3f3d;
    --cr-gray-400: #6e6d6a;
    --cr-gray-500: #9b9a96;
    --cr-gray-600: #b4b3af;
    --cr-gray-700: #cac9c5;
    --cr-gray-900: #ecebe7;

    --cr-accent: #7d87e6;
    --cr-accent-hover: #959df0;
    --cr-accent-soft: #25273d;
    --cr-focus-halo: rgb(125 135 230 / 0.3);
    --cr-danger: #f87171;
    --cr-info-line: #27406c;
    --cr-info-soft: #172136;
    --cr-info-ink: #bfd3fa;
    --cr-info-strong: #9db9f9;
    --cr-warn-line: #5b4517;
    --cr-warn-soft: #2a2211;
    --cr-warn-ink: #f3c46a;
    --cr-invalid-line: #7a2f2f;
    --cr-invalid-soft: #2c1b1b;

    --cr-shadow-popover: 0 18px 44px rgb(0 0 0 / 0.5), 0 2px 8px rgb(0 0 0 / 0.4);

    --color-red-50: oklch(25.5% 0.045 20);
    --color-red-100: oklch(29% 0.065 21);
    --color-red-200: oklch(35% 0.09 22);
    --color-red-300: oklch(42% 0.12 24);
    --color-red-400: oklch(57.7% 0.245 27.325);
    --color-red-600: oklch(70.4% 0.191 22.216);
    --color-red-700: oklch(80.8% 0.114 19.571);
    --color-red-800: oklch(88.5% 0.062 18.334);
    --color-red-900: oklch(93.6% 0.032 17.717);
    --color-red-950: oklch(97.1% 0.013 17.38);

    --color-emerald-50: oklch(25.5% 0.035 165);
    --color-emerald-100: oklch(29% 0.05 165);
    --color-emerald-200: oklch(35% 0.07 165);
    --color-emerald-300: oklch(42% 0.09 164);
    --color-emerald-400: oklch(59.6% 0.145 163.225);
    --color-emerald-600: oklch(76.5% 0.177 163.223);
    --color-emerald-700: oklch(84.5% 0.143 164.978);
    --color-emerald-800: oklch(90.5% 0.093 164.15);
    --color-emerald-900: oklch(95% 0.052 163.051);
    --color-emerald-950: oklch(97.9% 0.021 166.113);

    --color-indigo-50: oklch(25.5% 0.04 275);
    --color-indigo-100: oklch(29% 0.06 275);
    --color-indigo-200: oklch(35% 0.09 276);
    --color-indigo-300: oklch(42% 0.12 277);
    --color-indigo-400: oklch(51.1% 0.262 276.966);
    --color-indigo-600: oklch(67.3% 0.182 276.935);
    --color-indigo-700: oklch(78.5% 0.115 274.713);
    --color-indigo-800: oklch(87% 0.065 274.039);
    --color-indigo-900: oklch(93% 0.034 272.788);
    --color-indigo-950: oklch(96.2% 0.018 272.314);

    --color-blue-50: oklch(25.5% 0.04 260);
    --color-blue-100: oklch(29% 0.06 260);
    --color-blue-200: oklch(35% 0.08 258);
    --color-blue-300: oklch(42% 0.11 257);
    --color-blue-400: oklch(54.6% 0.245 262.881);
    --color-blue-600: oklch(70.7% 0.165 254.624);
    --color-blue-700: oklch(80.9% 0.105 251.813);
    --color-blue-800: oklch(88.2% 0.059 254.128);
    --color-blue-900: oklch(93.2% 0.032 255.585);
    --color-blue-950: oklch(97% 0.014 254.604);
  }
}

* { box-sizing: border-box; }

html {
  background: var(--cr-gray-0);
  color-scheme: light dark;
  scroll-behavior: smooth;
}

.cr-app {
  background: var(--cr-gray-0);
  color: var(--cr-gray-900);
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
  background: var(--cr-gray-900);
  color: var(--cr-gray-0);
  padding: 8px 12px;
  font-size: 0.875rem;
  font-weight: 600;
}

.cr-skip-link:focus { transform: translateY(0); }

/* The boosted-navigation progress bar, driven entirely by the `htmx-request`
   class htmx puts on `#cr-progress` while a request is in flight. While it is
   waiting it grows quickly at first and then slows, and never reaches the
   right-hand edge, because the server reports no progress: a bar that filled
   itself would be claiming something it cannot know. When the response lands
   the class goes, the bar snaps to its resting full width and fades out over
   150ms, so a finish reads as a finish rather than as an interruption.
   Everything here is dormant until a navigation is actually waiting. */
.cr-progress {
  position: fixed;
  top: 0;
  right: 0;
  left: 0;
  z-index: 110;
  height: 2px;
  background: var(--cr-accent-soft);
  opacity: 0;
  transition: opacity 150ms ease-out;
  pointer-events: none;
}

.cr-progress::after {
  content: "";
  display: block;
  height: 100%;
  background: var(--cr-accent);
  transform: scaleX(1);
  transform-origin: left center;
}

.cr-progress.htmx-request { opacity: 1; }

.cr-progress.htmx-request::after {
  animation: cr-progress 12s cubic-bezier(0, 0.65, 0.2, 1) forwards;
}

@keyframes cr-progress {
  from { transform: scaleX(0.04); }
  to { transform: scaleX(0.96); }
}

/* Present to a screen reader, absent from the layout. This is what hides the
   live region `page_layout` renders, and `display: none` or
   `visibility: hidden` — either of which would be simpler — would remove that
   element from the accessibility tree along with the viewport, which is exactly
   what it must not be. The 1px clipped box is the long-standing recipe for the
   difference; `white-space: nowrap` keeps a long sentence from being wrapped
   into that box and re-laying out the page around it. */
.cr-visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  padding: 0;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
  border: 0;
}

.cr-shell {
  display: grid;
  grid-template-columns: var(--cr-sidebar-width) minmax(0, 1fr);
  min-height: 100vh;
}

.cr-workspace { min-width: 0; background: var(--cr-gray-0); }

.cr-sidebar {
  position: sticky;
  top: 0;
  z-index: 30;
  display: flex;
  height: 100vh;
  min-width: 0;
  flex-direction: column;
  border-right: 1px solid var(--cr-gray-200);
  background: var(--cr-gray-50);
  color: var(--cr-gray-600);
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
  color: var(--cr-gray-900);
  font-size: 0.9rem;
  font-weight: 700;
  letter-spacing: -0.04em;
}

.cr-wordmark-mark {
  display: inline-grid;
  width: 24px;
  height: 24px;
  place-items: center;
  border: 1px solid var(--cr-gray-300);
  border-radius: 6px;
  background: var(--cr-gray-0);
  box-shadow: 0 1px 1px rgb(36 36 36 / 0.04);
  font-size: 0.78rem;
}

.cr-local-badge {
  border: 1px solid var(--cr-gray-300);
  border-radius: 999px;
  color: var(--cr-gray-500);
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
  color: var(--cr-gray-400);
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
  color: var(--cr-gray-600);
  padding: 5px 8px;
  font-size: 0.79rem;
  font-weight: 520;
  line-height: 1.25;
}

.cr-sidebar-link:hover { background: var(--cr-gray-100); color: var(--cr-gray-900); }
.cr-sidebar-link.is-active { background: var(--cr-gray-200); color: var(--cr-gray-900); font-weight: 620; }

/* Every navigation entry is marked by an emoji: a collection's own when its
   schema names one, a fixed one otherwise. The box is a fixed square so that
   labels line up whatever a platform's emoji font measures, and clips rather
   than wraps the rare icon that is really a short word. */
.cr-nav-glyph {
  display: inline-flex;
  width: 18px;
  height: 18px;
  flex: 0 0 18px;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  font-family: var(--cr-emoji);
  font-size: 0.86rem;
  line-height: 1;
}

.cr-nav-note { margin-left: auto; color: var(--cr-gray-400); font-size: 0.62rem; font-weight: 550; }
.cr-sidebar-notice { margin: 4px 8px; color: var(--cr-warn-ink); font-size: 0.68rem; line-height: 1.35; overflow-wrap: anywhere; }

.cr-mobile-icon { margin-right: 4px; font-family: var(--cr-emoji); }
.cr-title-icon { font-family: var(--cr-emoji); font-size: 1.35rem; line-height: 1; }
.cr-file-icon { display: inline-block; width: 1.4em; font-family: var(--cr-emoji); }

.cr-external { margin-left: auto; color: var(--cr-gray-400); font-size: 0.7rem; }

.cr-sidebar-utility {
  flex: 0 0 auto;
  border-top: 1px solid var(--cr-gray-200);
  padding: 8px;
}

.cr-sidebar-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 9px 8px 2px;
  color: var(--cr-gray-400);
  font-size: 0.62rem;
}

.cr-mobile-header { display: none; }

.cr-nav-link {
  border-radius: 6px;
  color: var(--cr-gray-600);
  padding: 6px 8px;
  font-size: 0.825rem;
  font-weight: 550;
}

.cr-nav-link:hover { background: var(--cr-gray-100); color: var(--cr-gray-900); }

.cr-perspective { display: grid; gap: 5px; margin-top: 8px; border-top: 1px solid var(--cr-gray-200); padding: 10px 8px 2px; }

.cr-perspective-label { color: var(--cr-gray-500); font-size: 0.65rem; font-weight: 650; }

.cr-perspective select {
  width: 100%;
  min-height: 30px;
  border: 1px solid var(--cr-gray-300);
  padding: 4px 28px 4px 8px;
  font-size: 0.72rem;
  font-weight: 600;
}

.cr-perspective-banner {
  border-bottom: 1px solid var(--cr-info-line);
  background: var(--cr-info-soft);
  color: var(--cr-info-ink);
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
  color: var(--cr-gray-900);
  font-size: clamp(1.5rem, 2vw, 1.8rem);
  font-weight: 670;
  letter-spacing: -0.028em;
  line-height: 1.12;
  text-wrap: balance;
}

.cr-lede {
  color: var(--cr-gray-600);
  font-size: 0.82rem;
  line-height: 1.45;
  text-wrap: pretty;
}

.cr-button {
  display: inline-flex;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--cr-gray-300);
  border-radius: 7px;
  background: var(--cr-gray-0);
  color: var(--cr-gray-700);
  padding: 6px 10px;
  font-size: 0.77rem;
  font-weight: 600;
  line-height: 1;
  white-space: nowrap;
}

.cr-button > span[aria-hidden="true"] { margin-left: 0.2em; }

.cr-button:hover { border-color: var(--cr-gray-400); background: var(--cr-gray-50); color: var(--cr-gray-900); }
.cr-button:active { transform: translateY(1px); }

.cr-button-primary {
  border-color: var(--cr-gray-900);
  background: var(--cr-gray-900);
  color: var(--cr-gray-0);
}

.cr-button-primary:hover { border-color: var(--cr-gray-700); background: var(--cr-gray-700); color: var(--cr-gray-0); }

.cr-empty-state {
  border: 1px dashed var(--cr-gray-300);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-0);
  padding: 40px 24px;
  text-align: center;
}

.cr-view-index {
  overflow: hidden;
  border: 1px solid var(--cr-gray-200);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-0);
}

.cr-view-index-header,
.cr-view-row {
  display: grid;
  grid-template-columns: minmax(200px, 1fr) 72px 118px minmax(0, 1.4fr) 20px;
  align-items: center;
  column-gap: 20px;
}

.cr-view-index-header {
  border-bottom: 1px solid var(--cr-gray-200);
  background: var(--cr-gray-50);
  color: var(--cr-gray-500);
  padding: 7px 14px;
  font-size: 0.66rem;
  font-weight: 650;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.cr-view-row {
  min-height: 38px;
  border-bottom: 1px solid var(--cr-gray-200);
  padding: 5px 14px;
}

.cr-view-row:last-child { border-bottom: 0; }
.cr-view-row:hover { background: var(--cr-gray-50); }
.cr-view-row:hover h2 { color: var(--cr-accent); }

.cr-view-name { display: flex; min-width: 0; align-items: center; gap: 8px; }
.cr-view-name h2 { min-width: 0; color: var(--cr-gray-900); font-size: 0.85rem; font-weight: 600; }
.cr-view-icon { flex: 0 0 auto; width: 18px; overflow: hidden; font-family: var(--cr-emoji); font-size: 0.95rem; line-height: 1; text-align: center; }
.cr-view-source { flex: 0 1 auto; min-width: 0; overflow: hidden; color: var(--cr-gray-500); font-size: 0.72rem; text-overflow: ellipsis; white-space: nowrap; }
.cr-view-source::before { content: "in "; }
.cr-view-count { color: var(--cr-gray-900); font-size: 0.8rem; font-variant-numeric: tabular-nums; text-align: right; white-space: nowrap; }
.cr-view-updated { white-space: nowrap; }
.cr-view-kind { display: flex; min-width: 0; flex-wrap: wrap; align-items: center; gap: 6px; }

/* A unit the column heading states where there is one: read aloud always,
   shown only once the headings are hidden. */
.cr-view-unit {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

.cr-view-arrow {
  color: var(--cr-gray-400);
  font-size: 1rem;
  text-align: right;
}

.cr-view-row:hover .cr-view-arrow { color: var(--cr-accent); transform: translateX(2px); }

.cr-path,
.cr-data {
  color: var(--cr-gray-500);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.72rem;
  font-variant-numeric: tabular-nums;
}

.cr-pill,
.cr-filter-tag {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--cr-gray-200);
  border-radius: 999px;
  background: var(--cr-gray-50);
  color: var(--cr-gray-600);
  padding: 3px 7px;
  font-size: 0.68rem;
  font-weight: 600;
  line-height: 1.2;
}

.cr-pill-accent { border-color: var(--cr-info-line); background: var(--cr-accent-soft); color: var(--cr-info-strong); }
.cr-pill-warn { border-color: var(--cr-warn-line); background: var(--cr-warn-soft); color: var(--cr-warn-ink); }

.cr-filter-tag {
  border-radius: 5px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-weight: 500;
}

.cr-surface {
  border: 1px solid var(--cr-gray-200);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-0);
  box-shadow: none;
}

.cr-app input:not([type="checkbox"]):not([type="radio"]),
.cr-app select,
.cr-app textarea {
  border-color: var(--cr-gray-300);
  border-radius: 7px;
  background-color: var(--cr-gray-0);
  color: var(--cr-gray-900);
}

.cr-app input:not([type="checkbox"]):not([type="radio"]):hover,
.cr-app select:hover,
.cr-app textarea:hover { border-color: var(--cr-gray-400); }

.cr-app input:not([type="checkbox"]):not([type="radio"]):focus,
.cr-app select:focus,
.cr-app textarea:focus { border-color: var(--cr-accent); box-shadow: 0 0 0 3px var(--cr-focus-halo); }

.cr-table-shell { overflow: hidden; border: 1px solid var(--cr-gray-200); border-radius: var(--cr-radius); background: var(--cr-gray-0); }

/* File previews in the filesystem browser. */
.cr-file-preview {
  max-height: 70vh;
  margin: 0;
  overflow: auto;
  background: var(--cr-gray-50);
  color: var(--cr-gray-900);
  padding: 16px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.75rem;
  line-height: 1.25rem;
}

/* Keep every space and newline, wrap at the panel edge, and break a token with
   no spaces at all — a URL, a minified line — rather than overflow. */
.cr-file-preview-wrap { white-space: pre-wrap; overflow-wrap: anywhere; }
.cr-table-shell table { font-variant-numeric: tabular-nums; }
.cr-table-shell thead { background: var(--cr-gray-50); }
.cr-table-shell th { padding: 8px 12px !important; color: var(--cr-gray-600) !important; font-size: 0.72rem; font-weight: 620 !important; }
.cr-table-shell td { padding: 8px 12px !important; font-size: 0.79rem; }
.cr-table-shell tbody tr:hover { background: var(--cr-gray-50); }

.cr-popover {
  border: 1px solid var(--cr-gray-200);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-0);
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

.cr-audit-list { overflow: hidden; border: 1px solid var(--cr-gray-200); border-radius: var(--cr-radius); background: var(--cr-gray-0); }
.cr-audit-entry { border-bottom: 1px solid var(--cr-gray-200); background: var(--cr-gray-0); padding: 13px 14px; }
.cr-audit-entry:last-child { border-bottom: 0; }
.cr-audit-entry:target { background: var(--cr-accent-soft); }

.cr-kanban-lane {
  border: 1px solid var(--cr-gray-200);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-50);
  box-shadow: none;
}

.cr-kanban-card {
  border: 1px solid var(--cr-gray-300);
  border-radius: 8px;
  background: var(--cr-gray-0);
  box-shadow: 0 1px 2px rgb(36 36 36 / 0.04);
}

.cr-kanban-card:hover { border-color: var(--cr-gray-400); box-shadow: 0 3px 8px rgb(36 36 36 / 0.07); }
.cr-kanban-card:active { transform: rotate(0.25deg); }
.cr-kanban-card dl > div { display: grid; grid-template-columns: minmax(64px, 0.42fr) minmax(0, 1fr); align-items: baseline; gap: 8px; }
.cr-kanban-card dl dt { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.cr-kanban-card dl dd { margin-top: 0 !important; min-width: 0; }
.cr-kanban-move summary { color: var(--cr-gray-500); font-size: 0.72rem; font-weight: 620; }
.cr-kanban-move[open] summary { margin-bottom: 8px; }

.cr-form-section,
.cr-field {
  border: 1px solid var(--cr-gray-200);
  border-radius: var(--cr-radius);
  background: var(--cr-gray-0);
  box-shadow: none;
}

.cr-field { background: var(--cr-gray-50); }

/* A field a refused submission had something to say about. Colour alone never
   carries the message: the reason is rendered above the control as text, and the
   control itself is marked `aria-invalid`. */
.cr-field-invalid {
  border-color: var(--cr-invalid-line);
  background: var(--cr-invalid-soft);
}

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
    border-bottom: 1px solid var(--cr-gray-200);
    background: color-mix(in srgb, var(--cr-gray-0) 96%, transparent);
    backdrop-filter: blur(14px);
  }
  .cr-mobile-topbar { display: flex; min-height: 46px; align-items: center; justify-content: space-between; gap: 12px; padding: 6px 16px; }
  .cr-mobile-utilities { display: flex; align-items: center; gap: 2px; }
  .cr-mobile-view-strip { display: flex; gap: 4px; overflow-x: auto; border-top: 1px solid var(--cr-gray-100); padding: 5px 12px 6px; scrollbar-width: none; }
  .cr-mobile-view-strip::-webkit-scrollbar { display: none; }
  .cr-mobile-view-strip a { flex: 0 0 auto; border-radius: 5px; color: var(--cr-gray-500); padding: 4px 7px; font-size: 0.72rem; font-weight: 550; }
  .cr-mobile-view-strip a:hover,
  .cr-mobile-view-strip a.is-active { background: var(--cr-gray-100); color: var(--cr-gray-900); }
  .cr-mobile-header .cr-perspective { display: flex; align-items: center; gap: 6px; margin: 0; border: 0; padding: 0; }
  .cr-mobile-header .cr-perspective-label { display: none; }
  .cr-mobile-header .cr-perspective select { width: auto; max-width: 210px; }
  .cr-main { min-height: calc(100vh - 82px); }
  .cr-filter-popover { top: 94px; }
}

@media (max-width: 640px) {
  .cr-view-index-header { display: none; }
  .cr-view-row { grid-template-columns: minmax(0, 1fr) auto 20px; column-gap: 10px; row-gap: 4px; padding: 8px 12px; }
  .cr-view-name { grid-column: 1; grid-row: 1; }
  .cr-view-count { grid-column: 2; grid-row: 1; color: var(--cr-gray-500); font-size: 0.72rem; }
  .cr-view-updated { display: none; }
  .cr-view-kind { grid-column: 1 / span 2; grid-row: 2; }
  .cr-view-arrow { grid-column: 3; grid-row: 1 / span 2; }
  .cr-view-unit { position: static; width: auto; height: auto; overflow: visible; clip-path: none; }
  .cr-title { font-size: 1.45rem; }
  .cr-mobile-header .cr-perspective select { max-width: 155px; }
}

@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  .cr-app *, .cr-app *::before, .cr-app *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
  /* The blanket rule above already collapses the progress bar's growth, but by
     accident rather than on purpose, and a 0.01ms animation is a strange thing
     to leave in the sheet. State the intent instead: no motion at all, which
     leaves the bar at the full width it rests at, so the feedback survives the
     preference as a plain static strip even though the movement does not. */
  .cr-progress { transition: none; }
  .cr-progress.htmx-request::after { animation: none; }
}
"#;

fn perspective_control(ui: &UiContext, csrf_token: &str, id: &str) -> Markup {
    html! {
        form method="post" action="/perspective" hx-boost=(UNBOOSTED) class="cr-perspective" {
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
                    span class="cr-nav-glyph" aria-hidden="true" { (HOME_ICON) }
                    span { "All views" }
                }
                @if views.iter().any(|view| view.saved) {
                    p class="cr-sidebar-label" { "Saved views" }
                    @for view in navigation_order(views).filter(|view| view.saved) {
                        @let path = format!("/{}", encode_segment(&view.name));
                        a href=(&path) class=(if current_path == path { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == path).then_some("page")] title=(&view.title) {
                            span class="cr-nav-glyph" aria-hidden="true" { (view_icon(view)) }
                            span class="truncate" { (&view.title) }
                        }
                    }
                }
                @if views.iter().any(|view| !view.saved) {
                    p class="cr-sidebar-label" { "Collections" }
                    @for view in navigation_order(views).filter(|view| !view.saved) {
                        @let path = format!("/{}", encode_segment(&view.name));
                        a href=(&path) class=(if current_path == path { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == path).then_some("page")] title=(&view.title) {
                            span class="cr-nav-glyph" aria-hidden="true" { (view_icon(view)) }
                            span class="truncate" { (&view.title) }
                        }
                    }
                }
                @if let Some(ui) = ui.filter(|ui| ui.can_browse_files) {
                    (browse_navigation(current_path, ui))
                }
                @if ui.is_some_and(|ui| ui.can_read_users) {
                    p class="cr-sidebar-label" { "Internal" }
                    a href="/users" class=(if current_path == "/users" { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == "/users").then_some("page")] title="Users · read-only" {
                        span class="cr-nav-glyph" aria-hidden="true" { (USERS_ICON) }
                        span class="truncate" { "Users" }
                        span class="cr-nav-note" { "read-only" }
                    }
                }
            }
            div class="cr-sidebar-utility" {
                nav aria-label="Utilities" {
                    @if ui.is_none_or(|ui| ui.can_view_global_audit) {
                        a href="/audit" class=(if current_path == "/audit" { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == "/audit").then_some("page")] {
                            span class="cr-nav-glyph" aria-hidden="true" { (AUDIT_ICON) }
                            span { "Audit log" }
                        }
                    }
                    a href="/openapi.json" hx-boost=(UNBOOSTED) class="cr-sidebar-link" {
                        span class="cr-nav-glyph" aria-hidden="true" { (OPENAPI_ICON) }
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

/// The sidebar's Browse section: every file, then the locations pinned to it.
///
/// "All files" is the active entry anywhere in the browser that is not itself
/// pinned, so the section always shows where the reader is — on a pin, or
/// somewhere reached from the database root.
fn browse_navigation(current_path: &str, ui: &UiContext) -> Markup {
    let on_pin = ui.pins.iter().any(|pin| pin.href == current_path);
    let in_browser = current_path == "/browse" || current_path.starts_with("/browse?");
    let all_files = in_browser && !on_pin;
    html! {
        p class="cr-sidebar-label" { "Browse" }
        a href="/browse" class=(if all_files { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[all_files.then_some("page")] title="Every file visible to the server · owner only · read-only" {
            span class="cr-nav-glyph" aria-hidden="true" { (ALL_FILES_ICON) }
            span class="truncate" { "All files" }
            span class="cr-nav-note" { "read-only" }
        }
        @for pin in &ui.pins {
            @let active = pin.href == current_path;
            a href=(&pin.href) class=(if active { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[active.then_some("page")] title=(&pin.location) {
                span class="cr-nav-glyph" aria-hidden="true" { (pin_icon(pin.kind)) }
                span class="truncate" { (&pin.label) }
                @if pin.kind == UiPinKind::Missing {
                    span class="cr-nav-note" { "missing" }
                }
            }
        }
        @if let Some(error) = &ui.pins_error {
            p class="cr-sidebar-notice" role="note" title=(error) { "Pins unavailable: " (error) }
        }
    }
}

fn pin_icon(kind: UiPinKind) -> &'static str {
    match kind {
        UiPinKind::Directory => DIRECTORY_ICON,
        UiPinKind::File => FILE_ICON,
        UiPinKind::Missing => MISSING_PIN_ICON,
    }
}

fn mobile_icon(icon: &str) -> Markup {
    html! { span class="cr-mobile-icon" aria-hidden="true" { (icon) } }
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
                        a href="/openapi.json" hx-boost=(UNBOOSTED) class="cr-nav-link" { "API" }
                    }
                }
            }
            nav aria-label="Views" class="cr-mobile-view-strip" {
                a href="/" class=(if current_path == "/" { "is-active" } else { "" }) { (mobile_icon(HOME_ICON)) "All views" }
                // Same order as the desktop sidebar: saved views, then
                // collections, then the internal registry.
                @for view in navigation_order(views) {
                    @let path = format!("/{}", encode_segment(&view.name));
                    a href=(&path) class=(if current_path == path { "is-active" } else { "" }) { (mobile_icon(view_icon(view))) (&view.title) }
                }
                @if ui.is_some_and(|ui| ui.can_read_users) {
                    a href="/users" class=(if current_path == "/users" { "is-active" } else { "" }) { (mobile_icon(USERS_ICON)) "Users" }
                }
                @if let Some(ui) = ui.filter(|ui| ui.can_browse_files) {
                    @let on_pin = ui.pins.iter().any(|pin| pin.href == current_path);
                    @let all_files = (current_path == "/browse" || current_path.starts_with("/browse?")) && !on_pin;
                    a href="/browse" class=(if all_files { "is-active" } else { "" }) { (mobile_icon(ALL_FILES_ICON)) "All files" }
                    @for pin in &ui.pins {
                        a href=(&pin.href) class=(if pin.href == current_path { "is-active" } else { "" }) title=(&pin.location) { (mobile_icon(pin_icon(pin.kind))) (&pin.label) }
                    }
                }
                @if ui.is_none_or(|ui| ui.can_view_global_audit) {
                    a href="/audit" class=(if current_path == "/audit" { "is-active" } else { "" }) { (mobile_icon(AUDIT_ICON)) "Audit" }
                }
                @if ui.is_some() {
                    a href="/openapi.json" hx-boost=(UNBOOSTED) { "API" }
                }
            }
        }
    }
}

/// The DOM id of the element that holds a page's content.
///
/// It is the `<main>` `page_layout` renders, so "the content of this page" and
/// "the element htmx swaps a content fragment into" are one element with one
/// name rather than two that have to be kept in step. The id was already there
/// as the skip link's destination; naming it once means a rename cannot leave
/// the seam pointing at an element that no longer exists.
const CONTENT_REGION: &str = "main-content";

/// The DOM id of the page's single live region — the element a screen reader
/// watches, and the only one on the page whose changes are spoken without being
/// asked for.
///
/// It is rendered by `page_layout` rather than by any page, which is the whole
/// point: a live region is only announced when an assistive technology was
/// already watching the element that changed, so a region delivered *inside* a
/// swap is a region that was created and filled in one step and may be read out
/// late, once, or never. Every fragment this server sends is a region of
/// `<main>` or smaller; this element is outside all of them, so a page turn, a
/// re-sort, a search and a filter apply all mutate an element that was on the
/// page before the request went out.
///
/// It is empty in every document. Nothing has changed when a page loads — the
/// page *is* the change — so the region starts silent and says something only
/// when a later interaction gives it something to say.
const ANNOUNCE_REGION: &str = "cr-announce";

/// The live region itself, visually hidden and initially empty.
///
/// `role="status"` already implies `aria-live="polite"` and `aria-atomic="true"`,
/// and both are stated anyway: the implicit mapping is what several screen
/// readers historically got wrong, and the cost of saying it twice is three
/// attributes in one place, while the cost of it being wrong is an announcement
/// nobody hears and no test can see.
///
/// Visually hidden rather than merely off-screen or `display: none`, which
/// removes an element from the accessibility tree along with the viewport and
/// would make this a no-op. The class is in the server's own stylesheet rather
/// than Tailwind's `sr-only`, because this is the one element whose styling is
/// load bearing for correctness: if the linked utility stylesheet fails to load,
/// every other page element degrades to unstyled but readable, and this one
/// would degrade to a duplicate sentence in the middle of the layout.
fn live_region() -> Markup {
    html! {
        div id=(ANNOUNCE_REGION) class="cr-visually-hidden" role="status" aria-live="polite" aria-atomic="true" {}
    }
}

/// The DOM id of a view's results region: the table and its pager, or the
/// Kanban board, whichever the view's layout renders.
///
/// One id for both layouts because it names a role rather than a shape — the
/// part of a view page that turning the page, re-sorting, filtering or
/// searching replaces, and nothing else — and the search and filter controls
/// that point at that role are shared by both layouts. A Kanban view is paged,
/// filtered and searched by the same three controls a table is, so answering
/// them with the board is what makes one id correct rather than convenient.
const VIEW_TABLE_REGION: &str = "cr-view-table";

/// `VIEW_TABLE_REGION` as the CSS selector an `hx-target` attribute takes.
///
/// Derived rather than written out a second time: htmx puts the *id* of the
/// element it resolved into `HX-Target`, and `Representation::requested` matches
/// that against `VIEW_TABLE_REGION`, so a selector that drifted from the id
/// would ask for a region the server does not answer and silently fall back to
/// whole pages.
static VIEW_TABLE_TARGET: LazyLock<String> = LazyLock::new(|| format!("#{VIEW_TABLE_REGION}"));

/// `hx-swap` for a control that lives *inside* the results region: replace the
/// region and put the top of the new rows at the top of the viewport.
///
/// Both halves are spelled out because both would otherwise be wrong by
/// default. A boosted element swaps `innerHTML` unless told otherwise — the
/// response here is the region including its own root element, so it has to be
/// `outerHTML` — and `htmx.config.scrollIntoViewOnBoost` already scrolls a
/// boosted swap's target into view, which is behaviour inherited from the body
/// swap this replaces rather than a decision about a page turn. Stating
/// `show:top` makes it the decision it looks like: turning a page or re-sorting
/// a column changes *which* rows are on screen, and a full reload used to leave
/// the reader at the top of them.
const VIEW_TABLE_SWAP_FROM_INSIDE: &str = "outerHTML show:top";

/// `hx-swap` for a control that lives *above* the results region: replace the
/// region and move nothing.
///
/// The filter and search controls sit in the page heading, and an open filter
/// panel hangs below them. Scrolling the region to the top of the viewport —
/// which is what `htmx.config.scrollIntoViewOnBoost` would do, because these
/// requests are still boosted — would push the panel that submitted them off
/// the top of the screen, and a panel nobody can see is not meaningfully
/// different from the panel that used to close on every apply.
const VIEW_TABLE_SWAP_IN_PLACE: &str = "outerHTML show:none";

/// The DOM id of the heading's record-count pill.
///
/// Not a region: no request may ask for it, and it is never an answer on its
/// own. It is the one fact outside `VIEW_TABLE_REGION` that replacing that
/// region changes, so the results fragment carries the pill beside the region as
/// an out-of-band swap. Widening the region to include the heading was the
/// alternative and it defeats the purpose — the filter panel is in the heading,
/// and re-rendering it is exactly what closes it.
const VIEW_COUNT_ID: &str = "cr-view-count";

/// The DOM id of the filter disclosure's `<summary>`, the second out-of-band
/// passenger of a results swap.
///
/// The summary is the closed state of the filter panel: the word "Filter" and a
/// badge counting the conditions currently applied. An apply changes that count
/// while deliberately leaving the panel itself alone, so the badge is the one
/// piece of the heading that a targeted apply has to re-render — the reader
/// closes the panel afterwards and reads it. It is the summary rather than the
/// badge alone because the badge is absent when no filter is applied, and an
/// out-of-band element whose target does not exist is dropped, which would make
/// "two filters" recoverable and "no filters" not.
const VIEW_FILTER_SUMMARY_ID: &str = "cr-view-filter-summary";

/// The DOM id of the record create and edit form.
///
/// The third region, and the only one that is a `<form>` rather than a container:
/// a refused submission is answered with this element and nothing else, so the
/// values the browser sent come back in the controls they were typed into while
/// the breadcrumb, the heading and the record's audit history beside it are left
/// alone. The form points `hx-target` at itself, which is what puts this name in
/// the `HX-Target` of every submission and is why only the two routes that render
/// the form can ever be asked for it.
const RECORD_FORM_REGION: &str = "cr-record-form";

/// The DOM id of the view index's rows, the part of the index with numbers in
/// it.
///
/// Counting what each view shows reads every record of every collection, and
/// the index is the page a server's address opens, so a browser navigating to
/// it is sent the rows with placeholders and this region asks for itself again
/// once htmx has loaded, answered by `?summary=inline` with the numbers filled
/// in. The heading's total travels beside it as an out-of-band patch.
/// `?summary=inline` without an htmx target is the whole document with the
/// numbers in it: what the `<noscript>` link beside the total offers a browser
/// that will never ask for the region.
const VIEW_INDEX_REGION: &str = "cr-view-index";

/// The DOM id of the view index heading's total-records pill; see
/// `view_index_total`.
const VIEW_INDEX_TOTAL_ID: &str = "cr-view-index-total";

/// The view index with its numbers rendered in, as a document or, asked for
/// `VIEW_INDEX_REGION`, as that region.
const VIEW_INDEX_SUMMARY_URL: &str = "/?summary=inline";

/// Which representation of a page a request is asking for: the whole document,
/// or one region of it.
///
/// Every URL in the HTML UI answers with a complete document unless the request
/// asks, in htmx's vocabulary, for something smaller. Asking takes all of:
///
/// * `HX-Request: true`, so a browser navigation, a `curl`, a feed reader and
///   the HTTP test suite — none of which send it — keep getting the page they
///   get today;
/// * no `HX-History-Restore-Request`, because a restore swaps the response into
///   `<body>` regardless of what it asked for, and a fragment there would
///   silently delete the sidebar. `cr.js` sets `historyRestoreAsHxRequest` to
///   `false` so a restore does not claim to be an htmx request in the first
///   place, and htmx sends no `HX-Target` on one either, so this check is the
///   third of three independent reasons a restore gets a document. It is here
///   because it costs a header lookup and removes the coupling: whoever turns
///   that configuration back on, for whatever reason, does not also have to
///   know that this file depends on it;
/// * an `HX-Target` naming a region *this route renders*. htmx sets that header
///   from the `id` of the element it will swap into, so the request states the
///   context the answer lands in, and the server can refuse to send a fragment
///   into a context it does not recognise. `hx-boost` targets `<body>`, which
///   has no id and therefore no header, which is why phase 1's boosted
///   navigation still gets whole documents.
///
/// Anything short of that is a document. That direction matters: a document
/// swapped where a fragment was expected is a visibly broken page, whereas the
/// reverse — a fragment swapped into `<body>` — is a page that has quietly lost
/// its navigation, and a shared cache is capable of doing it to a request that
/// never asked. `html_response` names these headers in `Vary` so it cannot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Representation {
    /// Whether htmx made this request and can therefore act on an htmx response
    /// header. False for every browser navigation, `curl`, and test in the HTTP
    /// suite, and false for a history restore, which is an ordinary navigation
    /// wearing htmx's label.
    htmx: bool,
    /// The `HX-Target` of an htmx request that may be answered with a fragment,
    /// verbatim. `None` means "send the whole document"; a target no route
    /// recognises is stored and simply matches nothing.
    region: Option<String>,
}

impl Representation {
    /// Read what the request asked for. The only place these headers are
    /// interpreted, so every route negotiates identically.
    fn requested(headers: &HeaderMap) -> Self {
        let header = |name: &'static str| headers.get(name).and_then(|value| value.to_str().ok());
        if header("hx-request") != Some("true") || header("hx-history-restore-request").is_some() {
            return Self::default();
        }
        Self {
            htmx: true,
            region: header("hx-target").map(str::to_owned),
        }
    }

    /// Whether this request asked for the named region, which a route may only
    /// answer with markup that really is that region's contents.
    fn wants(&self, region: &str) -> bool {
        self.region.as_deref() == Some(region)
    }

    /// Whether the answer may use htmx's response headers instead of a shape a
    /// browser understands on its own. A mutation asks this to choose between a
    /// `303` redirect and `204` plus `HX-Location`; see `mutation_redirect`.
    fn is_htmx(&self) -> bool {
        self.htmx
    }
}

/// Send a page's content in the envelope the request asked for.
///
/// Two envelopes, one set of markup: the content on its own when the request
/// targeted the content region, and otherwise the same content inside the same
/// shell every page has always had. Every renderer ends here rather than at
/// `page_layout` so that no route can grow its own idea of what a fragment is,
/// and so that adding a page needs no thought about the seam at all — a
/// renderer that never sees a matching `HX-Target` simply keeps rendering
/// documents.
fn page_or_content(
    representation: &Representation,
    title: &str,
    current_path: &str,
    views: &[ViewDefinition],
    content: Markup,
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    if representation.wants(CONTENT_REGION) {
        return fragment(title, content);
    }
    page_layout(title, current_path, views, content, ui, csrf_token)
}

/// The document title, rendered by the one function both envelopes use.
///
/// A whole document states it in `<head>`. A fragment states it as its first
/// top-level element, which is not decoration: htmx lifts a `<title>` out of a
/// response fragment, applies it to `document.title` and removes it before
/// anything is swapped into the page, so the element never reaches the DOM. That
/// is also the *only* mechanism available — htmx has no title response header, so
/// unlike the URL (`HX-Push-Url`) a title cannot be corrected out of band.
fn document_title(title: &str) -> Markup {
    html! { title { (title) " · cr" } }
}

/// Wrap a region's markup in the metadata a whole document would have carried.
///
/// Today that is the title and nothing else, and the reason to have a function
/// for it is that the alternative is a promise. A fragment that lands the reader
/// somewhere new is a page state like any other: the URL it pushed is
/// bookmarkable and comes back as a document, so the two have to agree about what
/// the state is called. Sending it from here makes that structural rather than
/// something each renderer remembers. The exception proves the rule — a refused
/// record form pushes no URL at all and so goes out unwrapped; see the comment
/// beside `RECORD_FORM_REGION` in `render_record_form`.
///
/// Nothing phase 4 of `.context/htmx-plan.md` swaps actually changes the title:
/// sorting, filtering, searching and turning a page all stay on the view they
/// started on, so the title a targeted swap sends is the title the tab already
/// shows. `main-content`, though, is a region of *every* page, and the first
/// control that targets it across two pages would otherwise be the commit that
/// discovers a fragment carries no title — after shipping a tab that names the
/// page the reader left.
fn fragment(title: &str, content: Markup) -> Markup {
    html! {
        (document_title(title))
        (content)
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
                // Both schemes, matching `color-scheme` in `GLOBAL_STYLES`:
                // said here as well so the browser paints the right canvas
                // before the sheet has been parsed, instead of flashing white.
                meta name="color-scheme" content="light dark";
                meta name="theme-color" media="(prefers-color-scheme: light)" content="#ffffff";
                meta name="theme-color" media="(prefers-color-scheme: dark)" content="#191919";
                meta name="robots" content="noindex, nofollow";
                link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect x='1' y='1' width='30' height='30' rx='7' fill='%23fff' stroke='%23d4d4d0'/%3E%3Cpath d='M20.5 20.2c-1.1 1-2.4 1.5-4 1.5-3.5 0-6-2.4-6-5.8s2.5-5.8 6-5.8c1.6 0 3 .5 4 1.5l-1.7 2a3.2 3.2 0 0 0-2.2-.8c-1.8 0-3 1.2-3 3.1s1.2 3.1 3 3.1c.9 0 1.6-.3 2.2-.8l1.7 2z' fill='%23242424'/%3E%3C/svg%3E";
                (document_title(title))
                // Linked, so it blocks the first paint until it has loaded
                // rather than restyling a page the reader is already looking
                // at. Its rules are all inside cascade layers and the sheet
                // below is not, so the two need no particular order.
                link rel="stylesheet" href=(TAILWIND_STYLESHEET_PATH.as_str());
                // htmx is linked before `cr.js` because `cr.js` configures
                // it, and two deferred scripts run in document order.
                script src=(HTMX_SCRIPT_PATH.as_str()) defer {}
                // `defer` keeps the previous execution order: the blocks used
                // to be emitted below the markup they enhance, so they ran
                // against a parsed document, and a deferred head script runs at
                // the same point without blocking the parse to get there.
                script src=(UI_SCRIPT_PATH.as_str()) defer {}
                style { (PreEscaped(GLOBAL_STYLES)) }
            }
            // `hx-boost` makes every same-origin link and every form in the
            // page an htmx request whose response replaces the body's contents,
            // so navigating keeps the parsed stylesheet and the JavaScript the
            // page already had running instead of rebuilding both. Everything
            // a navigation is supposed to change still changes: htmx takes
            // `<title>` from the response, pushes the URL, and scrolls to the
            // top exactly as a load would.
            //
            // htmx only intercepts. With JavaScript off, before the deferred
            // script has run, or on a link that leaves this origin, the very
            // same markup is an ordinary anchor and an ordinary form — which is
            // why the HTTP test suite, which never sends an htmx header, still
            // exercises every route end to end.
            //
            // The elements that must not be intercepted say so individually;
            // see `UNBOOSTED` for which ones and why.
            body class="cr-app min-h-full antialiased" data-design-system="cr-workspace"
                hx-boost="true" hx-indicator="#cr-progress" {
                a href=(format!("#{CONTENT_REGION}")) class="cr-skip-link" { "Skip to content" }
                // The navigation progress bar. htmx adds its `htmx-request`
                // class to whatever `hx-indicator` names for exactly as long as
                // a request is in flight, and `.cr-progress` in `GLOBAL_STYLES`
                // animates from nothing else, so this is inert markup rather
                // than a second mechanism to keep in step with the first. A
                // boosted navigation shows nothing at all until the response
                // arrives, and an audit-journal walk over a large database
                // takes long enough for that silence to read as a dead click.
                //
                // It sits inside the body the swap replaces, which is fine: the
                // request that replaced it has by definition finished, and every
                // page renders a fresh one.
                div id="cr-progress" class="cr-progress" aria-hidden="true" {}
                (live_region())
                div class="cr-shell" {
                    (sidebar_navigation(current_path, views, ui, csrf_token))
                    div class="cr-workspace" {
                        (mobile_navigation(current_path, views, ui, csrf_token))
                        @if let Some(ui) = ui {
                            @if ui.selected != ui.operator.principal {
                                // Not a live region. It states a standing fact
                                // about the whole page — you are impersonating
                                // someone — rather than the outcome of an
                                // interaction, and `hx-boost` re-creates it on
                                // every navigation, so marking it `role="status"`
                                // asked a screen reader to read the impersonation
                                // banner out again after every click. It is the
                                // first thing inside the workspace and is read in
                                // document order like the rest of the page.
                                div class="cr-perspective-banner" {
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
                        // The one element whose contents a content fragment
                        // replaces, which is why its id is a constant: the
                        // shell and the seam have to agree on the name.
                        main id=(CONTENT_REGION) class="cr-main w-full px-4 py-5 sm:px-6 sm:py-6 xl:px-8" tabindex="-1" { (content) }
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
    let record_owned =
        schema.is_some_and(|schema| schema.get(COLLECTION_ACCESS_EXTENSION).is_some());
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
        additional.extend(
            properties
                .keys()
                .filter(|key| !record_owned || key.as_str() != RECORD_ACCESS_FIELD)
                .cloned(),
        );
    }
    for record in records {
        additional.extend(record.attributes.keys().filter_map(|key| match key {
            YamlValue::String(key) if !record_owned || key != RECORD_ACCESS_FIELD => {
                Some(key.clone())
            }
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
        p class="mt-2 text-xs text-gray-500" {
            "Agent " span class="font-medium text-gray-700" { (&agent.id) }
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
        p class="mt-2 text-sm text-gray-600" {
            span class="text-xs font-semibold uppercase tracking-wide text-gray-500" { (label) }
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

fn browse_url(path: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("path", path);
    format!("/browse?{}", serializer.finish())
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

/// The audit-derived columns every table shows between the ID and the fields.
///
/// Fixed rather than selectable: they are not record data, they cost nothing
/// extra once the activity map is loaded, and "when did this happen?" is the
/// question a reader brings to a newest-first table.
const ACTIVITY_COLUMNS: [(&str, &str); 2] =
    [("$created_at", "created"), ("$updated_at", "updated")];

/// Render one audit timestamp compactly while keeping the exact value.
///
/// The table shows minutes; the `datetime` attribute and tooltip keep the
/// stored RFC 3339 instant, which is what a reader correlating a row with
/// `cr audit log` actually needs.
fn render_timestamp(value: Option<&str>) -> Markup {
    match value {
        Some(value) => html! {
            time datetime=(value) title=(value) class="cr-data" { (compact_timestamp(value)) }
        },
        // No audit history: a file created outside `cr` and not yet saved.
        None => html! { span class="text-gray-400" { "—" } },
    }
}

/// `2026-09-22T09:16:14.123456789Z` becomes `2026-09-22 09:16`.
fn compact_timestamp(value: &str) -> String {
    match value.split_once('T') {
        Some((date, time)) => format!("{date} {}", time.get(..5).unwrap_or(time)),
        None => value.to_owned(),
    }
}

/// The ordering a view uses when neither the URL nor the definition names one.
///
/// Newest first, because a table is read to answer "what changed?" before it is
/// read to answer "what exists?". Record ID order answers neither.
const DEFAULT_VIEW_SORT_FIELD: &str = "$created_at";

fn sort_view_records(
    records: &mut [Record],
    query: &ViewQuery,
    activity: &BTreeMap<String, RecordActivity>,
) -> ApiResult<()> {
    let Some(field) = view_sort_field(query) else {
        return Ok(());
    };
    // Audit-derived fields are not on the record, so they sort here rather
    // than in the shared record comparator. Sequence numbers are the journal's
    // exact total order; formatted instants can tie or, with fractional
    // seconds, compare in the wrong order as text.
    let sequence = match field {
        "$created_at" => |activity: &RecordActivity| activity.created_sequence,
        "$updated_at" => |activity: &RecordActivity| activity.updated_sequence,
        _ => {
            return sort_records_by_field(records, field, query.sort_direction.into())
                .map_err(ApiError::from_domain);
        }
    };
    let descending = query.sort_direction == ViewSortDirection::Desc;
    records.sort_by(|left, right| {
        let left_sequence = activity.get(&left.id).map(sequence);
        let right_sequence = activity.get(&right.id).map(sequence);
        // Records with no audit history stay last in both directions, exactly
        // like a missing front matter value.
        let ordering = match (left_sequence, right_sequence) {
            (Some(left), Some(right)) if descending => right.cmp(&left),
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        ordering.then_with(|| left.id.cmp(&right.id))
    });
    Ok(())
}

/// One page of a server-rendered view, positioned by record ID.
///
/// The complete ordered result is already in memory, which is what lets a
/// cursor page still report an exact position and total: `start` is the index
/// of the first row, so the footer can say `11–20 of 84` while Next and
/// Previous remain stable under concurrent writes.
struct ViewPage {
    records: Vec<Record>,
    limit: usize,
    start: usize,
    total: usize,
    next: Option<String>,
    previous: Option<String>,
}

/// Where a view page begins.
#[derive(Clone, Copy, Debug)]
enum ViewPosition<'a> {
    Start,
    After(&'a str),
    Before(&'a str),
    Offset(usize),
}

/// Read the requested position, preferring a cursor over a legacy offset.
fn view_position<'a>(query: &'a ViewQuery, offset: usize) -> ViewPosition<'a> {
    if let Some(after) = query.after.as_deref().filter(|id| !id.is_empty()) {
        return ViewPosition::After(after);
    }
    if let Some(before) = query.before.as_deref().filter(|id| !id.is_empty()) {
        return ViewPosition::Before(before);
    }
    if offset > 0 {
        return ViewPosition::Offset(offset);
    }
    ViewPosition::Start
}

/// Cut one page out of the ordered result.
///
/// A cursor naming a record that is no longer in the result — deleted, or
/// filtered out by a change to the query — resolves to the first page rather
/// than failing: the reader asked for records, and the honest answer to "the
/// row you were at is gone" is the beginning of the current ordering.
fn paginate_view(records: Vec<Record>, limit: usize, position: ViewPosition<'_>) -> ViewPage {
    let total = records.len();
    let locate = |id: &str| records.iter().position(|record| record.id == id);
    let start = match position {
        ViewPosition::Start => 0,
        ViewPosition::After(id) => locate(id).map_or(0, |at| at.saturating_add(1)),
        ViewPosition::Before(id) => locate(id).map_or(0, |at| at.saturating_sub(limit)),
        ViewPosition::Offset(offset) => offset,
    }
    .min(total);
    let records: Vec<_> = records.into_iter().skip(start).take(limit).collect();
    let returned = records.len();
    let next = (start.saturating_add(returned) < total)
        .then(|| records.last().map(|record| record.id.clone()))
        .flatten();
    let previous = (start > 0)
        .then(|| records.first().map(|record| record.id.clone()))
        .flatten();
    ViewPage {
        records,
        limit,
        start,
        total,
        next,
        previous,
    }
}

fn view_page_url(
    view: &ViewDefinition,
    query: &ViewQuery,
    limit: usize,
    position: ViewPosition<'_>,
) -> String {
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
    match position {
        ViewPosition::Start => {}
        ViewPosition::After(id) => {
            serializer.append_pair("after", id);
        }
        ViewPosition::Before(id) => {
            serializer.append_pair("before", id);
        }
        ViewPosition::Offset(offset) => {
            serializer.append_pair("offset", &offset.to_string());
        }
    }
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
    // Re-sorting starts the reader at the top of the new ordering: a cursor
    // from the previous one names a row that is now somewhere else entirely.
    view_page_url(view, &next, limit, ViewPosition::Start)
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
        )
        .map_err(|error| error.with_field(FRONT_MATTER_CONTROL));
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
            )
            .with_field(field));
        }
    }

    // Every refusal below is about text somebody typed into the
    // additional-attributes box, so each one says so and the re-rendered form
    // opens that box with the message inside it.
    let mut attributes = parse_front_matter(&form.additional_attributes)
        .map_err(|error| error.with_field(ADDITIONAL_ATTRIBUTES_CONTROL))?;
    for key in attributes.keys() {
        if let YamlValue::String(key) = key
            && properties.contains_key(key)
        {
            return Err(ApiError::bad_request(
                "invalid_form",
                format!("declared attribute '{key}' cannot be overridden in additional YAML"),
            )
            .with_field(ADDITIONAL_ATTRIBUTES_CONTROL));
        }
    }
    if !schema_allows_additional_attributes(schema) && !attributes.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "this collection schema does not allow additional attributes",
        )
        .with_field(ADDITIONAL_ATTRIBUTES_CONTROL));
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
        // Every refusal from here names the property it is about, so a
        // re-rendered form can put it beside that property's control.
        if let Some(value) =
            parse_schema_form_value(key, definition, required.contains(key.as_str()), values)
                .map_err(|error| error.with_field(key))?
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

/// Answer a successful HTML form post, in the shape the client can act on.
///
/// Two envelopes again, for the same reason a page has two. A browser gets the
/// `303 See Other` it has always got: the `POST` is answered by a `GET` of the
/// view, so a reload cannot repeat the write and the notice arrives in the URL.
///
/// htmx gets `204 No Content` and `HX-Location`, because an `XMLHttpRequest`
/// follows a `303` invisibly. htmx would see only the redirect's *target*, swap
/// that page's body in, and push the path that was posted to — `/deals/records`,
/// which renders nothing on its own — into the address bar. `HX-Location` hands
/// it the destination as something it can navigate to properly: it issues the
/// `GET` itself, swaps the body, and pushes the URL the redirect named, which is
/// exactly what a browser would have ended up showing.
///
/// Only the routes whose forms are boosted answer this way. A form that is still
/// an ordinary browser submission never sends `HX-Request`, so a shape nothing
/// can request would be a branch nothing exercises; see `UNBOOSTED`.
fn mutation_redirect(representation: &Representation, location: &str) -> ApiResult<Response> {
    if !representation.is_htmx() {
        return see_other(location);
    }
    let location = HeaderValue::from_str(location)
        .map_err(|error| ApiError::bad_request("invalid_location", error.to_string()))?;
    Ok((
        StatusCode::NO_CONTENT,
        [(HeaderName::from_static("hx-location"), location)],
    )
        .into_response())
}

/// The response header that tells htmx this answer is a form, not a page.
///
/// htmx refuses to swap a response that is not a success unless something says
/// otherwise, and the `htmx:beforeSwap` listener in `cr.js` says it for exactly
/// the responses carrying this header. A header rather than a list of statuses
/// in the browser, because the status of a refused write is the status of the
/// *refusal* — `422` for a schema violation, `412` for a stale version, `409`
/// for an identity already taken, `400` for YAML that does not parse — while the
/// answer is the same thing in every one of those cases. A listener that had to
/// enumerate them would quietly stop covering the day a route learned to refuse
/// for a new reason.
const FORM_INVALID_HEADER: HeaderName = HeaderName::from_static("cr-form-invalid");

fn rejected_form_response(status: StatusCode, markup: Markup) -> Response {
    let mut response = html_response(status, markup);
    response
        .headers_mut()
        .insert(FORM_INVALID_HEADER, HeaderValue::from_static("true"));
    // htmx pushes the URL of a boosted request whenever it swaps the response,
    // and the URL this one was posted to is not a page: `/deals/records` answers
    // nothing at all to a `GET`. Refusing the push leaves the address bar on the
    // form the reader is still looking at, which is where a browser with no
    // JavaScript leaves it too.
    response.headers_mut().insert(
        HeaderName::from_static("hx-push-url"),
        HeaderValue::from_static("false"),
    );
    response
}

fn html_result(result: ApiResult<Markup>) -> Response {
    match result {
        Ok(markup) => html_response(StatusCode::OK, markup),
        Err(error) => html_error(error),
    }
}

/// The rendered error page, always as a whole document.
///
/// Deliberately outside the fragment seam. htmx refuses to swap a non-2xx
/// response unless something says otherwise, and the two things that do are
/// both in the `htmx:beforeSwap` listener in `cr.js`: a boosted navigation
/// replacing the whole body, so a click on a link to a deleted record can land on
/// the 404 page the browser would have shown, and a response carrying
/// `CR-Form-Invalid`, which this page never does. A targeted request that fails
/// therefore swaps nothing, leaves the region it asked for as it was, and never
/// has a chance to paste an error page into a table cell.
///
/// "Replacing the whole body" is load bearing in that sentence and is checked
/// there rather than assumed: a view's own controls are boosted elements that
/// override `hx-target`, and htmx keeps calling those requests boosted, so
/// "boosted" alone stopped meaning "whole page" the moment they did.
///
/// A refused form does not come here at all; `reject_record_form` answers it
/// with the form and the values that were typed into it. What is left for this
/// page is a request that names something that does not exist, a principal who
/// may not do what was asked, a body that is not a form this server rendered,
/// and an internal failure — none of which has a form to go back to.
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
                h1 class="mt-2 text-2xl font-bold text-gray-900" { "Request could not be completed" }
                p class="mt-3 text-sm text-gray-700" { (error.message) }
                p class="mt-3 text-xs text-gray-500" { "Request ID " (error.request_id) }
                a href="/" class="mt-6 inline-flex rounded-lg bg-gray-900 px-4 py-2 text-sm font-semibold text-white hover:bg-gray-700" { "Back to views" }
            }
        },
        None,
        "",
    );
    html_response(status, markup)
}

/// Every request header an HTML answer's body depends on, as one `Vary` value.
///
/// `Cookie` is the perspective: with access control on, the same URL renders
/// what a different principal may see. The three htmx headers are the fragment
/// seam — `Representation::requested` reads exactly those, and reading is the
/// only thing that makes a representation negotiable — so they belong here for
/// the same reason `Cookie` does. `HX-Target` in particular: two htmx requests
/// for one URL with different targets get different bodies, and a cache told
/// only about `HX-Request` would serve one to the other.
///
/// Every HTML answer also carries `Cache-Control: no-store`, so nothing may
/// store these responses and this list describes a negotiation no cache should
/// be performing anyway. It is stated regardless. `no-store` is a rule about
/// storage that a future caching policy may relax; `Vary` is a fact about the
/// response that would still be true afterwards, and the failure it prevents —
/// a browser being handed a headless fragment for a page it asked for — is
/// invisible until someone puts a proxy in front of `cr serve`.
const HTML_VARY: &str = "Cookie, HX-Request, HX-Target, HX-History-Restore-Request";

fn html_response(status: StatusCode, markup: Markup) -> Response {
    let mut response = (status, Html(markup.into_string())).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static(HTML_VARY));
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
        let can_read_users = selected_database
            .access_allowed(AccessAction::ReadAccess, &AccessResource::Database)?;
        let can_browse_files = selected_database.owner_access_allowed(&AccessResource::Database)?;
        let pins = if can_browse_files {
            selected_database
                .pins()
                .map(|pins| resolve_pins(selected_database.root(), pins))
        } else {
            Ok(Vec::new())
        };
        let users = users
            .into_iter()
            .map(|(id, user)| UiUser {
                id,
                name: user.name,
                role: user_role_summary(&user.access),
                status: user.status,
            })
            .collect();
        let (pins, pins_error) = match pins {
            Ok(pins) => (pins, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        Ok((
            UiContext {
                operator: AccessIdentity {
                    principal: database.principal().to_owned(),
                    display: database.actor().to_owned(),
                },
                selected,
                selected_name,
                selected_status,
                can_view_global_audit,
                can_read_users,
                can_browse_files,
                pins,
                pins_error: None,
                users,
            },
            pins_error,
        ))
    })
    .await
    .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
    .map_err(ApiError::from_domain)
    .map(|(mut context, pins_error)| {
        // Published here, on the request's own task, so the log line carries
        // this request's ID; the sidebar shows only the public message.
        context.pins_error = pins_error.map(|error| ApiError::from_domain(error).publish().message);
        Some(context)
    })
}

/// Resolve stored pins into sidebar entries.
///
/// Each pin costs one `canonicalize` and one `metadata` call per page render.
/// That is why the domain caps the list: it is cheap for a sidebar's worth of
/// entries and would not be for an unbounded one.
fn resolve_pins(root: &FilePath, pins: Vec<crate::Pin>) -> Vec<UiPin> {
    pins.into_iter()
        .filter_map(|pin| {
            let location = pin.location(root);
            let canonical = std::fs::canonicalize(&location).ok();
            let kind = match canonical.as_deref().map(std::fs::metadata) {
                Some(Ok(metadata)) if metadata.is_dir() => UiPinKind::Directory,
                Some(Ok(_)) => UiPinKind::File,
                _ => UiPinKind::Missing,
            };
            // A pin is stored as UTF-8, so only a canonical target that is not
            // — reached through a link with a non-UTF-8 name — can fail here,
            // and the browser has no URL for such a place anyway.
            let target = match canonical.as_deref() {
                Some(canonical) => canonical.to_str()?,
                None => location.to_str()?,
            };
            let href = browse_url(target);
            let label = pin.label.clone().unwrap_or_else(|| {
                location.file_name().map_or_else(
                    || "/".to_owned(),
                    |name| name.to_string_lossy().into_owned(),
                )
            });
            Some(UiPin {
                stored: pin.path,
                label,
                location: location.to_string_lossy().into_owned(),
                href,
                canonical,
                kind,
            })
        })
        .collect()
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

fn parse_projection(select: &[String]) -> ApiResult<Option<Projection>> {
    Projection::from_lists(select).map_err(ApiError::from_domain)
}

/// A page of records, as summaries or, with a projection, as the flat objects
/// it selects.
fn record_page_response(
    page: Page<Record>,
    projection: Option<&Projection>,
) -> ApiResult<Response> {
    Ok(match projection {
        Some(projection) => {
            Json(page.try_map(|record| projection.object(&record).map_err(ApiError::from_domain))?)
                .into_response()
        }
        None => Json(page.try_map(ApiRecordSummary::try_from)?).into_response(),
    })
}

fn parse_filter(filter: Option<String>) -> ApiResult<Option<Filter>> {
    filter
        .map(|filter| filter.parse().map_err(ApiError::from_domain))
        .transpose()
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
    use super::{ApiError, INTERNAL_MESSAGE, ViewIndex};
    use crate::{
        Database, DomainError,
        audit::{reset_verify_chain_calls, verify_chain_calls},
    };
    use anyhow::anyhow;
    use axum::http::StatusCode;

    /// Every plaintext listing needs the journal replayed, and the index lists
    /// every collection. Replaying it once per collection made the index cost
    /// collections times history — a minute, on a database with a long one —
    /// so the number of walks is pinned here, and it does not grow with the
    /// number of collections.
    #[test]
    fn the_view_index_walks_the_journal_a_fixed_number_of_times() {
        let root = tempfile::tempdir().unwrap();
        let database = Database::init(root.path().join("database")).unwrap();
        for collection in ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"] {
            for id in ["one", "two"] {
                database.create(collection, id, &[], "").unwrap();
            }
        }
        let views = database.views().unwrap();

        // One walk for the activity, and one replay every listing shares.
        reset_verify_chain_calls();
        let index = ViewIndex::summarize(&database, &views).unwrap();
        assert_eq!(verify_chain_calls(), 2);
        assert_eq!(index.summary.unwrap().records, Some(12));

        // The server's database keeps the verified journal, so its first index
        // walks it once and the next does not walk it at all, even after an
        // append: only the new event is verified.
        let served = database.with_journal_cache();
        reset_verify_chain_calls();
        ViewIndex::summarize(&served, &views).unwrap();
        assert_eq!(verify_chain_calls(), 1);
        served.create("alpha", "three", &[], "").unwrap();
        reset_verify_chain_calls();
        let index = ViewIndex::summarize(&served, &views).unwrap();
        assert_eq!(verify_chain_calls(), 0);
        assert_eq!(index.summary.unwrap().records, Some(13));
    }

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
