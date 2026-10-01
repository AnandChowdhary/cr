use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path as FilePath, PathBuf},
    str::FromStr,
    sync::{
        Arc, LazyLock, PoisonError, RwLock,
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
    extract::{
        DefaultBodyLimit, FromRequestParts, Path, RawForm, RawQuery, State,
        rejection::JsonRejection,
    },
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Uri, header,
        request::Parts,
    },
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
    Attribution, AttributionOverrides, AuditAction, AuditAgent, AuditAuthorization, AuditEntry,
    AuditFilter, AuditIntent, AuditIntentPart, AuditSource, Authentication, AuthenticationMethod,
    Backlink, COLLECTION_ACCESS_EXTENSION, CheckScope, CheckSummary, CollectionModel,
    CollectionPresentation, Database, DomainError, FileChange, Filter, FilterExpression,
    FilterOperator, Finding, MAX_TRAVERSAL_DEPTH, Projection, RECORD_ACCESS_FIELD, Record,
    RecordActivity, RecordFile, RecordPrecondition, SchemaReview, SchemaViolation, SearchQuery,
    SearchTarget, SortDirection, SortKey, TOKEN_PREFIX, TrustedKeys, USERS_COLLECTION, User,
    UserKind, UserStatus, ViewDefinition, ViewFilterGroup, ViewLayout, ViewPredicateMatch,
    audit::AuditChange,
    cloudflare_access::{self, AssertionError, CloudflareAccess},
    database::relation_references,
    error::is_missing,
    parse_sort_keys, paths,
    readiness::{self, JournalWarmUp},
    sort::{HistoryField, MAX_SORT_KEYS, sort_with_history},
    sort_by_record_keys, sort_records,
    views::validate_view_name,
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
/// What a redirect target may not carry into its header as written; see
/// `location_header`. Non-ASCII bytes are always escaped, whatever the set.
const LOCATION_ENCODE_SET: &AsciiSet = &CONTROLS.add(b' ');

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub max_page_size: usize,
    pub max_body_bytes: usize,
    pub api_token: Option<String>,
    /// Refuse every protected request that does not present a principal
    /// token, rather than serving the launching owner's perspective console.
    pub require_token: bool,
    /// Sign people in by the email in a verified Cloudflare Access assertion.
    ///
    /// Like `require_token`, this removes the owner console. With both, a
    /// request may present either; with this alone, principal tokens are
    /// refused, so everybody reaches the server through the organisation's
    /// login.
    pub cloudflare_access: Option<Arc<CloudflareAccess>>,
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
            require_token: false,
            cloudflare_access: None,
        }
    }
}

#[derive(Clone)]
struct AppState {
    /// The database every request starts from, holding the last
    /// configuration that loaded; see [`AppState::database`].
    database: Arc<RwLock<Database>>,
    access_controlled: bool,
    max_page_size: usize,
    api_token: Option<Arc<str>>,
    require_token: bool,
    cloudflare_access: Option<Arc<CloudflareAccess>>,
    /// The console's form token, and the key every authenticated principal's
    /// own form token is derived from; see [`request_csrf_token`].
    csrf_token: Arc<str>,
    /// The walk that fills the verified journal, which readiness reports on.
    journal_warm_up: Arc<JournalWarmUp>,
}

impl AppState {
    /// The database a request starts from, with `.cr/config.yaml` as it is
    /// now.
    ///
    /// Every command reads the configuration when it opens the database, so
    /// the server reads it for every request rather than once: a server that
    /// kept what it started with read a collection declared as bundles since
    /// as an empty one. A configuration that no longer loads leaves the last
    /// one that did in place, and `/ready` reports `config_invalid` until it
    /// loads again.
    fn database(&self) -> Database {
        let current = self
            .database
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        match current.reconfigured() {
            Ok(Some(reconfigured)) => {
                *self
                    .database
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = reconfigured.clone();
                reconfigured
            }
            Ok(None) | Err(_) => current,
        }
    }
}

/// Who a request is, as the authorization layer established it.
///
/// Published for the handler's duration exactly as [`RequestContext`] is, so
/// the places that choose a request's database read one answer rather than
/// each re-reading the `Authorization` header.
#[derive(Clone)]
enum RequestIdentity {
    /// Nothing authenticated: the launching process's identity, and under
    /// access control the owner console and its perspective cookie.
    Console,
    /// A principal token or a Cloudflare Access assertion authenticated this
    /// database's principal, whose pages carry `csrf` as their form token.
    Authenticated {
        database: Box<Database>,
        csrf: Arc<str>,
    },
}

tokio::task_local! {
    static REQUEST_IDENTITY: RequestIdentity;
}

/// The authenticated database for this request, when a principal token or a
/// Cloudflare Access assertion established one.
///
/// Outside the authorization layer — `/health`, `/ready`, and `/static` —
/// there is no identity, which is the console's answer: none of them reads a
/// record.
fn authenticated_database() -> Option<Database> {
    REQUEST_IDENTITY
        .try_with(|identity| match identity {
            RequestIdentity::Authenticated { database, .. } => Some(database.as_ref().clone()),
            RequestIdentity::Console => None,
        })
        .ok()
        .flatten()
}

/// The form token this request's pages carry and its forms must send back.
///
/// The console has one operator, so one random token per server run is
/// enough. Authenticated principals are different people sharing a server,
/// and one of them could read a shared token out of their own page and forge
/// a form for another, which matters once a browser attaches the credential
/// by itself, as Cloudflare Access does. Each principal therefore gets its
/// own: an HMAC of its ID under the console's token, which never leaves the
/// server except as the console's own form token.
fn request_csrf_token(state: &AppState) -> Arc<str> {
    REQUEST_IDENTITY
        .try_with(|identity| match identity {
            RequestIdentity::Authenticated { csrf, .. } => Some(Arc::clone(csrf)),
            RequestIdentity::Console => None,
        })
        .ok()
        .flatten()
        .unwrap_or_else(|| Arc::clone(&state.csrf_token))
}

fn principal_csrf_token(key: &str, principal: &str) -> Arc<str> {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(b"cr:csrf:principal:v1\0");
    mac.update(principal.as_bytes());
    Arc::from(hexadecimal(&mac.finalize().into_bytes()))
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
    /// Whether this perspective may save views, and so whether an empty Saved
    /// views section in the sidebar says how to fill it.
    can_save_views: bool,
    /// Pinned filesystem locations, loaded only for a perspective that may
    /// browse files.
    pins: Vec<UiPin>,
    /// Why the pins could not be loaded — a hand-edited `.cr/pins.yaml` that no
    /// longer parses, say. The sidebar says so instead of every page failing,
    /// because a typo in a navigation preference must not lock the owner out
    /// of the UI they would use to see it.
    pins_error: Option<String>,
    users: Vec<UiUser>,
    /// Whether this is the owner console, which may view as another user. An
    /// authenticated principal is who its credential says and nobody else.
    can_switch_perspective: bool,
    /// Who is signed in, for an authenticated principal.
    account: Option<UiAccount>,
}

/// Who an authenticated request is, for the account card at the foot of the
/// sidebar.
///
/// The console has none. Nobody signed in to it: its operator is whoever
/// launched the server, and its perspective switcher already says whom it is
/// viewing as.
#[derive(Clone, Debug)]
struct UiAccount {
    /// The principal's ID, which picks the avatar's colour.
    principal: String,
    name: String,
    /// The user's email, or its ID when it has none.
    address: String,
    role: String,
    /// How the request was authenticated, in words.
    method: String,
    /// The same, short enough for the card's last line beside the role.
    method_short: String,
    /// Where signing out goes, for a method that has somewhere to go.
    sign_out: Option<&'static str>,
}

impl UiAccount {
    fn new(principal: &str, user: &User, authentication: Option<&Authentication>) -> Self {
        let method = authentication.map(|authentication| &authentication.method);
        let name = method.map_or("sign-in", authentication_method_name);
        Self {
            principal: principal.to_owned(),
            name: user.name.clone(),
            address: user.email.clone().unwrap_or_else(|| principal.to_owned()),
            role: user_role_summary(&user.access),
            method: name.to_owned(),
            method_short: match method {
                Some(AuthenticationMethod::CloudflareAccess) => "Cloudflare".to_owned(),
                _ => name.to_owned(),
            },
            // Cloudflare Access ends its session at this path on every host it
            // protects. A principal token has no session to end: whatever
            // attaches it keeps attaching it.
            sign_out: (method == Some(&AuthenticationMethod::CloudflareAccess))
                .then_some("/cdn-cgi/access/logout"),
        }
    }
}

/// Up to two letters for a person's avatar: the first of their name's first
/// and last words, or of `fallback` when the name is blank.
fn initials(name: &str, fallback: &str) -> String {
    let words = name.split_whitespace().collect::<Vec<_>>();
    let letters = match words.as_slice() {
        [] => vec![fallback.trim()],
        [only] => vec![*only],
        [first, .., last] => vec![*first, *last],
    };
    letters
        .into_iter()
        .filter_map(|word| word.chars().next())
        .flat_map(char::to_uppercase)
        .collect()
}

/// How many avatar colours `cr.css` defines, as `.cr-avatar-0` onwards.
const AVATAR_HUES: u32 = 8;

/// Which avatar colour a person gets, picked from their principal ID so that
/// the same person is the same colour on every page and in every list. The
/// colour comes from a class rather than a `style` attribute, which the
/// content security policy would refuse.
fn avatar_class(key: &str) -> String {
    // FNV-1a: stable across builds and platforms, unlike `std`'s hasher.
    let hash = key
        .trim()
        .to_lowercase()
        .bytes()
        .fold(0x811c_9dc5_u32, |hash, byte| {
            (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
        });
    format!("cr-avatar cr-avatar-{}", hash % AVATAR_HUES)
}

/// A person as the UI shows one wherever one appears: a tiny avatar of their
/// initials, in their colour, beside their name. `key` is their principal ID,
/// and `title` whatever the name leaves out, such as the ID or the recorded
/// actor.
fn user_chip(name: &str, key: &str, title: Option<&str>) -> Markup {
    html! {
        span class="cr-user" title=[title] {
            span class=(avatar_class(key)) aria-hidden="true" { (initials(name, key)) }
            span class="cr-user-name" { (name) }
        }
    }
}

/// An audit event's actor as a chip. The actor is what the event recorded,
/// `Name <email>` for any principal CR knows, so it names the person as they
/// were then, and is readable by anybody who may read the event, whatever
/// they may read of the registry. The whole recorded string is the tooltip.
fn actor_chip(actor: &str) -> Markup {
    let key = crate::principal_id(actor).unwrap_or_else(|_| actor.to_lowercase());
    user_chip(identity_name(actor), &key, Some(actor))
}

/// The names of the users `ids`, as far as this perspective may read them:
/// through the registry, which access managers and owners may read, or the
/// user's own record, which a `Database`-wide viewer may. A user it may read
/// neither way is left out, and shown by ID.
fn user_names<'a>(
    database: &Database,
    ids: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, String> {
    ids.into_iter()
        .filter_map(|id| {
            let name = match database.user(id) {
                Ok(user) => user.name,
                Err(_) => database
                    .get(USERS_COLLECTION, id)
                    .ok()?
                    .attributes
                    .get(YamlValue::String("name".to_owned()))?
                    .as_str()?
                    .to_owned(),
            };
            Some((id.to_owned(), name))
        })
        .collect()
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
    /// The file's version when the preview is the whole file as text, which is
    /// exactly when it may be edited: a textarea holding a truncated preview
    /// would save the truncation, and one holding a hex dump would save the
    /// dump.
    version: Option<String>,
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
    /// Where the document is, which its edit and delete controls act on.
    path: PathBuf,
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
struct ReadinessResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checks: Vec<ReadinessCheckResponse>,
    /// The ID a failure's log lines are under, as an error envelope carries.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReadinessCheckResponse {
    name: &'static str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct ApiRecord {
    collection: String,
    id: String,
    path: String,
    version: String,
    front_matter: JsonValue,
    markdown: String,
    /// A bundle record's supporting files; absent for a Markdown-file record.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    files: Vec<RecordFile>,
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
            files: record.files,
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

/// The file an edit or delete page acts on, and the browse page it was opened
/// from, which Cancel returns to.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowseFileQuery {
    path: String,
    from: Option<String>,
}

/// Scope and window for an integrity report.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckQuery {
    collection: Option<String>,
    /// Public keys to judge the signed checkpoint with, inline only.
    #[serde(default)]
    trusted_key: Vec<String>,
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
    #[serde(default)]
    sort: Vec<String>,
    direction: Option<SortDirectionParameter>,
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
    #[serde(default)]
    sort: Vec<String>,
    direction: Option<SortDirectionParameter>,
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
    /// The sort, most significant key first, as `sort_field` and
    /// `sort_direction` pairs matched by position the way a filter's field,
    /// operator and value are. None at all inherits the view's default; one
    /// empty `sort_field` is the panel's "None", record ID order.
    #[serde(default)]
    sort_field: Vec<String>,
    #[serde(default)]
    sort_direction: Vec<ViewSortDirection>,
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

impl From<SortDirection> for ViewSortDirection {
    fn from(direction: SortDirection) -> Self {
        match direction {
            SortDirection::Asc => Self::Asc,
            SortDirection::Desc => Self::Desc,
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

impl From<FilterOperator> for ViewFilterOperator {
    fn from(operator: FilterOperator) -> Self {
        match operator {
            FilterOperator::Equal => Self::Eq,
            FilterOperator::NotEqual => Self::Ne,
            FilterOperator::GreaterThan => Self::Gt,
            FilterOperator::GreaterThanOrEqual => Self::Gte,
            FilterOperator::LessThan => Self::Lt,
            FilterOperator::LessThanOrEqual => Self::Lte,
            FilterOperator::Contains => Self::Contains,
            FilterOperator::NotContains => Self::NotContains,
            FilterOperator::StartsWith => Self::StartsWith,
            FilterOperator::EndsWith => Self::EndsWith,
            FilterOperator::IsEmpty => Self::IsEmpty,
            FilterOperator::IsNotEmpty => Self::IsNotEmpty,
        }
    }
}

impl From<ViewFilterMatch> for ViewPredicateMatch {
    fn from(filter_match: ViewFilterMatch) -> Self {
        match filter_match {
            ViewFilterMatch::All => Self::All,
            ViewFilterMatch::Any => Self::Any,
        }
    }
}

impl From<ViewPredicateMatch> for ViewFilterMatch {
    fn from(match_mode: ViewPredicateMatch) -> Self {
        match match_mode {
            ViewPredicateMatch::All => Self::All,
            ViewPredicateMatch::Any => Self::Any,
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
    mode: DocumentFormMode,
    additional_attributes: String,
    fields: BTreeMap<String, Vec<String>>,
    /// The fields a `Fields` form listed, in its order, each with how its text
    /// is read back. Empty for the other two editors.
    field_kinds: Vec<(String, InferredFieldKind)>,
}

/// Which of the record form's three editors a submission came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DocumentFormMode {
    /// The whole front matter as one YAML mapping.
    Yaml,
    /// One control per property the collection's JSON Schema declares.
    Structured,
    /// One control per field the record already has, for a collection whose
    /// schema declares no properties.
    Fields,
}

/// How a field is edited on a record whose collection declares no properties.
///
/// There is no schema to ask, so the value the record holds decides, and saving
/// gives back a value of the same type: `ranking: 3` does not come back as the
/// string `"3"`, and a postcode stored as text does not come back as a number.
/// Leaving a box empty never removes the field; it stores the empty value of
/// its kind. Adding, renaming and removing fields is what the YAML editor is
/// for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InferredFieldKind {
    /// A string, saved exactly as typed.
    Text,
    /// A number; an empty box is `null`.
    Number,
    /// `true` or `false`; "Not set" is `null`.
    Boolean,
    /// `null`; anything typed is a string.
    Empty,
    /// Anything else — a list, a mapping, a tagged value, or a string a text
    /// control cannot carry intact — as typed YAML; an empty box is `null`.
    Yaml,
}

impl InferredFieldKind {
    fn of(value: &YamlValue) -> Self {
        match value {
            // A text control can only give back line feeds and tabs: an
            // `<input>` drops carriage returns and a `<textarea>` turns every
            // line break into CRLF, so any other control character would not
            // survive a save untouched.
            YamlValue::String(text)
                if text.chars().all(|character| {
                    !character.is_control() || matches!(character, '\n' | '\t')
                }) =>
            {
                Self::Text
            }
            // `.inf` and `.nan` are numbers a number input cannot hold.
            YamlValue::Number(number) if number.as_f64().is_some_and(f64::is_finite) => {
                Self::Number
            }
            YamlValue::Bool(_) => Self::Boolean,
            YamlValue::Null => Self::Empty,
            _ => Self::Yaml,
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Empty => "empty",
            Self::Yaml => "yaml",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        [
            Self::Text,
            Self::Number,
            Self::Boolean,
            Self::Empty,
            Self::Yaml,
        ]
        .into_iter()
        .find(|kind| kind.token() == token)
    }

    /// The control that edits a field of this kind holding `text`. Text that
    /// is a calendar date gets a date picker, which gives back exactly the
    /// `YYYY-MM-DD` it was given.
    fn control(self, text: Option<&str>) -> SchemaFieldKind {
        match self {
            Self::Text | Self::Empty => SchemaFieldKind::String {
                input_type: if self == Self::Text && text.is_some_and(is_calendar_date) {
                    "date"
                } else {
                    "text"
                },
                min_length: None,
                max_length: None,
            },
            Self::Number => SchemaFieldKind::Number {
                minimum: None,
                maximum: None,
            },
            Self::Boolean => SchemaFieldKind::Boolean,
            Self::Yaml => SchemaFieldKind::Yaml,
        }
    }

    fn parse(self, key: &str, raw: &str) -> ApiResult<YamlValue> {
        match self {
            Self::Text => Ok(YamlValue::String(form_text(raw))),
            Self::Empty if raw.is_empty() => Ok(YamlValue::Null),
            Self::Empty => Ok(YamlValue::String(form_text(raw))),
            Self::Number if raw.trim().is_empty() => Ok(YamlValue::Null),
            Self::Number => match parse_form_yaml_value(key, raw.trim())? {
                number @ YamlValue::Number(_) => Ok(number),
                _ => Err(ApiError::bad_request(
                    "invalid_form",
                    format!("attribute '{key}' must be a number"),
                )),
            },
            Self::Boolean => match raw {
                "" => Ok(YamlValue::Null),
                "true" => Ok(YamlValue::Bool(true)),
                "false" => Ok(YamlValue::Bool(false)),
                _ => Err(ApiError::bad_request(
                    "invalid_form",
                    format!("attribute '{key}' must be true or false"),
                )),
            },
            Self::Yaml if raw.trim().is_empty() => Ok(YamlValue::Null),
            Self::Yaml => parse_form_yaml_value(key, raw),
        }
    }
}

/// Whether `text` is a real `YYYY-MM-DD` date a date input can hold. Anything
/// else — `2026-02-30`, year zero — a browser would silently empty.
fn is_calendar_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        text[0..4].parse::<i32>(),
        text[5..7].parse::<u8>(),
        text[8..10].parse::<u8>(),
    ) else {
        return false;
    };
    year >= 1
        && time::Month::try_from(month)
            .and_then(|month| time::Date::from_calendar_date(year, month, day))
            .is_ok()
}

/// Text as a form control submitted it, with the CRLF a `<textarea>` sends for
/// every line break read back as the line feed it was.
fn form_text(raw: &str) -> String {
    raw.replace("\r\n", "\n")
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
    /// How the field's type was decided when there is no schema to declare
    /// it, which the form sends back so the server reads the text the same way.
    inferred: Option<InferredFieldKind>,
    /// The unit a number is in, from its `x-cr-unit`, shown beside the box.
    unit: Option<String>,
    /// An object's own fields, when the form edits it as a group of controls
    /// rather than as one YAML box. Empty for every other field. Each member's
    /// `key` is its path, `costs.total`, which is also what a violation inside
    /// the object is reported against.
    members: Vec<SchemaFormField>,
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
struct HtmlFileEditForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    path: String,
    /// The browse page the editor was opened from, which a save returns to.
    from: String,
    /// The version of the file the text was edited from.
    #[serde(rename = "_expected_version")]
    expected_version: String,
    contents: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlFileDeleteForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    path: String,
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

/// A link or unlink from the record page's relations panel.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlRelationForm {
    #[serde(rename = "_csrf")]
    csrf: String,
    #[serde(rename = "_expected_record_hash")]
    expected_record_hash: String,
    relation: String,
    /// The other record, as `collection/id`.
    target: String,
}

/// "Save as view", exactly as the browser sent it: the name and title typed
/// into it, the layout and grouping chosen in it, and the page's filters, sort
/// and columns from its hidden fields. A refused save is rendered back from this.
#[derive(Clone, Debug, Deserialize)]
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
    #[serde(default)]
    sort_field: Vec<String>,
    #[serde(default)]
    sort_direction: Vec<ViewSortDirection>,
    #[serde(default)]
    column: Vec<String>,
    layout: Option<ViewLayout>,
    group_by: Option<String>,
}

/// A confirmation that carries nothing but the token, such as deleting a
/// saved view.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlCsrfForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// The saved-view editor's submission: the whole definition apart from its
/// name and collection, which it cannot change.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HtmlViewEditForm {
    #[serde(rename = "_csrf")]
    csrf: String,
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
    /// Each `any` group the editor could not fold into its conditions, as
    /// JSON, submitted only while its checkbox is ticked.
    #[serde(default)]
    keep_group: Vec<String>,
    #[serde(default)]
    sort_field: Vec<String>,
    #[serde(default)]
    sort_direction: Vec<ViewSortDirection>,
    #[serde(default)]
    column: Vec<String>,
    /// The columns the view picked for itself when the editor opened, so
    /// leaving them as they were keeps the view picking.
    #[serde(default)]
    automatic_column: Vec<String>,
    layout: Option<ViewLayout>,
    group_by: Option<String>,
    #[serde(default)]
    page_size: String,
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
    #[serde(default)]
    sort: Vec<String>,
    direction: Option<SortDirectionParameter>,
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
    /// Public keys to judge the signed checkpoint with, inline only.
    #[serde(default)]
    trusted_key: Vec<String>,
}

/// The keys a request judges the signed checkpoint with.
///
/// The request's own `trusted_key` values when it gives any, and otherwise
/// whatever `CR_AUDIT_TRUSTED_KEYS` told the server to trust, so a monitor
/// polling the route checks the signature without knowing the key. A request
/// may only give keys inline: naming a file would let a remote caller choose
/// a path for the server to read. The environment is the operator's, so it
/// may name files, and it is read per request, like the encryption keyring.
fn request_trusted_keys(values: Vec<String>) -> anyhow::Result<Option<TrustedKeys>> {
    if values.is_empty() {
        TrustedKeys::from_environment()
    } else {
        TrustedKeys::parse_inline(values).map(Some)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRecordRequest {
    id: String,
    #[serde(default)]
    front_matter: Mapping,
    #[serde(default)]
    markdown: String,
    /// A bundle record's supporting files, by path.
    #[serde(default)]
    files: BTreeMap<String, FileContent>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRecordRequest {
    #[serde(default)]
    front_matter: Mapping,
    #[serde(default)]
    remove: Vec<String>,
    markdown: Option<String>,
    /// Supporting files to add or replace, by path, and `null` for each one
    /// to remove.
    #[serde(default)]
    files: BTreeMap<String, Option<FileContent>>,
}

/// The contents of one supporting file in a request body: text as is, or
/// any bytes as standard base64.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileContent {
    content: String,
    #[serde(default)]
    encoding: FileEncoding,
}

#[derive(Debug, Default, Deserialize)]
enum FileEncoding {
    #[default]
    #[serde(rename = "utf-8")]
    Utf8,
    #[serde(rename = "base64")]
    Base64,
}

impl FileContent {
    fn bytes(self, path: &str) -> ApiResult<Vec<u8>> {
        match self.encoding {
            FileEncoding::Utf8 => Ok(self.content.into_bytes()),
            FileEncoding::Base64 => {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(self.content.as_bytes())
                    .map_err(|_| {
                        ApiError::unprocessable(format!(
                            "file '{}' is not valid base64",
                            path.escape_default()
                        ))
                        .with_field(format!("files.{path}"))
                    })
            }
        }
    }
}

/// The file changes a create or patch body requests, in path order.
fn requested_files(
    files: impl IntoIterator<Item = (String, Option<FileContent>)>,
) -> ApiResult<Vec<FileChange>> {
    files
        .into_iter()
        .map(|(path, content)| {
            Ok(match content {
                Some(content) => FileChange::Write {
                    contents: content.bytes(&path)?,
                    path,
                },
                None => FileChange::Remove { path },
            })
        })
        .collect()
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
    /// How this request's principal was authenticated; `null` when it is the
    /// server's own identity or the owner console's selection.
    authentication: Option<Authentication>,
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

    /// Keep `detail` for the server log, which is the only place it goes.
    fn with_detail(mut self, detail: anyhow::Error) -> Self {
        self.detail = Some(detail);
        self
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
            | DomainError::AnchorMismatch(_)
            | DomainError::SignatureMismatch(_) => StatusCode::CONFLICT,
            DomainError::PreconditionFailed(_) => StatusCode::PRECONDITION_FAILED,
            DomainError::Forbidden(_) => StatusCode::FORBIDDEN,
            DomainError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            // The adapter is an upstream program `cr` runs, so its failure is
            // on the server's side of the exchange rather than the caller's.
            DomainError::AdapterFailed(_) => StatusCode::BAD_GATEWAY,
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
    application(database, config, Arc::default())
}

/// [`router`], with `journal_warm_up` as the walk its readiness reports on.
fn application(
    database: Database,
    config: ServerConfig,
    journal_warm_up: Arc<JournalWarmUp>,
) -> Result<Router> {
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
    // Either way of authenticating people replaces the owner console, and
    // with it everything the console needs: an owner launching it, and
    // loopback.
    let console = !config.require_token && config.cloudflare_access.is_none();
    if !console {
        let flag = if config.require_token {
            "--require-token"
        } else {
            "--cloudflare-access"
        };
        if !access_controlled {
            bail!(
                "{flag} authenticates registered principals, so it needs access control; run 'cr access init' first"
            );
        }
        if config.api_token.is_some() {
            bail!(
                "{flag} cannot be combined with CR_API_TOKEN, which acts as the launching owner; issue that caller a principal token instead"
            );
        }
    } else if access_controlled && !config.bind.ip().is_loopback() {
        bail!(
            "the RBAC perspective switcher is an owner-only local console and must bind to a loopback address; use --require-token or --cloudflare-access to serve authenticated principals beyond it"
        );
    }
    // The console serves the launching process as an owner, so it has to be
    // one. A server that authenticates its callers never acts as its
    // launcher, which is what lets it run as a service account with no user
    // record at all.
    if access_controlled && console {
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
        database: Arc::new(RwLock::new(database.with_source(AuditSource::Api))),
        access_controlled,
        max_page_size: config.max_page_size,
        api_token: config.api_token.map(Arc::from),
        require_token: config.require_token,
        cloudflare_access: config.cloudflare_access,
        csrf_token: Arc::from(random_token()?),
        journal_warm_up,
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
        // Like a record's delete, each is one path for both methods: `GET`
        // renders the editor or the question, and `POST` writes.
        .route("/browse/edit", get(edit_file_view).post(save_file_form))
        .route(
            "/browse/delete",
            get(confirm_delete_file).post(delete_file_form),
        )
        .route("/{view}", get(view_records))
        .route("/{view}/save-view", post(save_view_form))
        .route("/{view}/edit", get(edit_view_form).post(update_view_form))
        .route(
            "/{view}/delete",
            get(confirm_delete_view).post(delete_view_form),
        )
        .route("/{view}/new", get(new_record_form))
        .route("/{view}/records", post(create_record_form))
        .route(
            "/{view}/records/{id}",
            get(edit_record_form).post(update_record_form),
        )
        .route("/{view}/records/{id}/move", post(move_kanban_card))
        .route("/{view}/records/{id}/relations", post(link_record_form))
        .route(
            "/{view}/records/{id}/relations/remove",
            post(unlink_record_form),
        )
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
                    "/collections/{collection}/records/{id}/files/{*path}",
                    get(get_record_file),
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
        // Public like `/health`, because a probe cannot attach a bearer token,
        // and answered in a fixed vocabulary for the same reason; see `ready`.
        .route("/ready", get(ready))
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

/// Run the server until a shutdown signal, then drain it.
///
/// The first `SIGINT` or `SIGTERM` (Ctrl-C off Unix) closes the listener and
/// idle connections and waits, with no timer of its own, for every in-flight
/// request to be answered. A second one stops waiting and fails the command,
/// abandoning those responses.
///
/// Neither cuts a database operation in half. Handlers run them on the
/// runtime's blocking pool, and dropping the runtime — which `cr serve` does
/// on its way out — waits for pool work that has started and discards work
/// that has not, so by the time the process exits a mutation has either
/// committed its audit event or never written its pending file. Only
/// something that ends the process outright — `SIGKILL`, `SIGHUP`, a crash —
/// can stop one midway, and the write-ahead protocol recovers that on the
/// next start.
pub async fn serve(database: Database, config: ServerConfig) -> Result<()> {
    let bind = config.bind;
    // Before the listener exists, so a client that can connect can rely on a
    // signal draining the server rather than taking its default action and
    // ending the process in the middle of a request.
    let mut signals = ShutdownSignals::listen()?;
    // Given here rather than left to `router`, so the warm-up below fills the
    // cache every request will read.
    let database = database.with_journal_cache();
    let journal = database.clone();
    let warm_up = Arc::<JournalWarmUp>::default();
    let cloudflare_access = config.cloudflare_access.clone();
    let application = application(database, config, Arc::clone(&warm_up))?;
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
    // sooner waits on this walk rather than starting its own, and `/ready`
    // answers `journal_warming` until it returns.
    warm_up.start(journal);
    // Likewise the Cloudflare Access keys, so the first sign-in does not wait
    // for them, and a team domain that does not exist is reported now rather
    // than by the first person who tries. Not fatal: Cloudflare may be
    // unreachable for a moment, and the next sign-in or `/ready` probe tries
    // again, while `/ready` says why it cannot.
    if let Some(access) = cloudflare_access {
        tokio::task::spawn_blocking(move || match access.refresh_keys() {
            Ok(count) => println!(
                "Cloudflare Access: {} for audience {}, {count} signing key{}",
                access.issuer(),
                access.audience(),
                if count == 1 { "" } else { "s" }
            ),
            Err(error) => eprintln!(
                "warning: {error:#}; nobody can sign in through Cloudflare Access until the keys can be fetched"
            ),
        });
    }
    let (drain, drain_requested) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, application)
        .with_graceful_shutdown(async move {
            let _ = drain_requested.await;
        })
        .into_future();
    let mut server = std::pin::pin!(server);
    let signal = tokio::select! {
        result = server.as_mut() => return result.context("HTTP server failed"),
        signal = signals.recv() => signal?,
    };
    log_shutdown(format_args!(
        "signal={signal} state=draining detail=\"no longer accepting connections; waiting for in-flight requests; a second signal stops without waiting\""
    ));
    let _ = drain.send(());
    tokio::select! {
        result = server.as_mut() => {
            result.context("HTTP server failed")?;
            log_shutdown(format_args!("state=stopped detail=\"every in-flight request finished\""));
            Ok(())
        }
        signal = signals.recv() => {
            let signal = signal?;
            log_shutdown(format_args!(
                "signal={signal} state=abandoned detail=\"stopped waiting for in-flight requests; database work already running still finishes\""
            ));
            bail!("stopped before every in-flight request finished")
        }
    }
}

/// Write one shutdown line to standard error, beside the `cr error` lines.
///
/// Not `eprintln!`, which panics when standard error is a pipe nobody reads
/// any more: losing a log line is better than turning a drain into a panic.
fn log_shutdown(line: std::fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr(), "cr shutdown {line}");
}

/// The signals that ask `cr serve` to stop.
///
/// `SIGINT` is Ctrl-C at a terminal and `SIGTERM` is what `kill`, systemd,
/// Docker, and Kubernetes send, so both mean the same thing here. `SIGHUP` is
/// deliberately left alone: there is no configuration to reload, and catching
/// it would override the `SIG_IGN` that `nohup` sets, ending a server that was
/// asked to outlive its terminal. It keeps its default action and ends the
/// process at once, which the write-ahead protocol recovers from like any
/// other hard stop.
///
/// Registered once and for the life of the process: once tokio has replaced a
/// signal's default action it never restores it, so a signal after the
/// second is swallowed while database work finishes, and only `SIGKILL` stops
/// the process sooner.
#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn listen() -> Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("could not listen for SIGINT")?,
            terminate: signal(SignalKind::terminate()).context("could not listen for SIGTERM")?,
        })
    }

    async fn recv(&mut self) -> Result<&'static str> {
        tokio::select! {
            _ = self.interrupt.recv() => Ok("SIGINT"),
            _ = self.terminate.recv() => Ok("SIGTERM"),
        }
    }
}

/// Off Unix only Ctrl-C is handled; every other console event keeps its
/// default action.
#[cfg(not(unix))]
struct ShutdownSignals;

#[cfg(not(unix))]
impl ShutdownSignals {
    fn listen() -> Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> Result<&'static str> {
        tokio::signal::ctrl_c()
            .await
            .context("could not listen for Ctrl-C")?;
        Ok("Ctrl-C")
    }
}

/// Give every request a correlation ID, publish it to the handlers beneath
/// this layer, and return it so an operator can find the matching log line.
///
/// Every response also leaves here with `X-Content-Type-Options: nosniff`.
/// The content security policy's `'self'` trusts every URL on this origin as
/// a script or stylesheet source, not only `/static/`, and `nosniff` is what
/// makes a browser refuse a response in either role whose type is not
/// JavaScript or CSS. So it matters on the JSON API, its errors, `/health`,
/// `/openapi.json`, the assets, the redirects, and the fallbacks as much as on
/// the pages, and this is the one layer all of them pass through. No JSON
/// answer is a useful script today, so this is hardening rather than a fix:
/// what it buys is that a route added later cannot forget it. Inserted rather
/// than appended, so a handler that sets it too still sends one value.
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
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn authorize(State(state): State<AppState>, request: Request<Body>, next: Next) -> Response {
    let identity =
        match request_identity(&state, request.method(), request.uri(), request.headers()).await {
            Ok(identity) => identity,
            Err(error) => return refusal(&state, request.uri().path(), error),
        };
    let mut response = REQUEST_IDENTITY.scope(identity, next.run(request)).await;
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
        if state.cloudflare_access.is_some() {
            vary_on(response.headers_mut(), CLOUDFLARE_ACCESS_VARY);
        }
    }
    response
}

/// The assertion header as `Vary` names it.
const CLOUDFLARE_ACCESS_VARY: &str = "Cf-Access-Jwt-Assertion";

/// Answer a request the authorization layer refused.
///
/// In JSON, as every refusal always was, except to a browser that signs in
/// through Cloudflare Access: somebody whose address no user holds reaches
/// this by following a link, and should read a page rather than an envelope.
fn refusal(state: &AppState, path: &str, error: ApiError) -> Response {
    let unauthorized = error.status == StatusCode::UNAUTHORIZED;
    let is_api = path == "/openapi.json" || path == "/api" || path.starts_with("/api/");
    if state.cloudflare_access.is_none() || is_api {
        return error.into_response();
    }
    let mut response = html_error(error);
    if unauthorized {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"cr\""),
        );
    }
    response
}

/// Establish who a request is from its credentials.
///
/// A principal token either authenticates or is refused: it never falls back
/// to the console, because a revoked token that quietly became the launching
/// owner would turn revocation into escalation. `CR_API_TOKEN` keeps its
/// meaning — the console, as the launching owner — and `--require-token`
/// accepts nothing but a principal token.
///
/// Under `--cloudflare-access` a request without a principal token must carry
/// a Cloudflare Access assertion that verifies. The token is looked at first
/// because a script behind Access carries both — an assertion for its service
/// token, which names nobody, and the bearer token that names its principal —
/// and presenting a token is the more deliberate act. With
/// `--cloudflare-access` alone the token is refused instead, so an operator
/// who chose the organisation's login gets nothing that bypasses it.
async fn request_identity(
    state: &AppState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> ApiResult<RequestIdentity> {
    let unauthorized =
        |message: &str| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", message.to_owned());
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if let (Some(presented), Some(expected)) = (bearer, &state.api_token)
        && secrets_match(presented, expected)
    {
        return Ok(RequestIdentity::Console);
    }
    if let Some(presented) = bearer.filter(|value| value.starts_with(TOKEN_PREFIX)) {
        if !state.access_controlled {
            return Err(unauthorized(
                "principal tokens authenticate registered users, and access control is not initialized",
            ));
        }
        if state.cloudflare_access.is_some() && !state.require_token {
            return Err(unauthorized(
                "this server signs people in through Cloudflare Access and accepts no principal tokens; start it with --require-token as well to accept both",
            ));
        }
        let database = state.database();
        let presented = presented.to_owned();
        let authenticated =
            tokio::task::spawn_blocking(move || database.authenticate_token(&presented))
                .await
                .map_err(|error| {
                    ApiError::internal(anyhow!(error).context("database task failed"))
                })?
                .map_err(ApiError::from_domain)?;
        return authenticated
            .map(|database| authenticated_identity(state, database))
            .ok_or_else(|| unauthorized("the principal token is not valid"));
    }
    if let Some(access) = &state.cloudflare_access {
        let database = cloudflare_access_database(state, access, headers).await?;
        refuse_cross_site(method, uri, headers)?;
        return Ok(authenticated_identity(state, database));
    }
    if state.require_token {
        return Err(unauthorized("provide a principal token as a Bearer token"));
    }
    if state.api_token.is_some() {
        return Err(unauthorized("provide a valid Bearer token"));
    }
    Ok(RequestIdentity::Console)
}

fn authenticated_identity(state: &AppState, database: Database) -> RequestIdentity {
    RequestIdentity::Authenticated {
        csrf: principal_csrf_token(&state.csrf_token, database.principal()),
        database: Box::new(database),
    }
}

/// The database acting as the user a request's Cloudflare Access assertion
/// signed in.
///
/// Only the signed assertion is read. `Cf-Access-Authenticated-User-Email`
/// and the `CF_Authorization` cookie say the same thing unsigned, and
/// anything that can reach the server's port can send them.
async fn cloudflare_access_database(
    state: &AppState,
    access: &Arc<CloudflareAccess>,
    headers: &HeaderMap,
) -> ApiResult<Database> {
    let unauthorized =
        |message: String| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", message);
    let mut assertions = headers.get_all(cloudflare_access::ASSERTION_HEADER).iter();
    let assertion = match (assertions.next(), assertions.next()) {
        (Some(assertion), None) => assertion
            .to_str()
            .map_err(|_| unauthorized("the Cloudflare Access assertion is not valid".to_owned()))?
            .to_owned(),
        (Some(_), Some(_)) => {
            return Err(unauthorized(
                "a request carries one Cloudflare Access assertion, not several".to_owned(),
            ));
        }
        (None, _) => {
            return Err(unauthorized(
                if state.require_token {
                    "sign in through Cloudflare Access, or provide a principal token as a Bearer token"
                } else {
                    "sign in through Cloudflare Access"
                }
                .to_owned(),
            ));
        }
    };
    let access = Arc::clone(access);
    let database = state.database();
    tokio::task::spawn_blocking(move || {
        let verified = match access.verify(&assertion) {
            Ok(verified) => verified,
            Err(error @ AssertionError::Rejected(_)) => {
                return Ok(Err(unauthorized(error.to_string())));
            }
            Err(AssertionError::KeysUnavailable(error)) => {
                return Ok(Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authentication_unavailable",
                    "Cloudflare Access signing keys could not be fetched",
                )
                .with_detail(error)));
            }
        };
        let authentication = Authentication {
            method: AuthenticationMethod::CloudflareAccess,
            credential: verified.subject,
        };
        database
            .authenticate_email(&verified.email, authentication)
            .map(|database| {
                database.ok_or_else(|| {
                    unauthorized(format!(
                        "Cloudflare Access signed you in as {}, and no single active cr user has that email; ask a database owner to register it",
                        verified.email
                    ))
                })
            })
    })
    .await
    .map_err(|error| ApiError::internal(anyhow!(error).context("database task failed")))?
    .map_err(ApiError::from_domain)?
}

/// Refuse a state-changing request a browser says another site started.
///
/// A Cloudflare Access session is a cookie, which a browser attaches to a
/// request whichever page makes it, and Access then signs the request as the
/// person. So a form on another site, including another application on the
/// same domain, could post to this server as whoever visits it. Form tokens
/// cover cr's own forms, but not the JSON routes that take no body, and a
/// principal token is not ambient in this way, which is why only an
/// assertion-authenticated request is checked.
///
/// `Sec-Fetch-Site`, which a browser sets and a page cannot, answers the
/// question directly. A browser that predates it still sends `Origin` on a
/// POST, which must then name the host the request was sent to. A request
/// with neither did not come from a browser that could have been tricked.
fn refuse_cross_site(method: &Method, uri: &Uri, headers: &HeaderMap) -> ApiResult<()> {
    if method.is_safe() {
        return Ok(());
    }
    let refused = || {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "cross_site_request",
            "a browser signed in through Cloudflare Access may change data only from cr's own pages",
        )
    };
    if let Some(site) = headers.get("sec-fetch-site") {
        return if site.as_bytes() == b"same-origin" {
            Ok(())
        } else {
            Err(refused())
        };
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let origin = origin
            .to_str()
            .ok()
            .and_then(|origin| origin.split_once("://"))
            .map(|(_, authority)| authority);
        let host = headers
            .get(header::HOST)
            .and_then(|host| host.to_str().ok())
            .or_else(|| uri.authority().map(|authority| authority.as_str()));
        return match (origin, host) {
            (Some(origin), Some(host)) if origin.eq_ignore_ascii_case(host) => Ok(()),
            _ => Err(refused()),
        };
    }
    Ok(())
}

/// Compare two secrets in time that does not depend on where they differ.
fn secrets_match(presented: &str, expected: &str) -> bool {
    let presented = Sha256::digest(presented.as_bytes());
    let expected = Sha256::digest(expected.as_bytes());
    presented
        .iter()
        .zip(expected.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
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

/// Whether this server can answer requests that read the database, as
/// `200 {"status":"ready"}` or `503` with every check that ran and the request
/// ID.
///
/// Public like `/health`: a load balancer's probe cannot attach a bearer
/// token. So the answer is a fixed vocabulary of check names and codes that
/// never carries a path, a record, a sync, or a count, and why each check
/// failed goes to the server log under the request ID, as any error's detail
/// does. Each check is cheap and none waits for a lock; see `src/readiness.rs`.
async fn ready(State(state): State<AppState>) -> Response {
    let database = state.database();
    let warm_up = Arc::clone(&state.journal_warm_up);
    let cloudflare_access = state.cloudflare_access.clone();
    let readiness = match tokio::task::spawn_blocking(move || {
        readiness::assess(&database, &warm_up, cloudflare_access.as_ref())
    })
    .await
    {
        Ok(readiness) => readiness,
        Err(error) => {
            return ApiError::internal(anyhow!(error).context("readiness task failed"))
                .into_response();
        }
    };
    if readiness.ready() {
        return Json(ReadinessResponse {
            status: "ready",
            checks: Vec::new(),
            request_id: None,
        })
        .into_response();
    }
    let request_id = current_request_id();
    let checks = readiness
        .checks
        .into_iter()
        .map(|(check, failure)| {
            if let Some(failure) = &failure {
                log_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    failure.code,
                    &request_id,
                    &failure.detail,
                );
            }
            ReadinessCheckResponse {
                name: check.name(),
                ok: failure.is_none(),
                code: failure.map(|failure| failure.code),
            }
        })
        .collect();
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ReadinessResponse {
            status: "not_ready",
            checks,
            request_id: Some(request_id),
        }),
    )
        .into_response()
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

/// The server's own stylesheet: the colour tokens, the shell, and the `cr-`
/// component classes.
///
/// It was a string constant inlined as a `<style>` block in every page, the
/// last thing between these pages and a `style-src` that allows nothing inline.
/// It is a constant either way, so it moved to a file beside `cr.js` for the
/// reason the script did — an editor understands it there — and is linked like
/// the utilities. That costs the first page a second stylesheet request, from
/// the same origin and in parallel with the first, and costs every page after
/// it nothing: the name is content addressed and cached as `immutable`.
const UI_STYLESHEET: &str = include_str!("static/cr.css");

/// `cr-<digest>.css`, content addressed like `cr-<digest>.js`.
static UI_STYLESHEET_NAME: LazyLock<String> = LazyLock::new(|| {
    format!(
        "cr-{}.css",
        hexadecimal(&Sha256::digest(UI_STYLESHEET)[..8])
    )
});

/// The absolute path rendered pages link, as `/static/cr-<digest>.css`.
static UI_STYLESHEET_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/{}", UI_STYLESHEET_NAME.as_str()));

/// The tab icon, served rather than written into every page as a `data:` URL,
/// so that `img-src` needs no source beyond this origin.
const FAVICON: &str = include_str!("static/favicon.svg");

/// `favicon-<digest>.svg`, content addressed like the other assets.
static FAVICON_NAME: LazyLock<String> =
    LazyLock::new(|| format!("favicon-{}.svg", hexadecimal(&Sha256::digest(FAVICON)[..8])));

/// The absolute path rendered pages link, as `/static/favicon-<digest>.svg`.
static FAVICON_PATH: LazyLock<String> =
    LazyLock::new(|| format!("/static/{}", FAVICON_NAME.as_str()));

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
/// navigation, and a refusal it can show. Two forms have both — `204` with
/// `HX-Location` (see `mutation_redirect`) and the re-rendered form itself,
/// marked `CR-Form-Invalid` — and are therefore boosted like the rest of the
/// page: the record create and edit form (see `reject_record_form`) and "Save
/// as view" (see `reject_save_view_form`). The remaining ones keep the
/// attribute, each for a reason of its own:
///
/// * The **delete** form — now the one on the confirmation page, not a form on
///   the record page — answers a refusal with a rendered error document. A
///   version that no longer matches is a `412`, and htmx will not swap a failed
///   `POST`, so boosting it would turn a lost race into a button that visibly
///   does nothing. That reason replaces an older one: the form used to stay
///   native because its confirmation was an `onsubmit` handler that htmx's
///   submit listener does not consult, so a boost would have deleted a record
///   after a declined confirmation. That handler is gone. The confirmation is a
///   page the server renders, which is asked of a browser with no JavaScript
///   too; see `delete_confirmation_url`. The saved-view editor and the view
///   delete form stay native for the same first reason: a refusal is a page.
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
/// The **perspective** form answers a switch with `303 See Other` back to `/`
/// and a new cookie. An `XMLHttpRequest` follows that redirect invisibly, so a
/// boosted switch would swap the right page in while pushing `/perspective`
/// into the address bar. The attribute used to be belt and braces here, because
/// the `<select>` submitted itself with `form.submit()`, which fires no submit
/// event; it is load bearing now that the form is submitted by its own button
/// (see `perspective_control`).
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
/// The content type is per asset, because they are scripts, stylesheets and an
/// image. The cache lifetime is shared and never has to move into the match,
/// because every name here is derived from the bytes it names.
async fn static_asset(Segments(file): Segments<String>) -> Response {
    const JAVASCRIPT: &str = "text/javascript; charset=utf-8";
    const CSS: &str = "text/css; charset=utf-8";
    let (content, content_type) = match file.as_str() {
        name if name == UI_SCRIPT_NAME.as_str() => (UI_SCRIPT, JAVASCRIPT),
        name if name == HTMX_SCRIPT_NAME.as_str() => (HTMX_SCRIPT, JAVASCRIPT),
        name if name == TAILWIND_STYLESHEET_NAME.as_str() => (TAILWIND_STYLESHEET, CSS),
        name if name == UI_STYLESHEET_NAME.as_str() => (UI_STYLESHEET, CSS),
        name if name == FAVICON_NAME.as_str() => (FAVICON, "image/svg+xml"),
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
        if authenticated_database().is_some() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "an authenticated request acts as its own principal and has no perspective to switch",
            ));
        }
        let form: HtmlPerspectiveForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let principal = form.principal.trim().to_owned();
        let database = state.database();
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
        let mut response = see_other("/");
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
            &request_csrf_token(&state),
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
        let (entries, people) = run_database(&state, &headers, move |database| {
            let entries = database.audit_recent(
                requested,
                AuditFilter {
                    collection: collection.as_deref(),
                    id: id.as_deref(),
                    agent: agent.as_deref(),
                    session: session.as_deref(),
                },
            )?;
            let users = entries
                .iter()
                .map(|entry| &entry.payload.record)
                .filter(|record| record.collection == USERS_COLLECTION)
                .map(|record| record.id.as_str())
                .collect::<BTreeSet<_>>();
            let people = user_names(database, users);
            Ok((entries, people))
        })
        .await?;
        let page = paginate_unknown_total(entries, bounds);
        let navigation = run_database(&state, &headers, Database::views).await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_audit_view(
            &Representation::requested(&headers),
            &page,
            &people,
            &query,
            &navigation,
            ui.as_ref(),
            &request_csrf_token(&state),
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
            &request_csrf_token(&state),
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
        let (start, navigation) = authorize_file_browser(&state, &headers).await?;
        let query: BrowseQuery = parse_query(raw)?;
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
                    path: page.location.join(&entry.name),
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
            &request_csrf_token(&state),
        ))
    }
    .await;
    html_result(result)
}

/// The check every file-browser route makes before it touches the filesystem:
/// the routes exist only under RBAC, and only a database owner may use them,
/// from the local console or signed in by a token or Cloudflare Access.
///
/// The browser reads and writes any file the server's account can, beyond the
/// database and outside its audit log, so an owner's token or sign-in is worth
/// as much as that account.
///
/// Returns the database root, where browsing starts and which the editor and
/// the delete page compare a file against, and the sidebar's views.
async fn authorize_file_browser(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(PathBuf, Vec<ViewDefinition>)> {
    if !state.access_controlled {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "route_not_found",
            "route not found",
        ));
    }
    run_database(state, headers, |database| {
        if !database.owner_access_allowed(&AccessResource::Database)? {
            return Err(
                DomainError::Forbidden("principal cannot browse server files".to_owned()).into(),
            );
        }
        Ok((database.root().to_path_buf(), database.views()?))
    })
    .await
}

/// A text file, open for editing.
///
/// The pencil on a file panel links here, so with no JavaScript this is a page
/// of its own: the file's panel with a textarea where the preview was. htmx
/// asks for the panel alone, naming the section it sits in as the target, and
/// swaps it into that section, so the preview becomes the editor where it
/// stands — beneath a directory's listing too. That answer carries
/// `HX-Push-Url: false`: htmx pushes the URL of every boosted request, and an
/// editor in the middle of a page is not a page, so the address bar stays on
/// the one it was opened from. The attribute cannot say so; htmx ignores
/// `hx-push-url="false"` on a boosted link.
///
/// Only a file whose preview is the whole file as text can be edited. Anything
/// else is refused rather than offered as a truncation or a hex dump, which
/// saving would then write back over the file.
async fn edit_file_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Response> = async {
        let (root, navigation) = authorize_file_browser(&state, &headers).await?;
        let query: BrowseFileQuery = parse_query(raw)?;
        let requested = absolute_browse_path(&query.path)?;
        let from = query
            .from
            .as_deref()
            .map(absolute_browse_path)
            .transpose()?;
        let (path, file) = tokio::task::spawn_blocking(move || {
            let path = std::fs::canonicalize(&requested)
                .map_err(|error| browse_io_error(error, "could not resolve the file to edit"))?;
            let file = browse_file(&path)?;
            Ok::<_, ApiError>((path, file))
        })
        .await
        .map_err(|error| {
            ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
        })??;
        let (BrowserFileContents::Text(contents), Some(version)) = (file.contents, file.version)
        else {
            return Err(ApiError::unprocessable(format!(
                "only a text file of at most {} can be edited in the browser",
                format_file_size(MAX_FILE_PREVIEW_BYTES as u64)
            )));
        };
        let representation = Representation::requested(&headers);
        let region = FILE_PANEL_REGIONS
            .into_iter()
            .find(|region| representation.wants(region));
        let editor = FileEditor {
            from: from.unwrap_or_else(|| path.clone()),
            path,
            region: region.unwrap_or(FILE_PANEL_REGION),
            contents,
            version,
            rejection: None,
        };
        if region.is_some() {
            let mut response = html_response(
                StatusCode::OK,
                render_file_editor(&editor, &root, &request_csrf_token(&state)),
            );
            response.headers_mut().insert(
                HeaderName::from_static("hx-push-url"),
                HeaderValue::from_static("false"),
            );
            return Ok(response);
        }
        let ui = ui_context(&state, &headers).await?;
        Ok(html_response(
            StatusCode::OK,
            render_file_editor_page(
                &representation,
                &editor,
                &root,
                &navigation,
                ui.as_ref(),
                &request_csrf_token(&state),
            ),
        ))
    }
    .await;
    result.unwrap_or_else(html_error)
}

/// Save an edited file and return to the page it was edited on.
///
/// A save that fails once the form is known to be genuine — the file changed
/// since it was opened, it has gone, the server process may not write there —
/// answers with the editor again, holding exactly what was typed, under the
/// status of the refusal. The form is native, so a browser shows that page
/// whatever the status, and the typed text is never lost to a failed save.
async fn save_file_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let (root, navigation) = authorize_file_browser(&state, &headers).await?;
        let form: HtmlFileEditForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let path = absolute_browse_path(&form.path)?;
        let from = absolute_browse_path(&form.from)?;
        let saved = {
            let path = path.clone();
            let expected = form.expected_version.clone();
            let contents = form.contents.clone();
            tokio::task::spawn_blocking(move || save_browser_file(&path, &expected, &contents))
                .await
                .map_err(|error| {
                    ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
                })?
        };
        let region = file_panel_region(&path, &from);
        let Err(error) = saved else {
            return Ok(see_other(&file_panel_url(&from, region)));
        };
        let error = error.publish();
        let status = error.status;
        let ui = ui_context(&state, &headers).await?;
        let editor = FileEditor {
            path,
            from,
            region,
            contents: form.contents,
            version: form.expected_version,
            rejection: Some(error),
        };
        Ok(html_response(
            status,
            render_file_editor_page(
                &Representation::requested(&headers),
                &editor,
                &root,
                &navigation,
                ui.as_ref(),
                &request_csrf_token(&state),
            ),
        ))
    }
    .await;
    result.unwrap_or_else(html_error)
}

/// Ask before deleting a file, the way a record's deletion is asked.
///
/// The trash can on a file panel is a link to this page, and only this page
/// carries the form and the token, so nothing deletes a file on one click,
/// with or without JavaScript.
async fn confirm_delete_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let (root, navigation) = authorize_file_browser(&state, &headers).await?;
        let query: BrowseFileQuery = parse_query(raw)?;
        let requested = absolute_browse_path(&query.path)?;
        let from = query
            .from
            .as_deref()
            .map(absolute_browse_path)
            .transpose()?;
        let (path, size) = tokio::task::spawn_blocking(move || {
            let path = std::fs::canonicalize(&requested)
                .map_err(|error| browse_io_error(error, "could not resolve the file to delete"))?;
            let metadata = std::fs::metadata(&path)
                .map_err(|error| browse_io_error(error, "could not inspect the file to delete"))?;
            if !metadata.is_file() {
                return Err(ApiError::unprocessable(
                    "only a regular file can be deleted in the browser",
                ));
            }
            Ok((path, metadata.len()))
        })
        .await
        .map_err(|error| {
            ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
        })??;
        let from = from.unwrap_or_else(|| path.clone());
        let ui = ui_context(&state, &headers).await?;
        Ok(render_file_delete_confirmation(
            &Representation::requested(&headers),
            &path,
            &from,
            size,
            &root,
            &navigation,
            ui.as_ref(),
            &request_csrf_token(&state),
        ))
    }
    .await;
    html_result(result)
}

/// Delete a file and return to the directory that held it.
///
/// A file that is already gone is not an error: the form is native, so a double
/// click submits twice and the second has nothing left to do.
async fn delete_file_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        authorize_file_browser(&state, &headers).await?;
        let form: HtmlFileDeleteForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let path = absolute_browse_path(&form.path)?;
        let (Some(directory), Some(name)) = (path.parent(), path.file_name()) else {
            return Err(ApiError::unprocessable(
                "only a regular file can be deleted in the browser",
            ));
        };
        let back = browse_url(&directory.to_string_lossy());
        let (directory, name) = (directory.to_path_buf(), PathBuf::from(name));
        tokio::task::spawn_blocking(move || {
            match paths::remove_file(&directory, &name, BROWSER_FILE) {
                Err(error) if !is_missing(&error) => Err(browse_change_error(error)),
                _ => Ok(()),
            }
        })
        .await
        .map_err(|error| {
            ApiError::internal(anyhow!(error).context("filesystem browser task failed"))
        })??;
        Ok(see_other(&back))
    }
    .await;
    result.unwrap_or_else(html_error)
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
        Ok(see_other(&back))
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
            version: (!truncated).then(|| file_version(&bytes)),
        });
    }

    let binary_bytes = bytes.len().min(MAX_BINARY_PREVIEW_BYTES);
    truncated |= binary_bytes < bytes.len();
    Ok(BrowserFile {
        contents: BrowserFileContents::Binary(hex_preview(&bytes[..binary_bytes])),
        bytes_shown: binary_bytes,
        total_bytes,
        truncated,
        version: None,
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

/// What the symlink-safe file operations call the file the browser edits or
/// deletes, in the refusals a caller may see.
const BROWSER_FILE: &str = "the file";

/// Which of a browse page's file panels an in-place edit replaces, by the id
/// of the element holding it: an opened file's, or a directory's README or
/// `SKILL.md`, whose sections are named by their anchors.
const FILE_PANEL_REGION: &str = "file";
const FILE_PANEL_REGIONS: [&str; 3] = [FILE_PANEL_REGION, "readme", "skill"];

/// The panel `path` is shown in on the browse page for `from`: the directory
/// document it is, or else the page's own file panel.
fn file_panel_region(path: &FilePath, from: &FilePath) -> &'static str {
    let name = path.file_name().and_then(|name| name.to_str());
    match name {
        Some(name) if path.parent() == Some(from) => {
            if README_NAMES
                .iter()
                .any(|readme| name.eq_ignore_ascii_case(readme))
            {
                "readme"
            } else if name.eq_ignore_ascii_case(SKILL_NAME) {
                "skill"
            } else {
                FILE_PANEL_REGION
            }
        }
        _ => FILE_PANEL_REGION,
    }
}

/// The browse page for `from`, scrolled to the panel in `region` when it is a
/// directory document rather than the page's own file.
fn file_panel_url(from: &FilePath, region: &str) -> String {
    let url = browse_url(&from.to_string_lossy());
    if region == FILE_PANEL_REGION {
        url
    } else {
        format!("{url}#{region}")
    }
}

/// A route acting on one file, with the browse page it was opened from.
fn file_action_url(route: &str, path: &str, from: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("path", path);
    serializer.append_pair("from", from);
    format!("{route}?{}", serializer.finish())
}

fn absolute_browse_path(path: &str) -> ApiResult<PathBuf> {
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(ApiError::bad_request(
            "invalid_browse_path",
            "filesystem browser paths must be absolute",
        ));
    }
    Ok(path)
}

/// A file's exact bytes as the version an edit must still match to be saved.
fn file_version(bytes: &[u8]) -> String {
    format!("sha256:{}", hexadecimal(&Sha256::digest(bytes)))
}

/// Replace a file the browser edited, if it still holds what was edited.
///
/// The version is the hash of the whole file as the editor opened it, so a file
/// changed since — by an agent, an editor, another tab — is refused with `412`
/// rather than overwritten. A submission the file already holds is accepted
/// without writing, which is also what makes a second click on the native
/// form's Save harmless rather than a refusal of the first.
///
/// The write is the one a record's is: staged beside the file, given the
/// file's permissions, renamed over it through the directory's descriptor, and
/// synced, refusing a symbolic link at either end rather than following it.
fn save_browser_file(path: &FilePath, expected_version: &str, submitted: &str) -> ApiResult<()> {
    let (Some(directory), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(ApiError::unprocessable(
            "the requested filesystem location is not a regular file",
        ));
    };
    let name = FilePath::new(name);
    let mut current = Vec::new();
    paths::open_file(directory, name, BROWSER_FILE)
        .map_err(browse_change_error)?
        .take(MAX_FILE_PREVIEW_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut current)
        .map_err(|error| browse_io_error(error, "could not read the file being saved"))?;
    // A textarea submits every line break as CRLF. A file written with CRLF
    // throughout keeps it; any other file gets back the line feeds it had.
    let crlf = current.windows(2).any(|pair| pair == b"\r\n")
        && current
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte != b'\n' || index > 0 && current[index - 1] == b'\r');
    let contents = if crlf {
        submitted.to_owned()
    } else {
        form_text(submitted)
    };
    if current == contents.as_bytes() {
        return Ok(());
    }
    if file_version(&current) != expected_version {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            "the file changed after it was opened, so it was not overwritten; open it again to see what changed",
        ));
    }
    if contents.len() > MAX_FILE_PREVIEW_BYTES {
        return Err(ApiError::unprocessable(format!(
            "the browser saves a file of at most {}",
            format_file_size(MAX_FILE_PREVIEW_BYTES as u64)
        )));
    }
    paths::write_replace(directory, name, contents.as_bytes(), BROWSER_FILE)
        .map_err(browse_change_error)
}

/// Classify a failure to change a file from the browser: a refused link or
/// special file as the conflict it is, and the operating system's refusals by
/// kind, never by their text.
fn browse_change_error(error: anyhow::Error) -> ApiError {
    if DomainError::of(&error).is_some() {
        return ApiError::from_domain(error);
    }
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .map(io::Error::kind);
    let (status, code, message) = match kind {
        Some(io::ErrorKind::NotFound) => (
            StatusCode::NOT_FOUND,
            "filesystem_not_found",
            "the requested filesystem location does not exist",
        ),
        Some(io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem) => (
            StatusCode::FORBIDDEN,
            "filesystem_permission_denied",
            "the CR server process cannot change this filesystem location",
        ),
        _ => return ApiError::internal(error),
    };
    ApiError {
        status,
        code,
        message: message.to_owned(),
        detail: Some(error),
        field: None,
    }
}

async fn view_records(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
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
            quick_filter,
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
            records.retain(|record| predicates.matches(&record.attributes));
            let schema = database
                .collection_models()?
                .into_iter()
                .find(|model| model.name == view.collection)
                .and_then(|model| model.schema);
            // Counted before the ad hoc filters narrow the records, because a
            // chip's count is what the view would show with the chip's
            // condition in place of any on its field.
            let quick_filter = quick_filter(&view, schema.as_ref(), &records, &query_for_database);
            records.retain(|record| {
                query_for_database
                    .filter_match
                    .matches(&ad_hoc_filters, &record.attributes)
            });
            // One verified journal walk per page: the created and updated
            // columns are derived from history, and the sort default reads
            // them, so this is not optional work the renderer can skip.
            let activity = database.record_activity(&view.collection)?;
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
                quick_filter,
                navigation,
                can_create,
                can_manage_views,
                updatable,
            ))
        })
        .await?;

        // Making the default explicit in the query keeps the header
        // indicator, the sort controls, and every generated link agreeing
        // about what the page is actually ordered by, and spelling the
        // requested sort back out drops the rows the panel left at "None".
        let sort = query
            .requested_sort()
            .unwrap_or_else(|| view_default_sort(&view));
        query.set_sort(&sort);

        let available_columns = view_available_columns(&view, &records, schema.as_ref());
        let columns =
            selected_view_columns(&view, &query, &available_columns, schema.as_ref(), &records)?;
        sort_view_records(&mut records, &query, &activity)?;
        let bounds = page_bounds(
            query
                .limit
                .or(Some(view.page_size.min(state.max_page_size))),
            query.offset,
            state.max_page_size,
        )?;
        let page = match (view.layout, view.group_by.as_deref()) {
            (ViewLayout::Kanban, Some(group_by)) => {
                paginate_board(records, bounds.limit, state.max_page_size, group_by)
            }
            _ => paginate_view(
                records,
                bounds.limit,
                state.max_page_size,
                view_position(&query, bounds.offset),
            ),
        };
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
            &request_csrf_token(&state),
            &navigation,
            ui.as_ref(),
            can_create,
            can_manage_views,
            &updatable,
            quick_filter.as_ref(),
        ))
    }
    .await;
    html_result(result)
}

async fn save_view_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
    RawForm(raw): RawForm,
) -> Response {
    // As on the record form, a body that is not the form this server rendered
    // says nothing about what was typed, so it keeps the error page. Every
    // refusal after this point is answered with the form itself.
    let form: HtmlSaveViewForm = match parse_html_form(&raw) {
        Ok(form) => form,
        Err(error) => return html_error(error),
    };
    let submitted = form.clone();
    let result: ApiResult<Response> = async {
        verify_csrf(&state, &form.csrf)?;
        let name = form.name.trim().to_owned();
        if name.is_empty() {
            return Err(
                ApiError::bad_request("invalid_form", "view name cannot be empty")
                    .with_field(VIEW_NAME_CONTROL),
            );
        }
        let title = (!form.title.trim().is_empty()).then(|| form.title.trim().to_owned());
        let filter_group = submitted_filter_group(
            form.filter_match,
            &form.filter_field,
            &form.filter_operator,
            &form.filter_value,
        )?;
        let mut sort = submitted_sort(&form.sort_field, &form.sort_direction);
        // The panel's "None" is record ID order, and a view saved with no sort
        // would open on the default instead, so it is saved as what it is.
        if sort.is_empty() && !form.sort_field.is_empty() {
            sort.push(SortKey::new("$id", SortDirection::Asc));
        }
        let requested_view = view_name.clone();
        // Two layers of refusal: the outer one is reading the source view, and
        // the inner one is a refusal of what was submitted, classified where it
        // is known which control it is about.
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
                ViewLayout::Kanban => match submitted_group_by.or_else(|| {
                    (source.layout == ViewLayout::Kanban)
                        .then(|| source.group_by.clone())
                        .flatten()
                }) {
                    Some(group_by) => Some(group_by),
                    None => {
                        return Ok(Err(ApiError::from_domain(
                            DomainError::Invalid("Kanban layout must provide group_by".to_owned())
                                .into(),
                        )
                        .with_field(GROUP_BY_CONTROL)));
                    }
                },
            };
            Ok(database
                .create_view_with_options(
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
                    sort,
                )
                .map_err(|error| refused_view_name(ApiError::from_domain(error), &name)))
        })
        .await??;
        Ok(mutation_redirect(
            &Representation::requested(&headers),
            &notice_url(&saved.name, "View saved"),
        ))
    }
    .await;
    match result {
        Ok(response) => response,
        Err(error) => reject_save_view_form(&state, &headers, &view_name, submitted, error).await,
    }
}

/// Put a refused save beside the view name when the name is what was refused.
///
/// Classified by the stable domain code and never by the message: a name
/// already taken is `already_exists`, the one conflict creating a view can
/// report. A name no view may have — a path separator, `.`, a route the server
/// reserves — is a validation failure like any other, so it is recognised by
/// the name itself failing the check that `create_view_with_options` makes
/// before it validates anything else.
fn refused_view_name(error: ApiError, name: &str) -> ApiError {
    let taken = error.code == DomainError::AlreadyExists(String::new()).code();
    let unusable = error.code == DomainError::Invalid(String::new()).code()
        && validate_view_name(name).is_err();
    if taken || unusable {
        return error.with_field(VIEW_NAME_CONTROL);
    }
    error
}

/// Answer a refused "Save as view" with the form, holding what was sent.
///
/// The record form's contract on a smaller form. It used to be the generic
/// error page, which lost the filters, sort and columns the reader had
/// assembled along with the name they typed. Now the name and title come back
/// as typed, the layout and grouping as chosen, and the page's state in the
/// hidden fields it was submitted from, with the reason at the top and, for a
/// name that is taken or unusable or a Kanban layout with nothing to group by,
/// beside that control. The status is the status of the refusal — `409`,
/// `422`, `400`, `403` — which is what the rest of the server answers for it.
///
/// htmx asked for the form alone and swaps it into the popover it came from,
/// which stays open. A plain post is given the same form on a page of its own
/// rather than the view it was saved from, whose rows the form has no business
/// re-reading; see `render_refused_save_view`.
async fn reject_save_view_form(
    state: &AppState,
    headers: &HeaderMap,
    view_name: &str,
    submitted: HtmlSaveViewForm,
    error: ApiError,
) -> Response {
    // As for the record form: an internal failure keeps the error page, and so
    // does a source view that cannot be read, since the form is about it.
    if error.status.is_server_error() {
        return html_error(error);
    }
    let error_field = error.field.clone();
    let requested_view = view_name.to_owned();
    let loaded = async {
        let context = run_database(state, headers, move |database| {
            let view = database.view(&requested_view)?;
            // Every readable record, to offer its fields for grouping, as the
            // saved-view editor does.
            let records = database.list(&view.collection, &[])?;
            let schema = collection_schema(database, &view.collection)?;
            let navigation = database.views()?;
            Ok((view, records, schema, navigation))
        })
        .await?;
        Ok::<_, ApiError>((context, ui_context(state, headers).await?))
    }
    .await;
    let ((view, records, schema, navigation), ui) = match loaded {
        Ok(context) => context,
        Err(secondary) => {
            secondary.publish();
            return html_error(error);
        }
    };
    let published = error.publish();
    let status = published.status;
    let fields = error_field
        .map(|field| BTreeMap::from([(field, vec![published.message.clone()])]))
        .unwrap_or_default();
    let rejection = SaveViewRejection {
        error: published,
        fields,
        submitted,
    };
    let markup = render_refused_save_view(
        &Representation::requested(headers),
        &view,
        &view_available_columns(&view, &records, schema.as_ref()),
        schema.as_ref(),
        &request_csrf_token(state),
        &rejection,
        &navigation,
        ui.as_ref(),
        state.max_page_size,
    );
    rejected_form_response(status, markup)
}

/// Everything the saved-view editor shows besides the draft in its controls.
struct ViewEditorContext {
    view: ViewDefinition,
    schema: Option<JsonValue>,
    /// Every record of the collection, to offer its fields as columns and
    /// filters and to find its title field.
    records: Vec<Record>,
    navigation: Vec<ViewDefinition>,
}

async fn view_editor_context(
    state: &AppState,
    headers: &HeaderMap,
    view_name: &str,
) -> ApiResult<ViewEditorContext> {
    let requested_view = view_name.to_owned();
    run_database(state, headers, move |database| {
        let view = saved_view(database, &requested_view)?;
        let records = database.list(&view.collection, &[])?;
        let schema = collection_schema(database, &view.collection)?;
        let navigation = database.views()?;
        Ok(ViewEditorContext {
            view,
            schema,
            records,
            navigation,
        })
    })
    .await
}

/// A saved view the principal may change, refusing an automatic one, which
/// has no definition to edit or delete.
fn saved_view(database: &Database, name: &str) -> Result<ViewDefinition> {
    if !database.owner_access_allowed(&AccessResource::Database)? {
        return Err(DomainError::Forbidden(format!(
            "principal '{}' must be an owner of the database to change saved views",
            database.principal()
        ))
        .into());
    }
    let view = database.view(name)?;
    if !view.saved {
        return Err(DomainError::NotFound(format!(
            "'{name}' is a collection's own view rather than a saved view, so there is nothing to edit or delete"
        ))
        .into());
    }
    Ok(view)
}

/// The editor, opened on the view as the page that linked here showed it.
async fn edit_view_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let query: ViewQuery = parse_query(raw)?;
        let applied = submitted_filter_group(
            query.filter_match,
            &query.filter_field,
            &query.filter_operator,
            &query.filter_value,
        )?;
        let context = view_editor_context(&state, &headers, &view_name).await?;
        let draft = opened_view_draft(&context, &query, applied, state.max_page_size)?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_view_editor(
            &Representation::requested(&headers),
            &context,
            &draft,
            ui.as_ref(),
            &request_csrf_token(&state),
            None,
        ))
    }
    .await;
    html_result(result)
}

async fn update_view_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
    RawForm(raw): RawForm,
) -> Response {
    let form: HtmlViewEditForm = match parse_html_form(&raw) {
        Ok(form) => form,
        Err(error) => return html_error(error),
    };
    if let Err(error) = verify_csrf(&state, &form.csrf) {
        return html_error(error);
    }
    let result: ApiResult<Response> = async {
        let edit = submitted_view_edit(&form)?;
        let requested_view = view_name.clone();
        run_database(&state, &headers, move |database| {
            let view = saved_view(database, &requested_view)?;
            // What the reader left as it was stays as it was written, so a
            // new title does not rewrite a hand-written file's conditions,
            // sort or columns into the editor's equivalent spelling of them.
            let sort = if edit.sort == view_default_sort(&view) {
                view.sort.clone()
            } else {
                edit.sort
            };
            let (filters, where_expr, filter_groups) =
                if edit.conditions == fold_view_conditions(&view, None) {
                    (view.filters, view.where_expr, view.filter_groups)
                } else {
                    (Vec::new(), Vec::new(), edit.conditions.into_filter_groups())
                };
            let columns = if edit.automatic_columns && view.columns.is_empty() {
                Vec::new()
            } else {
                edit.columns
            };
            database.replace_view(
                &requested_view,
                &edit.title,
                filters,
                where_expr,
                filter_groups,
                columns,
                edit.page_size,
                edit.layout,
                edit.group_by,
                sort,
            )
        })
        .await?;
        Ok(see_other(&notice_url(&view_name, "View updated")))
    }
    .await;
    match result {
        Ok(response) => response,
        // A refusal of what was typed goes back to the form, holding it.
        Err(error)
            if matches!(
                error.status,
                StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
            ) =>
        {
            reject_view_edit(&state, &headers, &view_name, &form, error).await
        }
        Err(error) => html_error(error),
    }
}

async fn reject_view_edit(
    state: &AppState,
    headers: &HeaderMap,
    view_name: &str,
    form: &HtmlViewEditForm,
    error: ApiError,
) -> Response {
    let context = match view_editor_context(state, headers, view_name).await {
        Ok(context) => context,
        Err(error) => return html_error(error),
    };
    let ui = match ui_context(state, headers).await {
        Ok(ui) => ui,
        Err(error) => return html_error(error),
    };
    let error = error.publish();
    html_response(
        error.status,
        render_view_editor(
            &Representation::requested(headers),
            &context,
            &submitted_view_draft(form),
            ui.as_ref(),
            &request_csrf_token(state),
            Some(&error),
        ),
    )
}

async fn confirm_delete_view(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let (view, navigation) = run_database(&state, &headers, move |database| {
            Ok((saved_view(database, &view_name)?, database.views()?))
        })
        .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_view_delete_confirmation(
            &Representation::requested(&headers),
            &view,
            &navigation,
            ui.as_ref(),
            &request_csrf_token(&state),
        ))
    }
    .await;
    html_result(result)
}

async fn delete_view_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
    RawForm(raw): RawForm,
) -> Response {
    let result: ApiResult<Response> = async {
        let form: HtmlCsrfForm = parse_html_form(&raw)?;
        verify_csrf(&state, &form.csrf)?;
        let location = run_database(&state, &headers, move |database| {
            let view = saved_view(database, &view_name)?;
            database.delete_view(&view.name)?;
            // Back to the records the view was of, which is still a page
            // unless the view's collection is one the reader cannot see.
            Ok(match database.view(&view.collection) {
                Ok(collection) => notice_url(&collection.name, "View deleted"),
                Err(_) => "/".to_owned(),
            })
        })
        .await?;
        Ok(see_other(&location))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn new_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
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
            &request_csrf_token(&state),
            None,
            &navigation,
            ui.as_ref(),
            RecordPermissions {
                update: true,
                delete: false,
            },
            None,
            None,
            None,
        ))
    }
    .await;
    html_result(result)
}

/// What a record page's URL may say besides which record it is.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordPageQuery {
    /// The outcome of the relation change that redirected here.
    notice: Option<String>,
    /// The editor asked for instead of the one the collection gives the form.
    editor: Option<RecordEditor>,
}

async fn edit_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((view_name, id)): Segments<(String, String)>,
    RawQuery(raw): RawQuery,
) -> Response {
    let result: ApiResult<Markup> = async {
        let query: RecordPageQuery = parse_query(raw)?;
        let requested_view = view_name.clone();
        let requested_id = id.clone();
        let (view, record, audit_entries, schema, navigation, permissions, relations) =
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
                let relations = record_relations(database, &record, &navigation);
                Ok((
                    view,
                    record,
                    audit_entries,
                    schema,
                    navigation,
                    permissions,
                    relations,
                ))
            })
            .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_record_form(
            &Representation::requested(&headers),
            &view,
            Some(&record),
            &audit_entries,
            schema.as_ref(),
            &request_csrf_token(&state),
            None,
            &navigation,
            ui.as_ref(),
            permissions,
            Some(&relations),
            query.notice.as_deref(),
            query.editor,
        ))
    }
    .await;
    html_result(result)
}

async fn create_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments(view_name): Segments<String>,
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
        Ok(mutation_redirect(
            &Representation::requested(&headers),
            &notice_url(&view_name, "Record created"),
        ))
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
    Segments((view_name, id)): Segments<(String, String)>,
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
        // The YAML editor and the fields form already submit the record's
        // own order; the structured form submits the schema's.
        let keep_stored_order = form.mode == DocumentFormMode::Structured;
        let collection = view.collection;
        let markdown = form.markdown;
        let expected = form.expected_record_hash.ok_or_else(|| {
            ApiError::bad_request("invalid_form", "expected record hash is required")
        })?;
        let precondition = RecordPrecondition::version(expected).map_err(ApiError::from_domain)?;
        run_database(&state, &headers, move |database| {
            // Read in the same call as the write, and the version checked by
            // the write is what makes the two agree: if the record changed in
            // between, the write is refused whatever order this produced.
            let attributes = if keep_stored_order {
                in_stored_order(attributes, &database.get(&collection, &id)?.attributes)
            } else {
                attributes
            };
            database.replace_conditionally(
                &collection,
                &id,
                attributes,
                &markdown,
                Some(&precondition),
            )
        })
        .await?;
        Ok(mutation_redirect(
            &Representation::requested(&headers),
            &notice_url(&view_name, "Record updated"),
        ))
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
    relations: Option<RecordRelations>,
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
            let relations = record
                .as_ref()
                .map(|record| record_relations(database, record, &navigation));
            Ok((
                view,
                record,
                audit_entries,
                schema,
                navigation,
                permissions,
                violations,
                relations,
            ))
        })
        .await?;
        let (view, record, audit_entries, schema, navigation, permissions, violations, relations) =
            context;
        Ok(RecordFormContext {
            view,
            record,
            audit_entries,
            schema,
            navigation,
            permissions,
            violations,
            relations,
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
        &request_csrf_token(state),
        Some(&rejection),
        &context.navigation,
        context.ui.as_ref(),
        context.permissions,
        context.relations.as_ref(),
        None,
        None,
    );
    rejected_form_response(status, markup)
}

async fn link_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((view_name, id)): Segments<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    change_relation_form(
        &state,
        &headers,
        view_name,
        id,
        &raw,
        RelationChangeKind::Link,
    )
    .await
}

async fn unlink_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((view_name, id)): Segments<(String, String)>,
    RawForm(raw): RawForm,
) -> Response {
    change_relation_form(
        &state,
        &headers,
        view_name,
        id,
        &raw,
        RelationChangeKind::Unlink,
    )
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelationChangeKind {
    Link,
    Unlink,
}

/// Apply a link or unlink from the relations panel, then return to the record.
///
/// The same `link` and `unlink` the CLI and the API run, with the version the
/// page was rendered from as their precondition, so a change made against a
/// page that has gone stale is refused with `412` rather than applied to a
/// record the reader has not seen. A refusal is the ordinary error page; a
/// success redirects to the record page with a notice naming the other record.
async fn change_relation_form(
    state: &AppState,
    headers: &HeaderMap,
    view_name: String,
    id: String,
    raw: &[u8],
    kind: RelationChangeKind,
) -> Response {
    let result: ApiResult<Response> = async {
        let form: HtmlRelationForm = parse_html_form(raw)?;
        verify_csrf(state, &form.csrf)?;
        let relation = form.relation.trim().to_owned();
        let (target_collection, target_id) = form
            .target
            .trim()
            .split_once('/')
            .map(|(collection, id)| (collection.trim().to_owned(), id.trim().to_owned()))
            .filter(|(collection, id)| !collection.is_empty() && !id.is_empty())
            .ok_or_else(|| {
                ApiError::bad_request(
                    "invalid_form",
                    "the linked record must be written as collection/id, for example companies/acme",
                )
            })?;
        let precondition = RecordPrecondition::version(form.expected_record_hash)
            .map_err(ApiError::from_domain)?;
        let requested_view = view_name.clone();
        let record_id = id.clone();
        let notice = run_database(state, headers, move |database| {
            let view = database.view(&requested_view)?;
            match kind {
                RelationChangeKind::Link => database.link_conditionally(
                    &view.collection,
                    &record_id,
                    &relation,
                    &target_collection,
                    &target_id,
                    Some(&precondition),
                )?,
                RelationChangeKind::Unlink => database.unlink_conditionally(
                    &view.collection,
                    &record_id,
                    &relation,
                    &target_collection,
                    &target_id,
                    Some(&precondition),
                )?,
            };
            // Named only when this perspective may read it, like the panel.
            let target_schema = database.schema(&target_collection).ok().flatten();
            let target = database
                .get(&target_collection, &target_id)
                .map(|target| {
                    record_name(&target.attributes, target_schema.as_ref())
                        .unwrap_or(&target.id)
                        .to_owned()
                })
                .unwrap_or_else(|_| format!("{target_collection}/{target_id}"));
            let relation = humanize_field_name(&relation).to_lowercase();
            Ok(match kind {
                RelationChangeKind::Link => format!("Linked {target} as {relation}"),
                RelationChangeKind::Unlink => format!("Removed the {relation} link to {target}"),
            })
        })
        .await?;
        Ok(see_other(&record_notice_url(&view_name, &id, &notice)))
    }
    .await;
    result.unwrap_or_else(html_error)
}

async fn move_kanban_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((view_name, id)): Segments<(String, String)>,
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
        Ok(see_other(&notice_url(&view_name, "Card moved")))
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
    Segments((view_name, id)): Segments<(String, String)>,
) -> Response {
    let result: ApiResult<Markup> = async {
        let requested_view = view_name.clone();
        let requested_id = id.clone();
        let (view, record, schema, navigation) = run_database(&state, &headers, move |database| {
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
            // Only to name the record the way its collection does.
            let schema = database.schema(&view.collection).ok().flatten();
            Ok((view, record, schema, navigation))
        })
        .await?;
        let ui = ui_context(&state, &headers).await?;
        Ok(render_delete_confirmation(
            &Representation::requested(&headers),
            &view,
            &record,
            schema.as_ref(),
            &navigation,
            ui.as_ref(),
            &request_csrf_token(&state),
        ))
    }
    .await;
    html_result(result)
}

async fn delete_record_form(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((view_name, id)): Segments<(String, String)>,
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
        Ok(see_other(&notice_url(&view_name, "Record deleted")))
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
        authentication: database.authentication().cloned(),
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
    Segments(collection): Segments<String>,
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
    Segments(collection): Segments<String>,
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
    Segments(collection): Segments<String>,
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
    Segments(collection): Segments<String>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: ListQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let filter = parse_filter(query.filter)?;
    let projection = parse_projection(&query.select)?;
    let sort = parse_sort(&query.sort, query.direction)?;
    let records = run_database(&state, &headers, move |database| {
        let mut records = database.list(&collection, &filters)?;
        records.retain(|record| {
            expressions
                .iter()
                .all(|expression| expression.matches(&record.attributes))
                && filter.as_ref().is_none_or(|filter| filter.matches(record))
        });
        sort_records(&mut records, &sort)?;
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
    Segments(collection): Segments<String>,
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
    Segments((collection, id)): Segments<(String, String)>,
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
    Segments((collection, id)): Segments<(String, String)>,
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

/// One supporting file of a bundle record, byte for byte.
///
/// The ETag is the record's version, which covers every file, so a client can
/// make its next write conditional on the record it read the file from.
async fn get_record_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((collection, id, path)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    let (contents, version) = run_database(&state, &headers, move |database| {
        database.read_file(&collection, &id, &path)
    })
    .await?;
    let mut response = (
        [(header::CONTENT_TYPE, "application/octet-stream")],
        contents,
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
    Segments((collection, id, field)): Segments<(String, String, String)>,
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
    Segments(collection): Segments<String>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<CreateRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    let files = requested_files(
        payload
            .files
            .into_iter()
            .map(|(path, content)| (path, Some(content))),
    )?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_create_record_with_files(
                &collection,
                &payload.id,
                payload.front_matter,
                &payload.markdown,
                &files,
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
        database.create_record_with_files(
            &collection,
            &payload.id,
            payload.front_matter,
            &payload.markdown,
            &files,
        )
    })
    .await?;
    let mut response = api_record_response(StatusCode::CREATED, record)?;
    response
        .headers_mut()
        .insert(header::LOCATION, location_header(&location));
    Ok(response)
}

async fn patch_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((collection, id)): Segments<(String, String)>,
    RawQuery(raw): RawQuery,
    payload: std::result::Result<Json<PatchRecordRequest>, JsonRejection>,
) -> ApiResult<Response> {
    let query: PreviewQuery = parse_query(raw)?;
    let Json(payload) = json_payload(payload)?;
    let precondition = if_match(&headers, false)?;
    let files = requested_files(payload.files)?;
    if query.preview {
        let preview = run_idempotent_database(&state, &headers, move |database| {
            database.preview_patch_with_files_conditionally(
                &collection,
                &id,
                &payload.front_matter,
                &payload.remove,
                payload.markdown.as_deref(),
                &files,
                precondition.as_ref(),
            )
        })
        .await?;
        return Ok(Json(preview).into_response());
    }
    let record = run_idempotent_database(&state, &headers, move |database| {
        database.patch_with_files_conditionally(
            &collection,
            &id,
            &payload.front_matter,
            &payload.remove,
            payload.markdown.as_deref(),
            &files,
            precondition.as_ref(),
        )
    })
    .await?;
    api_record_response(StatusCode::OK, record)
}

async fn replace_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Segments((collection, id)): Segments<(String, String)>,
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
    Segments((collection, id)): Segments<(String, String)>,
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
    Segments((collection, id)): Segments<(String, String)>,
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
    Segments((collection, id)): Segments<(String, String)>,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let query: BacklinkQuery = parse_query(raw)?;
    let bounds = page_bounds(query.limit, query.offset, state.max_page_size)?;
    let filters = parse_filters(query.filters)?;
    let expressions = parse_filter_expressions(query.where_expr)?;
    let filter = parse_filter(query.filter)?;
    let projection = parse_projection(&query.select)?;
    let sort = parse_sort(&query.sort, query.direction)?;
    let (from, relation) = (query.from, query.relation);
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
        sort_by_record_keys(&mut backlinks, |backlink| &backlink.record, &sort)?;
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
    Segments((collection, id)): Segments<(String, String)>,
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
    Segments((collection, id, relation, target_collection, target_id)): Segments<(
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
    let sort = parse_sort(&parameters.sort, parameters.direction)?;
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
        sort_records(&mut records, &sort)?;
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
            trusted_keys: request_trusted_keys(query.trusted_key)?,
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
        let trusted = request_trusted_keys(parameters.trusted_key)?;
        database.audit_verify_trusting(parameters.expected_head.as_deref(), trusted.as_ref())
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
    let token_enabled = state.api_token.is_some() || state.require_token;
    let cloudflare_access = state.cloudflare_access.is_some();
    let document = run_database(&state, &headers, move |database| {
        let mut document = openapi_document(database, token_enabled)?;
        if cloudflare_access {
            describe_cloudflare_access(&mut document);
        }
        Ok(document)
    })
    .await?;
    Ok(Json(document))
}

/// Declare the Cloudflare Access assertion as a way in, as an alternative to
/// a bearer token when the server also accepts one.
fn describe_cloudflare_access(document: &mut JsonValue) {
    document["components"]["securitySchemes"]["cloudflareAccess"] = json!({
        "type": "apiKey",
        "in": "header",
        "name": CLOUDFLARE_ACCESS_VARY,
        "description": "The signed assertion Cloudflare Access adds to every request it lets through. The server verifies its RS256 signature, issuer, audience, and lifetime, acts as the one active user whose email matches its email claim, and records access.authentication {method: cloudflare-access, credential: <sub>} on every event it writes."
    });
    let mut security = document["security"].as_array().cloned().unwrap_or_default();
    security.push(json!({ "cloudflareAccess": [] }));
    document["security"] = JsonValue::Array(security);
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
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "description": "Either the server's CR_API_TOKEN, which acts as the launching owner, or a principal token from `cr access token issue`, which authenticates its registered principal and is recorded in access.authentication on every event it writes."
            }
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
                        "markdown": { "type": "string" },
                        "files": {
                            "type": "array",
                            "description": "A bundle record's supporting files, in path order. Absent for a record stored as one Markdown file. The record's version covers every one of them.",
                            "items": { "$ref": "#/components/schemas/RecordFile" }
                        }
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
                "markdown": { "type": "string", "default": "" },
                "files": {
                    "type": "object",
                    "description": "Supporting files of a bundle record, by path. Refused for a collection that stores each record as one Markdown file.",
                    "additionalProperties": { "$ref": "#/components/schemas/FileContent" }
                }
            }
        },
        "PatchRecordRequest": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "front_matter": { "$ref": "#/components/schemas/FrontMatter" },
                "remove": { "type": "array", "items": { "type": "string" } },
                "markdown": { "type": "string" },
                "files": {
                    "type": "object",
                    "description": "Supporting files of a bundle record to add or replace, by path, and null for each one to remove. Recorded in the same audit event as the rest of the patch.",
                    "additionalProperties": { "oneOf": [{ "$ref": "#/components/schemas/FileContent" }, { "type": "null" }] }
                }
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
            "description": "The effective principal and attribution this request would record. In the local RBAC console, impersonated_by identifies the owner operating the selected perspective. authentication is present when a principal token or a Cloudflare Access assertion authenticated the principal.",
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
                "authentication": {
                    "oneOf": [
                        {
                            "type": "object",
                            "required": ["method"],
                            "properties": {
                                "method": { "type": "string", "description": "How the principal was authenticated: token or cloudflare-access." },
                                "credential": { "type": "string", "description": "The public ID of the credential that passed: a principal token's ID, or the sub of a Cloudflare Access assertion." }
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
                    "enum": ["environment", "hook", "flag", "header", "config"],
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
    let bundles: Map<String, JsonValue> = serde_json::from_value(json!({
        "RecordFile": {
            "type": "object",
            "required": ["path", "hash"],
            "properties": {
                "path": { "type": "string", "description": "The file's path inside the record's folder, /-separated." },
                "hash": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "description": "The plain SHA-256 of the file's bytes." }
            }
        },
        "FileContent": {
            "type": "object",
            "required": ["content"],
            "additionalProperties": false,
            "description": "The contents of one supporting file: text as is, or any bytes as standard base64.",
            "properties": {
                "content": { "type": "string" },
                "encoding": { "enum": ["utf-8", "base64"], "default": "utf-8" }
            }
        },
        "AuditFileChange": {
            "type": "object",
            "required": ["operation", "path"],
            "additionalProperties": false,
            "description": "One supporting file of a bundle record that an event added, removed, or replaced. before and after are the plain SHA-256 of its bytes on each side; diff, present for UTF-8 text of at most 256 KiB, is a unified diff that replay applies and holds to after.",
            "properties": {
                "operation": { "enum": ["add", "remove", "replace"] },
                "path": { "type": "string" },
                "before": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                "after": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                "diff": { "type": "string" }
            }
        }
    }))
    .expect("static OpenAPI schemas are objects");
    schemas.extend(bundles);
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
                "files": { "type": "array", "items": { "$ref": "#/components/schemas/AuditFileChange" } },
                "before_hash": { "type": ["string", "null"] },
                "after_hash": { "type": ["string", "null"] },
                "digest": { "type": "string", "description": "sha256 over the canonical bytes of changes, and of files when there are any. Send back as X-CR-Approved-Changes." }
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
                    "audit_anchor_missing", "audit_signature_mismatch", "audit_signature_behind",
                    "audit_signature_missing"
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
                "version": { "type": "integer", "minimum": 1, "maximum": 4 },
                "sequence": { "type": "integer", "minimum": 1 },
                "timestamp": { "type": "string", "format": "date-time" },
                "actor": { "type": "string" },
                "source": { "enum": ["cli", "api", "filesystem", "sync"] },
                "action": { "enum": ["baseline", "create", "update", "link", "delete"] },
                "record": { "type": "object" },
                "changes": { "type": "array", "description": "Logical audit changes. Protected values are decrypted for authorized history reads; hash and authorization.approved_changes still commit to the stored ciphertext representation.", "items": { "type": "object" } },
                "files": { "type": "array", "description": "A bundle record's supporting files this event added, removed, or replaced. Version 4 and later.", "items": { "$ref": "#/components/schemas/AuditFileChange" } },
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
                "anchor": { "$ref": "#/components/schemas/AnchorStatus" },
                "signature": { "$ref": "#/components/schemas/SignatureStatus" }
            }
        },
        "SignatureStatus": {
            "type": "object",
            "required": ["state"],
            "description": "How the signed checkpoint at the database root relates to the journal head. Absent when no trusted key was given and nothing is signed. With trusted keys, a missing, untrusted, or disagreeing checkpoint is not reported here: it fails the request with 409 signature_mismatch.",
            "properties": {
                "state": { "enum": ["unverified", "empty", "matched", "behind"], "description": "unverified means a signed checkpoint is recorded but no trusted key was given to judge it with. behind means a trusted key signed an earlier event the journal still agrees with, which is a reduced guarantee rather than altered history." },
                "sequence": { "type": "integer", "minimum": 1, "description": "The audit sequence the signature attests to." },
                "head": { "type": "integer", "minimum": 1, "description": "The current head sequence, present when the signature is behind." },
                "key_id": { "type": "string", "description": "The fingerprint of the trusted key that signed." }
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
    let sort_parameter = json!({
        "name": "sort", "in": "query",
        "description": format!("Sort keys, most significant first: a dotted front matter field or $id, $collection, or $path, as FIELD, FIELD:asc, or FIELD:desc. Comma-separated or repeated, at most {MAX_SORT_KEYS}, each field once. Missing fields remain last in either direction, and collection then record ID, ascending, break the remaining ties."),
        "schema": { "type": "array", "items": { "type": "string" }, "maxItems": MAX_SORT_KEYS },
        "style": "form", "explode": true
    });
    let direction_parameter = json!({
        "name": "direction", "in": "query",
        "description": "The direction of a sort with a single key written without one, the same as FIELD:desc. Refused with several keys.",
        "schema": { "type": "string", "enum": ["asc", "desc"], "default": "asc" }
    });
    let page_parameters = vec![
        json!({ "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "default": DEFAULT_PAGE_SIZE } }),
        json!({ "name": "offset", "in": "query", "schema": { "type": "integer", "minimum": 0, "default": 0 } }),
    ];
    json!({
        "/health": {
            "get": {
                "operationId": "health",
                "description": "Liveness: the server process is running and answering HTTP. It reads nothing from the database; `/ready` does.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "The server process is running",
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
        "/ready": {
            "get": {
                "operationId": "ready",
                "description": "Readiness: the database directory is reachable, its configuration loads, no interrupted mutation or sync run is waiting for recovery, and the server's verified audit journal still describes the journal on disk. Every check is cheap and none waits for a lock. A failure names the check and a stable code and nothing else; the reason is in the server log under the request ID.",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Ready to serve requests that read the database",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["status"],
                                    "properties": { "status": { "const": "ready" } }
                                }
                            }
                        }
                    },
                    "503": {
                        "description": "Not ready; every check that ran, in order",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["status", "checks", "request_id"],
                                    "properties": {
                                        "status": { "const": "not_ready" },
                                        "request_id": { "type": "string", "description": "The ID the server log records each failure's reason under, also returned as X-Request-Id" },
                                        "checks": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "required": ["name", "ok"],
                                                "properties": {
                                                    "name": { "enum": ["database", "config", "audit_recovery", "sync_recovery", "journal"] },
                                                    "ok": { "type": "boolean" },
                                                    "code": { "enum": [
                                                        "database_unreachable",
                                                        "config_invalid",
                                                        "pending_mutation",
                                                        "audit_recovery_unreadable",
                                                        "interrupted_sync_run",
                                                        "sync_recovery_unreadable",
                                                        "journal_warming",
                                                        "journal_unverified",
                                                        "journal_changed",
                                                        "journal_unreadable"
                                                    ] }
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
                    sort_parameter.clone(),
                    direction_parameter.clone(),
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
        "/api/v1/collections/{collection}/records/{id}/files/{path}": {
            "get": { "operationId": "getRecordFile", "description": "One supporting file of a bundle record, byte for byte. Reading it needs the permission reading the record does. The ETag is the record's version, which covers every file.", "parameters": [collection.clone(), id.clone(), json!({ "name": "path", "in": "path", "required": true, "description": "The file's path inside the record's folder; its slashes are part of the path.", "schema": { "type": "string" } })], "responses": { "200": { "description": "The file's exact bytes", "headers": { "ETag": etag_response_header() }, "content": { "application/octet-stream": { "schema": { "type": "string", "format": "binary" } } } }, "404": error_response() } }
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
                sort_parameter.clone(),
                direction_parameter.clone(),
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
                sort_parameter,
                direction_parameter,
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
            trusted_key_parameter(),
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
            { "name": "expected_head", "in": "query", "schema": { "type": "string" } },
            trusted_key_parameter()
        ], "responses": ok("#/components/schemas/AuditVerification") } },
        "/api/v1/audit/baseline": { "post": { "operationId": "baselineAudit", "responses": ok("#/components/schemas/BaselineResponse") } }
    })
}

/// The repeatable `trusted_key` parameter the verifying routes share.
fn trusted_key_parameter() -> JsonValue {
    json!({
        "name": "trusted_key", "in": "query",
        "description": "A public key, as ed25519: and 43 base64url characters, to verify the signed checkpoint with. Repeat it to trust several. Keys are given inline only; a key file cannot be named in a request. Without any, the server's CR_AUDIT_TRUSTED_KEYS applies, and without that the signed checkpoint is not judged.",
        "schema": { "type": "array", "items": { "type": "string" } }, "style": "form", "explode": true
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
            (page_bar(
                &[],
                Some(HOME_ICON),
                "All views",
                html! {
                    span class="cr-page-meta" {
                        (count_noun(views.len(), "view", "views"))
                        (view_index_total(views, index, OutOfBand::No))
                        @if deferred {
                            // Nothing will ask for the region without a script, so
                            // offer the document that has the numbers in it.
                            noscript {
                                span class="mx-1.5 text-gray-300" aria-hidden="true" { "·" }
                                a href=(VIEW_INDEX_SUMMARY_URL) class="underline hover:text-gray-900" { "Count records" }
                            }
                        }
                    }
                },
                html! {},
            ))
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
                @for (label, saved) in [("Saved views", true), ("Collections", false)] {
                    @if views.iter().any(|view| view.saved == saved) {
                        section class="cr-view-index mb-5" aria-label=(label) {
                            (view_index_header(label))
                            @for (view, summary) in navigation_order_with(views, &summaries).filter(|(view, _)| view.saved == saved) {
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
                }
            }
            @if ui.is_some_and(|ui| ui.can_read_users) {
                section class="cr-view-index" aria-label="Internal records" {
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
            Some(total) => span id=(VIEW_INDEX_TOTAL_ID) hx-swap-oob=[out_of_band.attribute()] {
                span class="mx-1.5 text-gray-300" aria-hidden="true" { "·" }
                (count_noun(total, "record", "records"))
            },
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

/// How many of a principal's grants the users table lists before folding the
/// rest behind a `+N` that opens to show them. Grants are kept sorted by
/// resource, so the broad ones on a collection or the database come first and
/// a long run of per-record grants is what folds away.
const ACCESS_GRANTS_SHOWN: usize = 3;

fn render_access_grant(grant: &crate::AccessGrant) -> Markup {
    html! {
        span class="cr-pill" title=(format!("{} at {}", grant.role, grant.resource)) {
            (grant.role) " · " (grant.resource)
        }
    }
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
            (page_bar(
                &[("/".to_owned(), None, "Views")],
                Some(USERS_ICON),
                "Users",
                html! {
                    span class="cr-page-meta" {
                        (count_noun(users.len(), "principal", "principals"))
                        span class="mx-1.5 text-gray-300" aria-hidden="true" { "·" }
                        "read-only"
                    }
                },
                html! {
                    a href="/api/v1/collections/users/records" hx-boost=(UNBOOSTED) class="cr-button" { "JSON API" span aria-hidden="true" { " ↗" } }
                },
            ))
            p class="cr-page-note max-w-3xl" {
                "Every principal registered in the reserved "
                code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { "users" }
                " collection. CR owns its schema and history, so it is read-only here: register a principal, change a role, or disable an identity with "
                code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs" { "cr access" }
                " or the REST API."
            }
            div class="cr-table-shell" {
                div class="overflow-x-auto" {
                    table class="min-w-full divide-y divide-gray-200 text-left text-sm" {
                        thead {
                            tr {
                                th scope="col" class="whitespace-nowrap px-4 py-3 font-semibold text-gray-700" { "User" }
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
                                        td class="px-4 py-3" {
                                            span class="block font-medium text-gray-900" { (user_chip(&user.name, id, None)) }
                                            span class="cr-user-id" { (id) }
                                        }
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
                                                @let (shown, more) = user.access.split_at(user.access.len().min(ACCESS_GRANTS_SHOWN));
                                                div class="flex flex-wrap gap-1.5" {
                                                    @for grant in shown {
                                                        (render_access_grant(grant))
                                                    }
                                                    @if !more.is_empty() {
                                                        details class="cr-access-more" {
                                                            summary class="cr-pill" title=(count_noun(more.len(), "more grant", "more grants")) {
                                                                span class="cr-access-more-count" { "+" (more.len()) }
                                                                span class="cr-access-more-less" { "Show fewer" }
                                                            }
                                                            div class="flex flex-wrap gap-1.5" {
                                                                @for grant in more {
                                                                    (render_access_grant(grant))
                                                                }
                                                            }
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
            (page_bar(
                &[("/".to_owned(), None, "Views")],
                Some(ALL_FILES_ICON),
                "All files",
                html! {
                    span class="cr-page-meta" { "owner only" }
                },
                html! {
                    @if let Some(here) = page.location.to_str() {
                        (render_pin_control(here, pinned, csrf_token))
                    }
                    a href=(sort.carry("/browse")) class="cr-button" { "Database root" }
                    @if let Some(parent) = &page.parent {
                        a href=(sort.carry(&browse_url(parent.to_string_lossy().as_ref()))) class="cr-button" { "Up" }
                    }
                },
            ))
            (render_browse_location(&page.location, &page.crumbs, sort))
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
                                    (render_file_preview(
                                        file,
                                        Some((&document.name, document.href.as_deref())),
                                        FilePanel { path: &document.path, page: &page.location, region: document.anchor },
                                    ))
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
                    div id=(FILE_PANEL_REGION) {
                        (render_file_preview(
                            file,
                            None,
                            FilePanel { path: &page.location, page: &page.location, region: FILE_PANEL_REGION },
                        ))
                    }
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

/// Where a browse page is, as the path's own steps, each one a way back up.
fn render_browse_location(
    location: &FilePath,
    crumbs: &[BrowserCrumb],
    sort: BrowseSort,
) -> Markup {
    html! {
        nav aria-label="Location" class="cr-page-note flex min-w-0 flex-wrap items-center gap-x-1 font-mono text-xs" title=(location.to_string_lossy()) {
            @for (index, crumb) in crumbs.iter().enumerate() {
                @if index > 0 {
                    span class="text-gray-300" aria-hidden="true" { "/" }
                }
                a href=(sort.carry(&crumb.href)) class="max-w-48 truncate hover:text-gray-900" { (&crumb.label) }
            }
        }
    }
}

/// Pin or unpin the location a browse page shows.
///
/// Unpinning submits the pin's stored spelling rather than this page's
/// location. A pin written through a symbolic link resolves to this page, but
/// only its own spelling names it in `.cr/pins.yaml`.
///
/// Both forms stay native (`UNBOOSTED`): a refusal — a stale token, the pin
/// limit — answers with an error document, which htmx will not swap into a
/// failed `POST`, the same reason the view delete form is native.
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
///
/// Its header ends in the file's two actions. Edit is a link to the editor that
/// htmx follows into this panel's own section, so the preview turns into a
/// textarea in place; it is offered only when the preview is the whole file as
/// text, and otherwise shown disabled with the reason. Delete is a link to a
/// confirmation page, as a record's is. Neither is offered for a path that is
/// not UTF-8, which cannot be put in a URL.
fn render_file_preview(
    file: &BrowserFile,
    document: Option<(&str, Option<&str>)>,
    panel: FilePanel<'_>,
) -> Markup {
    let (contents, class) = match &file.contents {
        BrowserFileContents::Text(contents) => (contents, "cr-file-preview cr-file-preview-wrap"),
        BrowserFileContents::Binary(contents) => (contents, "cr-file-preview"),
    };
    let name = panel
        .path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let actions = panel
        .path
        .to_str()
        .zip(panel.page.to_str())
        .map(|(path, page)| {
            (
                file_action_url("/browse/edit", path, page),
                file_action_url("/browse/delete", path, page),
            )
        });
    let not_editable = match file.contents {
        BrowserFileContents::Binary(_) => "A binary file cannot be edited here",
        BrowserFileContents::Text(_) => "A file larger than 1.0 MiB cannot be edited here",
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
                div class="flex items-center gap-3" {
                    span {
                        "Showing " (format_file_size(file.bytes_shown as u64))
                        @if file.truncated { " · preview truncated" }
                    }
                    @if let Some((edit, delete)) = &actions {
                        div class="flex items-center gap-1" {
                            @if file.version.is_some() {
                                a href=(edit) hx-target=(format!("#{}", panel.region)) hx-swap="innerHTML show:none" class="cr-icon-button" title="Edit" aria-label=(format!("Edit {name}")) {
                                    (PreEscaped(PENCIL_ICON))
                                }
                            } @else {
                                span class="cr-icon-button" data-disabled="true" title=(not_editable) {
                                    (PreEscaped(PENCIL_ICON))
                                    span class="sr-only" { (not_editable) }
                                }
                            }
                            a href=(delete) class="cr-icon-button cr-icon-button-danger" title="Delete" aria-label=(format!("Delete {name}")) {
                                (PreEscaped(TRASH_ICON))
                            }
                        }
                    }
                }
            }
            pre class=(class) tabindex="0" {
                code { (contents) }
            }
        }
    }
}

/// Which file a panel shows and where, for its edit and delete actions.
#[derive(Clone, Copy)]
struct FilePanel<'a> {
    path: &'a FilePath,
    /// The browse page the panel is on — the file itself, or the directory it
    /// documents — which the editor and the delete page return to.
    page: &'a FilePath,
    /// The id of the element holding the panel, which an in-place edit
    /// replaces the contents of.
    region: &'static str,
}

/// A text file open in the browser's editor.
struct FileEditor {
    path: PathBuf,
    /// The browse page the editor was opened from, which Save and Cancel return
    /// to.
    from: PathBuf,
    /// The panel the editor stands in on that page.
    region: &'static str,
    /// What the textarea holds: the file as it was read, or, after a refused
    /// save, exactly what was submitted.
    contents: String,
    /// The version of the file the text was edited from. A refused save keeps
    /// the one it was submitted with, so saving again cannot quietly overwrite
    /// whatever changed the file.
    version: String,
    rejection: Option<PublicError>,
}

/// The editor itself: a file panel whose preview is a textarea, with Save and
/// Cancel where the panel's actions were.
///
/// The form is native (`UNBOOSTED`), as the pin and delete forms are. A save
/// answers with a redirect back to the page, and a refusal with the editor page
/// and what was typed, which a browser shows whatever the status and htmx would
/// not swap into a failed `POST`.
fn render_file_editor(editor: &FileEditor, root: &FilePath, csrf_token: &str) -> Markup {
    let name = editor
        .path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let textarea = format!("{}-editor", editor.region);
    html! {
        form method="post" action="/browse/edit" hx-boost=(UNBOOSTED) data-file-editor="true" class="cr-table-shell overflow-hidden" {
            input type="hidden" name="_csrf" value=(csrf_token);
            input type="hidden" name="path" value=(editor.path.to_string_lossy());
            input type="hidden" name="from" value=(editor.from.to_string_lossy());
            input type="hidden" name="_expected_version" value=(&editor.version);
            div class="flex flex-wrap items-center justify-between gap-2 border-b border-gray-200 bg-gray-50 px-4 py-3 text-xs text-gray-600" {
                div class="flex flex-wrap items-center gap-2" {
                    label for=(&textarea) class="font-mono text-sm font-semibold text-gray-900" { (name) }
                    span class="cr-pill" { "editing" }
                }
                div class="flex items-center gap-2" {
                    // A link rather than a second button, because cancelling is
                    // a navigation back to the preview and must not be able to
                    // submit the form it sits inside. Boosted again, since the
                    // form's `UNBOOSTED` is inherited: a boosted navigation is
                    // one the unsaved-changes guard can ask about in words.
                    a href=(file_panel_url(&editor.from, editor.region)) hx-boost="true" class="cr-button cr-button-small" { "Cancel" }
                    button type="submit" class="cr-button cr-button-small cr-button-primary" { "Save" }
                }
            }
            @if let Some(error) = &editor.rejection {
                div role="alert" class="border-b border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" {
                    p class="font-semibold" { "The file was not saved" }
                    p class="mt-1" { (&error.message) }
                    p class="mt-2 text-xs text-red-700" {
                        "The text below is exactly what you submitted. Request ID " (&error.request_id)
                    }
                }
            }
            textarea id=(&textarea) name="contents" spellcheck="false" autofocus class="cr-file-editor" { (textarea_text(&editor.contents)) }
            @if editor.path.starts_with(root) {
                p class="border-t border-gray-200 bg-gray-50 px-4 py-2 text-xs text-gray-600" {
                    "This file is inside the database, and saving it here records no audit event. A changed record is listed by "
                    code { "cr status" } " until " code { "cr save" } " accepts it."
                }
            }
        }
    }
}

/// The editor as a page of its own: what a browser with no JavaScript gets for
/// the pencil, and what a refused save answers with.
fn render_file_editor_page(
    representation: &Representation,
    editor: &FileEditor,
    root: &FilePath,
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let name = editor
        .path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    page_or_content(
        representation,
        &format!("Edit {name}"),
        &browse_url(&editor.path.to_string_lossy()),
        views,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    ("/browse".to_owned(), Some(ALL_FILES_ICON), "All files"),
                ],
                None,
                "Edit",
                html! { span class="cr-page-meta" { "owner only" } },
                html! {},
            ))
            (render_browse_location(&editor.path, &browse_crumbs(&editor.path), BrowseSort::DEFAULT))
            (render_file_editor(editor, root, csrf_token))
        },
        ui,
        csrf_token,
    )
}

/// The question before a file is deleted: which file, what cannot be undone,
/// and the two ways out.
#[allow(clippy::too_many_arguments)]
fn render_file_delete_confirmation(
    representation: &Representation,
    path: &FilePath,
    from: &FilePath,
    size: u64,
    root: &FilePath,
    views: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    let directory = path
        .parent()
        .map(|directory| directory.to_string_lossy())
        .unwrap_or_default();
    page_or_content(
        representation,
        &format!("Delete {name}"),
        &browse_url(&path.to_string_lossy()),
        views,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    ("/browse".to_owned(), Some(ALL_FILES_ICON), "All files"),
                ],
                None,
                "Delete",
                html! { span class="cr-page-meta" { "owner only" } },
                html! {},
            ))
            (render_browse_location(path, &browse_crumbs(path), BrowseSort::DEFAULT))
            div class="mx-auto max-w-2xl" {
                div class="cr-record-danger rounded-xl border border-red-200 bg-red-50 p-6" {
                    h2 class="text-lg font-semibold text-red-900" { "Delete this file?" }
                    p class="mt-2 text-sm text-red-800" {
                        "You are about to delete "
                        code class="cr-filter-tag" { (name) }
                        " (" (format_file_size(size)) ") from "
                        code class="cr-filter-tag" { (directory) }
                        "."
                    }
                    p class="mt-2 text-sm text-red-700" {
                        "The file is removed from disk, not moved to a trash, so this cannot be undone from the web app."
                        @if path.starts_with(root) {
                            " It is inside the database, and deleting it here records no audit event: a deleted record is listed by "
                            code class="cr-filter-tag" { "cr status" }
                            " until "
                            code class="cr-filter-tag" { "cr save" }
                            " accepts the deletion or the file is restored."
                        }
                    }
                    form method="post" action="/browse/delete" hx-boost=(UNBOOSTED) class="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center" {
                        input type="hidden" name="_csrf" value=(csrf_token);
                        input type="hidden" name="path" value=(path.to_string_lossy());
                        button type="submit" class="rounded-lg border border-red-300 bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800" { "Delete file" }
                        a href=(file_panel_url(from, file_panel_region(path, from))) class="cr-button" { "Cancel" }
                    }
                }
            }
        },
        ui,
        csrf_token,
    )
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
    people: &BTreeMap<String, String>,
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
            (page_bar(
                &[("/".to_owned(), None, "Views")],
                Some(AUDIT_ICON),
                "Audit log",
                html! { span class="cr-page-meta" { "every accepted change, newest first" } },
                html! {
                    a href="/api/v1/audit/log" hx-boost=(UNBOOSTED) class="cr-button" { "JSON API" span aria-hidden="true" { " ↗" } }
                },
            ))
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
            (render_audit_entries(&page.data, people))
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

/// How a server authenticated an event's principal, in words: the method,
/// and the public ID of the credential that passed.
fn authentication_label(authentication: &Authentication) -> Markup {
    html! {
        "authenticated by " (authentication_method_name(&authentication.method))
        @if let Some(credential) = &authentication.credential {
            " " code class="font-mono" { (credential) }
        }
    }
}

/// An authentication method as a person reads it.
fn authentication_method_name(method: &AuthenticationMethod) -> &str {
    match method {
        AuthenticationMethod::CloudflareAccess => "Cloudflare Access",
        method => method.label(),
    }
}

/// `people` names the users whose own records some of `entries` changed, so
/// those events show the person rather than `users/<id>`.
fn render_audit_entries(entries: &[AuditEntry], people: &BTreeMap<String, String>) -> Markup {
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
                                @let record = &entry.payload.record;
                                @if record.collection == USERS_COLLECTION {
                                    a href=(audit_filter_url(&record.collection, &record.id)) class="mt-3 block truncate text-sm font-semibold text-gray-900 hover:text-blue-700" {
                                        (user_chip(people.get(&record.id).map_or(&record.id, String::as_str), &record.id, Some(&record.reference())))
                                    }
                                } @else {
                                    a href=(audit_filter_url(&record.collection, &record.id)) class="mt-3 block truncate font-mono text-sm font-semibold text-gray-900 hover:text-blue-700" {
                                        (record.reference())
                                    }
                                }
                                p class="mt-1 text-xs text-gray-500" {
                                    "by " span class="font-medium text-gray-700" { (actor_chip(&entry.payload.actor)) }
                                    @if let Some(operator) = entry
                                        .payload
                                        .access
                                        .as_ref()
                                        .and_then(|access| access.impersonated_by.as_ref())
                                    {
                                        " · impersonated by " span class="font-medium text-gray-700" { (actor_chip(&operator.display)) }
                                    }
                                    @if let Some(authentication) = entry
                                        .payload
                                        .access
                                        .as_ref()
                                        .and_then(|access| access.authentication.as_ref())
                                    {
                                        " · " (authentication_label(authentication))
                                    }
                                    @if let Some(agent) = &entry.payload.agent {
                                        " · via " a href=(audit_agent_url(&agent.id)) class="font-medium text-gray-700 hover:text-blue-700" { (&agent.id) }
                                    }
                                    " · " (render_timestamp(Some(&entry.payload.timestamp)))
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
                            (render_audit_changes(&entry.payload.changes, false))
                        }
                    }
                }
            }
        }
    }
}

/// An event's changes, each with the value before and after it. `narrow` is
/// for a sidebar, where before and after are stacked rather than side by side.
/// A string that spans lines, a record's notes most often, is shown as a diff
/// instead: two full copies of a long text hide the one line that changed.
fn render_audit_changes(changes: &[AuditChange], narrow: bool) -> Markup {
    html! {
        div class=(if narrow { "mt-2 space-y-2" } else { "mt-3 space-y-3" }) {
            @for change in changes {
                div class=(if narrow { "rounded-lg border border-gray-200 bg-gray-50 p-2" } else { "rounded-lg border border-gray-200 bg-gray-50 p-3" }) {
                    div class="flex flex-wrap items-center gap-2" {
                        span class="rounded bg-gray-200 px-2 py-0.5 text-xs font-bold uppercase text-gray-700" { (audit_change_operation(change)) }
                        code class="text-xs text-gray-700" { (audit_change_path(change)) }
                    }
                    @if let Some((before, after)) = audit_change_text(change) {
                        div class=(if narrow { "cr-diff mt-2" } else { "cr-diff mt-3" }) {
                            (render_text_diff(before, after))
                        }
                    } @else {
                        div class=(if narrow { "mt-2 grid gap-2" } else { "mt-3 grid gap-3 lg:grid-cols-2" }) {
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

/// How much of a text diff a page shows, in characters of its lines and in
/// lines. A rewrite of a long document is otherwise as long as the document,
/// on every page that lists the event.
const TEXT_DIFF_PREVIEW_CHARS: usize = 8_000;
const TEXT_DIFF_PREVIEW_LINES: usize = 200;

/// The most words and separators a removed line and its replacement may have
/// between them for the words that changed to be marked. Longer pairs are
/// still shown, only as whole lines.
const MAX_WORD_DIFF_TOKENS: usize = 2_000;

/// A line of a text diff as a page shows it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DiffLine {
    Hunk,
    Context,
    Removed,
    Added,
}

/// The two sides of a change that replaced one string with another where
/// either spans lines. Only a replacement has two sides to compare, and a
/// single line reads fine as before and after.
fn audit_change_text(change: &AuditChange) -> Option<(&str, &str)> {
    let AuditChange::Replace { before, after, .. } = change else {
        return None;
    };
    let (before, after) = (before.as_str()?, after.as_str()?);
    (before.contains('\n') || after.contains('\n')).then_some((before, after))
}

/// `before` to `after` as a unified diff, the same one `cr` audits a bundle's
/// text files with: hunk headers, then context, removed and added lines, with
/// the words that changed marked where a removed line is followed by the line
/// that replaced it. Past [`TEXT_DIFF_PREVIEW_CHARS`] or
/// [`TEXT_DIFF_PREVIEW_LINES`] the rest is elided.
fn render_text_diff(before: &str, after: &str) -> Markup {
    let diff = crate::bundle::diff_text(before, after);
    let mut lines: Vec<(DiffLine, &str)> = Vec::new();
    let mut budget = TEXT_DIFF_PREVIEW_CHARS;
    let mut elided = false;
    for line in diff.lines() {
        if lines.len() == TEXT_DIFF_PREVIEW_LINES {
            elided = true;
            break;
        }
        // A missing final newline is a change no one can see on a page, so
        // its marker, the one line starting with a backslash, is left out.
        let (kind, text) = match line.as_bytes().first() {
            Some(b'@') => (DiffLine::Hunk, line),
            Some(b' ') => (DiffLine::Context, &line[1..]),
            Some(b'-') => (DiffLine::Removed, &line[1..]),
            Some(b'+') => (DiffLine::Added, &line[1..]),
            _ => continue,
        };
        match text.char_indices().nth(budget) {
            Some((cut, _)) => {
                lines.push((kind, &text[..cut]));
                elided = true;
                break;
            }
            None => {
                budget -= text.chars().count();
                lines.push((kind, text));
            }
        }
    }

    let mut spans: Vec<MarkedRuns<'_>> =
        lines.iter().map(|(_, text)| vec![(false, *text)]).collect();
    let mut index = 0;
    while index < lines.len() {
        let removed = lines[index..]
            .iter()
            .take_while(|(kind, _)| *kind == DiffLine::Removed)
            .count();
        let added = lines[index + removed..]
            .iter()
            .take_while(|(kind, _)| *kind == DiffLine::Added)
            .count();
        for offset in 0..removed.min(added) {
            let (old, new) = (index + offset, index + removed + offset);
            // A line cut short would be marked as having lost its tail.
            if elided && new == lines.len() - 1 {
                break;
            }
            if let Some((old_spans, new_spans)) = changed_words(lines[old].1, lines[new].1) {
                spans[old] = old_spans;
                spans[new] = new_spans;
            }
        }
        index += (removed + added).max(1);
    }

    html! {
        @for ((kind, text), spans) in lines.iter().zip(&spans) {
            @match kind {
                DiffLine::Hunk => div class="cr-diff-hunk" { (text) },
                DiffLine::Context => div class="cr-diff-line" {
                    span class="cr-diff-sign" { " " }
                    span { (text) }
                },
                DiffLine::Removed => div class="cr-diff-line cr-diff-removed" {
                    span class="cr-diff-sign" { "-" }
                    span {
                        @for (changed, text) in spans {
                            @if *changed { del { (text) } } @else { (text) }
                        }
                    }
                },
                DiffLine::Added => div class="cr-diff-line cr-diff-added" {
                    span class="cr-diff-sign" { "+" }
                    span {
                        @for (changed, text) in spans {
                            @if *changed { ins { (text) } } @else { (text) }
                        }
                    }
                },
            }
        }
        @if elided {
            div class="cr-diff-hunk" { "…" }
        }
    }
}

/// A line of a diff as runs of text, each marked by whether it changed.
type MarkedRuns<'a> = Vec<(bool, &'a str)>;

/// A removed line and the line added in its place, each as [`MarkedRuns`], or
/// `None` when the two share too little for marking words to say more than
/// marking the whole lines already does.
fn changed_words<'a>(old: &'a str, new: &'a str) -> Option<(MarkedRuns<'a>, MarkedRuns<'a>)> {
    let (old_words, new_words) = (diff_words(old), diff_words(new));
    if old_words.len() + new_words.len() > MAX_WORD_DIFF_TOKENS {
        return None;
    }
    let operations =
        similar::capture_diff_slices(similar::Algorithm::Myers, &old_words, &new_words);
    if similar::diff_ratio(&operations, old_words.len(), new_words.len()) < 0.5 {
        return None;
    }
    let mut old_changed = vec![false; old_words.len()];
    let mut new_changed = vec![false; new_words.len()];
    for operation in &operations {
        if operation.tag() != similar::DiffTag::Equal {
            old_changed[operation.old_range()].fill(true);
            new_changed[operation.new_range()].fill(true);
        }
    }
    Some((
        marked_runs(old, &old_words, &old_changed),
        marked_runs(new, &new_words, &new_changed),
    ))
}

/// A line cut where a diff of its words should be able to tell pieces apart:
/// runs of letters and digits, runs of whitespace, and every other character
/// on its own, so a word that gained backticks keeps the word unchanged.
fn diff_words(line: &str) -> Vec<&str> {
    #[derive(PartialEq)]
    enum Class {
        Word,
        Space,
        Other,
    }
    let class = |character: char| {
        if character.is_alphanumeric() || character == '_' {
            Class::Word
        } else if character.is_whitespace() {
            Class::Space
        } else {
            Class::Other
        }
    };
    let mut words = Vec::new();
    let mut start = 0;
    let mut previous = None;
    for (index, character) in line.char_indices() {
        let current = class(character);
        if index > start && (current == Class::Other || previous.as_ref() != Some(&current)) {
            words.push(&line[start..index]);
            start = index;
        }
        previous = Some(current);
    }
    if start < line.len() {
        words.push(&line[start..]);
    }
    words
}

/// `line`, whose pieces are `words`, as runs of pieces that are all changed or
/// all unchanged. Whitespace between two changed pieces counts as changed, so
/// a rewritten phrase is marked as one run rather than word by word.
fn marked_runs<'a>(line: &'a str, words: &[&str], changed: &[bool]) -> MarkedRuns<'a> {
    let mut runs: Vec<(bool, usize, usize)> = Vec::new();
    let mut start = 0;
    for (index, word) in words.iter().enumerate() {
        let end = start + word.len();
        let marked = changed[index]
            || (word.trim().is_empty()
                && index > 0
                && changed[index - 1]
                && changed.get(index + 1).copied().unwrap_or(false));
        match runs.last_mut() {
            Some((last, _, last_end)) if *last == marked => *last_end = end,
            _ => runs.push((marked, start, end)),
        }
        start = end;
    }
    runs.into_iter()
        .map(|(marked, start, end)| (marked, &line[start..end]))
        .collect()
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
            // A nested field the schema describes filters with its own
            // control, an enum's dropdown included.
            fields.push(ViewFilterField {
                key: column.clone(),
                label: field_label(schema, column),
                kind: property_definition(schema, column)
                    .map(schema_field_kind)
                    .unwrap_or(SchemaFieldKind::Yaml),
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
        select name="filter_operator" data-filter-operator="true" aria-label=(format!("Filter operator {}", index + 1)) class="cr-input" {
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
    // "Owner is empty" is the whole condition, so the slot stays blank.
    if !selected_operator.requires_value() {
        return html! {
            input type="hidden" name="filter_value" data-filter-value="true" value="";
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
                select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="cr-input" {
                    option value="" selected[value.is_empty()] { "Choose a value…" }
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
            select name="filter_value" data-filter-value="true" aria-label=(aria_label) class="cr-input" {
                option value="" selected[value.is_empty()] { "Choose a value…" }
                option value="true" selected[value == "true"] { "True" }
                option value="false" selected[value == "false"] { "False" }
            }
        },
        Some(SchemaFieldKind::Integer { .. }) => html! {
            input type="number" step="1" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Number" class="cr-input";
        },
        Some(SchemaFieldKind::Number { .. }) => html! {
            input type="number" step="any" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Number" class="cr-input";
        },
        Some(SchemaFieldKind::String { input_type, .. }) => html! {
            input type=(input_type) name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Value" class="cr-input";
        },
        _ => html! {
            input type="text" name="filter_value" data-filter-value="true" aria-label=(aria_label) value=(value) placeholder="Value" title="Read as YAML: 10 is a number, \"10\" is text" class="cr-input";
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
        div data-filter-row="true" class="cr-filter-row" {
            // A row reads as a sentence: "Where Stage is Proposal", then "and
            // Value is at least 10000". All three words are always here and the
            // stylesheet shows the one that fits the row's place and the match
            // mode, so they stay right as rows come and go and as All and Any
            // are switched, with or without the script.
            span class="cr-filter-join" {
                span class="cr-filter-join-where" { "Where" }
                span class="cr-filter-join-all" { "and" }
                span class="cr-filter-join-any" { "or" }
            }
            select name="filter_field" data-filter-field="true" aria-label=(format!("Filter field {}", index + 1)) class="cr-input" {
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
            div data-filter-value-slot="true" class="cr-filter-value" {
                (render_filter_value_control(fields, index, selected_field, selected_operator, value))
            }
            button type="button" data-remove-filter="true" aria-label=(format!("Remove filter {}", index + 1)) title="Remove filter" class="cr-filter-remove" { "×" }
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
    quick_filter: Option<&QuickFilter>,
) -> Markup {
    let new_url = format!("/{}/new", encode_segment(&view.name));
    let reset_url = format!("/{}", encode_segment(&view.name));
    let filter_fields = view_filter_fields(schema, available_columns);
    let title_field = view_title_field(schema, &page.records);
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
        view,
        columns,
        page,
        activity,
        query,
        schema,
        csrf_token,
        updatable,
        quick_filter,
    );
    // The one route that can answer with something smaller than its content.
    // It comes first because it is the narrower answer: everything below builds
    // the heading, the search box and the filter panel, none of which the
    // request asked for.
    //
    // Other elements travel with the region, marked `hx-swap-oob` so htmx
    // applies each to the element of the same id already on the page and then
    // drops it from the content it swaps. Two are the heading's facts about
    // the results — the record count and the badge counting applied filters —
    // and, for a reader who may change views, two more carry the page's state
    // into its view controls: the hidden inputs "Save as view" submits and the
    // "Edit view" link. Each is rendered here by the same function the heading
    // below calls, with the attribute as its only difference, so none can
    // start disagreeing with the page it patches.
    //
    // The last is the announcement, and it is last because it is not part of
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
                @if can_manage_views {
                    (view_save_state(query, columns, schema, OutOfBand::Yes))
                    @if view.saved {
                        (view_edit_link(view, query, page.limit, OutOfBand::Yes))
                    }
                }
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
            (page_bar(
                &[("/".to_owned(), None, "Views")],
                Some(view_icon(view)),
                &view.title,
                // What the page holds: how many records, and for a saved view
                // which collection they come from.
                html! {
                    span class="cr-page-meta" data-view-summary="true" {
                        @if view.saved {
                            (match view.layout {
                                ViewLayout::Table => "Saved view",
                                ViewLayout::Kanban => "Saved Kanban view",
                            })
                            " of " code class="font-mono text-gray-700" { (&view.collection) }
                            span class="mx-1.5 text-gray-300" aria-hidden="true" { "·" }
                        }
                        (view_record_count(page.total, OutOfBand::No))
                    }
                },
                html! {
                    // One form, two submit buttons, and both of them only change
                    // which records are listed: the magnifying glass beside the
                    // search box and "Apply" at the bottom of the filter
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
                            // The magnifier leads the box, where a search field's
                            // icon is expected, and is drawn rather than typed:
                            // `⌕` is a tiny glyph on macOS and a missing one in
                            // fonts without it. The button stays the submit
                            // control, so its accessible name is its label.
                            input type="search" name="q" value=(query.q.as_deref().unwrap_or("")) aria-label="Search records" placeholder="Search records…" autocomplete="off" data-view-search="true" class="h-8 w-full border bg-white pl-9 pr-3 text-[0.8rem] outline-none placeholder:text-gray-400 sm:w-56";
                            button type="submit" aria-label="Submit search" title="Search" class="absolute inset-y-1 left-1 inline-flex w-7 items-center justify-center rounded-md text-gray-400 hover:bg-gray-100 hover:text-blue-700" {
                                (PreEscaped(SEARCH_ICON))
                            }
                        }
                        details class="relative" data-filter-disclosure="true" {
                            (view_filter_summary(active_filter_count, OutOfBand::No))
                            div data-filter-panel="true" class="cr-popover cr-filter-popover z-30" {
                                div class="cr-filter-body" {
                                    section class="cr-filter-section" aria-labelledby="cr-filter-heading" {
                                        div class="cr-filter-section-head" {
                                            h2 id="cr-filter-heading" { "Filters" }
                                            // Only a choice once there are two
                                            // conditions to combine, so the
                                            // stylesheet hides it until then. The
                                            // checked radio is still submitted.
                                            div class="cr-filter-match" {
                                                span id="cr-filter-match-label" { "Match" }
                                                div role="radiogroup" aria-labelledby="cr-filter-match-label" class="cr-choice-row cr-choice-row-small" {
                                                    label class="cr-choice-option" {
                                                        input type="radio" name="filter_match" value="all" checked[query.filter_match == ViewFilterMatch::All];
                                                        "All"
                                                    }
                                                    label class="cr-choice-option" {
                                                        input type="radio" name="filter_match" value="any" checked[query.filter_match == ViewFilterMatch::Any];
                                                        "Any"
                                                    }
                                                }
                                            }
                                        }
                                        div data-filter-list="true" class="cr-filter-list" {
                                            @for (index, (field, operator, value)) in filter_rows.iter().enumerate() {
                                                (render_filter_row(&filter_fields, index, field, *operator, value))
                                            }
                                        }
                                        template data-filter-template="true" {
                                            (render_filter_row(&filter_fields, 0, "", ViewFilterOperator::default(), ""))
                                        }
                                        button type="button" data-add-filter="true" class="cr-filter-add" { "+ Add filter" }
                                    }
                                    section class="cr-filter-section" aria-labelledby="cr-sort-heading" {
                                        div class="cr-filter-section-head" {
                                            h2 id="cr-sort-heading" { "Sort" }
                                        }
                                        (render_sort_controls(
                                            &view_sort_options(&filter_fields, "Created (default)"),
                                            &view_sort(query),
                                            SortPrimary::Panel,
                                        ))
                                        p class="cr-field-help" { "Each key orders what the one before it leaves tied. Missing values stay last in either direction, and record ID breaks the remaining ties." }
                                    }
                                    details class="cr-filter-section cr-filter-columns" open[query_columns_custom(query)] {
                                        summary class="cr-filter-section-head" {
                                            h2 { "Columns" }
                                            span class="cr-pill" { (columns.iter().filter(|column| Some(column.as_str()) != title_field).count()) " shown" }
                                        }
                                        input type="hidden" name="columns" value="custom";
                                        div role="group" aria-label="Visible columns" class="cr-checkbox-row" {
                                            // The title field is the first column, or a card's
                                            // heading, whatever is chosen here, so like the ID it
                                            // is not offered.
                                            @for column in available_columns.iter().filter(|column| Some(column.as_str()) != title_field) {
                                                label class="cr-checkbox-option" title=(column) {
                                                    input type="checkbox" name="column" value=(column) checked[columns.contains(column)];
                                                    span { (field_label(schema, column)) }
                                                }
                                            }
                                        }
                                        p class="cr-field-help" { "Shown in the table, or on Kanban cards. Keep at least one." }
                                    }
                                }
                                div class="cr-filter-footer" {
                                    // "Reset" is the one control in this
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
                                    a href=(reset_url.clone()) class="cr-button" { "Reset" }
                                    button type="submit" class="cr-button cr-button-primary" { "Apply" }
                                }
                            }
                        }
                    }
                    @if can_manage_views {
                        @if view.saved {
                            (view_edit_link(view, query, page.limit, OutOfBand::No))
                        }
                        (render_save_view_control(
                            view,
                            query,
                            columns,
                            available_columns,
                            schema,
                            csrf_token,
                        ))
                    }
                    @if can_create {
                        a href=(new_url) class="cr-button cr-button-primary" {
                            "New record"
                        }
                    }
                },
            ))
            // A saved view's own filters: what the view is, so not removable.
            @if !view.filters.is_empty() || !view.where_expr.is_empty() || !view.filter_groups.is_empty() {
                div class="mb-3 flex flex-wrap items-center gap-1.5" data-view-filters="true" {
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
fn sortable_headings<'a>(
    title_field: Option<&'a str>,
    columns: &[&'a String],
    schema: Option<&JsonValue>,
) -> Vec<(&'a str, String, String)> {
    let first = match title_field {
        Some(field) => {
            let label = field_label(schema, field);
            (field, label.clone(), label)
        }
        None => ("$id", "ID".to_owned(), "record ID".to_owned()),
    };
    std::iter::once(first)
        .chain(
            ACTIVITY_COLUMNS
                .iter()
                .map(|(field, label)| (*field, humanize_field_name(label), (*label).to_owned())),
        )
        .chain(columns.iter().map(|column| {
            let label = field_label(schema, column);
            (column.as_str(), label.clone(), label)
        }))
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
            } @else if page.next.is_some() {
                // The first of several pages. The button is drawn, unusable,
                // so that Next does not move the first time it is pressed; the
                // page number beside the range already says where the reader
                // is, so a screen reader is not told about a control it cannot
                // use.
                span class="cr-button" data-disabled="true" aria-hidden="true" { "Previous" }
            }
            @if let Some(cursor) = page.next.as_deref() {
                a id="cr-page-next" href=(view_page_url(view, query, page.limit, ViewPosition::After(cursor))) rel="next" class="cr-button"
                    hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" { "Next" }
            } @else if page.previous.is_some() {
                span class="cr-button" data-disabled="true" aria-hidden="true" { "Next" }
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

/// The "*n* records" in the line under a view's title.
///
/// Lives outside the results region and is changed by every filter and search
/// that hits it, which is why it is a function: the heading renders it and a
/// results fragment sends it again as an out-of-band patch, and two copies of
/// `page.total` in two `html!` blocks is how a count starts disagreeing with the
/// pager six inches below it.
fn view_record_count(total: usize, out_of_band: OutOfBand) -> Markup {
    html! {
        span id=(VIEW_COUNT_ID) hx-swap-oob=[out_of_band.attribute()] {
            (total) @if total == 1 { " record" } @else { " records" }
        }
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

/// Which page of how many this is, when there are records on it.
///
/// Cursor pages are addressed by record rather than by number, and a write
/// while someone is paging can leave a page starting part of the way into
/// what would be a numbered page. The number is then the page the first row
/// falls on, which is where the reader would find it again.
fn page_number(page: &ViewPage) -> Option<(usize, usize)> {
    if page.records.is_empty() || page.limit == 0 {
        return None;
    }
    let pages = page.total.div_ceil(page.limit).max(1);
    Some(((page.start / page.limit + 1).min(pages), pages))
}

/// The page sizes a table's footer offers.
const VIEW_PAGE_SIZE_CHOICES: [usize; 4] = [10, 25, 50, 100];

/// The sizes offered under this page: the standard ones the server allows,
/// plus the current size if a view or URL asked for another.
fn view_page_size_choices(page: &ViewPage) -> Vec<usize> {
    let mut choices = VIEW_PAGE_SIZE_CHOICES
        .into_iter()
        .filter(|size| *size <= page.max_limit)
        .collect::<Vec<_>>();
    if !choices.contains(&page.limit) {
        choices.push(page.limit);
        choices.sort_unstable();
    }
    choices
}

/// Links that show the same view with another number of rows per page.
///
/// Links rather than a `<select>`, like the pager beside them: each is the URL
/// the page would be at, so it works without JavaScript, can be opened in a
/// new tab, and swaps only the results when htmx is there. A new size starts
/// again at the first page, because the cursor the reader was at would put a
/// different set of rows on screen under a different size. Nothing is offered
/// when every record already fits on a page of the smallest size.
fn view_page_size_links(view: &ViewDefinition, query: &ViewQuery, page: &ViewPage) -> Markup {
    let choices = view_page_size_choices(page);
    html! {
        @if choices.len() > 1 && choices.first().is_some_and(|smallest| page.total > *smallest) {
            div role="group" aria-label="Rows per page" class="flex items-center gap-1" {
                span class="mr-1 text-gray-500" aria-hidden="true" { "Rows" }
                @for size in choices {
                    a id=(format!("cr-page-size-{size}")) href=(view_page_url(view, query, size, ViewPosition::Start))
                        aria-label=(format!("{size} rows per page")) aria-current=[(size == page.limit).then_some("true")]
                        class=(if size == page.limit { "rounded bg-gray-200 px-1.5 py-0.5 font-semibold text-gray-900" } else { "rounded px-1.5 py-0.5 text-gray-600 hover:bg-gray-100 hover:text-gray-900" })
                        hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" { (size) }
                }
            }
        }
    }
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
    if page.lanes.is_some() {
        return format!("Showing {} of {} records", page.records.len(), page.total);
    }
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

/// How many characters at the end of a long record ID stay visible when its
/// table cell is too narrow for the whole ID.
const RECORD_ID_KEPT_TAIL_CHARS: usize = 10;

/// A record ID in the first cell of a table row, linking to the record.
///
/// IDs are often generated — a kind, a name, then a hash — and a hundred and
/// fifty characters of that in a column that could not wrap left no room for
/// any other column. The link is capped instead, and a long ID is shortened in
/// the middle rather than at the end: the start says what sort of record it is
/// and the end is usually what tells two of them apart, which is exactly what
/// an ellipsis at the end would hide. The two halves are adjacent spans with
/// nothing between them, so the text a screen reader reads, find-in-page
/// matches and a copy takes is still the whole ID, and `title` shows it on
/// hover. An ID short enough never to be cut is one span and has no `title`,
/// because a tooltip repeating the visible text is noise.
fn render_record_id_link(href: &str, id: &str) -> Markup {
    let shortened = id_tail_start(id).is_some();
    html! {
        a href=(href) title=[shortened.then_some(id)] class="flex max-w-80 font-mono text-gray-600 hover:text-indigo-700 hover:underline" {
            (render_id_halves(id))
        }
    }
}

/// Where the kept end of a long ID starts, or `None` for an ID short enough
/// never to be shortened.
fn id_tail_start(id: &str) -> Option<usize> {
    id.char_indices()
        .rev()
        .nth(RECORD_ID_KEPT_TAIL_CHARS - 1)
        .map(|(index, _)| index)
        .filter(|_| id.chars().count() > 2 * RECORD_ID_KEPT_TAIL_CHARS)
}

/// An ID as the spans that shorten it in the middle inside a flex container:
/// a start that gives way to an ellipsis and an end that does not.
fn render_id_halves(id: &str) -> Markup {
    html! {
        @match id_tail_start(id) {
            Some(tail_start) => {
                span class="truncate" { (&id[..tail_start]) }
                span class="shrink-0" { (&id[tail_start..]) }
            }
            None => span class="truncate" { (id) },
        }
    }
}

/// A record's title in the first cell of a table row, linking to the record.
///
/// The title is what a reader scans for, so it is the row's one bold value,
/// and the ID it replaces is kept in the tooltip beneath the title, in full,
/// for whoever needs the stable identifier.
fn render_record_title_link(href: &str, title: &str, id: &str) -> Markup {
    html! {
        a href=(href) title=(format!("{title}\n{id}")) class="flex max-w-80 font-semibold text-gray-900 hover:text-indigo-700 hover:underline" {
            span class="truncate" { (title) }
        }
    }
}

/// Values at least this long may not fit a table cell, so they carry their
/// full text as a tooltip.
const CELL_TITLE_MIN_CHARS: usize = 40;

/// The tooltip for a table cell showing `value`, if it needs one.
///
/// A row is one line. A cell used to wrap to a second line and clamp there, so
/// a name with a hyphen in it broke at the hyphen and a table of short values
/// was twice as tall as it needed to be. Now a value keeps to one line and a
/// long one ends in an ellipsis at the cell's width, which leaves the whole of
/// it for hovering. Whether a value is cut depends on the font and the
/// characters in it, which the server cannot measure, so the tooltip goes on
/// every value long enough that it might be; a short one never is, and a
/// tooltip repeating the visible text is noise. It also shows a nested value
/// on its own lines, where the cell has run them together.
fn cell_title(value: &str) -> Option<&str> {
    (value.chars().count() >= CELL_TITLE_MIN_CHARS).then_some(value)
}

/// How many values a row of quick filters offers besides **All**.
const QUICK_FILTER_VALUES: usize = 8;

/// One-click filters on the field that says what state a view's records are
/// in, with how many records each would show.
///
/// A collection of a few hundred tasks is mostly read one state at a time —
/// what failed, what is still queued — and that took opening the filter panel,
/// choosing the field, the operator and the value, and applying it. The row
/// above the table does it in one click and says beforehand how many records
/// the click will leave. Each chip is an ordinary link to the URL the filter
/// panel would have built, so it is shareable, and the panel shows the
/// condition when opened.
struct QuickFilter {
    field: String,
    /// How many records the view shows with no condition on `field`.
    total: usize,
    /// The values offered, each with how many records it would show, in the
    /// order they are offered. `None` stands for records with no value.
    values: Vec<(Option<YamlValue>, usize)>,
}

/// The field a view's quick filters are on, if it has one worth offering: a
/// top-level `status` or `state` field of plain text or an enum, which is what
/// collections call their states, or else the first enum field in column
/// order. Never the title field, and never on a Kanban board, whose lanes are
/// already this.
fn quick_filter_field(
    view: &ViewDefinition,
    schema: Option<&JsonValue>,
    records: &[Record],
) -> Option<String> {
    if view.layout == ViewLayout::Kanban {
        return None;
    }
    let title = view_title_field(schema, records);
    let is_enum = |field: &str| {
        property_definition(schema, field)
            .is_some_and(|definition| definition.get("enum").is_some())
    };
    let holds_text = |field: &str| {
        let key = YamlValue::String(field.to_owned());
        records
            .iter()
            .any(|record| matches!(record.attributes.get(&key), Some(YamlValue::String(_))))
            && !records.iter().any(|record| {
                matches!(
                    record.attributes.get(&key),
                    Some(YamlValue::Mapping(_) | YamlValue::Sequence(_))
                )
            })
    };
    ["status", "state"]
        .into_iter()
        .find(|field| Some(*field) != title && (is_enum(field) || holds_text(field)))
        .map(str::to_owned)
        .or_else(|| {
            view_available_columns(view, records, schema)
                .into_iter()
                .find(|column| {
                    !column.contains('.') && Some(column.as_str()) != title && is_enum(column)
                })
        })
}

/// Count what each quick filter would show.
///
/// `records` are the view's records before the URL's ad hoc filters, which
/// are applied here without any on the quick filter's own field: clicking a
/// chip replaces those, so the count beside it is the count the reader will
/// get. Any-of matching with a condition on another field is left without
/// quick filters, because there a chip's condition would widen the result
/// rather than narrow it, and no count per value would say what clicking does.
fn quick_filter(
    view: &ViewDefinition,
    schema: Option<&JsonValue>,
    records: &[Record],
    query: &ViewQuery,
) -> Option<QuickFilter> {
    let field = quick_filter_field(view, schema, records)?;
    let others = query_without_field(query, &field);
    if query.filter_match == ViewFilterMatch::Any && !others.filter_field.is_empty() {
        return None;
    }
    // A subset of the conditions the page has already parsed, so this does
    // not fail where the page did not.
    let others = view_filter_expressions(&others).ok()?;
    let key = YamlValue::String(field.clone());
    let mut total = 0;
    let mut unset = 0;
    let mut counts = BTreeMap::<String, (YamlValue, usize)>::new();
    for record in records
        .iter()
        .filter(|record| ViewFilterMatch::All.matches(&others, &record.attributes))
    {
        total += 1;
        match record.attributes.get(&key) {
            None => unset += 1,
            Some(value) if is_empty_value(value) => unset += 1,
            Some(value @ (YamlValue::String(_) | YamlValue::Number(_) | YamlValue::Bool(_))) => {
                counts
                    .entry(serialize_yaml_value(value))
                    .or_insert_with(|| (value.clone(), 0))
                    .1 += 1;
            }
            Some(_) => {}
        }
    }
    let active = quick_filter_selection(query, &field);
    // An enum's values in the schema's order, so a chip stays where it was as
    // the counts change; anything else most frequent first.
    let order = property_definition(schema, &field)
        .and_then(|definition| definition.get("enum"))
        .and_then(JsonValue::as_array)
        .map(|values| json_values_as_yaml(values))
        .unwrap_or_default();
    let mut values = counts.into_values().collect::<Vec<_>>();
    values.sort_by(|(left, left_count), (right, right_count)| {
        let rank = |value: &YamlValue| {
            order
                .iter()
                .position(|known| known == value)
                .unwrap_or(usize::MAX)
        };
        rank(left)
            .cmp(&rank(right))
            .then_with(|| right_count.cmp(left_count))
            .then_with(|| serialize_yaml_value(left).cmp(&serialize_yaml_value(right)))
    });
    let mut offered = values
        .into_iter()
        .enumerate()
        .filter(|(index, (value, _))| {
            *index < QUICK_FILTER_VALUES
                || matches!(&active, QuickFilterSelection::Value(chosen) if chosen == value)
        })
        .map(|(_, (value, count))| (Some(value), count))
        .collect::<Vec<_>>();
    if unset > 0 || active == QuickFilterSelection::Unset {
        offered.push((None, unset));
    }
    // One value is no choice, unless the reader has already made it.
    if offered.len() < 2 && active == QuickFilterSelection::None {
        return None;
    }
    Some(QuickFilter {
        field,
        total,
        values: offered,
    })
}

/// `query` without its conditions on `field`, operators kept beside their
/// fields.
fn query_without_field(query: &ViewQuery, field: &str) -> ViewQuery {
    let kept = query_filter_conditions(query)
        .into_iter()
        .filter(|(condition, _, _)| condition != field)
        .collect::<Vec<_>>();
    ViewQuery {
        filter_field: kept.iter().map(|(field, _, _)| field.clone()).collect(),
        filter_operator: kept.iter().map(|(_, operator, _)| *operator).collect(),
        filter_value: kept.into_iter().map(|(_, _, value)| value).collect(),
        ..query.clone()
    }
}

/// The URL's filter conditions as triples, with the operator a condition
/// written without one defaults to.
fn query_filter_conditions(query: &ViewQuery) -> Vec<(String, ViewFilterOperator, String)> {
    query
        .filter_field
        .iter()
        .zip(&query.filter_value)
        .enumerate()
        .map(|(index, (field, value))| {
            (
                field.clone(),
                query
                    .filter_operator
                    .get(index)
                    .copied()
                    .unwrap_or_default(),
                value.clone(),
            )
        })
        .collect()
}

/// Which quick filter the URL has applied.
#[derive(Debug, PartialEq)]
enum QuickFilterSelection {
    /// No condition on the field: **All**.
    None,
    /// Exactly the condition a value's chip applies.
    Value(YamlValue),
    /// Exactly the condition the chip for records with no value applies.
    Unset,
    /// Conditions on the field no chip applies, which any chip replaces.
    Other,
}

fn quick_filter_selection(query: &ViewQuery, field: &str) -> QuickFilterSelection {
    let conditions = query_filter_conditions(query)
        .into_iter()
        .filter(|(condition, _, _)| condition == field)
        .collect::<Vec<_>>();
    match conditions.as_slice() {
        [] => QuickFilterSelection::None,
        [(_, ViewFilterOperator::IsEmpty, _)] => QuickFilterSelection::Unset,
        [(_, ViewFilterOperator::Eq, value)] => yaml_serde::from_str::<YamlValue>(value)
            .map(QuickFilterSelection::Value)
            .unwrap_or(QuickFilterSelection::Other),
        _ => QuickFilterSelection::Other,
    }
}

/// A pencil for a file panel's Edit action, drawn like the magnifier.
const PENCIL_ICON: &str = r#"<svg aria-hidden="true" focusable="false" width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M10.75 2.75l2.5 2.5-8 8H2.75v-2.5z"/><path d="m9 4.5 2.5 2.5"/></svg>"#;

/// A trash can for a file panel's Delete action, drawn like the magnifier.
const TRASH_ICON: &str = r#"<svg aria-hidden="true" focusable="false" width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M2.75 4.25h10.5"/><path d="M6.25 4.25v-1.5h3.5v1.5"/><path d="M4.25 4.25l.6 8.5a1 1 0 0 0 1 .95h4.3a1 1 0 0 0 1-.95l.6-8.5"/><path d="M6.75 7v4M9.25 7v4"/></svg>"#;

/// A magnifier for the search box's submit button, in the text's colour.
const SEARCH_ICON: &str = r#"<svg aria-hidden="true" focusable="false" width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"><circle cx="7" cy="7" r="4.75"/><path d="m10.5 10.5 3.25 3.25"/></svg>"#;

/// Which timestamp a table's rows are grouped by day on, when it is ordered by
/// one.
///
/// The server only names the column. Where a day begins depends on the
/// reader's time zone, which the browser knows and the server does not, so
/// `cr.js` reads the `<time>` in that column of each row and heads each run of
/// rows from one local day with it: "Today", "Yesterday", a weekday within the
/// week, then a date. Without JavaScript the table is the same table,
/// ungrouped.
fn date_groups(query: &ViewQuery) -> Option<&'static str> {
    match view_sort_field(query) {
        Some("$created_at") => Some("created"),
        Some("$updated_at") => Some("updated"),
        _ => None,
    }
}

/// The URL's filter conditions as chips, each with a link that removes it.
///
/// The Filter button counted the conditions a page applied but did not say
/// which, so finding out why a table was short took opening the panel and
/// reading it, and dropping one condition took finding its row and applying
/// again. Each chip says its condition in the panel's words and removes it in
/// one click; with more than one, a last link removes them all. A saved view's
/// own filters are not here, because they are what the view is and cannot be
/// removed; the heading lists them. Like the quick filters below, the chips
/// live in the results region, so applying the panel updates them, and their
/// links navigate the whole page so the panel updates too.
fn render_active_filters(
    view: &ViewDefinition,
    query: &ViewQuery,
    page: &ViewPage,
    schema: Option<&JsonValue>,
) -> Markup {
    let conditions = query_filter_conditions(query)
        .into_iter()
        .filter(|(field, _, value)| !(field.is_empty() && value.is_empty()))
        .collect::<Vec<_>>();
    let without = |removed: Option<usize>| {
        let kept = conditions
            .iter()
            .enumerate()
            .filter(|(index, _)| removed.is_some_and(|removed| removed != *index))
            .map(|(_, condition)| condition.clone())
            .collect::<Vec<_>>();
        let next = ViewQuery {
            filter_field: kept.iter().map(|(field, _, _)| field.clone()).collect(),
            filter_operator: kept.iter().map(|(_, operator, _)| *operator).collect(),
            filter_value: kept.into_iter().map(|(_, _, value)| value).collect(),
            ..query.clone()
        };
        view_page_url(view, &next, page.limit, ViewPosition::Start)
    };
    html! {
        @if !conditions.is_empty() {
            div data-filter-chips=(conditions.len()) class="mb-3 flex flex-wrap items-center gap-1.5" {
                span class="mr-1 text-xs font-semibold text-gray-500" {
                    @if query.filter_match == ViewFilterMatch::Any && conditions.len() > 1 { "Any of" } @else { "Filtered by" }
                }
                @for (index, (field, operator, value)) in conditions.iter().enumerate() {
                    @let text = describe_condition(schema, field, *operator, value);
                    span class="cr-active-filter" {
                        (text)
                        a href=(without(Some(index))) aria-label=(format!("Remove filter: {text}")) class="cr-active-filter-remove" {
                            span aria-hidden="true" { "×" }
                        }
                    }
                }
                @if conditions.len() > 1 {
                    a href=(without(None)) class="text-xs text-gray-500 hover:text-gray-900 hover:underline" { "Clear filters" }
                }
            }
        }
    }
}

/// A condition in the filter panel's words: "Status is Failed", "Assignee is
/// empty".
fn describe_condition(
    schema: Option<&JsonValue>,
    field: &str,
    operator: ViewFilterOperator,
    value: &str,
) -> String {
    let label = field_label(schema, field);
    match operator {
        ViewFilterOperator::IsEmpty | ViewFilterOperator::IsNotEmpty => {
            format!("{label} {}", operator.label())
        }
        _ => {
            let enum_option = property_definition(schema, field)
                .is_some_and(|definition| definition.get("enum").is_some());
            let value = if enum_option {
                humanize_field_name(value)
            } else {
                value.to_owned()
            };
            format!("{label} {} {value}", operator.label())
        }
    }
}

/// The row of quick filters above a table.
///
/// It is inside the results region, so a search or a page turn that swaps the
/// region brings its counts up to date. The chips themselves navigate the
/// whole page, boosted, rather than swapping the region: a chip changes the
/// URL's conditions, and the filter panel and its badge, which are outside the
/// region, have to show them.
fn render_quick_filter(
    view: &ViewDefinition,
    query: &ViewQuery,
    page: &ViewPage,
    quick_filter: &QuickFilter,
    schema: Option<&JsonValue>,
) -> Markup {
    let field = quick_filter.field.as_str();
    let definition = property_definition(schema, field);
    let label = field_label(schema, field);
    let selection = quick_filter_selection(query, field);
    let url = |condition: Option<(ViewFilterOperator, String)>| {
        let mut next = query_without_field(query, field);
        if let Some((operator, value)) = condition {
            next.filter_field.push(field.to_owned());
            next.filter_operator.push(operator);
            next.filter_value.push(value);
        }
        view_page_url(view, &next, page.limit, ViewPosition::Start)
    };
    html! {
        nav aria-label=(format!("Filter by {label}")) data-quick-filter=(field) class="mb-3 flex flex-wrap items-center gap-1.5" {
            span class="mr-1 text-xs font-semibold text-gray-500" { (label) }
            a href=(url(None)) class="cr-quick-filter" aria-current=[(selection == QuickFilterSelection::None).then_some("true")] {
                "All" span class="cr-quick-filter-count" { (quick_filter.total) }
            }
            @for (value, count) in &quick_filter.values {
                @match value {
                    Some(value) => {
                        a href=(url(Some((ViewFilterOperator::Eq, serialize_yaml_value(value)))))
                            class="cr-quick-filter"
                            aria-current=[matches!(&selection, QuickFilterSelection::Value(chosen) if chosen == value).then_some("true")] {
                            (match value {
                                YamlValue::String(text) if shows_as_badge(field, definition) => humanize_field_name(text),
                                value => display_value(value, definition, None),
                            })
                            span class="cr-quick-filter-count" { (count) }
                        }
                    }
                    None => {
                        a href=(url(Some((ViewFilterOperator::IsEmpty, String::new()))))
                            class="cr-quick-filter"
                            aria-current=[(selection == QuickFilterSelection::Unset).then_some("true")] {
                            "Not set" span class="cr-quick-filter-count" { (count) }
                        }
                    }
                }
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
    quick_filter: Option<&QuickFilter>,
) -> Markup {
    let (first, last) = page_range(page);
    // The title field is the first column, so it is not repeated among the
    // others.
    let title_field = view_title_field(schema, &page.records);
    let shown_columns = columns
        .iter()
        .filter(|column| Some(column.as_str()) != title_field)
        .collect::<Vec<_>>();
    html! {
        div id=(VIEW_TABLE_REGION) {
            (render_active_filters(view, query, page, schema))
            @if view.layout == ViewLayout::Kanban {
                (render_kanban_board(view, columns, page, activity, query, schema, csrf_token, updatable))
            } @else {
            @if let Some(quick_filter) = quick_filter {
                (render_quick_filter(view, query, page, quick_filter, schema))
            }
            div class="cr-table-shell" {
                div class="cr-table-scroll" {
                    // Every row opens its record: the first cell's link is
                    // its one link, and `cr.js` follows it from a click
                    // anywhere else on the row.
                    table class="min-w-full text-left text-sm" data-date-groups=[date_groups(query)] data-row-links="true" {
                        thead {
                            tr {
                                // One loop over the three kinds of sortable
                                // heading — the record id, the two audit
                                // timestamps and the view's own columns — rather
                                // than three near-identical blocks, because every
                                // one of them now needs its position for
                                // `sort_link_id` and a position is only
                                // meaningful across the whole row.
                                @for (index, (field, heading, spoken)) in sortable_headings(title_field, &shown_columns, schema).iter().enumerate() {
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
                                tr { td colspan=(shown_columns.len() + ACTIVITY_COLUMNS.len() + 2) class="px-4 py-12 text-center text-gray-500" { "No records match this view." } }
                            } @else {
                                @for record in &page.records {
                                    @let record_activity = activity.get(&record.id);
                                    @let href = format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id));
                                    tr {
                                        td class="px-4 py-3" {
                                            @match title_field.and_then(|field| record_title(record, field)) {
                                                Some(title) => (render_record_title_link(&href, title, &record.id)),
                                                None => (render_record_id_link(&href, &record.id)),
                                            }
                                        }
                                        td class="whitespace-nowrap px-4 py-3" data-activity="created" {
                                            (render_timestamp(record_activity.map(|activity| activity.created_at.as_str())))
                                        }
                                        td class="whitespace-nowrap px-4 py-3" data-activity="updated" {
                                            (render_timestamp(record_activity.map(|activity| activity.updated_at.as_str())))
                                        }
                                        @for column in &shown_columns {
                                            @let value = display_field(record, column, schema);
                                            td class="px-4 py-3 text-gray-700" {
                                                span title=[cell_title(&value)] class="block max-w-xs truncate" { (render_field_value(record, column, schema, &value)) }
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
                    div class="flex items-center gap-3 text-gray-600" {
                        p { "Showing " (first) "–" (last) " of " (page.total) }
                        @if let Some((current, pages)) = page_number(page) {
                            p class="text-gray-500" { "Page " (current) " of " (pages) }
                        }
                    }
                    div class="flex flex-wrap items-center gap-x-4 gap-y-2" {
                        (view_page_size_links(view, query, page))
                        (view_pager_links(view, query, page))
                    }
                }
            }
            }
        }
    }
}

/// The names of the two "Save as view" controls a refusal can be about, which
/// are the form field names the browser submits, as the record form's are.
const VIEW_NAME_CONTROL: &str = "name";
const GROUP_BY_CONTROL: &str = "group_by";

fn render_save_view_control(
    view: &ViewDefinition,
    query: &ViewQuery,
    columns: &[String],
    available_columns: &[String],
    schema: Option<&JsonValue>,
    csrf_token: &str,
) -> Markup {
    html! {
        details class="relative" data-save-view-disclosure="true" {
            summary class="cr-button cursor-pointer list-none" {
                "Save as view"
            }
            div class="cr-popover cr-save-view-popover absolute right-0 z-20 mt-2" {
                (render_save_view_form(view, query, columns, available_columns, schema, csrf_token, None))
            }
        }
    }
}

/// The "Save as view" form: the page's state in hidden fields, then the name,
/// title, layout and grouping, holding either the page as it was rendered or
/// exactly what a refused submission sent.
///
/// Boosted, with the record form's contract: it answers success with `204` and
/// `HX-Location` (`mutation_redirect`) and a refusal with this element again,
/// marked `CR-Form-Invalid` (`reject_save_view_form`). It points `hx-target` at
/// itself, which narrows the swap to the form, keeps the popover around it open,
/// and names `SAVE_VIEW_FORM_REGION` in `HX-Target`. `hx-disabled-elt` is there
/// for the reason it is on the record form: a second click is a second
/// submission, which would be refused as a name already taken by the first.
fn render_save_view_form(
    view: &ViewDefinition,
    query: &ViewQuery,
    columns: &[String],
    available_columns: &[String],
    schema: Option<&JsonValue>,
    csrf_token: &str,
    rejection: Option<&SaveViewRejection>,
) -> Markup {
    let action = format!("/{}/save-view", encode_segment(&view.name));
    let submitted = rejection.map(|rejection| &rejection.submitted);
    let layout = submitted
        .and_then(|submitted| submitted.layout)
        .unwrap_or(view.layout);
    let group_by = match submitted {
        Some(submitted) => submitted.group_by.as_deref(),
        None => view.group_by.as_deref(),
    };
    // A field no record holds is still the one chosen, so it stays an option
    // rather than silently becoming "Choose a field…".
    let unlisted_group_by = group_by.filter(|field| {
        !field.is_empty() && !available_columns.iter().any(|column| column == field)
    });
    let name_diagnostics = form_diagnostics(rejection, VIEW_NAME_CONTROL);
    let group_by_diagnostics = form_diagnostics(rejection, GROUP_BY_CONTROL);
    html! {
        form id=(SAVE_VIEW_FORM_REGION) method="post" action=(action)
            hx-target="this" hx-swap="outerHTML" hx-disabled-elt="find button[type=submit]" class="cr-save-view" {
            input type="hidden" name="_csrf" value=(csrf_token);
            div class="cr-save-view-body" {
                div {
                    h2 class="cr-save-view-heading" { "Save current view" }
                    p class="cr-field-help" { "Preserves applied filters, all/any matching, layout, columns, and sorting. Search text remains shareable in the URL." }
                }
                (view_save_state(query, columns, schema, OutOfBand::No))
                @if let Some(rejection) = rejection {
                    (rejected_form_alert(
                        "This view was not saved.",
                        &rejection.error,
                        "Nothing was written. The values below are exactly what you submitted.",
                    ))
                }
                // The two controls a refusal can be about are labelled by `for`
                // rather than by wrapping, because the reason goes between the
                // label and the control and a list cannot go inside a `<label>`.
                div class=(if name_diagnostics.is_empty() { "cr-field" } else { "cr-field cr-field-invalid" }) {
                    label for="cr-save-view-name" class="cr-field-label" { "View name" span class="cr-required" aria-hidden="true" { "*" } }
                    (render_field_diagnostics(name_diagnostics))
                    input id="cr-save-view-name" required name="name" value=[submitted.map(|submitted| submitted.name.as_str())] placeholder="enterprise-deals" autocomplete="off" aria-invalid=[(!name_diagnostics.is_empty()).then_some("true")] class="cr-input";
                }
                div class="cr-field" {
                    div class="cr-field-head" {
                        label for="cr-save-view-title" class="cr-field-label" { "Title" }
                        span class="cr-field-hint" { "Optional" }
                    }
                    input id="cr-save-view-title" name="title" value=[submitted.map(|submitted| submitted.title.as_str())] placeholder=(format!("{} copy", view.title)) autocomplete="off" class="cr-input";
                }
                div class="cr-save-view-grid" {
                    label class="cr-field" {
                        span class="cr-field-label" { "Layout" }
                        select name="layout" aria-label="Layout" data-view-layout="true" class="cr-input" {
                            option value="table" selected[layout == ViewLayout::Table] { "Table" }
                            option value="kanban" selected[layout == ViewLayout::Kanban] { "Kanban" }
                        }
                    }
                    div class=(if group_by_diagnostics.is_empty() { "cr-field" } else { "cr-field cr-field-invalid" }) {
                        label for="cr-save-view-group-by" class="cr-field-label" { "Group Kanban by" }
                        (render_field_diagnostics(group_by_diagnostics))
                        select id="cr-save-view-group-by" name="group_by" aria-label="Group Kanban by" data-view-group-by="true" aria-invalid=[(!group_by_diagnostics.is_empty()).then_some("true")] class="cr-input" {
                            option value="" selected[group_by.is_none_or(str::is_empty)] { "Choose a field…" }
                            @for column in available_columns.iter().map(String::as_str).chain(unlisted_group_by) {
                                option value=(column) selected[group_by == Some(column)] { (field_label(schema, column)) }
                            }
                        }
                    }
                    p class="cr-field-help cr-field-wide" { "Kanban uses the chosen front matter field as lanes; moving a card updates that field through the audited database path." }
                }
            }
            div class="cr-save-view-footer" {
                button type="submit" class="cr-button cr-button-primary" { "Save view" }
            }
        }
    }
}

/// A refused "Save as view", as the form alone or as a page around it.
///
/// htmx names `SAVE_VIEW_FORM_REGION` and gets the form, byte for byte what the
/// page below embeds. A plain post — a browser with JavaScript off — is given
/// the form on a page of its own rather than the view it was saved from: that
/// page is its rows, which the form has no reason to re-read and could not
/// reproduce, since the search text and the page it was on are deliberately
/// not part of what is saved. Cancel goes back to the view with the submitted
/// filters, sort and columns applied, which is the page the reader left.
#[allow(clippy::too_many_arguments)]
fn render_refused_save_view(
    representation: &Representation,
    view: &ViewDefinition,
    available_columns: &[String],
    schema: Option<&JsonValue>,
    csrf_token: &str,
    rejection: &SaveViewRejection,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    max_page_size: usize,
) -> Markup {
    let submitted = &rejection.submitted;
    let query = ViewQuery {
        filter_match: submitted.filter_match,
        filter_field: submitted.filter_field.clone(),
        filter_operator: submitted.filter_operator.clone(),
        filter_value: submitted.filter_value.clone(),
        sort_field: submitted.sort_field.clone(),
        sort_direction: submitted.sort_direction.clone(),
        columns: if submitted.column.is_empty() {
            ViewColumnsMode::Default
        } else {
            ViewColumnsMode::Custom
        },
        column: submitted.column.clone(),
        ..ViewQuery::default()
    };
    let form = render_save_view_form(
        view,
        &query,
        &submitted.column,
        available_columns,
        schema,
        csrf_token,
        Some(rejection),
    );
    // Not wrapped by `fragment`, for the record form's reason: a refusal pushes
    // no URL, so there is no new state for a title to name.
    if representation.wants(SAVE_VIEW_FORM_REGION) {
        return form;
    }
    let view_url = format!("/{}", encode_segment(&view.name));
    let back = format!(
        "{view_url}?{}",
        view_query_string(
            &query,
            view.page_size.min(max_page_size),
            ViewPosition::Start
        )
    );
    page_or_content(
        representation,
        "Save as view",
        &view_url,
        navigation,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    (view_url.clone(), Some(view_icon(view)), &view.title),
                ],
                None,
                "Save as view",
                html! {},
                html! {
                    a href=(back) class="cr-button" { "Cancel" }
                },
            ))
            // The popover's width, which is what the form is laid out for.
            div class="cr-popover cr-save-view-popover mx-auto" {
                (form)
            }
        },
        ui,
        csrf_token,
    )
}

/// The page's current filters, sort and columns as the hidden inputs of "Save
/// as view", and the sort they save in words, in the element a results swap
/// patches; see `VIEW_SAVE_STATE_ID`.
fn view_save_state(
    query: &ViewQuery,
    columns: &[String],
    schema: Option<&JsonValue>,
    out_of_band: OutOfBand,
) -> Markup {
    html! {
        div id=(VIEW_SAVE_STATE_ID) hx-swap-oob=[out_of_band.attribute()] {
            // Said because it is not seen anywhere else: a column heading
            // shows only the first key, and the filter panel is closed.
            p class="cr-save-view-sort" {
                span { "Sort: " }
                (saved_sort_summary(query, schema))
            }
            input type="hidden" name="filter_match" value=(match query.filter_match { ViewFilterMatch::All => "all", ViewFilterMatch::Any => "any" });
            // Every row, rather than the pairs a zip would keep. A page only
            // ever has pairs, but a refused save is rendered back from what was
            // submitted, and dropping a condition sent without its value would
            // let the corrected resubmission save fewer than were asked for.
            @for index in 0..query.filter_field.len().max(query.filter_value.len()) {
                @if let Some(field) = query.filter_field.get(index) {
                    input type="hidden" name="filter_field" value=(field);
                    input type="hidden" name="filter_operator" value=(query.filter_operator.get(index).copied().unwrap_or_default().as_str());
                }
                @if let Some(value) = query.filter_value.get(index) {
                    input type="hidden" name="filter_value" value=(value);
                }
            }
            @match query.requested_sort() {
                None => {}
                Some(keys) if keys.is_empty() => {
                    input type="hidden" name="sort_field" value="";
                }
                Some(keys) => {
                    @for key in &keys {
                        input type="hidden" name="sort_field" value=(key.field);
                        input type="hidden" name="sort_direction" value=(key.direction.as_str());
                    }
                }
            }
            @for column in columns {
                input type="hidden" name="column" value=(column);
            }
        }
    }
}

/// The sort "Save as view" writes, as "Updated descending, then Name
/// ascending": the panel's "None" is saved as record ID order, and a query
/// naming no sort leaves the new view on the default.
fn saved_sort_summary(query: &ViewQuery, schema: Option<&JsonValue>) -> String {
    let keys = match query.requested_sort() {
        None => vec![SortKey::new(DEFAULT_VIEW_SORT_FIELD, SortDirection::Desc)],
        Some(keys) if keys.is_empty() => return "Record ID".to_owned(),
        Some(keys) => keys,
    };
    keys.iter()
        .map(|key| {
            let label = match key.field.as_str() {
                "$created_at" => "Created".to_owned(),
                "$updated_at" => "Updated".to_owned(),
                "$id" => "Record ID".to_owned(),
                field => field_label(schema, field),
            };
            let direction = match key.direction {
                SortDirection::Asc => "ascending",
                SortDirection::Desc => "descending",
            };
            format!("{label} {direction}")
        })
        .collect::<Vec<_>>()
        .join(", then ")
}

/// "Edit view" on a saved view, linking to its editor with the page's query,
/// so the editor starts from the filters, sort, columns and page size on
/// screen rather than from the file alone.
fn view_edit_link(
    view: &ViewDefinition,
    query: &ViewQuery,
    limit: usize,
    out_of_band: OutOfBand,
) -> Markup {
    let href = format!(
        "{}?{}",
        view_edit_path(view),
        view_query_string(query, limit, ViewPosition::Start)
    );
    html! {
        a id=(VIEW_EDIT_LINK_ID) href=(href) class="cr-button" hx-swap-oob=[out_of_band.attribute()] { "Edit view" }
    }
}

fn view_edit_path(view: &ViewDefinition) -> String {
    format!("/{}/edit", encode_segment(&view.name))
}

fn view_delete_path(view: &ViewDefinition) -> String {
    format!("/{}/delete", encode_segment(&view.name))
}

/// A view's conditions folded into the one list the filter builder edits,
/// plus the groups that cannot join it.
///
/// A definition can hold equality `filters`, `where_expr` expressions and any
/// number of groups, each matching all or any of its own expressions, and all
/// of them must hold. Everything that must hold together is one `all` list:
/// the filters, the expressions, every `all` group, and every group of one.
/// An `any` group of several cannot join that list without changing what the
/// view matches, so it stays a group of its own — unless it is the only
/// condition there is, when the builder can show it as its `any` list.
#[derive(Debug, PartialEq, Eq)]
struct FoldedConditions {
    filter_match: ViewFilterMatch,
    expressions: Vec<String>,
    groups: Vec<ViewFilterGroup>,
}

impl FoldedConditions {
    fn into_filter_groups(self) -> Vec<ViewFilterGroup> {
        let mut groups = Vec::new();
        if !self.expressions.is_empty() {
            groups.push(ViewFilterGroup {
                match_mode: self.filter_match.into(),
                expressions: self.expressions,
            });
        }
        groups.extend(self.groups);
        groups
    }
}

/// Fold a view's conditions, and `applied` — the filters on the page that
/// opened the editor — with them.
fn fold_view_conditions(
    view: &ViewDefinition,
    applied: Option<ViewFilterGroup>,
) -> FoldedConditions {
    let mut all = Vec::new();
    let mut any = Vec::new();
    for expression in view.filters.iter().chain(&view.where_expr) {
        push_unique(&mut all, canonical_expression(expression));
    }
    for group in view.filter_groups.iter().cloned().chain(applied) {
        let group = canonical_group(group);
        if group.match_mode == ViewPredicateMatch::All || group.expressions.len() == 1 {
            for expression in group.expressions {
                push_unique(&mut all, expression);
            }
        } else {
            push_unique(&mut any, group);
        }
    }
    if all.is_empty() && any.len() == 1 {
        let group = any.remove(0);
        return FoldedConditions {
            filter_match: ViewFilterMatch::Any,
            expressions: group.expressions,
            groups: Vec::new(),
        };
    }
    FoldedConditions {
        filter_match: ViewFilterMatch::All,
        expressions: all,
        groups: any,
    }
}

fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if !items.contains(&item) {
        items.push(item);
    }
}

/// An expression spelled the way the filter builder writes it, so `stage =
/// won` in a hand-written file and `stage=won` from the form compare equal.
fn canonical_expression(expression: &str) -> String {
    match FilterExpression::split(expression) {
        Ok((field, operator, value)) => filter_expression_text(field, operator.into(), value),
        Err(_) => expression.to_owned(),
    }
}

fn canonical_group(group: ViewFilterGroup) -> ViewFilterGroup {
    ViewFilterGroup {
        match_mode: group.match_mode,
        expressions: group
            .expressions
            .iter()
            .map(|expression| canonical_expression(expression))
            .collect(),
    }
}

/// Stored expressions as the builder's `(field, operator, value)` rows.
fn expression_rows(expressions: &[String]) -> Vec<(String, ViewFilterOperator, String)> {
    expressions
        .iter()
        .filter_map(|expression| FilterExpression::split(expression).ok())
        .map(|(field, operator, value)| (field.to_owned(), operator.into(), value.to_owned()))
        .collect()
}

/// The order a view opens in when no URL chooses one: its own default, or
/// newest first.
fn view_default_sort(view: &ViewDefinition) -> Vec<SortKey> {
    if view.sort.is_empty() {
        vec![SortKey::new(DEFAULT_VIEW_SORT_FIELD, SortDirection::Desc)]
    } else {
        view.sort.clone()
    }
}

/// A saved view as its editor shows it: one control per setting, holding
/// either the view as it was opened or what a refused submission typed.
struct ViewDraft {
    title: String,
    filter_match: ViewFilterMatch,
    conditions: Vec<(String, ViewFilterOperator, String)>,
    /// The `any` groups `FoldedConditions` keeps apart, each kept or removed
    /// whole with a checkbox.
    groups: Vec<ViewFilterGroup>,
    sort: Vec<SortKey>,
    columns: Vec<String>,
    automatic_columns: Vec<String>,
    layout: ViewLayout,
    group_by: Option<String>,
    page_size: String,
}

fn opened_view_draft(
    context: &ViewEditorContext,
    query: &ViewQuery,
    applied: Option<ViewFilterGroup>,
    max_page_size: usize,
) -> ApiResult<ViewDraft> {
    let view = &context.view;
    let schema = context.schema.as_ref();
    let folded = fold_view_conditions(view, applied);
    let available = view_available_columns(view, &context.records, schema);
    let columns = selected_view_columns(view, query, &available, schema, &context.records)?;
    // What the view picks for itself, which the page's links spell out as a
    // choice once the filter panel has been applied.
    let automatic_columns = if view.columns.is_empty() {
        selected_view_columns(
            view,
            &ViewQuery::default(),
            &available,
            schema,
            &context.records,
        )?
    } else {
        Vec::new()
    };
    let sort = match query.requested_sort() {
        // The page's "None", which is record ID order.
        Some(keys) if keys.is_empty() => vec![SortKey::new("$id", SortDirection::Asc)],
        Some(keys) => keys,
        None => view_default_sort(view),
    };
    Ok(ViewDraft {
        title: view.title.clone(),
        filter_match: folded.filter_match,
        conditions: expression_rows(&folded.expressions),
        groups: folded.groups,
        sort,
        columns,
        automatic_columns,
        layout: view.layout,
        group_by: view.group_by.clone(),
        // Every link on a view page names its limit, so only one other than
        // the page's own default is a choice the reader made.
        page_size: query
            .limit
            .filter(|limit| *limit != view.page_size.min(max_page_size))
            .unwrap_or(view.page_size)
            .to_string(),
    })
}

fn submitted_view_draft(form: &HtmlViewEditForm) -> ViewDraft {
    ViewDraft {
        title: form.title.clone(),
        filter_match: form.filter_match,
        conditions: form
            .filter_field
            .iter()
            .zip(&form.filter_value)
            .enumerate()
            .filter(|(_, (field, value))| !(field.is_empty() && value.is_empty()))
            .map(|(index, (field, value))| {
                (
                    field.clone(),
                    form.filter_operator.get(index).copied().unwrap_or_default(),
                    value.clone(),
                )
            })
            .collect(),
        groups: form
            .keep_group
            .iter()
            .filter_map(|group| serde_json::from_str(group).ok())
            .collect(),
        sort: submitted_sort(&form.sort_field, &form.sort_direction),
        columns: form.column.clone(),
        automatic_columns: form.automatic_column.clone(),
        layout: form.layout.unwrap_or_default(),
        group_by: form
            .group_by
            .clone()
            .filter(|field| !field.trim().is_empty()),
        page_size: form.page_size.clone(),
    }
}

/// What an editor submission asks the view to become, read from the form
/// alone; `update_view_form` then keeps whatever it left unchanged.
struct ViewEdit {
    title: String,
    conditions: FoldedConditions,
    sort: Vec<SortKey>,
    columns: Vec<String>,
    /// The columns are the ones the view picked for itself when the editor
    /// opened, so it should go on picking them.
    automatic_columns: bool,
    layout: ViewLayout,
    group_by: Option<String>,
    page_size: usize,
}

fn submitted_view_edit(form: &HtmlViewEditForm) -> ApiResult<ViewEdit> {
    let invalid = |message: &str| ApiError::bad_request("invalid_form", message);
    let title = form.title.trim();
    if title.is_empty() {
        return Err(invalid("give the view a title"));
    }
    let (filter_match, expressions) = match submitted_filter_group(
        form.filter_match,
        &form.filter_field,
        &form.filter_operator,
        &form.filter_value,
    )? {
        Some(group) => (group.match_mode.into(), group.expressions),
        None => (ViewFilterMatch::All, Vec::new()),
    };
    let groups = form
        .keep_group
        .iter()
        .map(|group| {
            serde_json::from_str::<ViewFilterGroup>(group)
                .map(canonical_group)
                .map_err(|error| invalid(&format!("a kept filter group is not valid: {error}")))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let sort = submitted_sort(&form.sort_field, &form.sort_direction);
    if sort.is_empty() {
        return Err(invalid("choose a field to sort by"));
    }
    let layout = form.layout.unwrap_or_default();
    let group_by = match layout {
        ViewLayout::Table => None,
        ViewLayout::Kanban => Some(
            form.group_by
                .as_deref()
                .map(str::trim)
                .filter(|field| !field.is_empty())
                .ok_or_else(|| invalid("choose a field to group the Kanban board by"))?
                .to_owned(),
        ),
    };
    let page_size = form
        .page_size
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|size| (1..=crate::views::MAX_VIEW_PAGE_SIZE).contains(size))
        .ok_or_else(|| {
            invalid(&format!(
                "rows per page must be a whole number from 1 to {}",
                crate::views::MAX_VIEW_PAGE_SIZE
            ))
        })?;
    let mut distinct = BTreeSet::new();
    if let Some(column) = form.column.iter().find(|column| !distinct.insert(*column)) {
        return Err(invalid(&format!(
            "column '{column}' cannot be selected more than once"
        )));
    }
    if form.column.len() > MAX_VIEW_COLUMNS {
        return Err(invalid(&format!(
            "a view can show at most {MAX_VIEW_COLUMNS} columns"
        )));
    }
    let automatic_columns = !form.automatic_column.is_empty()
        && distinct == form.automatic_column.iter().collect::<BTreeSet<_>>();
    Ok(ViewEdit {
        title: title.to_owned(),
        conditions: FoldedConditions {
            // One condition matches the same under either word.
            filter_match: if expressions.len() > 1 {
                filter_match
            } else {
                ViewFilterMatch::All
            },
            expressions,
            groups,
        },
        sort,
        columns: form.column.clone(),
        automatic_columns,
        layout,
        group_by,
        page_size,
    })
}

/// The saved-view editor: a page, like a record's, holding every setting of
/// the definition, with deleting the view kept apart below it.
///
/// The filter builder is the filter panel's own — the same rows, the same
/// `data-filter-builder` enhancement, the same sentences — so a condition is
/// written the same way whether it narrows a page or defines a view.
fn render_view_editor(
    representation: &Representation,
    context: &ViewEditorContext,
    draft: &ViewDraft,
    ui: Option<&UiContext>,
    csrf_token: &str,
    error: Option<&PublicError>,
) -> Markup {
    let view = &context.view;
    let schema = context.schema.as_ref();
    let view_url = format!("/{}", encode_segment(&view.name));
    let available = view_available_columns(view, &context.records, schema);
    let filter_fields = view_filter_fields(schema, &available);
    let title_field = view_title_field(schema, &context.records);
    let mut rows = draft.conditions.clone();
    if rows.is_empty() {
        rows.push((String::new(), ViewFilterOperator::default(), String::new()));
    }
    let sort_options = view_sort_options(&filter_fields, "Created");
    let mut column_options = available
        .iter()
        .filter(|column| Some(column.as_str()) != title_field)
        .collect::<Vec<_>>();
    for column in &draft.columns {
        if !column_options.contains(&column) && Some(column.as_str()) != title_field {
            column_options.push(column);
        }
    }
    page_or_content(
        representation,
        &format!("Edit {}", view.title),
        &view_url,
        &context.navigation,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    (view_url.clone(), Some(view_icon(view)), &view.title),
                ],
                None,
                "Edit view",
                html! {
                    span class="cr-page-meta" {
                        "Saved view of " code class="font-mono text-gray-700" { (&view.collection) }
                        span class="mx-1.5 text-gray-300" aria-hidden="true" { "·" }
                        code class="font-mono text-gray-700" { (&view_url) }
                    }
                },
                html! {},
            ))
            // Native rather than boosted: a refusal is this page again with an
            // alert, which htmx would not swap into a boosted `POST` because
            // it does not carry `CR-Form-Invalid`. "Save as view" shows what
            // boosting it would take.
            form method="post" action=(view_edit_path(view)) hx-boost=(UNBOOSTED)
                data-filter-builder="true" data-max-filters=(MAX_VIEW_FILTERS) data-view-editor="true"
                class="cr-view-editor" {
                input type="hidden" name="_csrf" value=(csrf_token);
                @if let Some(error) = error {
                    (rejected_form_alert(
                        "The view was not saved.",
                        error,
                        "Its definition is unchanged. The form below holds what you submitted.",
                    ))
                }
                section class="cr-filter-section" {
                    div class="cr-filter-section-head" {
                        h2 { label for="cr-view-title" { "Title" } }
                    }
                    input id="cr-view-title" name="title" value=(&draft.title) required autocomplete="off" class="cr-input";
                }
                section class="cr-filter-section" aria-labelledby="cr-view-filters-heading" {
                    div class="cr-filter-section-head" {
                        h2 id="cr-view-filters-heading" { "Filters" }
                        div class="cr-filter-match" {
                            span id="cr-view-match-label" { "Match" }
                            div role="radiogroup" aria-labelledby="cr-view-match-label" class="cr-choice-row cr-choice-row-small" {
                                label class="cr-choice-option" {
                                    input type="radio" name="filter_match" value="all" checked[draft.filter_match == ViewFilterMatch::All];
                                    "All"
                                }
                                label class="cr-choice-option" {
                                    input type="radio" name="filter_match" value="any" checked[draft.filter_match == ViewFilterMatch::Any];
                                    "Any"
                                }
                            }
                        }
                    }
                    div data-filter-list="true" class="cr-filter-list" {
                        @for (index, (field, operator, value)) in rows.iter().enumerate() {
                            (render_filter_row(&filter_fields, index, field, *operator, value))
                        }
                    }
                    template data-filter-template="true" {
                        (render_filter_row(&filter_fields, 0, "", ViewFilterOperator::default(), ""))
                    }
                    button type="button" data-add-filter="true" class="cr-filter-add" { "+ Add filter" }
                    @if !draft.groups.is_empty() {
                        div class="cr-view-editor-groups" data-view-groups=(draft.groups.len()) {
                            p class="cr-field-label" { "Also required" }
                            @for group in &draft.groups {
                                @let text = expression_rows(&group.expressions)
                                    .iter()
                                    .map(|(field, operator, value)| describe_condition(schema, field, *operator, value))
                                    .collect::<Vec<_>>()
                                    .join(" or ");
                                label class="cr-checkbox-option" {
                                    input type="checkbox" name="keep_group" value=(serde_json::to_string(group).expect("filter groups are JSON serializable")) checked;
                                    span { "Any of: " (text) }
                                }
                            }
                            p class="cr-field-help" { "Each of these matches when any one of its conditions does. Uncheck one to remove it." }
                        }
                    }
                    p class="cr-field-help" { "Every record in the view meets these conditions. Filters applied on the view's page narrow it further without changing it." }
                }
                section class="cr-filter-section" {
                    div class="cr-filter-section-head" {
                        h2 id="cr-view-sort-heading" { "Sort" }
                    }
                    (render_sort_controls(&sort_options, &draft.sort, SortPrimary::Editor))
                }
                section class="cr-filter-section" {
                    div class="cr-filter-section-head" {
                        h2 id="cr-view-columns-heading" { "Columns" }
                    }
                    // The title field heads every row and card whatever is
                    // chosen, so like the filter panel this does not offer it,
                    // but a view that names it keeps it.
                    @for column in draft.columns.iter().filter(|column| Some(column.as_str()) == title_field) {
                        input type="hidden" name="column" value=(column);
                    }
                    @for column in &draft.automatic_columns {
                        input type="hidden" name="automatic_column" value=(column);
                    }
                    div role="group" aria-labelledby="cr-view-columns-heading" class="cr-checkbox-row" {
                        @for column in column_options {
                            label class="cr-checkbox-option" title=(column) {
                                input type="checkbox" name="column" value=(column) checked[draft.columns.contains(column)];
                                span { (field_label(schema, column)) }
                            }
                        }
                    }
                    p class="cr-field-help" { "Shown in the table, or on Kanban cards. With none chosen, the view picks for itself." }
                }
                section class="cr-filter-section" {
                    div class="cr-view-editor-grid" {
                        label class="cr-field" {
                            span class="cr-field-label" { "Layout" }
                            select name="layout" data-view-layout="true" class="cr-input" {
                                option value="table" selected[draft.layout == ViewLayout::Table] { "Table" }
                                option value="kanban" selected[draft.layout == ViewLayout::Kanban] { "Kanban" }
                            }
                        }
                        label class="cr-field" {
                            span class="cr-field-label" { "Group Kanban by" }
                            select name="group_by" data-view-group-by="true" class="cr-input" {
                                option value="" selected[draft.group_by.is_none()] { "Choose a field…" }
                                @for column in &available {
                                    option value=(column) selected[draft.group_by.as_deref() == Some(column.as_str())] { (field_label(schema, column)) }
                                }
                                @if let Some(group_by) = draft.group_by.as_deref().filter(|field| !available.iter().any(|column| column == field)) {
                                    option value=(group_by) selected { (group_by) " (custom)" }
                                }
                            }
                        }
                        label class="cr-field" {
                            span class="cr-field-label" { "Rows per page" }
                            input type="number" name="page_size" value=(&draft.page_size) min="1" max=(crate::views::MAX_VIEW_PAGE_SIZE) step="1" required class="cr-input";
                        }
                    }
                }
                div class="cr-view-editor-footer" {
                    a href=(&view_url) class="cr-button" { "Cancel" }
                    button type="submit" class="cr-button cr-button-primary" { "Save changes" }
                }
            }
            div class="cr-view-editor-danger cr-record-danger rounded-xl border border-red-200 bg-red-50 p-5" {
                h2 class="text-sm font-semibold text-red-900" { "Delete this view" }
                p class="mt-1 text-sm text-red-800" { "Removes the view from the sidebar and its route. The records it shows are not touched." }
                a href=(view_delete_path(view)) class="mt-3 inline-flex rounded-lg border border-red-300 bg-white px-3 py-1.5 text-sm font-semibold text-red-700 hover:bg-red-100" { "Delete view…" }
            }
        },
        ui,
        csrf_token,
    )
}

/// Asked before a saved view is deleted, as a record's deletion is.
fn render_view_delete_confirmation(
    representation: &Representation,
    view: &ViewDefinition,
    navigation: &[ViewDefinition],
    ui: Option<&UiContext>,
    csrf_token: &str,
) -> Markup {
    let view_url = format!("/{}", encode_segment(&view.name));
    let edit_url = view_edit_path(view);
    page_or_content(
        representation,
        &format!("Delete {}", view.title),
        &view_url,
        navigation,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    (view_url.clone(), Some(view_icon(view)), &view.title),
                    (edit_url.clone(), None, "Edit view"),
                ],
                None,
                "Delete",
                html! {},
                html! {},
            ))
            div class="mx-auto max-w-2xl" {
                div class="cr-record-danger rounded-xl border border-red-200 bg-red-50 p-6" {
                    h2 class="text-lg font-semibold text-red-900" { "Delete this view?" }
                    p class="mt-2 text-sm text-red-800" {
                        "You are about to delete the saved view "
                        strong { (&view.title) }
                        " ("
                        code class="cr-filter-tag" { (&view_url) }
                        ")."
                    }
                    p class="mt-2 text-sm text-red-700" {
                        "Only its definition, "
                        code class="cr-filter-tag" { ".cr/views/" (&view.name) ".yaml" }
                        ", is removed. Every record in "
                        code class="cr-filter-tag" { (&view.collection) }
                        " stays as it is"
                        @if view.name == view.collection {
                            ", and " code class="cr-filter-tag" { (&view_url) } " goes back to showing all of them"
                        }
                        "."
                    }
                    form method="post" action=(view_delete_path(view)) hx-boost=(UNBOOSTED) class="mt-5 flex flex-col gap-3 sm:flex-row sm:items-center" {
                        input type="hidden" name="_csrf" value=(csrf_token);
                        button type="submit" class="rounded-lg border border-red-300 bg-red-700 px-4 py-2 text-sm font-semibold text-white hover:bg-red-800" { "Delete view" }
                        a href=(&edit_url) class="cr-button" { "Cancel" }
                    }
                }
            }
        },
        ui,
        csrf_token,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_kanban_board(
    view: &ViewDefinition,
    columns: &[String],
    page: &ViewPage,
    activity: &BTreeMap<String, RecordActivity>,
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
    let title_field = view_title_field(schema, &page.records);
    let card_columns = columns
        .iter()
        .filter(|column| column.as_str() != group_by && Some(column.as_str()) != title_field)
        .collect::<Vec<_>>();
    // A card says when its record was made, or last changed when that is what
    // the board is ordered by.
    let card_time: fn(&RecordActivity) -> &str = if view_sort_field(query) == Some("$updated_at") {
        |activity| activity.updated_at.as_str()
    } else {
        |activity| activity.created_at.as_str()
    };
    html! {
        div class="mb-2 flex flex-wrap items-center justify-between gap-2 text-xs text-gray-600" {
            p {
                "Grouped by " span class="font-semibold text-gray-900" { (field_label(schema, group_by)) }
            }
            @if updatable.is_empty() {
                p { "This perspective can view cards but cannot move them." }
            } @else {
                p { "Drag permitted cards between lanes or use each card’s move control." }
            }
        }
        div class="cr-board-scroll" {
            div data-kanban-board="true" class="cr-board" {
                @for (lane_index, lane) in lanes.iter().enumerate() {
                    section
                        data-kanban-lane="true"
                        data-kanban-target=(kanban_target_json(&lane.target))
                        data-kanban-csrf=(csrf_token)
                        class="cr-kanban-lane"
                    {
                        @let lane_total = lane_total(page, &lane.target).max(lane.records.len());
                        div class="cr-lane-head" {
                            span class=(match &lane.target {
                                KanbanTarget::Value { value } => match yaml_serde::from_str::<YamlValue>(value).ok().and_then(|value| value.as_str().and_then(badge_tone)) {
                                    Some(tone) => format!("cr-lane-dot {tone}"),
                                    None => "cr-lane-dot".to_owned(),
                                },
                                KanbanTarget::Unset => "cr-lane-dot".to_owned(),
                            }) aria-hidden="true" {}
                            h2 { (&lane.label) }
                            span class="cr-lane-count" { (lane_total) }
                        }
                        div class="cr-lane-cards" {
                            @if lane.records.is_empty() {
                                p class="rounded-lg border border-dashed border-gray-300 px-3 py-5 text-center text-xs text-gray-500" { "Drop cards here" }
                            }
                            @for record in &lane.records {
                                @let can_move = updatable.contains(&record.id);
                                article
                                    draggable=(if can_move { "true" } else { "false" })
                                    data-kanban-card=(if can_move { "true" } else { "false" })
                                    data-move-url=(kanban_move_url(view, &record.id))
                                    class=(if can_move { "cr-kanban-card cursor-grab active:cursor-grabbing" } else { "cr-kanban-card" })
                                {
                                    @let href = format!("/{}/records/{}", encode_segment(&view.name), encode_segment(&record.id));
                                    @match title_field.and_then(|field| record_title(record, field)) {
                                        Some(title) => {
                                            a href=(href) class="cr-card-title" { (title) }
                                            p class="cr-card-id" title=[id_tail_start(&record.id).map(|_| record.id.as_str())] { (render_id_halves(&record.id)) }
                                        }
                                        None => {
                                            a href=(href) class="cr-card-title cr-card-title-id" title=[id_tail_start(&record.id).map(|_| record.id.as_str())] { (render_id_halves(&record.id)) }
                                        }
                                    }
                                    (render_card_properties(record, &card_columns, schema))
                                    @let time = activity.get(&record.id).map(card_time);
                                    @if time.is_some() || can_move {
                                    div class="cr-card-foot" {
                                    @if let Some(time) = time {
                                        (render_timestamp(Some(time)))
                                    }
                                    @if can_move {
                                        details class="cr-kanban-move" {
                                            summary { "Move…" }
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
                                                button type="submit" class="cr-button cr-button-primary cr-button-small" { "Move" }
                                            }
                                        }
                                    }
                                    }
                                    }
                                }
                            }
                        }
                        @if lane_total > lane.records.len() {
                            (render_lane_more(view, query, page, lane_index, lane_total - lane.records.len()))
                        }
                    }
                }
            }
        }
        p class="mt-1 text-xs text-gray-500" data-board-summary="true" {
            "Showing " (page.records.len()) " of " (count_noun(page.total, "record", "records"))
            @if page.records.len() < page.total {
                ", up to " (page.limit) " in each lane"
            }
        }
    }
}

/// How many records the lane for `target` holds in the whole view.
fn lane_total(page: &ViewPage, target: &KanbanTarget) -> usize {
    let key = match target {
        KanbanTarget::Value { value } => Some(value.clone()),
        KanbanTarget::Unset => None,
    };
    page.lanes
        .as_ref()
        .and_then(|lanes| lanes.get(&key))
        .copied()
        .unwrap_or_default()
}

/// The foot of a lane that holds more records than it shows: a link to the
/// same board showing more of every lane, or, once a lane is at the most the
/// server will send, a word on how to see the rest.
///
/// The link swaps the board alone, as the pager does a table's page, and has
/// an id so that focus comes back to it after the swap.
fn render_lane_more(
    view: &ViewDefinition,
    query: &ViewQuery,
    page: &ViewPage,
    lane: usize,
    hidden: usize,
) -> Markup {
    let more = page.limit.saturating_mul(2).min(page.max_limit);
    html! {
        @if more > page.limit {
            a id=(format!("cr-lane-more-{lane}")) href=(view_page_url(view, query, more, ViewPosition::Start)) class="cr-lane-more"
                hx-target=(VIEW_TABLE_TARGET.as_str()) hx-swap=(VIEW_TABLE_SWAP_FROM_INSIDE) hx-push-url="true" {
                "Show " (hidden.min(more - page.limit)) " more"
            }
        } @else {
            p class="cr-lane-more" { (hidden) " more not shown; filter the board to reach them" }
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
    let definition = property_definition(schema, group_by);
    for value in kanban_schema_values(schema, group_by) {
        let serialized = serialize_yaml_value(&value);
        if known.insert(serialized.clone()) {
            lane_values.push((serialized, display_value(&value, definition, None)));
        }
    }

    let mut observed = BTreeSet::new();
    let mut has_unassigned = false;
    for record in records {
        match record.field(group_by).ok().flatten() {
            Some(value) => {
                let serialized = serialize_yaml_value(value);
                if !known.contains(&serialized) {
                    observed.insert((serialized, display_value(value, definition, None)));
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
    let required = schema_required_fields(schema)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let configured_order = schema_ui_order(schema);
    let mut fields = properties
        .iter()
        .map(|(key, definition)| SchemaFormField {
            key: key.clone(),
            label: field_label(Some(schema), key),
            description: definition
                .get("description")
                .and_then(JsonValue::as_str)
                .map(str::to_owned),
            required: required.contains(key.as_str()),
            value: attributes.get(YamlValue::String(key.clone())).cloned(),
            submitted: None,
            kind: schema_field_kind(definition),
            inferred: None,
            unit: definition
                .get("x-cr-unit")
                .and_then(|unit| amount_unit(unit, Some(attributes))),
            members: Vec::new(),
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

/// The structured form's fields: [`schema_form_fields`], with each object the
/// form can edit as a group of controls given its members. An object that
/// another top-level property's name starts with, `costs` beside `costs.total`,
/// stays YAML, because the two would name one control.
fn record_form_fields(schema: &JsonValue, attributes: &Mapping) -> Option<Vec<SchemaFormField>> {
    let properties = schema.get("properties")?.as_object()?;
    let mut fields = schema_form_fields(schema, attributes)?;
    for field in &mut fields {
        let prefix = format!("{}.", field.key);
        if let Some(definition) = properties.get(&field.key)
            && !properties.keys().any(|key| key.starts_with(&prefix))
            && object_value_fits_group(definition, field.value.as_ref())
        {
            field.members = object_members(field, definition);
        }
    }
    Some(fields)
}

/// The properties of an object the form can edit one control per property,
/// or `None` when it stays a YAML box.
///
/// Only an object the schema describes, one level down: a property inside it
/// that is itself an object, or a list the schema gives no options for, is a
/// YAML box within the group. A name with a `.` in it stays YAML too, because
/// the form names each control by its dotted path and could not tell
/// `costs.total` inside `costs` from a property called `costs.total`.
fn object_group_properties(definition: &JsonValue) -> Option<&serde_json::Map<String, JsonValue>> {
    if definition.get("type").and_then(JsonValue::as_str) != Some("object")
        || definition.get("enum").is_some()
    {
        return None;
    }
    let properties = definition.get("properties")?.as_object()?;
    (!properties.is_empty()
        && properties
            .keys()
            .all(|key| !key.is_empty() && !key.contains('.')))
    .then_some(properties)
}

/// Whether a stored value can be shown as the group of controls its schema
/// describes without leaving any of it out. A record that has none yet can.
/// One holding a key the schema does not declare, or something other than a
/// mapping, is shown as YAML, so everything in it is still in front of the
/// reader and saving the form writes it back as it was.
fn object_value_fits_group(definition: &JsonValue, value: Option<&YamlValue>) -> bool {
    let Some(properties) = object_group_properties(definition) else {
        return false;
    };
    match value {
        None | Some(YamlValue::Null) => true,
        Some(YamlValue::Mapping(object)) => object
            .keys()
            .all(|key| key.as_str().is_some_and(|key| properties.contains_key(key))),
        Some(_) => false,
    }
}

/// An object's controls, each keyed by its path. A property is required here
/// only when the object is, so leaving an optional object empty is not refused
/// by the browser for a property the object would need if it existed.
fn object_members(field: &SchemaFormField, definition: &JsonValue) -> Vec<SchemaFormField> {
    if field.key.contains('.') {
        return Vec::new();
    }
    let object = match &field.value {
        Some(YamlValue::Mapping(object)) => object.clone(),
        _ => Mapping::new(),
    };
    schema_form_fields(definition, &object)
        .unwrap_or_default()
        .into_iter()
        .map(|member| SchemaFormField {
            key: format!("{}.{}", field.key, member.key),
            required: field.required && member.required,
            ..member
        })
        .collect()
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

/// A top-level field's schema definition, when the schema declares one.
fn property_definition<'a>(schema: Option<&'a JsonValue>, key: &str) -> Option<&'a JsonValue> {
    let properties = schema?.get("properties")?;
    if let Some(definition) = properties.get(key) {
        return Some(definition);
    }
    // A nested column, `learning.status`, is described inside its parent.
    let mut segments = key.split('.');
    let mut definition = properties.get(segments.next()?)?;
    for segment in segments {
        definition = definition.get("properties")?.get(segment)?;
    }
    Some(definition)
}

/// What a field is called on screen: its schema `title`, or else its key made
/// readable. It is the rule the record form has always used for its labels,
/// so a column heading and the control that edits the column say the same
/// thing.
fn field_label(schema: Option<&JsonValue>, key: &str) -> String {
    property_definition(schema, key)
        .and_then(|definition| definition.get("title"))
        .and_then(JsonValue::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| humanize_field_name(key))
}

/// What a field with nothing in it shows: missing, `null`, an empty or blank
/// string, or an empty list or mapping.
const EMPTY_VALUE: &str = "—";

/// Whether `value` is one of the ways YAML writes nothing.
fn is_empty_value(value: &YamlValue) -> bool {
    match value {
        YamlValue::Null => true,
        YamlValue::String(text) => text.trim().is_empty(),
        YamlValue::Sequence(items) => items.is_empty(),
        YamlValue::Mapping(entries) => entries.is_empty(),
        _ => false,
    }
}

/// A record's field as a table cell or Kanban card shows it.
fn display_field(record: &Record, column: &str, schema: Option<&JsonValue>) -> String {
    match record.field(column).ok().flatten() {
        Some(value) => display_value(
            value,
            property_definition(schema, column),
            Some(&record.attributes),
        ),
        None => EMPTY_VALUE.to_owned(),
    }
}

/// How many of an object's fields a cell summarises before counting the rest.
const OBJECT_SUMMARY_FIELDS: usize = 2;

/// A record's field as a table cell or Kanban card shows it: `text`, which is
/// [`display_field`]'s rendering of it, unless the value is an object or a
/// list of objects, which is summarised instead.
///
/// Printed as text, an object was its YAML run together on one line —
/// `status: done attempts: 0 retry: at: '' session: learning-…` — which is
/// long, mostly noise, and hides the one part a reader wants. So an object with
/// a state says only that: its `status` or `state`, or else the first field the
/// schema gives an enum, as a badge. Any other object shows its first few
/// fields that hold something, as `key value` chips, leaving out empty strings,
/// zeroes, `false`, nulls, and nested values, and counts the rest; one with
/// nothing worth showing is a dash. A list of objects is counted. The whole
/// value is still in the cell's tooltip, which `text` supplies.
fn render_field_value(
    record: &Record,
    column: &str,
    schema: Option<&JsonValue>,
    text: &str,
) -> Markup {
    if text == EMPTY_VALUE {
        return render_empty_value();
    }
    let definition = property_definition(schema, column);
    match record.field(column).ok().flatten() {
        Some(YamlValue::Mapping(object)) => render_object_summary(object, definition),
        Some(YamlValue::Sequence(items))
            if items
                .iter()
                .any(|item| matches!(item, YamlValue::Mapping(_))) =>
        {
            html! {
                span class="text-gray-500" {
                    (items.len()) @if items.len() == 1 { " item" } @else { " items" }
                }
            }
        }
        Some(YamlValue::String(value)) if shows_as_badge(column, definition) => render_badge(value),
        Some(YamlValue::Sequence(items))
            if definition
                .and_then(|definition| definition.get("items"))
                .is_some_and(|items| items.get("enum").is_some()) =>
        {
            html! {
                @for item in items {
                    @if let YamlValue::String(item) = item {
                        span class="mr-1" { (render_badge(item)) }
                    }
                }
            }
        }
        _ => html! { (text) },
    }
}

/// The dash an empty value shows, quieter than a value, so a column of them
/// reads as the absence it is rather than as a column of data.
fn render_empty_value() -> Markup {
    html! { span class="text-gray-400" { (EMPTY_VALUE) } }
}

/// Whether a field's string values are badges: an enum's, whose values are a
/// fixed set of states, and a `status` or `state` field's, which is what a
/// schemaless collection calls its states.
fn shows_as_badge(column: &str, definition: Option<&JsonValue>) -> bool {
    definition.is_some_and(|definition| definition.get("enum").is_some())
        || matches!(column.rsplit('.').next(), Some("status" | "state"))
            && definition
                .is_none_or(|definition| definition.get("type").is_none_or(|kind| kind == "string"))
}

/// A state as a badge, read like an enum's option and coloured by what it
/// says.
fn render_badge(value: &str) -> Markup {
    html! {
        span class=(match badge_tone(value) {
            Some(tone) => format!("cr-pill {tone}"),
            None => "cr-pill".to_owned(),
        }) { (humanize_field_name(value)) }
    }
}

/// The colour a state's badge takes, from the words collections most often
/// use for them: green when something finished well, red when it did not,
/// blue while it is under way, and amber while it waits its turn. Anything
/// else stays grey, because a colour guessed from an unfamiliar word would be
/// a claim about it the data never made. `in-progress`, `In progress` and
/// `in_progress` are one word here.
fn badge_tone(value: &str) -> Option<&'static str> {
    let word = value.trim().to_lowercase().replace([' ', '-'], "_");
    Some(match word.as_str() {
        "done" | "complete" | "completed" | "success" | "succeeded" | "successful" | "won"
        | "approved" | "accepted" | "resolved" | "passed" | "shipped" | "delivered" | "sent"
        | "paid" | "published" | "merged" | "hired" | "advance" | "advanced" | "active"
        | "healthy" | "ok" => "cr-pill-positive",
        "failed" | "failure" | "error" | "errored" | "lost" | "rejected" | "reject"
        | "declined" | "denied" | "cancelled" | "canceled" | "blocked" | "expired"
        | "timed_out" | "timeout" | "overdue" | "broken" | "unhealthy" => "cr-pill-negative",
        "running" | "in_progress" | "processing" | "started" | "working" | "doing" | "claimed"
        | "in_review" | "reviewing" | "retrying" => "cr-pill-active",
        "queued" | "pending" | "waiting" | "scheduled" | "todo" | "to_do" | "draft" | "new"
        | "paused" | "on_hold" | "backlog" => "cr-pill-warn",
        _ => return None,
    })
}

/// A card's details: each field in `columns` that holds something, as a small
/// chip, or as the badge a state already is.
///
/// Cards used to list every chosen field as a labelled row, `ASKED BY` over
/// its value, empty ones included, so a card with five fields was a dozen
/// lines whatever it held. Now a card shows only the values it has, side by
/// side and wrapping, and says what each one is in its tooltip and to a screen
/// reader rather than in a label that repeats down every card of the lane.
fn render_card_properties(
    record: &Record,
    columns: &[&String],
    schema: Option<&JsonValue>,
) -> Markup {
    let shown = columns
        .iter()
        .map(|column| (column.as_str(), display_field(record, column, schema)))
        .filter(|(_, text)| text != EMPTY_VALUE)
        .collect::<Vec<_>>();
    html! {
        @if !shown.is_empty() {
            div class="cr-card-props" {
                @for (column, text) in shown {
                    @let label = field_label(schema, column);
                    @let definition = property_definition(schema, column);
                    @let badge = match record.field(column).ok().flatten() {
                        Some(YamlValue::String(_)) => shows_as_badge(column, definition),
                        Some(YamlValue::Mapping(_)) => true,
                        _ => false,
                    };
                    span class=(if badge { "cr-card-prop-badge" } else { "cr-card-prop" }) title=(format!("{label}: {text}")) {
                        span class="sr-only" { (label) ": " }
                        (render_field_value(record, column, schema, &text))
                    }
                }
            }
        }
    }
}

/// The badge or chips [`render_field_value`] shows for one object.
fn render_object_summary(object: &Mapping, definition: Option<&JsonValue>) -> Markup {
    let scalar = |value: &YamlValue| match value {
        YamlValue::String(text) if !text.trim().is_empty() => Some(text.clone()),
        YamlValue::Number(number) if number.as_f64() != Some(0.0) => Some(number.to_string()),
        YamlValue::Bool(true) => Some("True".to_owned()),
        _ => None,
    };
    let state = ["status", "state"]
        .into_iter()
        .find_map(|key| object.get(YamlValue::String(key.to_owned())))
        .or_else(|| {
            let properties = definition?.get("properties")?.as_object()?;
            object.iter().find_map(|(key, value)| {
                let key = key.as_str()?;
                properties.get(key)?.get("enum").is_some().then_some(value)
            })
        })
        .and_then(scalar);
    if let Some(state) = state {
        return render_badge(&state);
    }
    let fields = object
        .iter()
        .filter_map(|(key, value)| Some((key.as_str()?, scalar(value)?)))
        .collect::<Vec<_>>();
    html! {
        @if fields.is_empty() {
            (render_empty_value())
        }
        @for (key, value) in fields.iter().take(OBJECT_SUMMARY_FIELDS) {
            span class="mr-1 inline-flex items-baseline gap-1 rounded bg-gray-100 px-1.5 py-px text-xs" {
                span class="text-gray-500" { (key) }
                span class="text-gray-700" { (value) }
            }
        }
        @if fields.len() > OBJECT_SUMMARY_FIELDS {
            span class="text-xs text-gray-500" { "+" (fields.len() - OBJECT_SUMMARY_FIELDS) }
        }
    }
}

/// A value as a reader sees it, following what the record form shows.
///
/// A table used to print the stored YAML beside a form that printed the same
/// value readably, so the two disagreed about what `negotiation` was called.
/// Now an enum's value reads as the form's option does, a list of scalars is a
/// comma-separated list, and a boolean is capitalised as in the form. A number
/// the schema gives an `x-cr-unit` is an amount: its digits are grouped and the
/// unit follows it. A number without one is printed as stored, because a bare
/// integer is as likely to be a year, a postcode or an identifier as a
/// quantity, and grouping any of those would misprint it. `unit_source` is the
/// record a `{"field": …}` unit is read from.
fn display_value(
    value: &YamlValue,
    definition: Option<&JsonValue>,
    unit_source: Option<&Mapping>,
) -> String {
    // Nothing, however it is written, reads as a missing field does: `''` and
    // `null` are how YAML spells an empty value, not what a reader should see.
    if is_empty_value(value) {
        return EMPTY_VALUE.to_owned();
    }
    match value {
        YamlValue::String(text)
            if definition.is_some_and(|definition| definition.get("enum").is_some()) =>
        {
            humanize_field_name(text)
        }
        YamlValue::Number(number) => {
            match definition.and_then(|definition| definition.get("x-cr-unit")) {
                Some(unit) => {
                    let amount = group_digits(&number.to_string());
                    match amount_unit(unit, unit_source) {
                        Some(unit) if unit == "%" => format!("{amount}%"),
                        // A no-break space, so a narrow column cannot put the
                        // unit on a line of its own.
                        Some(unit) => format!("{amount}\u{a0}{unit}"),
                        None => amount,
                    }
                }
                None => number.to_string(),
            }
        }
        YamlValue::Bool(true) => "True".to_owned(),
        YamlValue::Bool(false) => "False".to_owned(),
        YamlValue::Sequence(items)
            if !items.is_empty()
                && items.iter().all(|item| {
                    matches!(
                        item,
                        YamlValue::String(_) | YamlValue::Number(_) | YamlValue::Bool(_)
                    )
                }) =>
        {
            let item_definition = definition.and_then(|definition| definition.get("items"));
            items
                .iter()
                .map(|item| display_value(item, item_definition, unit_source))
                .collect::<Vec<_>>()
                .join(", ")
        }
        _ => yaml_value(value),
    }
}

/// The unit an `x-cr-unit` names: the string itself, or the value of the
/// sibling field `{"field": "currency"}` points at, which is how an amount
/// whose currency varies per record is written.
fn amount_unit(unit: &JsonValue, record: Option<&Mapping>) -> Option<String> {
    match unit {
        JsonValue::String(unit) if !unit.is_empty() => Some(unit.clone()),
        JsonValue::Object(reference) => {
            let field = reference.get("field")?.as_str()?;
            match record?.get(YamlValue::String(field.to_owned()))? {
                YamlValue::String(unit) if !unit.is_empty() => Some(unit.clone()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// `1234567.5` becomes `1,234,567.5`. Anything that is not plain decimal
/// notation — an exponent, `.inf` — is returned as it was.
fn group_digits(number: &str) -> String {
    let (sign, unsigned) = match number.strip_prefix('-') {
        Some(unsigned) => ("-", unsigned),
        None => ("", number),
    };
    let (whole, fraction) = match unsigned.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (unsigned, None),
    };
    if whole.is_empty() || !whole.bytes().all(|byte| byte.is_ascii_digit()) {
        return number.to_owned();
    }
    let mut grouped = String::with_capacity(number.len() + whole.len() / 3);
    grouped.push_str(sign);
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if let Some(fraction) = fraction {
        grouped.push('.');
        grouped.push_str(fraction);
    }
    grouped
}

/// The fields a collection names its records by when its schema does not
/// say, in the order they are tried.
const CONVENTIONAL_TITLE_FIELDS: [&str; 2] = ["name", "title"];

/// The top-level field a collection's schema says names its records:
/// `x-cr-ui.title`. A presentation hint like the others under `x-cr-ui`, so a
/// value that is not a field name is ignored rather than refused.
fn schema_title_field(schema: Option<&JsonValue>) -> Option<&str> {
    schema?
        .get("x-cr-ui")?
        .get("title")?
        .as_str()
        .filter(|field| !field.trim().is_empty())
}

/// What a record is called on screen: the field `x-cr-ui.title` names when
/// the schema names one, and otherwise a non-empty `name` or `title` field,
/// which is what nearly every collection names its records by. Only a
/// non-empty string counts. `None` sends the caller back to the record ID,
/// which is always there.
fn record_name<'a>(attributes: &'a Mapping, schema: Option<&JsonValue>) -> Option<&'a str> {
    let named = |key: &str| match attributes.get(YamlValue::String(key.to_owned())) {
        Some(YamlValue::String(name)) if !name.trim().is_empty() => Some(name.as_str()),
        _ => None,
    };
    match schema_title_field(schema) {
        Some(field) => named(field),
        None => CONVENTIONAL_TITLE_FIELDS.into_iter().find_map(named),
    }
}

/// The field a table's first column and a Kanban card's heading show for the
/// records of one collection, if it names them by one.
///
/// One field for the whole table rather than [`record_name`]'s choice per
/// record, because the column has one heading and sorts by one field. The
/// schema's `x-cr-ui.title` when it sets one, and otherwise the first
/// conventional field the schema declares or a record on the page has. A
/// record without a value for it is shown by its ID instead.
fn view_title_field<'a>(schema: Option<&'a JsonValue>, records: &[Record]) -> Option<&'a str> {
    schema_title_field(schema).or_else(|| {
        CONVENTIONAL_TITLE_FIELDS.into_iter().find(|field| {
            schema
                .and_then(|schema| schema.get("properties"))
                .is_some_and(|properties| properties.get(field).is_some())
                || records
                    .iter()
                    .any(|record| record_title(record, field).is_some())
        })
    })
}

/// `record`'s value for its collection's title field, when it is a non-empty
/// string.
fn record_title<'a>(record: &'a Record, field: &str) -> Option<&'a str> {
    match record.attributes.get(YamlValue::String(field.to_owned())) {
        Some(YamlValue::String(title)) if !title.trim().is_empty() => Some(title.as_str()),
        _ => None,
    }
}

fn schema_field_is_wide(kind: &SchemaFieldKind) -> bool {
    matches!(
        kind,
        SchemaFieldKind::MultiSelect(_) | SchemaFieldKind::Yaml
    )
}

/// The text a `<textarea>` should be given to show `text`.
///
/// The HTML parser drops one line feed straight after `<textarea>`, so a value
/// that starts with a blank line would lose it on every save unless a line feed
/// is there for the parser to drop.
fn textarea_text(text: &str) -> Cow<'_, str> {
    if text.starts_with('\n') || text.starts_with("\r\n") {
        Cow::Owned(format!("\n{text}"))
    } else {
        Cow::Borrowed(text)
    }
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

/// The most options a single choice offers as a row of buttons rather than a
/// dropdown, and the most characters their labels may add up to: past either,
/// the row stops fitting beside another field and a `<select>` reads better.
const CHOICE_ROW_MAX_OPTIONS: usize = 3;
const CHOICE_ROW_MAX_LABEL_CHARS: usize = 36;

/// A single choice's options as a row of buttons, each `(value, label,
/// chosen)`, or `None` when there are too many to sit in one row. A field that
/// may be left empty ends with "Not set"; a field of a record with no schema
/// does not, because the value it holds is what made it a choice.
fn choice_row(field: &SchemaFormField) -> Option<Vec<(String, String, bool)>> {
    let mut choices = match &field.kind {
        SchemaFieldKind::Select(options) if options.len() <= CHOICE_ROW_MAX_OPTIONS => options
            .iter()
            .map(|option| {
                (
                    serialize_yaml_value(option),
                    schema_value_label(option),
                    option_is_chosen(field, option),
                )
            })
            .collect::<Vec<_>>(),
        SchemaFieldKind::Boolean => [(true, "True"), (false, "False")]
            .into_iter()
            .map(|(value, label)| {
                (
                    value.to_string(),
                    label.to_owned(),
                    option_is_chosen(field, &YamlValue::Bool(value)),
                )
            })
            .collect(),
        _ => return None,
    };
    if !field.required && field.inferred.is_none() {
        choices.push((String::new(), "Not set".to_owned(), field_is_unset(field)));
    }
    let label_chars: usize = choices
        .iter()
        .map(|(_, label, _)| label.chars().count())
        .sum();
    (label_chars <= CHOICE_ROW_MAX_LABEL_CHARS).then_some(choices)
}

/// The address a text field holds when it is a web page worth opening from
/// the form. Only `http` and `https`: this becomes a link's `href`.
fn field_web_address(field: &SchemaFormField, text: &str) -> Option<String> {
    if !matches!(field.kind, SchemaFieldKind::String { .. }) {
        return None;
    }
    let text = text.trim();
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"))?;
    (!rest.is_empty() && !text.chars().any(char::is_whitespace)).then(|| text.to_owned())
}

fn render_schema_field(field: &SchemaFormField, diagnostics: &[String]) -> Markup {
    let name = format!("attribute.{}", field.key);
    let id = format!("field-{}", field.key);
    let label_id = format!("{id}-label");
    let help = field.description.as_ref().map(|_| format!("{id}-help"));
    let text = field_control_text(field);
    // A one-line `<input>` silently drops every line break in what it is
    // given, so a string that has one is edited in a box that keeps it.
    let multiline = matches!(&field.kind, SchemaFieldKind::String { input_type, .. } if *input_type == "text")
        && text.contains('\n');
    let choices = choice_row(field);
    // A group of buttons is named by its heading rather than by a `<label>`,
    // which can only name one control.
    let group = choices.is_some() || matches!(field.kind, SchemaFieldKind::MultiSelect(_));
    let web_address = field_web_address(field, &text);
    let wide = schema_field_is_wide(&field.kind) || multiline;
    let unset = field_is_unset(field);
    // Maud writes an attribute with a `[…]` value only when the option is
    // `Some`, so a field nothing was said about carries no `aria-invalid` at all
    // rather than carrying `aria-invalid="false"`.
    let invalid = (!diagnostics.is_empty()).then_some("true");
    let field_class = match (wide, diagnostics.is_empty()) {
        (false, true) => "cr-field",
        (true, true) => "cr-field cr-field-wide",
        (false, false) => "cr-field cr-field-invalid",
        (true, false) => "cr-field cr-field-wide cr-field-invalid",
    };
    let label = html! {
        (&field.label)
        @if field.required {
            span class="cr-required" aria-hidden="true" { "*" }
        }
    };
    let number = |step: &str, minimum: &Option<String>, maximum: &Option<String>| {
        html! {
            input id=(&id) type="number" step=(step) name=(&name) value=(&text) required[field.required] min=[minimum.as_deref()] max=[maximum.as_deref()] aria-invalid=[invalid] aria-describedby=[help.as_deref()] class="cr-input";
        }
    };
    html! {
        div class=(field_class) {
            @if let Some(kind) = field.inferred {
                input type="hidden" name=(format!("_field.{}", field.key)) value=(kind.token());
            }
            div class="cr-field-head" {
                @if group {
                    span id=(&label_id) class="cr-field-label" { (label) }
                } @else {
                    label for=(&id) class="cr-field-label" { (label) }
                }
                @if matches!(field.kind, SchemaFieldKind::Yaml) {
                    span class="cr-field-hint" { "YAML" }
                }
                @if let Some(address) = &web_address {
                    a href=(address) target="_blank" rel="noopener noreferrer" hx-boost=(UNBOOSTED) class="cr-field-hint cr-field-open" { "Open" span aria-hidden="true" { " ↗" } }
                }
            }
            (render_field_diagnostics(diagnostics))
            @if let Some(choices) = &choices {
                div id=(&id) role="radiogroup" aria-labelledby=(&label_id) aria-describedby=[help.as_deref()] aria-invalid=[invalid] class="cr-choice-row" {
                    @for (value, choice, chosen) in choices {
                        label class="cr-choice-option" {
                            input type="radio" name=(&name) value=(value) checked[*chosen] required[field.required];
                            span { (choice) }
                        }
                    }
                }
            } @else {
                @match &field.kind {
                    SchemaFieldKind::Select(options) => {
                        select id=(&id) name=(&name) required[field.required] aria-invalid=[invalid] aria-describedby=[help.as_deref()] class="cr-input" {
                            option value="" selected[unset] disabled[field.required] {
                                @if field.required { "Select a value…" } @else { "Not set" }
                            }
                            @for option in options {
                                option value=(serialize_yaml_value(option)) selected[option_is_chosen(field, option)] { (schema_value_label(option)) }
                            }
                        }
                    }
                    SchemaFieldKind::MultiSelect(options) => {
                        div id=(&id) role="group" aria-labelledby=(&label_id) aria-describedby=[help.as_deref()] class="cr-checkbox-row" {
                            @for option in options {
                                label class="cr-checkbox-option" {
                                    input type="checkbox" name=(&name) value=(serialize_yaml_value(option)) checked[option_is_chosen(field, option)] aria-invalid=[invalid];
                                    span { (schema_value_label(option)) }
                                }
                            }
                        }
                    }
                    SchemaFieldKind::String { min_length, max_length, .. } if multiline => {
                        textarea id=(&id) name=(&name) rows="4" required[field.required] minlength=[*min_length] maxlength=[*max_length] aria-invalid=[invalid] aria-describedby=[help.as_deref()] class="cr-input" { (textarea_text(&text)) }
                    }
                    SchemaFieldKind::String { input_type, min_length, max_length } => {
                        input id=(&id) type=(input_type) name=(&name) value=(&text) required[field.required] minlength=[*min_length] maxlength=[*max_length] aria-invalid=[invalid] autocomplete=(if *input_type == "email" { "email" } else { "off" }) aria-describedby=[help.as_deref()] placeholder=[(field.inferred == Some(InferredFieldKind::Empty)).then_some("Empty")] class="cr-input";
                    }
                    SchemaFieldKind::Integer { minimum, maximum } | SchemaFieldKind::Number { minimum, maximum } => {
                        @let step = if matches!(field.kind, SchemaFieldKind::Integer { .. }) { "1" } else { "any" };
                        @if let Some(unit) = &field.unit {
                            div class="cr-input-group" {
                                (number(step, minimum, maximum))
                                span class="cr-input-unit" aria-hidden="true" { (unit) }
                            }
                        } @else {
                            (number(step, minimum, maximum))
                        }
                    }
                    // Always a row of buttons, above.
                    SchemaFieldKind::Boolean => {}
                    SchemaFieldKind::Yaml => {
                        textarea id=(&id) name=(&name) rows="5" spellcheck="false" required[field.required] aria-invalid=[invalid] aria-describedby=[help.as_deref()] class="cr-input cr-input-code" { (field_yaml_text(field)) }
                    }
                }
            }
            @if let (Some(help), Some(description)) = (&help, &field.description) {
                p id=(help) class="cr-field-help" { (description) }
            }
        }
    }
}

/// An object as a group of controls, one per property its schema declares,
/// under the object's own label. What is said about the object as a whole, a
/// missing property for one, is shown under that label.
///
/// An optional object with nothing in it is folded to its label. A record can
/// declare a dozen objects and hold two, and a dozen boxes of empty controls
/// would bury the two. It opens when it holds something, when the schema
/// requires it, and when a refusal has something to say inside it.
fn render_object_field(field: &SchemaFormField, rejection: Option<&RecordFormRejection>) -> Markup {
    let id = format!("field-{}", field.key);
    let help = field.description.as_ref().map(|_| format!("{id}-help"));
    let diagnostics = form_diagnostics(rejection, &field.key);
    let holds_something = field.members.iter().any(|member| match &member.submitted {
        Some(values) => values.iter().any(|value| !value.is_empty()),
        None => member
            .value
            .as_ref()
            .is_some_and(|value| !is_empty_value(value)),
    });
    let open = field.required
        || holds_something
        || !diagnostics.is_empty()
        || field
            .members
            .iter()
            .any(|member| !form_diagnostics(rejection, &member.key).is_empty());
    html! {
        details id=(&id) open[open] aria-describedby=[help.as_deref()] class=(if diagnostics.is_empty() { "cr-field cr-field-wide cr-field-group" } else { "cr-field cr-field-wide cr-field-group cr-field-invalid" }) {
            summary class="cr-field-label" {
                (&field.label)
                @if field.required {
                    span class="cr-required" aria-hidden="true" { "*" }
                }
            }
            (render_field_diagnostics(diagnostics))
            @if let (Some(help), Some(description)) = (&help, &field.description) {
                p id=(help) class="cr-field-help" { (description) }
            }
            div class="cr-form-grid cr-field-group-grid" {
                @for member in &field.members {
                    (render_schema_field(member, form_diagnostics(rejection, &member.key)))
                }
            }
        }
    }
}

/// Whether a structured submission edited `key` as a group of controls rather
/// than as a YAML box: it sent a control for a property inside the object.
fn submitted_as_group(submitted: &HtmlDocumentForm, key: &str) -> bool {
    let prefix = format!("{key}.");
    submitted
        .fields
        .keys()
        .any(|field| field.starts_with(&prefix))
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
struct FormRejection<Form> {
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
    submitted: Form,
}

type RecordFormRejection = FormRejection<HtmlDocumentForm>;

type SaveViewRejection = FormRejection<HtmlSaveViewForm>;

/// The diagnostics about one control, or nothing when this is not a re-render.
fn form_diagnostics<'a, Form>(
    rejection: Option<&'a FormRejection<Form>>,
    control: &str,
) -> &'a [String] {
    rejection
        .and_then(|rejection| rejection.fields.get(control))
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// The alert a refused form opens with: what did not happen, the reason, and
/// the request ID the refusal was logged under, which is what somebody quotes
/// when they ask why.
fn rejected_form_alert(headline: &str, error: &PublicError, outcome: &str) -> Markup {
    html! {
        div role="alert" class="cr-form-alert rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" {
            p class="font-semibold" { (headline) }
            p class="mt-1 whitespace-pre-line" { (&error.message) }
            p class="mt-2 text-xs text-red-700" { (outcome) " Request ID " (&error.request_id) }
        }
    }
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
/// is therefore explicit: a violation about a field the structured or fields
/// form renders goes to that field's control; one about `profile.team` goes to
/// the `team` control when the form rendered `profile` as a group, and
/// otherwise to the `profile` control, keeping the full path in its text,
/// because that is the box the value was typed into; and anything the form
/// does not render a control for — an attribute the schema does not declare, or a schema-shaped name on a
/// form that has no schema — goes to whichever free-text box carries it, which is
/// the whole point of that box existing. A fields form has no such box, so there
/// it stays in the message at the top.
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
    // The fields the form rendered a control of their own for, and each
    // property of an object it rendered as a group.
    let rendered = match submitted.mode {
        DocumentFormMode::Structured => schema
            .and_then(|schema| record_form_fields(schema, &Mapping::new()))
            .unwrap_or_default()
            .into_iter()
            .flat_map(|field| {
                let members =
                    if !field.members.is_empty() && submitted_as_group(submitted, &field.key) {
                        field.members.into_iter().map(|member| member.key).collect()
                    } else {
                        Vec::new()
                    };
                std::iter::once(field.key).chain(members)
            })
            .collect::<BTreeSet<_>>(),
        DocumentFormMode::Fields => submitted
            .field_kinds
            .iter()
            .map(|(key, _)| key.clone())
            .collect(),
        DocumentFormMode::Yaml => BTreeSet::new(),
    };
    // Where anything the form renders no control for ends up. A fields form
    // has no such box, so that stays in the message at the top.
    let overflow = match submitted.mode {
        DocumentFormMode::Structured => Some(ADDITIONAL_ATTRIBUTES_CONTROL),
        DocumentFormMode::Yaml => Some(FRONT_MATTER_CONTROL),
        DocumentFormMode::Fields => None,
    };
    let control_for = |field: &str| -> Option<String> {
        let mut segments = field.splitn(3, '.');
        let root = segments.next().unwrap_or(field);
        if let Some(property) = segments.next() {
            let member = format!("{root}.{property}");
            if rendered.contains(&member) {
                return Some(member);
            }
        }
        if rendered.contains(root) {
            return Some(root.to_owned());
        }
        if matches!(
            root,
            ID_CONTROL | FRONT_MATTER_CONTROL | ADDITIONAL_ATTRIBUTES_CONTROL
        ) {
            return Some(root.to_owned());
        }
        overflow.map(str::to_owned)
    };

    let mut diagnostics: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for violation in violations {
        let Some(field) = &violation.field else {
            continue;
        };
        let Some(control) = control_for(field) else {
            continue;
        };
        let message = if control == *field {
            violation.message.clone()
        } else {
            // A nested path keeps naming itself, so a diagnostic on a YAML box
            // says which key inside it is meant.
            format!("{field}: {}", violation.message)
        };
        diagnostics.entry(control).or_default().push(message);
    }
    if let Some(control) = error_field.and_then(control_for) {
        diagnostics
            .entry(control)
            .or_default()
            .push(error.message.clone());
    }
    diagnostics
}

/// The field `cr link` writes relations into.
const RELATIONS_FIELD: &str = "relations";

/// The most records the link form suggests. The suggestions are a `<datalist>`
/// the browser filters as the reader types, so a few hundred cost nothing; past
/// that the list is cut, and any record can still be linked by typing its
/// `collection/id`.
const RELATION_SUGGESTION_LIMIT: usize = 500;

/// One end of a relation, as the record page lists it.
struct RelatedRecord {
    relation: String,
    collection: String,
    id: String,
    /// What the other record is called, when this perspective may read it.
    /// `None` for a record that is missing or hidden, which is then shown only
    /// by the `collection/id` the relation states — no more than the record
    /// being viewed already says about it.
    name: Option<String>,
    /// Its page, when it has one; the `users` collection, for one, has none.
    url: Option<String>,
    /// The other record's collection as the sidebar names it.
    collection_title: String,
}

/// What the record page's relations panel shows.
struct RecordRelations {
    /// The relations this record holds, in the order it stores them.
    outgoing: Vec<RelatedRecord>,
    /// The relations readable records hold to this one, in collection, then
    /// ID order.
    incoming: Vec<RelatedRecord>,
    /// Relation names already in use, suggested by the link form.
    relation_names: Vec<String>,
    /// Readable records the link form suggests, as `collection/id` and a
    /// description of the record.
    targets: Vec<(String, String)>,
}

/// Read what `record` links to and what links to it.
///
/// One pass over every record this perspective can read answers all of it:
/// the names of the records it links to, the records that link to it, and the
/// suggestions for a new link. It is the scan `cr backlinks` makes — there is
/// no relation index — so a record page reads the database once, the cost
/// `TODO.md` already records for listing pages. A collection that cannot be
/// listed or decrypted contributes nothing rather than failing the page: the
/// panel shows what can be read.
fn record_relations(
    database: &Database,
    record: &Record,
    views: &[ViewDefinition],
) -> RecordRelations {
    let mut readable = Vec::new();
    let mut titles = BTreeMap::new();
    let mut schemas = BTreeMap::new();
    let mut audited_states = None;
    for model in database.collection_models().unwrap_or_default() {
        titles.insert(
            model.name.clone(),
            CollectionPresentation::from_schema(model.schema.as_ref()).title(&model.name),
        );
        schemas.insert(model.name.clone(), model.schema.clone());
        if let Ok(records) = database.list_with_audited_cache(&model.name, &[], &mut audited_states)
        {
            readable.extend(records);
        }
    }
    let index: BTreeMap<(&str, &str), &Record> = readable
        .iter()
        .map(|other| ((other.collection.as_str(), other.id.as_str()), other))
        .collect();
    let title = |collection: &str| {
        titles
            .get(collection)
            .cloned()
            .unwrap_or_else(|| humanize_field_name(collection))
    };
    let schema = |collection: &str| schemas.get(collection).and_then(Option::as_ref);
    let describe = |relation: &str, collection: &str, id: &str| {
        let found = index.get(&(collection, id));
        RelatedRecord {
            relation: relation.to_owned(),
            collection: collection.to_owned(),
            id: id.to_owned(),
            name: found.map(|other| {
                record_name(&other.attributes, schema(collection))
                    .unwrap_or(&other.id)
                    .to_owned()
            }),
            url: found.and_then(|_| record_page_url(views, collection, id)),
            collection_title: title(collection),
        }
    };

    let own = relation_references(&record.attributes);
    let outgoing = own
        .iter()
        .map(|(relation, collection, id)| describe(relation, collection, id))
        .collect();
    let mut relation_names: BTreeSet<String> =
        own.into_iter().map(|(relation, _, _)| relation).collect();
    let mut incoming = Vec::new();
    for source in &readable {
        for (relation, collection, id) in relation_references(&source.attributes) {
            if collection == record.collection && id == record.id {
                incoming.push(describe(&relation, &source.collection, &source.id));
            }
            relation_names.insert(relation);
        }
    }
    let targets = readable
        .iter()
        .filter(|other| !(other.collection == record.collection && other.id == record.id))
        .take(RELATION_SUGGESTION_LIMIT)
        .map(|other| {
            (
                format!("{}/{}", other.collection, other.id),
                format!(
                    "{} · {}",
                    record_name(&other.attributes, schema(&other.collection)).unwrap_or(&other.id),
                    title(&other.collection)
                ),
            )
        })
        .collect();
    RecordRelations {
        outgoing,
        incoming,
        relation_names: relation_names.into_iter().collect(),
        targets,
    }
}

/// The page a record of `collection` is shown on.
///
/// Its collection's own view when there is one — the automatic view, or a
/// saved view that has taken the collection's name — and otherwise any view of
/// the collection. `None` for a collection no view shows, `users` among them.
fn record_page_url(views: &[ViewDefinition], collection: &str, id: &str) -> Option<String> {
    let view = views
        .iter()
        .find(|view| view.name == collection && view.collection == collection)
        .or_else(|| views.iter().find(|view| view.collection == collection))?;
    Some(format!(
        "/{}/records/{}",
        encode_segment(&view.name),
        encode_segment(id)
    ))
}

/// The record page's relations panel: what this record links to, what links
/// to it, and a form to add a link.
///
/// Linking and unlinking are their own small forms rather than part of the
/// record form, because they are their own audited operations — the same
/// `link` and `unlink` the CLI and the API perform, each recorded as such —
/// and because a reference can carry more than the form could show, which
/// `unlink` preserves and a rewritten `relations` field would not. Each carries
/// the record's version, so a link made against a stale page is refused rather
/// than applied to a record the reader has not seen. They post natively for the
/// reason `UNBOOSTED` gives the Kanban move form: a refusal is a rendered error
/// page, which htmx would not swap in.
fn render_record_relations(
    view: &ViewDefinition,
    record: &Record,
    relations: &RecordRelations,
    permissions: RecordPermissions,
    csrf_token: &str,
) -> Markup {
    let base = format!(
        "/{}/records/{}",
        encode_segment(&view.name),
        encode_segment(&record.id)
    );
    let link_url = format!("{base}/relations");
    let unlink_url = format!("{base}/relations/remove");
    let other_end = |related: &RelatedRecord| {
        // A user is a person, and shown as one: avatar and name.
        let is_user = related.collection == USERS_COLLECTION;
        let label = |name: &str| {
            html! {
                @if is_user { (user_chip(name, &related.id, Some(&related.id))) } @else { (name) }
            }
        };
        html! {
            @match (&related.name, &related.url) {
                (Some(name), Some(url)) => a href=(url) class="cr-relation-target" { (label(name)) },
                (Some(name), None) => span class="cr-relation-target" { (label(name)) },
                // Only the ID the relation states, since this perspective may
                // not read the user's name; still marked as a person.
                (None, _) if is_user => span class="cr-relation-missing" title="Missing, or not visible to this perspective" { (user_chip(&related.id, &related.id, None)) },
                (None, _) => span class="cr-relation-missing" title="Missing, or not visible to this perspective" { (&related.collection) "/" (&related.id) },
            }
        }
    };
    html! {
        section id="relations" class="cr-relations" aria-labelledby="relations-heading" {
            h2 id="relations-heading" class="cr-aside-heading" { "Relations" }
            @if relations.outgoing.is_empty() && relations.incoming.is_empty() {
                p class="mt-1 text-xs text-gray-500" { "No linked records yet." }
            }
            @if !relations.outgoing.is_empty() {
                h3 class="cr-relations-label" { "Links to" }
                ul class="cr-relations-list" {
                    @for related in &relations.outgoing {
                        li class="cr-relation" {
                            div class="min-w-0" {
                                span class="cr-relation-kind" { (humanize_field_name(&related.relation)) }
                                (other_end(related))
                                span class="cr-relation-meta" { (&related.collection_title) }
                            }
                            @if permissions.update {
                                form method="post" action=(&unlink_url) hx-boost=(UNBOOSTED) {
                                    input type="hidden" name="_csrf" value=(csrf_token);
                                    input type="hidden" name="_expected_record_hash" value=(&record.version);
                                    input type="hidden" name="relation" value=(&related.relation);
                                    input type="hidden" name="target" value=(format!("{}/{}", related.collection, related.id));
                                    button type="submit" class="cr-relation-remove"
                                        aria-label=(format!("Remove the {} link to {}", humanize_field_name(&related.relation), related.name.as_deref().unwrap_or(&related.id))) {
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            @if !relations.incoming.is_empty() {
                h3 class="cr-relations-label" { "Linked from" }
                ul class="cr-relations-list" {
                    @for related in &relations.incoming {
                        li class="cr-relation" {
                            div class="min-w-0" {
                                (other_end(related))
                                span class="cr-relation-meta" {
                                    (&related.collection_title) " · " (humanize_field_name(&related.relation))
                                }
                            }
                        }
                    }
                }
            }
            @if permissions.update {
                details class="cr-relation-add" {
                summary { "+ Link a record" }
                form method="post" action=(&link_url) hx-boost=(UNBOOSTED) class="cr-relation-form" {
                    input type="hidden" name="_csrf" value=(csrf_token);
                    input type="hidden" name="_expected_record_hash" value=(&record.version);
                    label class="block" {
                        span class="cr-relations-label" { "Relation" }
                        input name="relation" list="cr-relation-names" required autocomplete="off" placeholder="company"
                            class="w-full rounded-lg border border-gray-300 px-2.5 py-1.5 text-sm";
                    }
                    label class="block" {
                        span class="cr-relations-label" { "Record" }
                        input name="target" list="cr-relation-targets" required autocomplete="off" placeholder="companies/acme"
                            // `/` escaped inside the classes, as on the record
                            // ID field: browsers compile `pattern` in
                            // Unicode-sets mode, where a bare one is an error.
                            pattern="[^\\/]+/[^\\/]+" title="collection/id, for example companies/acme"
                            class="w-full rounded-lg border border-gray-300 px-2.5 py-1.5 font-mono text-sm";
                    }
                    button type="submit" class="cr-button" { "Link record" }
                    datalist id="cr-relation-names" {
                        @for name in &relations.relation_names {
                            option value=(name) {}
                        }
                    }
                    datalist id="cr-relation-targets" {
                        @for (target, description) in &relations.targets {
                            option value=(target) { (description) }
                        }
                    }
                }
                }
            }
        }
    }
}

/// The form for a record whose collection declares no properties: one control
/// per field it has, in the order it has them, each typed by its value. `None`
/// for a record with no fields, or with a key no form control can be named by,
/// which leaves the YAML editor as the way to edit it.
fn inferred_form_fields(attributes: &Mapping) -> Option<Vec<SchemaFormField>> {
    if attributes.is_empty() {
        return None;
    }
    attributes
        .iter()
        .map(|(key, value)| {
            let YamlValue::String(key) = key else {
                return None;
            };
            if key.is_empty() {
                return None;
            }
            let kind = InferredFieldKind::of(value);
            Some(SchemaFormField {
                key: key.clone(),
                label: inferred_field_label(key),
                description: None,
                required: false,
                value: Some(value.clone()),
                submitted: None,
                kind: kind.control(value.as_str()),
                inferred: Some(kind),
                unit: None,
                members: Vec::new(),
            })
        })
        .collect()
}

/// The fields a refused `Fields` form listed, holding what was typed into them.
fn submitted_inferred_fields(submitted: &HtmlDocumentForm) -> Vec<SchemaFormField> {
    submitted
        .field_kinds
        .iter()
        .map(|(key, kind)| {
            let values = submitted.fields.get(key).cloned().unwrap_or_default();
            SchemaFormField {
                key: key.clone(),
                label: inferred_field_label(key),
                description: None,
                required: false,
                value: None,
                kind: kind.control(values.first().map(String::as_str)),
                submitted: Some(values),
                inferred: Some(*kind),
                unit: None,
                members: Vec::new(),
            }
        })
        .collect()
}

/// A key made readable, or the key itself when it is nothing but separators.
fn inferred_field_label(key: &str) -> String {
    let label = humanize_field_name(key);
    if label.is_empty() {
        key.to_owned()
    } else {
        label
    }
}

/// Which editor a record page asks for in its URL.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum RecordEditor {
    /// The whole front matter as one YAML mapping, whatever the collection's
    /// schema would otherwise give the form.
    Yaml,
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
    relations: Option<&RecordRelations>,
    notice: Option<&str>,
    editor: Option<RecordEditor>,
) -> Markup {
    let editing = record.is_some();
    let submitted = rejection.map(|rejection| &rejection.submitted);
    // A record is called by its name, with the ID beside it as the stable
    // identifier it is, rather than by the ID alone: "Acme annual renewal", not
    // "Edit acme-renewal". Whether the page can edit is said by the form
    // itself, so the title carries no verb for it.
    let name = record.map(|record| record_name(&record.attributes, schema).unwrap_or(&record.id));
    let title = name
        .map(str::to_owned)
        .unwrap_or_else(|| format!("New {} record", view.collection));
    let shown_id = record
        .filter(|record| name != Some(record.id.as_str()))
        .map(|record| record.id.as_str());
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
    let schema_fields = schema.and_then(|schema| record_form_fields(schema, attributes));
    let inferred_fields = if schema_fields.is_none() {
        inferred_form_fields(attributes)
    } else {
        None
    };
    // The editor the form offers when nothing asks for another: the schema's
    // fields when it declares any, and otherwise the fields the record has.
    // YAML is the fallback for a record neither can describe.
    let fields_mode = if schema_fields.is_some() {
        Some(DocumentFormMode::Structured)
    } else if inferred_fields.is_some() {
        Some(DocumentFormMode::Fields)
    } else {
        None
    };
    // A refused submission comes back in the editor it was typed into.
    let mode = match submitted.map(|submitted| submitted.mode) {
        Some(DocumentFormMode::Structured) if schema_fields.is_none() => DocumentFormMode::Yaml,
        Some(mode) => mode,
        None if editor == Some(RecordEditor::Yaml) => DocumentFormMode::Yaml,
        None => fields_mode.unwrap_or(DocumentFormMode::Yaml),
    };
    // Every value below is the submitted text when there is one, and the stored
    // record's otherwise. The two are overlaid here rather than inside each
    // control so that "show what was typed" is one decision per field group
    // instead of a judgement call repeated a dozen times in the markup — and so
    // that the text is the submitted string throughout: re-serializing what the
    // server parsed would answer a rejected `1.50` with `1.5` and a rejected
    // YAML mapping with its keys reordered.
    let form_fields = match mode {
        DocumentFormMode::Structured => {
            let mut fields = schema_fields.unwrap_or_default();
            if let Some(submitted) =
                submitted.filter(|submitted| submitted.mode == DocumentFormMode::Structured)
            {
                // What each object's group is when nothing is stored in it.
                let groups = schema
                    .and_then(|schema| record_form_fields(schema, &Mapping::new()))
                    .unwrap_or_default();
                for field in &mut fields {
                    // An object comes back the way it was submitted: as the
                    // group of controls or as the YAML box, whichever the
                    // browser sent, even if the record has changed since.
                    if submitted.fields.contains_key(&field.key) {
                        field.members.clear();
                    } else if field.members.is_empty()
                        && submitted_as_group(submitted, &field.key)
                        && let Some(group) = groups.iter().find(|group| group.key == field.key)
                    {
                        field.members = group.members.clone();
                    }
                    for member in &mut field.members {
                        member.submitted = Some(
                            submitted
                                .fields
                                .get(&member.key)
                                .cloned()
                                .unwrap_or_default(),
                        );
                    }
                    field.submitted = Some(
                        submitted
                            .fields
                            .get(&field.key)
                            .cloned()
                            .unwrap_or_default(),
                    );
                }
            }
            fields
        }
        DocumentFormMode::Fields => match submitted {
            Some(submitted) => submitted_inferred_fields(submitted),
            None => inferred_fields.unwrap_or_default(),
        },
        DocumentFormMode::Yaml => Vec::new(),
    };
    let front_matter = submitted
        .and_then(|submitted| submitted.front_matter.clone())
        .unwrap_or_else(|| yaml_serde::to_string(attributes).unwrap_or_else(|_| "{}\n".to_owned()));
    let additional = schema
        .map(|schema| additional_attributes(attributes, schema))
        .unwrap_or_default();
    let additional_yaml = submitted
        .filter(|submitted| submitted.mode == DocumentFormMode::Structured)
        .map(|submitted| submitted.additional_attributes.clone())
        .unwrap_or_else(|| {
            yaml_serde::to_string(&additional).unwrap_or_else(|_| "{}\n".to_owned())
        });
    let additional_diagnostics = form_diagnostics(rejection, ADDITIONAL_ATTRIBUTES_CONTROL);
    let allows_additional = schema.is_some_and(schema_allows_additional_attributes);
    let has_additional = !additional_yaml.trim().is_empty() && additional_yaml.trim() != "{}";
    // A collapsed disclosure would hide a diagnostic about what is inside it, and
    // hide the YAML the reader is being asked to correct.
    let additional_open = has_additional || !additional_diagnostics.is_empty();
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
    // The other editor, on a record page where there is one to switch to. A
    // new record has no page to switch on, and its form is the one the
    // collection gives it.
    let editor_switch = match (editing, mode, fields_mode) {
        (true, DocumentFormMode::Yaml, Some(_)) => Some((action.clone(), "Edit as form")),
        (true, DocumentFormMode::Structured | DocumentFormMode::Fields, _) => {
            Some((format!("{action}?editor=yaml"), "Edit as YAML"))
        }
        _ => None,
    };
    let front_matter_diagnostics = form_diagnostics(rejection, FRONT_MATTER_CONTROL);
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
            hx-target="this" hx-swap="outerHTML" hx-disabled-elt="find button[type=submit]" {
            input type="hidden" name="_csrf" value=(csrf_token);
            @if let Some(version) = &expected_version {
                input type="hidden" name="_expected_record_hash" value=(version);
            }
            @match mode {
                DocumentFormMode::Structured => {
                    input type="hidden" name="_form_mode" value="structured";
                }
                DocumentFormMode::Fields => {
                    input type="hidden" name="_form_mode" value="fields";
                }
                DocumentFormMode::Yaml => {}
            }
            @if let Some(rejection) = rejection {
                (rejected_form_alert(
                    rejected_form_headline(editing),
                    &rejection.error,
                    "Nothing was written and no audit event was recorded. The values below are exactly what you submitted.",
                ))
            }
            fieldset disabled[!permissions.update] class="contents" {
            div class="cr-form-section" {
                div class="cr-form-grid" {
                    @if !editing {
                        div class=(if form_diagnostics(rejection, ID_CONTROL).is_empty() { "cr-field cr-field-wide" } else { "cr-field cr-field-wide cr-field-invalid" }) {
                            div class="cr-field-head" {
                                label for="record-id" class="cr-field-label" { "Record ID" span class="cr-required" aria-hidden="true" { "*" } }
                            }
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
                            input id="record-id" type="text" name="id" value=(record_id) required pattern="[^\\/\\\\]+" placeholder="acme-renewal" aria-describedby="record-id-help" aria-invalid=[(!form_diagnostics(rejection, ID_CONTROL).is_empty()).then_some("true")] class="cr-input cr-input-code";
                            p id="record-id-help" class="cr-field-help" { "Used in the record’s URL and filename. It cannot be changed later." }
                        }
                    }
                    @for field in &form_fields {
                        // Relations are edited in the relations panel beside
                        // the form, one audited link at a time, so the form
                        // carries the stored value through unchanged rather
                        // than offering it as YAML to retype. The record's
                        // version is what keeps that safe: a link made after
                        // this page was rendered changes it, and the save is
                        // refused instead of writing the old relations back.
                        // A value the panel could not have produced — not a
                        // mapping — or one the save was refused over stays an
                        // editable field.
                        @if relations.is_some()
                            && field.key == RELATIONS_FIELD
                            && matches!(field.kind, SchemaFieldKind::Yaml)
                            && matches!(field.value, None | Some(YamlValue::Mapping(_)))
                            && form_diagnostics(rejection, &field.key).is_empty()
                        {
                            @if let Some(kind) = field.inferred {
                                input type="hidden" name=(format!("_field.{}", field.key)) value=(kind.token());
                            }
                            input type="hidden" name=(format!("attribute.{}", field.key)) value=(field_yaml_text(field));
                        } @else if !field.members.is_empty() {
                            (render_object_field(field, rejection))
                        } @else {
                            (render_schema_field(field, form_diagnostics(rejection, &field.key)))
                        }
                    }
                    @if mode == DocumentFormMode::Yaml {
                        div class=(if front_matter_diagnostics.is_empty() { "cr-field cr-field-wide" } else { "cr-field cr-field-wide cr-field-invalid" }) {
                            div class="cr-field-head" {
                                label for="front-matter" class="cr-field-label" { "Fields" }
                                span class="cr-field-hint" { "YAML" }
                            }
                            (render_field_diagnostics(front_matter_diagnostics))
                            textarea id="front-matter" name="front_matter" rows="12" spellcheck="false" aria-invalid=[(!front_matter_diagnostics.is_empty()).then_some("true")] class="cr-input cr-input-code cr-input-tall" { (front_matter) }
                        }
                    }
                }
                // Front matter the schema does not declare. A record page
                // only shows the box when there is some, because "Edit as
                // YAML" is the way to add it there; a new record has no such
                // switch.
                @if mode == DocumentFormMode::Structured && allows_additional && (!editing || additional_open) {
                    details class="cr-form-more" open[additional_open] {
                        summary {
                            "Other fields"
                            @if has_additional { " (" (additional.len()) ")" }
                        }
                        div class="cr-field" {
                            p class="cr-field-help" { "Front matter this collection’s schema does not declare, as YAML. It cannot override the fields above." }
                            (render_field_diagnostics(additional_diagnostics))
                            textarea name="_additional_attributes" rows="5" spellcheck="false" aria-label="Other fields" aria-invalid=[(!additional_diagnostics.is_empty()).then_some("true")] class="cr-input cr-input-code" { (additional_yaml) }
                        }
                    }
                }
            }
            div class="cr-form-section" {
                div class="cr-field" {
                    div class="cr-field-head" {
                        label for="record-markdown" class="cr-field-label" { "Notes" }
                        span class="cr-field-hint" { "Markdown" }
                    }
                    textarea id="record-markdown" name="markdown" rows="10" class="cr-input cr-input-tall" { (textarea_text(markdown)) }
                }
            }
            }
            div class="cr-form-footer" {
                @if let Some((href, label)) = &editor_switch {
                    a href=(href) class="cr-form-link" { (label) }
                }
                div class="cr-form-actions" {
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
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    (back.clone(), Some(view_icon(view)), &view.title),
                ],
                None,
                &title,
                html! {
                    @if let Some(id) = shown_id {
                        span class="cr-page-meta font-mono" { (id) }
                    }
                },
                html! {
                    @if let Some(record) = record {
                        a href="#audit-history" class="cr-button cr-activity-jump" {
                            "Activity" span aria-hidden="true" { "↓" }
                        }
                        // A link to the confirmation page, not a form that
                        // deletes. See `delete_confirmation_url` for why the
                        // confirmation is a page rather than a dialog; the
                        // consequence here is that this element cannot write
                        // anything, so it needs no CSRF token, no version,
                        // and no handler to guard it.
                        @if permissions.delete {
                            a href=(delete_confirmation_url(view, record)) class="cr-button cr-button-danger" { "Delete record…" }
                        }
                    }
                },
            ))
            // The outcome of a link or unlink, which redirects back here. See
            // the same banner on view pages for how it reaches a screen reader.
            @if let Some(notice) = notice {
                div data-notice="true" class="mx-auto mb-5 max-w-7xl rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800" { (notice) }
            }
            div class="mx-auto max-w-7xl" {
                @if editing && !permissions.update {
                    p class="cr-page-note" { "This perspective has read-only access to the record." }
                }
                div class=(if editing { "cr-record-layout" } else { "max-w-3xl" }) {
                div class="cr-record-primary min-w-0" {
                (form_region)
                }
                @if let Some(record) = record {
                    aside id="audit-history" class="cr-record-activity scroll-mt-20" {
                        @if let Some(relations) = relations {
                            (render_record_relations(view, record, relations, permissions, csrf_token))
                        }
                        @if !record.files.is_empty() {
                            (render_record_files(record))
                        }
                        section aria-labelledby="activity-heading" {
                            div class="flex items-baseline justify-between gap-2" {
                                h2 id="activity-heading" class="cr-aside-heading" { "Activity" }
                                a href=(audit_filter_url(&view.collection, &record.id)) class="cr-aside-link" { "All activity" span aria-hidden="true" { " →" } }
                            }
                            (render_record_activity(audit_entries))
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

/// A bundle record's supporting files, each a download of its exact bytes.
///
/// The form edits the entry alone and a save keeps every file as it is, so
/// the page lists them rather than offering an editor that could not round-trip
/// a font or an image.
fn render_record_files(record: &Record) -> Markup {
    let base = format!(
        "/api/v1/collections/{}/records/{}/files",
        encode_segment(&record.collection),
        encode_segment(&record.id)
    );
    html! {
        section id="files" class="cr-relations" aria-labelledby="files-heading" {
            h2 id="files-heading" class="cr-aside-heading" { "Files" }
            ul class="cr-relations-list" {
                @for file in &record.files {
                    @let segments = file.path.split('/').map(encode_segment).collect::<Vec<_>>();
                    li class="cr-relation" {
                        a href=(format!("{base}/{}", segments.join("/"))) class="cr-relation-target font-mono" download { (file.path) }
                    }
                }
            }
        }
    }
}

/// A record's recent history as its page shows it beside the form: what
/// happened, who did it, when, and which fields it touched, with the change
/// itself one click away. Everything else an event records — its hash, the
/// agent's session and delegation chain, the authorization, the intent — is
/// on the audit log, which "All activity" opens filtered to this record.
fn render_record_activity(entries: &[AuditEntry]) -> Markup {
    html! {
        @if entries.is_empty() {
            p class="cr-activity-empty" { "No recorded changes yet." }
        } @else {
            ol class="cr-activity" {
                @for entry in entries {
                    @let payload = &entry.payload;
                    @let fields = audit_changed_fields(&payload.changes);
                    li id=(format!("event-{}", payload.sequence)) class="cr-activity-item scroll-mt-20" {
                        p class="cr-activity-title" {
                            (audit_action_label(&payload.action))
                            @if !fields.is_empty() && payload.action != AuditAction::Create {
                                " "
                                span class="cr-activity-fields" { (fields.join(", ")) }
                            }
                        }
                        p class="cr-activity-meta" {
                            (actor_chip(&payload.actor))
                            @if let Some(operator) = payload
                                .access
                                .as_ref()
                                .and_then(|access| access.impersonated_by.as_ref())
                            {
                                " · impersonated by " (actor_chip(&operator.display))
                            }
                            @if let Some(authentication) = payload
                                .access
                                .as_ref()
                                .and_then(|access| access.authentication.as_ref())
                            {
                                " · " (authentication_label(authentication))
                            }
                            @if let Some(agent) = &payload.agent {
                                " · via " a href=(audit_agent_url(&agent.id)) class="hover:text-blue-700" { (&agent.id) }
                            }
                            " · " (render_timestamp(Some(&payload.timestamp)))
                        }
                        @if let Some(message) = &payload.message {
                            p class="cr-activity-message" { (message) }
                        }
                        @if !payload.changes.is_empty() {
                            details class="cr-activity-changes" {
                                summary { "Show changes" }
                                (render_audit_changes(&payload.changes, true))
                            }
                        }
                    }
                }
            }
        }
    }
}

/// What an audit action is called in a record's activity.
fn audit_action_label(action: &AuditAction) -> &'static str {
    match action {
        AuditAction::Baseline => "Recorded",
        AuditAction::Create => "Created",
        AuditAction::Update => "Updated",
        AuditAction::Link => "Linked",
        AuditAction::Delete => "Deleted",
    }
}

/// The fields an event changed, named as the record names them: the first
/// segment under `/attributes`, and "notes" for the Markdown body. At most
/// three, then how many more, so a sweeping change stays one line.
fn audit_changed_fields(changes: &[AuditChange]) -> Vec<String> {
    let mut fields: Vec<String> = Vec::new();
    for change in changes {
        let path = change.path();
        let field = match path.strip_prefix("/attributes/") {
            Some(rest) => rest
                .split('/')
                .next()
                .unwrap_or(rest)
                .replace("~1", "/")
                .replace("~0", "~"),
            None if path == "/body" => "notes".to_owned(),
            None if path.is_empty() => continue,
            None => path.trim_start_matches('/').to_owned(),
        };
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    if fields.len() > 3 {
        let more = fields.len() - 3;
        fields.truncate(3);
        fields.push(format!("+{more} more"));
    }
    fields
}

/// `Jane Doe <jane@example.com>` as `Jane Doe`: the name a reader knows them
/// by, with the full identity left in the tooltip. An identity with no name in
/// front of its address is shown whole.
fn identity_name(identity: &str) -> &str {
    match identity.split_once('<') {
        Some((name, _)) if !name.trim().is_empty() => name.trim(),
        _ => identity,
    }
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
    schema: Option<&JsonValue>,
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
    let name = record_name(&record.attributes, schema).unwrap_or(&record.id);
    page_or_content(
        representation,
        &format!("Delete {name}"),
        &back,
        navigation,
        html! {
            (page_bar(
                &[
                    ("/".to_owned(), None, "Views"),
                    (back.clone(), Some(view_icon(view)), &view.title),
                    (record_url.clone(), None, name),
                ],
                None,
                "Delete",
                html! {},
                html! {},
            ))
            div class="mx-auto max-w-2xl" {
                div class="cr-record-danger rounded-xl border border-red-200 bg-red-50 p-6" {
                    h2 class="text-lg font-semibold text-red-900" { "Delete this record?" }
                    p class="mt-2 text-sm text-red-800" {
                        "You are about to delete "
                        @if name != record.id {
                            strong { (name) } " ("
                            code class="cr-filter-tag" { (&record.id) }
                            ")"
                        } @else {
                            code class="cr-filter-tag" { (&record.id) }
                        }
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

fn perspective_control(ui: &UiContext, csrf_token: &str, id: &str) -> Markup {
    html! {
        form method="post" action="/perspective" hx-boost=(UNBOOSTED) class="cr-perspective" {
            input type="hidden" name="_csrf" value=(csrf_token);
            label for=(id) class="cr-perspective-label" { "Viewing as" }
            // Choosing a user changes nothing until the button is pressed. The
            // select used to submit itself from an inline `onchange`, so
            // arrowing through the options with a keyboard switched perspective,
            // and reloaded the page, at every option it passed: a change of
            // context on input, which WCAG 3.2.2 rules out. It was also the last
            // inline handler, which the content security policy refuses. The
            // button used to be inside `<noscript>`; it is now how everyone
            // switches, with or without JavaScript.
            div class="cr-perspective-choice" {
                select id=(id) name="principal" aria-label="View as user" {
                    @for user in &ui.users {
                        option value=(&user.id) selected[user.id == ui.selected] {
                            (&user.name) " — " (&user.role)
                            @if user.status == UserStatus::Disabled { " (disabled)" }
                        }
                    }
                }
                button type="submit" class="cr-button" { "Switch" }
            }
        }
    }
}

/// Who is signed in, at the foot of the sidebar: an avatar, the name, the
/// address, the role and how they signed in, and a way to sign out where there
/// is one.
fn account_card(account: &UiAccount) -> Markup {
    html! {
        div class="cr-account" role="group" aria-label="Signed in" {
            span class=(format!("cr-account-avatar {}", avatar_class(&account.principal))) aria-hidden="true" {
                (initials(&account.name, &account.address))
            }
            p class="cr-account-name" title=(&account.name) { (&account.name) }
            @if let Some(sign_out) = account.sign_out {
                // Unboosted: Cloudflare answers it, and then sends the browser
                // to its own sign-in page.
                a href=(sign_out) hx-boost=(UNBOOSTED) class="cr-account-sign-out" { "Sign out" }
            }
            p class="cr-account-address" title=(&account.address) { (&account.address) }
            p class="cr-account-meta" title=(format!("{} · signed in with {}", account.role, account.method)) {
                (&account.role) " · via " (&account.method_short)
            }
        }
    }
}

/// The narrow header has no foot to put the card in, so the avatar opens it.
/// A `<details>` needs no script, and a keyboard or a screen reader operates
/// it as it would any disclosure.
fn account_menu(account: &UiAccount) -> Markup {
    html! {
        details class="cr-account-menu" {
            summary class=(format!("cr-account-avatar {}", avatar_class(&account.principal))) aria-label=(format!("Signed in as {}", account.name)) title=(format!("{} · {}", account.name, account.address)) {
                (initials(&account.name, &account.address))
            }
            div class="cr-account-popover" {
                (account_card(account))
            }
        }
    }
}

/// Whether `current_path` is somewhere the sidebar reaches only through **All
/// views**: the index itself, or a collection's automatic view and the records
/// opened from it. Collections are listed on the index rather than in the
/// sidebar, so on their pages it is **All views** that shows where the reader
/// is, as the breadcrumb does.
fn under_all_views(current_path: &str, views: &[ViewDefinition]) -> bool {
    current_path == "/"
        || views
            .iter()
            .any(|view| !view.saved && format!("/{}", encode_segment(&view.name)) == current_path)
}

/// The sidebar lists saved views and not collections.
///
/// It used to list every collection under the saved views, which repeated the
/// **All views** index beside it and grew with every collection an agent made,
/// until the views someone had chosen to keep were a few entries lost among
/// dozens they had not. Now the sidebar holds what the reader chose: saving a
/// view is how a collection, or a filtered, sorted, or Kanban way of reading
/// one, gets a place in it. Every collection is still one click away on the
/// index.
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
                a href="/" class=(if under_all_views(current_path, views) { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[(current_path == "/").then_some("page")] {
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
                } @else if ui.is_none_or(|ui| ui.can_save_views) {
                    p class="cr-sidebar-label" { "Saved views" }
                    p class="cr-sidebar-hint" { "Use " strong { "Save as view" } " on any collection to keep it here." }
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
                @if let Some(ui) = ui.filter(|ui| ui.can_switch_perspective) {
                    (perspective_control(ui, csrf_token, "cr-perspective-sidebar"))
                }
                @if let Some(account) = ui.and_then(|ui| ui.account.as_ref()) {
                    (account_card(account))
                } @else {
                    div class="cr-sidebar-meta" {
                        span { "Markdown database" }
                        code { "cr serve" }
                    }
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
        a href="/browse" class=(if all_files { "cr-sidebar-link is-active" } else { "cr-sidebar-link" }) aria-current=[all_files.then_some("page")] title="Every file visible to the server · owner only" {
            span class="cr-nav-glyph" aria-hidden="true" { (ALL_FILES_ICON) }
            span class="truncate" { "All files" }
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
                @if let Some(ui) = ui.filter(|ui| ui.can_switch_perspective) {
                    (perspective_control(ui, csrf_token, "cr-perspective-mobile"))
                } @else {
                    div class="cr-mobile-utilities" {
                        a href="/audit" class="cr-nav-link" { "Audit" }
                        a href="/openapi.json" hx-boost=(UNBOOSTED) class="cr-nav-link" { "API" }
                        @if let Some(account) = ui.and_then(|ui| ui.account.as_ref()) {
                            (account_menu(account))
                        }
                    }
                }
            }
            nav aria-label="Views" class="cr-mobile-view-strip" {
                a href="/" class=(if under_all_views(current_path, views) { "is-active" } else { "" }) aria-current=[(current_path == "/").then_some("page")] { (mobile_icon(HOME_ICON)) "All views" }
                // The same entries as the desktop sidebar: saved views, then
                // the internal registry, with collections on the index.
                @for view in navigation_order(views).filter(|view| view.saved) {
                    @let path = format!("/{}", encode_segment(&view.name));
                    a href=(&path) class=(if current_path == path { "is-active" } else { "" }) aria-current=[(current_path == path).then_some("page")] { (mobile_icon(view_icon(view))) (&view.title) }
                }
                @if ui.is_some_and(|ui| ui.can_read_users) {
                    a href="/users" class=(if current_path == "/users" { "is-active" } else { "" }) aria-current=[(current_path == "/users").then_some("page")] { (mobile_icon(USERS_ICON)) "Users" }
                }
                @if let Some(ui) = ui.filter(|ui| ui.can_browse_files) {
                    @let on_pin = ui.pins.iter().any(|pin| pin.href == current_path);
                    @let all_files = (current_path == "/browse" || current_path.starts_with("/browse?")) && !on_pin;
                    a href="/browse" class=(if all_files { "is-active" } else { "" }) aria-current=[all_files.then_some("page")] { (mobile_icon(ALL_FILES_ICON)) "All files" }
                    @for pin in &ui.pins {
                        a href=(&pin.href) class=(if pin.href == current_path { "is-active" } else { "" }) aria-current=[(pin.href == current_path).then_some("page")] title=(&pin.location) { (mobile_icon(pin_icon(pin.kind))) (&pin.label) }
                    }
                }
                @if ui.is_none_or(|ui| ui.can_view_global_audit) {
                    a href="/audit" class=(if current_path == "/audit" { "is-active" } else { "" }) aria-current=[(current_path == "/audit").then_some("page")] { (mobile_icon(AUDIT_ICON)) "Audit" }
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

/// The DOM id of the hidden inputs inside "Save as view" that carry the page's
/// current filters, sort and columns into the new definition, beside the
/// sentence saying which sort that is.
///
/// A passenger of every results swap for the reason the filter summary is: an
/// apply, a re-sort or a column change alters what the page shows while
/// leaving the heading, and the save form in it, alone. Without the patch the
/// form kept the state the page was *loaded* with, so filtering and then
/// saving wrote a view of everything.
const VIEW_SAVE_STATE_ID: &str = "cr-view-save-state";

/// The DOM id of a saved view's "Edit view" link, which opens the editor on
/// the page as the reader is looking at it and so changes with every swap.
const VIEW_EDIT_LINK_ID: &str = "cr-view-edit";

/// The DOM id of the record create and edit form.
///
/// The third region, and the first that is a `<form>` rather than a container:
/// a refused submission is answered with this element and nothing else, so the
/// values the browser sent come back in the controls they were typed into while
/// the breadcrumb, the heading and the record's audit history beside it are left
/// alone. The form points `hx-target` at itself, which is what puts this name in
/// the `HX-Target` of every submission and is why only the two routes that render
/// the form can ever be asked for it.
const RECORD_FORM_REGION: &str = "cr-record-form";

/// The DOM id of the "Save as view" form, a region for the record form's
/// reason: a refused save is answered with this element alone, swapped into
/// the popover it was submitted from, and only the route it posts to answers
/// with it alone. It holds `VIEW_SAVE_STATE_ID`, so a refused form goes on
/// receiving the state every later results swap patches.
const SAVE_VIEW_FORM_REGION: &str = "cr-save-view-form";

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
/// One step of a page bar's breadcrumb: where it goes, an icon, and a label.
type Crumb<'a> = (String, Option<&'a str>, &'a str);

/// The bar at the top of every page, after Linear's and GitHub's.
///
/// Pages used to open with a breadcrumb, an eyebrow, a display-sized title, a
/// sentence of description, and buttons beside the lot, which was five lines
/// before the first record and a heading far larger than anything it
/// introduced. The bar says the same in one line: the breadcrumb, which ends in
/// the page's `<h1>` at the size of the text around it; `meta`, a quiet word
/// about what the page holds; and `actions` on the right. What a page must say
/// before it is used goes under the bar in a `cr-page-note`.
fn page_bar(
    crumbs: &[Crumb<'_>],
    icon: Option<&str>,
    title: &str,
    meta: Markup,
    actions: Markup,
) -> Markup {
    html! {
        header class="cr-page-bar" {
            div class="cr-page-bar-title" {
                div class="cr-page-path" {
                    @if !crumbs.is_empty() {
                        nav aria-label="Breadcrumb" class="cr-crumbs" {
                            @for (href, icon, label) in crumbs {
                                a href=(href) {
                                    @if let Some(icon) = icon {
                                        span class="cr-page-icon" aria-hidden="true" { (icon) }
                                    }
                                    span class="cr-crumb-label" { (label) }
                                }
                                span class="cr-crumb-separator" aria-hidden="true" { "›" }
                            }
                        }
                    }
                    h1 class="cr-page-title" {
                        @if let Some(icon) = icon {
                            span class="cr-page-icon" aria-hidden="true" { (icon) }
                        }
                        span { (title) }
                    }
                }
                (meta)
            }
            div class="cr-page-actions" { (actions) }
        }
    }
}

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
                // Both schemes, matching `color-scheme` in `static/cr.css`:
                // said here as well so the browser paints the right canvas
                // before the sheet has been parsed, instead of flashing white.
                meta name="color-scheme" content="light dark";
                meta name="theme-color" media="(prefers-color-scheme: light)" content="#ffffff";
                meta name="theme-color" media="(prefers-color-scheme: dark)" content="#191919";
                meta name="robots" content="noindex, nofollow";
                // A file on this origin rather than a `data:` URL, for the
                // content security policy; see `CONTENT_SECURITY_POLICY`.
                link rel="icon" type="image/svg+xml" href=(FAVICON_PATH.as_str());
                (document_title(title))
                // Both sheets are linked, so they block the first paint until
                // they have loaded rather than restyling a page the reader is
                // already looking at. The utilities' rules are all inside
                // cascade layers and the server's own are not, so the two need
                // no particular order.
                link rel="stylesheet" href=(TAILWIND_STYLESHEET_PATH.as_str());
                link rel="stylesheet" href=(UI_STYLESHEET_PATH.as_str());
                // htmx is linked before `cr.js` because `cr.js` configures
                // it, and two deferred scripts run in document order.
                script src=(HTMX_SCRIPT_PATH.as_str()) defer {}
                // `defer` keeps the previous execution order: the blocks used
                // to be emitted below the markup they enhance, so they ran
                // against a parsed document, and a deferred head script runs at
                // the same point without blocking the parse to get there.
                script src=(UI_SCRIPT_PATH.as_str()) defer {}
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
                // a request is in flight, and `.cr-progress` in `static/cr.css`
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
                                            "Viewing as " strong { (user_chip(&ui.selected_name, &ui.selected, Some(&ui.selected))) }
                                            @if ui.selected_status == UserStatus::Disabled { " · disabled" }
                                        }
                                        span { "Impersonated by " (actor_chip(&ui.operator.display)) }
                                    }
                                }
                            }
                        }
                        // The one element whose contents a content fragment
                        // replaces, which is why its id is a constant: the
                        // shell and the seam have to agree on the name.
                        main id=(CONTENT_REGION) class="cr-main w-full" tabindex="-1" { (content) }
                    }
                }
            }
        }
    }
}

/// Every column a view can show: its own, then every other field the schema
/// declares or a record has.
///
/// The others are ordered the way the people who wrote them ordered them,
/// rather than alphabetically, which put `asked_by` and `attempts` in front of
/// `title` and `status` and let the default twelve columns miss the fields a
/// reader came for. First the schema's `x-cr-ui.order`, the order the record
/// form already follows; then its `required` fields, in the order it lists
/// them; then the rest by where they sit in the front matter of the records
/// that have them. A position is averaged over those records, so one file
/// written in an unusual order cannot move a column on its own, and the
/// ordering does not depend on which records sort first. A field only the
/// schema knows, which no record has yet, comes last, and the name settles
/// any tie.
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
    // The sum of a field's positions and the number of records it is in.
    let mut positions = BTreeMap::<String, (usize, usize)>::new();
    for record in records {
        for (position, key) in record
            .attributes
            .keys()
            .filter_map(|key| match key {
                YamlValue::String(key) if !record_owned || key != RECORD_ACCESS_FIELD => Some(key),
                _ => None,
            })
            .enumerate()
        {
            let (sum, count) = positions.entry(key.clone()).or_default();
            *sum += position;
            *count += 1;
            additional.insert(key.clone());
        }
    }
    let configured = schema.map(schema_ui_order).unwrap_or_default();
    let required = schema.map(schema_required_fields).unwrap_or_default();
    let rank = |key: &str| {
        (
            configured.get(key).copied().unwrap_or(usize::MAX),
            required
                .iter()
                .position(|field| *field == key)
                .unwrap_or(usize::MAX),
        )
    };
    let mut additional = additional
        .into_iter()
        .filter(|column| known.insert(column.clone()))
        .collect::<Vec<_>>();
    additional.sort_by(|left, right| {
        rank(left)
            .cmp(&rank(right))
            .then_with(|| compare_average_positions(&positions, left, right))
    });
    for column in additional {
        let nested = nested_columns(&column, schema, records);
        columns.push(column);
        columns.extend(nested.into_iter().filter(|path| known.insert(path.clone())));
    }
    columns
}

/// Order two fields by their average position in the records that have them,
/// then fields no record has, then by name. `positions` holds each field's
/// summed positions and the number of records it is in.
fn compare_average_positions(
    positions: &BTreeMap<String, (usize, usize)>,
    left: &str,
    right: &str,
) -> std::cmp::Ordering {
    match (positions.get(left), positions.get(right)) {
        // The two averages compared without dividing either.
        (Some((left_sum, left_count)), Some((right_sum, right_count))) => {
            (left_sum * right_count).cmp(&(right_sum * left_count))
        }
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
    .then_with(|| left.cmp(right))
}

/// The columns inside an object field: `learning.status` for `learning`.
///
/// A whole object is too much for one cell, and its summary shows only one
/// part of it, so each field inside that holds a plain value, or a list of
/// them, can be a column of its own. The dotted path is already what sorting,
/// filtering and `Record::field` read. One level deep: a field inside those
/// that is itself an object stays in its parent's tooltip. They are ordered
/// like top-level fields, by where the records put them, then the ones only
/// the schema declares, and they follow their parent wherever it is listed.
fn nested_columns(parent: &str, schema: Option<&JsonValue>, records: &[Record]) -> Vec<String> {
    let is_plain = |value: &YamlValue| match value {
        YamlValue::Mapping(_) => false,
        YamlValue::Sequence(items) => items
            .iter()
            .all(|item| !matches!(item, YamlValue::Mapping(_) | YamlValue::Sequence(_))),
        _ => true,
    };
    let mut keys = BTreeSet::new();
    let mut positions = BTreeMap::<String, (usize, usize)>::new();
    for record in records {
        let Some(YamlValue::Mapping(object)) =
            record.attributes.get(YamlValue::String(parent.to_owned()))
        else {
            continue;
        };
        for (position, (key, value)) in object.iter().enumerate() {
            if let YamlValue::String(key) = key
                && is_plain(value)
            {
                let (sum, count) = positions.entry(key.clone()).or_default();
                *sum += position;
                *count += 1;
                keys.insert(key.clone());
            }
        }
    }
    if let Some(properties) = property_definition(schema, parent)
        .and_then(|definition| definition.get("properties"))
        .and_then(JsonValue::as_object)
    {
        keys.extend(
            properties
                .iter()
                .filter(|(_, definition)| !declares_objects(definition))
                .map(|(key, _)| key.clone()),
        );
    }
    let mut keys = keys
        .into_iter()
        .filter(|key| !key.is_empty() && !key.contains('.'))
        .collect::<Vec<_>>();
    keys.sort_by(|left, right| compare_average_positions(&positions, left, right));
    keys.into_iter()
        .map(|key| format!("{parent}.{key}"))
        .collect()
}

/// Each field `x-cr-ui.order` names, with its place in that list.
fn schema_ui_order(schema: &JsonValue) -> BTreeMap<String, usize> {
    schema
        .get("x-cr-ui")
        .and_then(|ui| ui.get("order"))
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .enumerate()
        .map(|(index, key)| (key.to_owned(), index))
        .collect()
}

/// The schema's `required` fields, in the order it lists them.
fn schema_required_fields(schema: &JsonValue) -> Vec<&str> {
    schema
        .get("required")
        .and_then(JsonValue::as_array)
        .into_iter()
        .flatten()
        .filter_map(JsonValue::as_str)
        .collect()
}

fn selected_view_columns(
    view: &ViewDefinition,
    query: &ViewQuery,
    available: &[String],
    schema: Option<&JsonValue>,
    records: &[Record],
) -> ApiResult<Vec<String>> {
    if !query_columns_custom(query) {
        return Ok(if view.columns.is_empty() {
            match (view.layout, view.group_by.as_deref()) {
                (ViewLayout::Kanban, Some(group_by)) => {
                    default_card_columns(available, schema, records, group_by)
                }
                _ => default_view_columns(available, schema, records),
            }
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

/// How many fields an automatic table shows beside its title or ID and its
/// two timestamps, before the reader picks others.
const DEFAULT_VIEW_COLUMNS: usize = 6;

/// The fields a view with no columns of its own shows.
///
/// The first few the column order puts forward, which is six rather than the
/// twelve it was: with the title and both timestamps that is already nine
/// columns, and twelve fields more pushed most of them out of sight on any
/// screen. Two kinds of field are passed over. The one the first column
/// already shows would only say it twice. And a field whose values are
/// objects, or lists of them, can only be printed in a one-line cell as a run
/// of `key: value` pairs, which fills the width a readable field could have
/// had. Every field is still in the column picker.
fn default_view_columns(
    available: &[String],
    schema: Option<&JsonValue>,
    records: &[Record],
) -> Vec<String> {
    let title = view_title_field(schema, records);
    available
        .iter()
        .filter(|column| Some(column.as_str()) != title)
        // A field inside an object is offered, never chosen for the reader.
        .filter(|column| !column.contains('.'))
        .filter(|column| !field_holds_objects(column, schema, records))
        .take(DEFAULT_VIEW_COLUMNS)
        .cloned()
        .collect()
}

/// How many values a Kanban card shows before the reader picks others.
const DEFAULT_CARD_COLUMNS: usize = 4;

/// A text field whose values average more characters than this is prose, which
/// a card's chip could only cut short.
const CARD_TEXT_MAX_CHARS: usize = 40;

/// The values a Kanban card shows when its view names none.
///
/// A card has a fraction of a table row's room and a board shows dozens of
/// them at once, so every value on one has to earn its place. The table's
/// rules come first: not the title, which heads the card; nothing inside an
/// object; no objects. Then three of a card's own. Not the field the board is
/// grouped by, which the lane already says. Not prose, whose chip would be an
/// ellipsis. And not a field with a single value across the board — the same
/// requester on every task, `attempts: 0` everywhere — which tells a reader
/// nothing about the card it is on, however true it is. Four at most, in
/// column order. Every field can still be chosen in the column picker.
fn default_card_columns(
    available: &[String],
    schema: Option<&JsonValue>,
    records: &[Record],
    group_by: &str,
) -> Vec<String> {
    let title = view_title_field(schema, records);
    available
        .iter()
        .filter(|column| Some(column.as_str()) != title && column.as_str() != group_by)
        .filter(|column| !column.contains('.'))
        .filter(|column| !field_holds_objects(column, schema, records))
        .filter(|column| !field_holds_prose(column, schema, records))
        .filter(|column| !field_has_one_value(column, records))
        .take(DEFAULT_CARD_COLUMNS)
        .cloned()
        .collect()
}

/// Whether `field` holds prose: text, not an enum's option, averaging more than
/// [`CARD_TEXT_MAX_CHARS`] characters where it is set.
fn field_holds_prose(field: &str, schema: Option<&JsonValue>, records: &[Record]) -> bool {
    if property_definition(schema, field).is_some_and(|definition| definition.get("enum").is_some())
    {
        return false;
    }
    let key = YamlValue::String(field.to_owned());
    let lengths = records
        .iter()
        .filter_map(|record| match record.attributes.get(&key) {
            Some(YamlValue::String(text)) if !text.trim().is_empty() => Some(text.chars().count()),
            _ => None,
        })
        .collect::<Vec<_>>();
    !lengths.is_empty() && lengths.iter().sum::<usize>() / lengths.len() > CARD_TEXT_MAX_CHARS
}

/// Whether every record that sets `field` sets it to the same value, on a
/// board with enough records for that to mean something. A field no record
/// sets counts too: it has nothing to show.
fn field_has_one_value(field: &str, records: &[Record]) -> bool {
    if records.len() < 3 {
        return false;
    }
    let key = YamlValue::String(field.to_owned());
    let mut values = records
        .iter()
        .filter_map(|record| record.attributes.get(&key))
        .filter(|value| !is_empty_value(value));
    match values.next() {
        None => true,
        Some(first) => values.all(|value| value == first),
    }
}

/// Whether the schema declares `field` an object or a list of objects, or a
/// record holds one there.
fn field_holds_objects(field: &str, schema: Option<&JsonValue>, records: &[Record]) -> bool {
    if property_definition(schema, field).is_some_and(declares_objects) {
        return true;
    }
    records.iter().any(
        |record| match record.attributes.get(YamlValue::String(field.to_owned())) {
            Some(YamlValue::Mapping(_)) => true,
            Some(YamlValue::Sequence(items)) => items
                .iter()
                .any(|item| matches!(item, YamlValue::Mapping(_))),
            _ => false,
        },
    )
}

/// Whether a schema definition is of an object, or of a list of objects.
fn declares_objects(definition: &JsonValue) -> bool {
    let is_object = |definition: Option<&JsonValue>| {
        definition
            .and_then(|definition| definition.get("type"))
            .is_some_and(|kind| match kind {
                JsonValue::String(kind) => kind == "object",
                JsonValue::Array(kinds) => kinds.iter().any(|kind| kind == "object"),
                _ => false,
            })
    };
    is_object(Some(definition)) || is_object(definition.get("items"))
}

fn query_columns_custom(query: &ViewQuery) -> bool {
    query.columns == ViewColumnsMode::Custom || !query.column.is_empty()
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

/// The conditions a form submitted, as the filter group a saved view stores,
/// or `None` when every row was left blank.
fn submitted_filter_group(
    filter_match: ViewFilterMatch,
    fields: &[String],
    operators: &[ViewFilterOperator],
    values: &[String],
) -> ApiResult<Option<ViewFilterGroup>> {
    let query = ViewQuery {
        filter_match,
        filter_field: fields.to_vec(),
        filter_operator: operators.to_vec(),
        filter_value: values.to_vec(),
        ..ViewQuery::default()
    };
    view_filter_expressions(&query)?;

    let mut expressions = Vec::new();
    for (index, (field, value)) in fields.iter().zip(values).enumerate() {
        if field.is_empty() && value.is_empty() {
            continue;
        }
        let operator = operators.get(index).copied().unwrap_or_default();
        let expression = filter_expression_text(field, operator, value);
        FilterExpression::from_str(&expression).map_err(ApiError::from_domain)?;
        expressions.push(expression);
    }

    if expressions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(ViewFilterGroup {
            match_mode: filter_match.into(),
            expressions,
        }))
    }
}

/// A condition as the text a saved view stores it in, such as `value>=10000`.
fn filter_expression_text(field: &str, operator: ViewFilterOperator, value: &str) -> String {
    if operator.requires_value() {
        format!(
            "{}{}{}",
            field.trim(),
            operator.expression_token(),
            value.trim()
        )
    } else {
        format!("{}{}", field.trim(), operator.expression_token())
    }
}

impl ViewQuery {
    /// The sort the URL asks for, or `None` when it names none and the view's
    /// default applies. An empty list is the panel's "None".
    ///
    /// The panel offers a field in every row, so a field chosen twice keeps
    /// the place it was first chosen in rather than failing the page.
    fn requested_sort(&self) -> Option<Vec<SortKey>> {
        if self.sort_field.is_empty() {
            return None;
        }
        let mut keys: Vec<SortKey> = Vec::new();
        for key in submitted_sort(&self.sort_field, &self.sort_direction) {
            if !keys.iter().any(|earlier| earlier.field == key.field) {
                keys.push(key);
            }
        }
        Some(keys)
    }

    /// Ask for exactly `keys`, with no keys meaning record ID order.
    fn set_sort(&mut self, keys: &[SortKey]) {
        if keys.is_empty() {
            self.sort_field = vec![String::new()];
            self.sort_direction = Vec::new();
        } else {
            self.sort_field = keys.iter().map(|key| key.field.clone()).collect();
            self.sort_direction = keys.iter().map(|key| key.direction.into()).collect();
        }
    }
}

/// Submitted `sort_field`s paired with their `sort_direction`s by position,
/// without the rows left at "None". A field without a direction is ascending.
fn submitted_sort(fields: &[String], directions: &[ViewSortDirection]) -> Vec<SortKey> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| (field.trim(), directions.get(index).copied()))
        .filter(|(field, _)| !field.is_empty())
        .map(|(field, direction)| SortKey::new(field, direction.unwrap_or_default().into()))
        .collect()
}

/// The sort a normalized view query asks for.
fn view_sort(query: &ViewQuery) -> Vec<SortKey> {
    query.requested_sort().unwrap_or_default()
}

/// The most significant key a view page is ordered by: what its column
/// headings, its day grouping and its cards' times follow.
fn view_primary_sort(query: &ViewQuery) -> Option<(&str, ViewSortDirection)> {
    query
        .sort_field
        .iter()
        .enumerate()
        .find_map(|(index, field)| {
            let field = field.trim();
            (!field.is_empty()).then(|| {
                (
                    field,
                    query.sort_direction.get(index).copied().unwrap_or_default(),
                )
            })
        })
}

fn view_sort_field(query: &ViewQuery) -> Option<&str> {
    view_primary_sort(query).map(|(field, _)| field)
}

/// Every field a view can be sorted by, as `(field, label)`: the audit
/// columns, the record ID, and the view's fields.
fn view_sort_options(filter_fields: &[ViewFilterField], created: &str) -> Vec<(String, String)> {
    let mut options = vec![
        ("$created_at".to_owned(), created.to_owned()),
        ("$updated_at".to_owned(), "Updated".to_owned()),
        ("$id".to_owned(), "Record ID".to_owned()),
    ];
    options.extend(
        filter_fields
            .iter()
            .map(|field| (field.key.clone(), field.label.clone())),
    );
    options
}

/// Which sort controls are being drawn, which decides how the first key's
/// field is labelled and whether it can be left empty.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortPrimary {
    /// The filter panel, where "None" is record ID order.
    Panel,
    /// The view editor, where a view always has a sort.
    Editor,
}

/// A sort's controls: the first key as a field and a pair of direction
/// radios, a "Then by" row for each further key, and one empty row to add
/// another while there is room.
///
/// Every row submits one `sort_field` and one `sort_direction`, in order, so
/// the server pairs them by position, and a row left at "None" is dropped.
/// That is what lets a reader add, change and remove keys with JavaScript
/// switched off. A key on a field `options` does not list — one a view file
/// names, say — is offered as it is, so applying the panel does not quietly
/// drop it.
fn render_sort_controls(
    options: &[(String, String)],
    keys: &[SortKey],
    primary: SortPrimary,
) -> Markup {
    let mut options = options.to_vec();
    for key in keys {
        if !options.iter().any(|(field, _)| *field == key.field) {
            options.push((key.field.clone(), format!("{} (custom)", key.field)));
        }
    }
    let first = keys.first();
    let direction = first.map_or(SortDirection::Asc, |key| key.direction);
    let selected = |key: Option<&SortKey>, field: &str| key.is_some_and(|key| key.field == field);
    let rest = keys.iter().skip(1).map(Some);
    let blank = (!keys.is_empty() && keys.len() < MAX_SORT_KEYS).then_some(None);
    html! {
        div class="cr-sort-row" {
            @match primary {
                SortPrimary::Panel => {
                    select name="sort_field" aria-label="Sort by" class="cr-input" {
                        option value="" selected[first.is_none()] { "None (record ID order)" }
                        @for (field, label) in &options {
                            option value=(field) selected[selected(first, field)] { (label) }
                        }
                    }
                }
                SortPrimary::Editor => {
                    select name="sort_field" aria-labelledby="cr-view-sort-heading" class="cr-input" {
                        @for (field, label) in &options {
                            option value=(field) selected[selected(first, field)] { (label) }
                        }
                    }
                }
            }
            div role="radiogroup" aria-label="Sort direction" class="cr-choice-row" {
                label class="cr-choice-option" {
                    input type="radio" name="sort_direction" value="asc" checked[direction == SortDirection::Asc];
                    "Ascending"
                }
                label class="cr-choice-option" {
                    input type="radio" name="sort_direction" value="desc" checked[direction == SortDirection::Desc];
                    "Descending"
                }
            }
        }
        @for (index, key) in rest.chain(blank).enumerate() {
            @let position = index + 2;
            @let direction = key.map_or(SortDirection::Asc, |key| key.direction);
            div class="cr-sort-row cr-sort-then" data-sort-key=(position) {
                span class="cr-sort-then-label" aria-hidden="true" { "Then by" }
                select name="sort_field" aria-label=(format!("Then by, sort key {position}")) class="cr-input" {
                    option value="" selected[key.is_none()] { "None" }
                    @for (field, label) in &options {
                        option value=(field) selected[selected(key, field)] { (label) }
                    }
                }
                select name="sort_direction" aria-label=(format!("Direction of sort key {position}")) class="cr-input cr-sort-direction" {
                    option value="asc" selected[direction == SortDirection::Asc] { "Ascending" }
                    option value="desc" selected[direction == SortDirection::Desc] { "Descending" }
                }
            }
        }
    }
}

/// The audit-derived columns every table shows between the ID and the fields.
///
/// Fixed rather than selectable: they are not record data, they cost nothing
/// extra once the activity map is loaded, and "when did this happen?" is the
/// question a reader brings to a newest-first table.
const ACTIVITY_COLUMNS: [(&str, &str); 2] =
    [("$created_at", "created"), ("$updated_at", "updated")];

/// Render one timestamp as how long ago it was, keeping the exact instant.
///
/// "3 hours ago" is what a reader scanning a table or an activity feed wants;
/// the exact time is one hover away in the tooltip, and the `datetime`
/// attribute keeps the stored RFC 3339 instant, which is what a reader
/// correlating a row with `cr audit log` needs. The tooltip is in UTC because
/// the server cannot know the reader's time zone; `cr.js` rewrites it into
/// local time where it runs. A value that does not parse is shown as stored.
fn render_timestamp(value: Option<&str>) -> Markup {
    match value {
        Some(value) => match OffsetDateTime::parse(value, &Rfc3339) {
            Ok(instant) => html! {
                time datetime=(value) title=(exact_utc(instant)) class="cr-time" {
                    (relative_time(instant, OffsetDateTime::now_utc()))
                }
            },
            Err(_) => html! {
                time datetime=(value) title=(value) class="cr-data" { (compact_timestamp(value)) }
            },
        },
        // No audit history: a file created outside `cr` and not yet saved.
        None => html! { span class="text-gray-400" { "—" } },
    }
}

/// `instant` relative to `now`, as "just now", "5 minutes ago", "in 2 days".
///
/// The thresholds round to the nearest unit and move to the next one early —
/// 45 minutes is "1 hour ago", 26 days "1 month ago" — so the number shown is
/// never a large count of a small unit.
fn relative_time(instant: OffsetDateTime, now: OffsetDateTime) -> String {
    const MINUTE: i64 = 60;
    const HOUR: i64 = 60 * MINUTE;
    const DAY: i64 = 24 * HOUR;
    const MONTH: i64 = 2_629_746;
    const YEAR: i64 = 31_556_952;
    let elapsed = (now - instant).whole_seconds();
    let magnitude = elapsed.abs();
    if magnitude < 45 {
        return "just now".to_owned();
    }
    let (size, unit) = match magnitude {
        seconds if seconds < 45 * MINUTE => (MINUTE, "minute"),
        seconds if seconds < 22 * HOUR => (HOUR, "hour"),
        seconds if seconds < 26 * DAY => (DAY, "day"),
        seconds if seconds < 320 * DAY => (MONTH, "month"),
        _ => (YEAR, "year"),
    };
    let count = ((magnitude + size / 2) / size).max(1);
    let plural = if count == 1 { "" } else { "s" };
    if elapsed >= 0 {
        format!("{count} {unit}{plural} ago")
    } else {
        format!("in {count} {unit}{plural}")
    }
}

/// `2026-09-22 09:16 UTC`, the tooltip under a relative time.
fn exact_utc(instant: OffsetDateTime) -> String {
    let instant = instant.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        instant.year(),
        u8::from(instant.month()),
        instant.day(),
        instant.hour(),
        instant.minute()
    )
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

/// Order a view's records by its query's sort, which, unlike a record scan,
/// may name the audit-derived `$created_at` and `$updated_at`: the activity
/// map the page already holds gives their journal sequence numbers.
fn sort_view_records(
    records: &mut [Record],
    query: &ViewQuery,
    activity: &BTreeMap<String, RecordActivity>,
) -> ApiResult<()> {
    let sequence = |record: &Record, field: HistoryField| {
        activity.get(&record.id).map(|activity| match field {
            HistoryField::Created => activity.created_sequence,
            HistoryField::Updated => activity.updated_sequence,
        })
    };
    sort_with_history(records, |record| record, &view_sort(query), Some(sequence))
        .map_err(ApiError::from_domain)
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
    /// The largest page the server will serve, which bounds the page sizes the
    /// footer offers.
    max_limit: usize,
    start: usize,
    total: usize,
    next: Option<String>,
    previous: Option<String>,
    /// On a Kanban board, how many records each lane holds in the whole view,
    /// keyed by the lane's serialized value, `None` for records without one.
    /// A board is not paged; each lane shows up to `limit` of its own.
    lanes: Option<BTreeMap<Option<String>, usize>>,
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
fn paginate_view(
    records: Vec<Record>,
    limit: usize,
    max_limit: usize,
    position: ViewPosition<'_>,
) -> ViewPage {
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
        max_limit,
        start,
        total,
        next,
        previous,
        lanes: None,
    }
}

/// Cut a Kanban board out of the ordered result: up to `limit` records from
/// each lane, in order, and how many each lane holds.
///
/// A board used to be one page of the view, cut across all its lanes before
/// they were filled, so a lane showed however many of the page's records fell
/// into it: a queue of fifteen said six, and the next page moved every lane at
/// once. Now each lane shows the first `limit` of its own records and says
/// how many it has, and asking for more asks for more of every lane. Every
/// record is already in memory for the ordering, so counting the lanes costs
/// nothing more; what stays bounded is what is sent, at `limit` per lane.
fn paginate_board(
    records: Vec<Record>,
    limit: usize,
    max_limit: usize,
    group_by: &str,
) -> ViewPage {
    let total = records.len();
    let mut lanes = BTreeMap::<Option<String>, usize>::new();
    let records = records
        .into_iter()
        .filter(|record| {
            let lane = record
                .field(group_by)
                .ok()
                .flatten()
                .map(serialize_yaml_value);
            let shown = lanes.entry(lane).or_default();
            *shown += 1;
            *shown <= limit
        })
        .collect();
    ViewPage {
        records,
        limit,
        max_limit,
        start: 0,
        total,
        next: None,
        previous: None,
        lanes: Some(lanes),
    }
}

fn view_page_url(
    view: &ViewDefinition,
    query: &ViewQuery,
    limit: usize,
    position: ViewPosition<'_>,
) -> String {
    format!(
        "/{}?{}",
        encode_segment(&view.name),
        view_query_string(query, limit, position)
    )
}

/// The query string of a view page, shared by the page's own links and the
/// link that opens its editor.
fn view_query_string(query: &ViewQuery, limit: usize, position: ViewPosition<'_>) -> String {
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
    match query.requested_sort() {
        None => {}
        Some(keys) if keys.is_empty() => {
            serializer.append_pair("sort_field", "");
        }
        Some(keys) => {
            for key in keys {
                serializer.append_pair("sort_field", &key.field);
                serializer.append_pair("sort_direction", key.direction.as_str());
            }
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
    serializer.finish()
}

/// Where a column heading's sort link goes: that column alone, ascending, or
/// descending when it already leads the sort ascending. A click replaces
/// the whole sort, keys after the first included; several keys are chosen in
/// the filter panel.
fn view_sort_url(view: &ViewDefinition, query: &ViewQuery, field: &str, limit: usize) -> String {
    let mut next = query.clone();
    let direction = if view_primary_sort(query) == Some((field, ViewSortDirection::Asc)) {
        SortDirection::Desc
    } else {
        SortDirection::Asc
    };
    next.set_sort(&[SortKey::new(field, direction)]);
    // Re-sorting starts the reader at the top of the new ordering: a cursor
    // from the previous one names a row that is now somewhere else entirely.
    view_page_url(view, &next, limit, ViewPosition::Start)
}

fn sort_indicator(query: &ViewQuery, field: &str) -> &'static str {
    match view_primary_sort(query) {
        Some((sorted, ViewSortDirection::Asc)) if sorted == field => "↑",
        Some((sorted, ViewSortDirection::Desc)) if sorted == field => "↓",
        _ => "↕",
    }
}

/// Only the first key's heading is marked, because `aria-sort` belongs on one
/// heading at a time.
fn sort_aria_state(query: &ViewQuery, field: &str) -> &'static str {
    match view_primary_sort(query) {
        Some((sorted, ViewSortDirection::Asc)) if sorted == field => "ascending",
        Some((sorted, ViewSortDirection::Desc)) if sorted == field => "descending",
        _ => "none",
    }
}

fn sort_link_label(query: &ViewQuery, label: &str, field: &str) -> String {
    let direction = if view_primary_sort(query) == Some((field, ViewSortDirection::Asc)) {
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
    let mut field_kinds: Vec<(String, InferredFieldKind)> = Vec::new();

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
            _ if name.starts_with("_field.") => {
                let field = &name["_field.".len()..];
                let kind = InferredFieldKind::from_token(&value).ok_or_else(|| {
                    ApiError::bad_request(
                        "invalid_form",
                        format!("unsupported field type '{value}' for attribute '{field}'"),
                    )
                })?;
                if field.is_empty() || field_kinds.iter().any(|(key, _)| key == field) {
                    return Err(ApiError::bad_request(
                        "invalid_form",
                        format!("form field '{name}' cannot be empty or repeated"),
                    ));
                }
                field_kinds.push((field.to_owned(), kind));
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

    let mode = match mode.as_deref() {
        Some("structured") => DocumentFormMode::Structured,
        Some("fields") => DocumentFormMode::Fields,
        Some(other) => {
            return Err(ApiError::bad_request(
                "invalid_form",
                format!("unsupported form mode '{other}'"),
            ));
        }
        None => DocumentFormMode::Yaml,
    };
    if mode != DocumentFormMode::Yaml && front_matter.is_some() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "structured fields and raw front matter cannot be submitted together",
        ));
    }
    if mode == DocumentFormMode::Yaml && front_matter.is_none() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "front_matter is required when structured fields are not used",
        ));
    }
    if mode != DocumentFormMode::Fields && !field_kinds.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_form",
            "field types are only submitted by the fields form",
        ));
    }
    if let Some(field) = fields.keys().find(|field| {
        mode == DocumentFormMode::Fields && !field_kinds.iter().any(|(key, _)| key == *field)
    }) {
        return Err(ApiError::bad_request(
            "invalid_form",
            format!("attribute '{field}' was submitted without a field type"),
        ));
    }

    Ok(HtmlDocumentForm {
        csrf: csrf.ok_or_else(|| ApiError::bad_request("invalid_form", "_csrf is required"))?,
        expected_record_hash,
        id,
        front_matter,
        // Read back as the line feeds it was shown with, so saving a record
        // from a browser does not rewrite every line of its body as CRLF.
        markdown: markdown
            .map(|markdown| form_text(&markdown))
            .ok_or_else(|| ApiError::bad_request("invalid_form", "markdown is required"))?,
        mode,
        additional_attributes: additional_attributes.unwrap_or_else(|| "{}".to_owned()),
        fields,
        field_kinds,
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
    match form.mode {
        DocumentFormMode::Yaml => {
            return parse_front_matter(
                form.front_matter
                    .as_deref()
                    .expect("raw forms have front matter"),
            )
            .map_err(|error| error.with_field(FRONT_MATTER_CONTROL));
        }
        DocumentFormMode::Fields => return parse_inferred_attributes(form),
        DocumentFormMode::Structured => {}
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
    let fields = record_form_fields(schema, &Mapping::new()).unwrap_or_default();
    let controls = fields
        .iter()
        .flat_map(|field| {
            std::iter::once(field.key.as_str())
                .chain(field.members.iter().map(|member| member.key.as_str()))
        })
        .collect::<BTreeSet<_>>();
    for field in form.fields.keys() {
        if !controls.contains(field.as_str()) {
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
    let additional = parse_front_matter(&form.additional_attributes)
        .map_err(|error| error.with_field(ADDITIONAL_ATTRIBUTES_CONTROL))?;
    for key in additional.keys() {
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
    if !schema_allows_additional_attributes(schema) && !additional.is_empty() {
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
    // Declared fields in the order the form shows them, then the rest, so a
    // new record's file reads in the same order as its form. Saving an
    // existing record puts its own order back; see `in_stored_order`.
    let mut attributes = Mapping::new();
    for field in fields {
        if !field.members.is_empty() && submitted_as_group(form, &field.key) {
            if form.fields.contains_key(&field.key) {
                return Err(ApiError::bad_request(
                    "invalid_form",
                    format!(
                        "attribute '{}' cannot be submitted both as YAML and as separate fields",
                        field.key
                    ),
                )
                .with_field(&field.key));
            }
            if let Some(object) = parse_object_group(form, &field, &properties[&field.key])? {
                attributes.insert(YamlValue::String(field.key), object);
            }
            continue;
        }
        let key = field.key;
        let values = form.fields.get(&key).map(Vec::as_slice).unwrap_or(&[]);
        // Every refusal from here names the property it is about, so a
        // re-rendered form can put it beside that property's control.
        if let Some(value) = parse_schema_form_value(
            &key,
            &properties[&key],
            required.contains(key.as_str()),
            values,
        )
        .map_err(|error| error.with_field(&key))?
        {
            attributes.insert(YamlValue::String(key), value);
        }
    }
    attributes.extend(additional);
    Ok(attributes)
}

/// The object a group of controls describes, each property read as the
/// top-level field it would be. A group left entirely empty is no object at
/// all unless the schema requires one, which is then `{}` for the schema to
/// judge.
fn parse_object_group(
    form: &HtmlDocumentForm,
    field: &SchemaFormField,
    definition: &JsonValue,
) -> ApiResult<Option<YamlValue>> {
    let values = |member: &SchemaFormField| {
        form.fields
            .get(&member.key)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };
    let untouched = field
        .members
        .iter()
        .all(|member| values(member).iter().all(String::is_empty));
    if untouched && !field.required {
        return Ok(None);
    }
    let mut object = Mapping::new();
    for member in &field.members {
        let property = &member.key[field.key.len() + 1..];
        if let Some(value) = parse_schema_form_value(
            &member.key,
            &definition["properties"][property],
            member.required,
            values(member),
        )
        .map_err(|error| error.with_field(&member.key))?
        {
            object.insert(YamlValue::String(property.to_owned()), value);
        }
    }
    Ok(Some(YamlValue::Mapping(object)))
}

/// `attributes` with the keys `stored` has in the order it has them, and any
/// others after those in the order they came.
///
/// The structured form lists fields in the schema's order, which is rarely the
/// order a record's file keeps them in: a record written by the CLI, an agent
/// or by hand has its own. Writing the form's order back moved the front
/// matter's lines around on every save, so a one-field change showed up in the
/// file's diff as a reshuffle of all of them.
///
/// Each object's own keys are put back in their stored order too, one level
/// down, for the same reason: the form lists an object's properties in its
/// schema's order.
fn in_stored_order(attributes: Mapping, stored: &Mapping) -> Mapping {
    keys_in_stored_order(attributes, stored)
        .into_iter()
        .map(|(key, value)| {
            let value = match (value, stored.get(&key)) {
                (YamlValue::Mapping(object), Some(YamlValue::Mapping(stored))) => {
                    YamlValue::Mapping(keys_in_stored_order(object, stored))
                }
                (value, _) => value,
            };
            (key, value)
        })
        .collect()
}

fn keys_in_stored_order(mut mapping: Mapping, stored: &Mapping) -> Mapping {
    let mut ordered = Mapping::with_capacity(mapping.len());
    for key in stored.keys() {
        if let Some(value) = mapping.shift_remove(key) {
            ordered.insert(key.clone(), value);
        }
    }
    ordered.extend(mapping);
    ordered
}

/// The front matter a `Fields` form describes: each listed field, in the order
/// the form listed it, read back as the kind it was rendered as. The collection
/// schema, whatever it says, is applied afterwards by the write itself, exactly
/// as it is to YAML typed into the raw editor.
fn parse_inferred_attributes(form: &HtmlDocumentForm) -> ApiResult<Mapping> {
    let mut attributes = Mapping::new();
    for (key, kind) in &form.field_kinds {
        let values = form.fields.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let raw = single_schema_form_value(key, values)
            .and_then(|raw| {
                raw.ok_or_else(|| {
                    ApiError::bad_request(
                        "invalid_form",
                        format!("attribute '{key}' is missing from the form"),
                    )
                })
            })
            .map_err(|error| error.with_field(key))?;
        let value = kind
            .parse(key, raw)
            .map_err(|error| error.with_field(key))?;
        attributes.insert(YamlValue::String(key.clone()), value);
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
                Ok(Some(YamlValue::String(form_text(raw))))
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

/// A record's page with a notice at the top, as `notice_url` is for a view.
fn record_notice_url(view: &str, id: &str, notice: &str) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("notice", notice);
    format!(
        "/{}/records/{}?{}",
        encode_segment(view),
        encode_segment(id),
        serializer.finish()
    )
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
    if secrets_match(provided, &request_csrf_token(state)) {
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

/// A redirect target as a header value, which no target can fail to become.
///
/// Every location a route builds is already a URL, its dynamic parts escaped by
/// `encode_segment` or `form_urlencoded`, and this changes none of them. What
/// it adds is that the header no longer depends on every caller having done so:
/// control characters — CR and LF among them, so no target can end the header
/// and begin another — spaces, and non-ASCII bytes are percent-escaped, and
/// what is left is visible ASCII, every byte of which `HeaderValue` accepts.
/// `%` and the rest of URL syntax stay as the caller wrote them, so an escape
/// already in the URL is not escaped twice.
fn location_header(location: &str) -> HeaderValue {
    let location = utf8_percent_encode(location, LOCATION_ENCODE_SET).to_string();
    HeaderValue::try_from(location).expect("a percent-encoded location is visible ASCII")
}

fn see_other(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location_header(location))],
    )
        .into_response()
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
fn mutation_redirect(representation: &Representation, location: &str) -> Response {
    if !representation.is_htmx() {
        return see_other(location);
    }
    (
        StatusCode::NO_CONTENT,
        [(
            HeaderName::from_static("hx-location"),
            location_header(location),
        )],
    )
        .into_response()
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
/// A refused form does not come here at all; `reject_record_form` and
/// `reject_save_view_form` answer it with the form and the values that were
/// typed into it. What is left for this page is a request that names something
/// that does not exist, a principal who may not do what was asked, a body that
/// is not a form this server rendered, and an internal failure — none of which
/// has a form to go back to.
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

/// The content security policy every HTML answer carries.
///
/// Templates escape every value they render, so this is the second line of
/// defence rather than the first: if an escape were ever missed, injected
/// markup could still not run a script, load anything from another origin, or
/// send a form anywhere else. It costs the pages nothing, because they already
/// work within it: every script, both stylesheets and the icon are files under
/// `/static/`, and no page carries an inline `<script>`, `<style>`, `style=`
/// attribute or event handler attribute. `tests/csp_http.rs` holds every page
/// to that.
///
/// * `default-src 'self'` is the fallback for every fetch: scripts, styles,
///   images, fonts, frames, workers, and htmx's requests. This origin and
///   nothing else. With no `'unsafe-inline'` no inline script or event
///   handler runs and no `<style>` block or `style=` attribute applies, and
///   with no `'unsafe-eval'` neither does `eval`, which `cr.js` also tells
///   htmx not to use (`allowEval`).
/// * `object-src 'none'`: no plugin content, which the fallback would allow
///   from this origin and nothing here uses.
/// * `base-uri 'none'`: no page uses `<base>`, and an injected one would
///   re-point every relative URL on the page, the script sources included.
///   `default-src` does not cover it.
/// * `form-action 'self'`: every form submits to this origin, so an injected
///   form cannot send what is typed into it, or the CSRF token, anywhere else.
///   `default-src` does not cover this either. Browsers apply it to the
///   redirects that follow a submission too, so behind an authenticating proxy
///   whose expired session redirects a form post to a sign-in page on another
///   origin, that one submission is refused rather than followed. The next
///   link followed reaches the sign-in page as before.
/// * `frame-ancestors 'none'`: no other page may frame these. A delete is two
///   clicks on pages this server renders, and a page that framed them under
///   something else could collect both. It is what `X-Frame-Options: DENY`
///   says, in the form that supersedes it.
///
/// There is no `upgrade-insecure-requests`, because `cr serve` speaks plain
/// HTTP and would be told to fetch its own assets over a scheme it does not
/// serve, and no reporting endpoint, because there is nothing to collect
/// reports.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

fn html_response(status: StatusCode, markup: Markup) -> Response {
    let mut response = (status, Html(markup.into_string())).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static(HTML_VARY));
    // No `nosniff` here: `request_context` sets it on every response, this
    // one included.
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
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
    let authenticated = authenticated_database();
    let mut database = authenticated.clone().unwrap_or_else(|| state.database());
    // For an authenticated principal the header can only restyle how that
    // same principal is displayed: `with_actor` refuses any other principal
    // under access control, which authentication requires.
    if let Some(actor) = headers.get(ACTOR_HEADER) {
        let actor = actor.to_str().map_err(|_| {
            ApiError::bad_request("invalid_actor", "X-CR-Actor must be valid UTF-8")
        })?;
        database = database.with_actor(actor).map_err(ApiError::from_domain)?;
    }
    if state.access_controlled && authenticated.is_none() {
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
    let authenticated = authenticated_database();
    let database = authenticated.clone().unwrap_or_else(|| state.database());
    let selected = match &authenticated {
        Some(database) => database.principal().to_owned(),
        None => perspective_principal(headers)?.unwrap_or_else(|| database.principal().to_owned()),
    };
    tokio::task::spawn_blocking(move || {
        // The registry is the owner console's to list. An authenticated
        // principal reads its own user record, which it always may, and is
        // offered no one else to be.
        let users = match &authenticated {
            Some(database) => vec![(selected.clone(), database.user(&selected)?)],
            None => database.users()?,
        };
        let selected_user = users
            .iter()
            .find(|(id, _)| id == &selected)
            .map(|(_, user)| user)
            .ok_or_else(|| DomainError::record_not_found("users", &selected))?;
        let selected_name = selected_user.name.clone();
        let selected_status = selected_user.status;
        let account = authenticated
            .as_ref()
            .map(|database| UiAccount::new(&selected, selected_user, database.authentication()));
        let can_switch_perspective = authenticated.is_none();
        let selected_database = match authenticated {
            Some(database) => database,
            None => database.impersonate_verified(&selected)?,
        };
        let can_view_global_audit =
            selected_database.owner_access_allowed(&AccessResource::Database)?;
        let can_read_users = selected_database
            .access_allowed(AccessAction::ReadAccess, &AccessResource::Database)?;
        let can_browse_files = selected_database.owner_access_allowed(&AccessResource::Database)?;
        let can_save_views = selected_database.owner_access_allowed(&AccessResource::Database)?;
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
                can_save_views,
                pins,
                pins_error: None,
                users,
                can_switch_perspective,
                account,
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

/// `Path`, answering a segment it cannot decode — invalid UTF-8 once
/// percent-decoded — with the error envelope rather than axum's plain-text
/// rejection, as [`json_payload`] does for a body and [`parse_query`] for a
/// query string.
#[derive(Debug)]
struct Segments<T>(T);

impl<T, S> FromRequestParts<S> for Segments<T>
where
    T: DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> ApiResult<Self> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(rejection) if rejection.status().is_server_error() => {
                Err(ApiError::internal(anyhow!(rejection.body_text())))
            }
            Err(rejection) => Err(ApiError::new(
                rejection.status(),
                "invalid_path",
                rejection.body_text(),
            )),
        }
    }
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

/// `sort` and the one-key `direction` as the keys they ask for.
fn parse_sort(
    sort: &[String],
    direction: Option<SortDirectionParameter>,
) -> ApiResult<Vec<SortKey>> {
    parse_sort_keys(sort, direction.map(SortDirection::from), "direction")
        .map_err(ApiError::from_domain)
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
    use super::{
        ApiError, INTERNAL_MESSAGE, TEXT_DIFF_PREVIEW_CHARS, TEXT_DIFF_PREVIEW_LINES, ViewIndex,
        avatar_class, initials, render_audit_changes,
    };
    use crate::{
        Database, DomainError,
        audit::{AuditChange, reset_verify_chain_calls, verify_chain_calls},
    };
    use anyhow::anyhow;
    use axum::http::StatusCode;
    use serde_json::json;

    fn replaced(before: &str, after: &str) -> String {
        render_audit_changes(
            &[AuditChange::Replace {
                path: "/body".to_owned(),
                before: json!(before),
                after: json!(after),
            }],
            true,
        )
        .into_string()
    }

    /// Notes that changed in one paragraph show that paragraph, the lines
    /// around it and the words that changed, not two copies of the notes.
    #[test]
    fn a_change_to_text_that_spans_lines_is_shown_as_a_diff() {
        let before = "# Title\n\none\ntwo\nthree\nCheck `drafts` for a draft before creating another.\nfour\nfive\nsix\nseven\n";
        let after =
            "# Title\n\none\ntwo\nthree\nCheck drafts for a draft.\nfour\nfive\nsix\nseven\n";
        let html = replaced(before, after);

        assert!(html.contains(r#"<div class="cr-diff mt-2">"#), "{html}");
        assert!(
            html.contains(r#"<div class="cr-diff-hunk">@@ -3,7 +3,7 @@</div>"#),
            "{html}"
        );
        assert!(html.contains(
            r#"<div class="cr-diff-line cr-diff-removed"><span class="cr-diff-sign">-</span><span>Check <del>`</del>drafts<del>`</del> for a draft<del> before creating another</del>.</span></div>"#
        ), "{html}");
        assert!(html.contains(
            r#"<div class="cr-diff-line cr-diff-added"><span class="cr-diff-sign">+</span><span>Check drafts for a draft.</span></div>"#
        ), "{html}");
        // Three lines of context either side, and nothing further away.
        assert!(html.contains(r#"<span class="cr-diff-sign"> </span><span>three</span>"#));
        assert!(html.contains(r#"<span class="cr-diff-sign"> </span><span>six</span>"#));
        assert!(!html.contains("Title") && !html.contains("seven"), "{html}");
        assert!(
            !html.contains("Before") && !html.contains("After"),
            "{html}"
        );
    }

    /// Lines that share almost nothing are shown whole rather than as a
    /// scatter of marked words.
    #[test]
    fn a_rewritten_line_is_not_marked_word_by_word() {
        let html = replaced("alpha beta gamma\nkept\n", "one two three\nkept\n");
        assert!(html.contains("<span>alpha beta gamma</span>"), "{html}");
        assert!(html.contains("<span>one two three</span>"), "{html}");
        assert!(!html.contains("<del>") && !html.contains("<ins>"), "{html}");
    }

    /// A single line reads fine as before and after, and so does anything
    /// that is not a string on both sides.
    #[test]
    fn a_change_to_a_single_line_keeps_before_and_after() {
        let html = replaced("open", "won");
        assert!(html.contains("Before") && html.contains("After"), "{html}");
        assert!(!html.contains("cr-diff"), "{html}");

        let html = render_audit_changes(
            &[AuditChange::Replace {
                path: "/attributes/notes".to_owned(),
                before: json!(null),
                after: json!("one\ntwo"),
            }],
            true,
        )
        .into_string();
        assert!(!html.contains("cr-diff"), "{html}");
    }

    /// A rewrite of a long document is cut short rather than repeated whole
    /// on every page that lists it, whether its lines are many or long.
    #[test]
    fn a_long_text_diff_is_elided() {
        let html = replaced(&"old\n".repeat(1_000), &"new\n".repeat(1_000));
        assert!(html.ends_with(r#"<div class="cr-diff-hunk">…</div></div></div></div>"#));
        // The lines, the hunk header among them, and then the ellipsis.
        assert_eq!(
            html.matches(r#"<div class="cr-diff-"#).count(),
            TEXT_DIFF_PREVIEW_LINES + 1,
            "{html}"
        );

        let html = replaced(
            &"old ".repeat(5_000),
            &format!("{}\n", "new ".repeat(5_000)),
        );
        assert!(html.ends_with(r#"<div class="cr-diff-hunk">…</div></div></div></div>"#));
        assert!(
            html.len() < TEXT_DIFF_PREVIEW_CHARS + 1_000,
            "{}",
            html.len()
        );
    }

    #[test]
    fn a_person_is_shown_by_the_initials_of_their_first_and_last_names() {
        let initials = |name: &str| initials(name, "ada@example.com");
        assert_eq!(initials("Ada Lovelace"), "AL");
        assert_eq!(initials("Ada"), "A");
        assert_eq!(initials("ada king lovelace"), "AL");
        assert_eq!(initials("  Grace   Hopper "), "GH");
        assert_eq!(initials("élodie ørsted"), "ÉØ");
        assert_eq!(initials(""), "A");
    }

    #[test]
    fn a_person_keeps_one_avatar_colour_however_their_id_is_spelled() {
        assert_eq!(
            avatar_class("ada@example.com"),
            avatar_class(" Ada@Example.com ")
        );
        let colours = [
            "ada@example.com",
            "grace@example.com",
            "alan@example.com",
            "edsger@example.com",
            "barbara@example.com",
            "ken@example.com",
        ]
        .map(avatar_class)
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        // Not a promise any two differ, only that the colours are spread.
        assert!(colours.len() > 1);
        assert!(
            colours
                .iter()
                .all(|class| class.starts_with("cr-avatar cr-avatar-"))
        );
    }

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
            (
                DomainError::SignatureMismatch(
                    "the signed audit checkpoint was made for a different database".to_owned(),
                ),
                StatusCode::CONFLICT,
                "signature_mismatch",
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

    /// An adapter failure is classified, so it keeps its own code, but it is a
    /// 5xx like every failure that is not the caller's, so it is published
    /// with the same generic message as an internal error.
    #[test]
    fn a_failed_sync_adapter_is_a_bad_gateway_with_a_generic_message() {
        let error = ApiError::from_domain(leaky_cause().context(DomainError::AdapterFailed(
            "sync 'daily' exited unsuccessfully (exit status: 23)".to_owned(),
        )));
        assert_eq!(error.status, StatusCode::BAD_GATEWAY);
        assert_eq!(error.code, "adapter_failed");

        let published = error.publish();
        assert_eq!(published.status, StatusCode::BAD_GATEWAY);
        assert_eq!(published.code, "adapter_failed");
        assert_eq!(published.message, INTERNAL_MESSAGE);
        assert!(!published.request_id.is_empty());
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

    /// A redirect's header cannot fail to build, so it has no error to answer
    /// with. A URL built the way the routes build one passes through untouched,
    /// and whatever else reaches it leaves with nothing that could end the
    /// header early or that a header may not carry.
    #[test]
    fn every_redirect_target_becomes_a_header_that_cannot_split_the_response() {
        use super::{
            Representation, browse_url, encode_segment, location_header, mutation_redirect,
            notice_url, record_notice_url, see_other,
        };
        use axum::http::{HeaderMap, HeaderValue, header};

        let awkward = "a b%c?d#e/f\u{e9}\u{1f600}\t\r\n\0\x7f";
        for url in [
            notice_url(awkward, awkward),
            record_notice_url(awkward, awkward, awkward),
            browse_url(awkward),
            format!(
                "/api/v1/collections/{}/records/{}",
                encode_segment(awkward),
                encode_segment(awkward)
            ),
        ] {
            assert_eq!(location_header(&url), url.as_str());
        }

        assert_eq!(
            location_header(&format!("/{awkward}")),
            "/a%20b%c?d#e/f%C3%A9%F0%9F%98%80%09%0D%0A%00%7F"
        );
        let injected = see_other("/deals\r\nSet-Cookie: session=stolen");
        assert_eq!(injected.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            injected.headers()[header::LOCATION],
            "/deals%0D%0ASet-Cookie:%20session=stolen"
        );
        assert!(!injected.headers().contains_key(header::SET_COOKIE));
        let mut htmx = HeaderMap::new();
        htmx.insert("hx-request", HeaderValue::from_static("true"));
        let injected = mutation_redirect(&Representation::requested(&htmx), "/deals\n\r");
        assert_eq!(injected.status(), StatusCode::NO_CONTENT);
        assert_eq!(injected.headers()["hx-location"], "/deals%0A%0D");

        // Every Unicode scalar value at once, so no character is left out.
        let everything: String = (0..=u32::from(char::MAX))
            .filter_map(char::from_u32)
            .collect();
        let value = location_header(&everything);
        assert!(value.as_bytes().iter().all(u8::is_ascii_graphic));
    }

    #[test]
    fn amounts_are_grouped_and_anything_else_is_left_as_written() {
        use super::group_digits;
        assert_eq!(group_digits("125000"), "125,000");
        assert_eq!(group_digits("-1234567.891"), "-1,234,567.891");
        assert_eq!(group_digits("999"), "999");
        assert_eq!(group_digits("1000"), "1,000");
        assert_eq!(group_digits("1e+21"), "1e+21");
        assert_eq!(group_digits(".inf"), ".inf");
    }

    #[test]
    fn values_read_as_the_form_shows_them() {
        use super::display_value;
        use serde_json::json;
        use yaml_serde::{Mapping, Value};
        let record: Mapping = yaml_serde::from_str("currency: EUR").unwrap();
        let amount = json!({ "type": "integer", "x-cr-unit": { "field": "currency" } });
        let percent = json!({ "type": "integer", "x-cr-unit": "%" });
        let stage = json!({ "enum": ["closed_won"] });
        let tags = json!({ "type": "array", "items": { "enum": ["key_account", "renewal"] } });
        let number = |text: &str| yaml_serde::from_str::<Value>(text).unwrap();
        assert_eq!(
            display_value(&number("84000"), Some(&amount), Some(&record)),
            "84,000\u{a0}EUR"
        );
        // An amount whose unit field is missing is still an amount.
        assert_eq!(
            display_value(&number("84000"), Some(&amount), None),
            "84,000"
        );
        assert_eq!(display_value(&number("60"), Some(&percent), None), "60%");
        // A number with no unit may be a year or a postcode: left alone.
        assert_eq!(display_value(&number("2019"), None, None), "2019");
        assert_eq!(display_value(&number("94103"), None, None), "94103");
        assert_eq!(
            display_value(&Value::String("closed_won".into()), Some(&stage), None),
            "Closed Won"
        );
        // Only an enum's values are made readable; free text is as typed.
        assert_eq!(
            display_value(&Value::String("closed_won".into()), None, None),
            "closed_won"
        );
        assert_eq!(
            display_value(&number("[key_account, renewal]"), Some(&tags), None),
            "Key Account, Renewal"
        );
        assert_eq!(display_value(&Value::Bool(true), None, None), "True");
        // However YAML spells nothing, it reads as a missing field does.
        for empty in ["''", "'  '", "null", "~", "[]", "{}"] {
            assert_eq!(display_value(&number(empty), None, None), "—", "{empty}");
        }
        assert_eq!(display_value(&number("0"), None, None), "0");
        assert_eq!(display_value(&Value::Bool(false), None, None), "False");
    }

    #[test]
    fn times_read_as_how_long_ago_they_were() {
        use super::{exact_utc, relative_time};
        use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
        let now = OffsetDateTime::parse("2026-09-23T12:00:00Z", &Rfc3339).unwrap();
        let ago = |duration: Duration| relative_time(now - duration, now);
        assert_eq!(ago(Duration::seconds(10)), "just now");
        assert_eq!(ago(Duration::seconds(-10)), "just now");
        assert_eq!(ago(Duration::seconds(50)), "1 minute ago");
        assert_eq!(ago(Duration::minutes(5)), "5 minutes ago");
        assert_eq!(ago(Duration::minutes(50)), "1 hour ago");
        assert_eq!(ago(Duration::hours(3)), "3 hours ago");
        assert_eq!(ago(Duration::hours(30)), "1 day ago");
        assert_eq!(ago(Duration::days(10)), "10 days ago");
        assert_eq!(ago(Duration::days(50)), "2 months ago");
        assert_eq!(ago(Duration::days(400)), "1 year ago");
        assert_eq!(ago(Duration::days(-3)), "in 3 days");
        assert_eq!(
            exact_utc(now - Duration::minutes(5)),
            "2026-09-23 11:55 UTC"
        );
    }
}
