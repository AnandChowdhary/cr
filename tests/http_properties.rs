//! Properties of `cr serve` over generated requests, and of the OpenAPI
//! document over generated collection schemas.
//!
//! Every request goes through the in-process router, as in
//! `tests/server_api.rs`, so a case costs milliseconds and needs no socket.
//! The requests are built to be near misses: real routes with awkward path
//! segments, query strings mixing real parameters with malformed ones,
//! attribution and precondition headers, and JSON bodies that are valid,
//! truncated, deeply nested, mistyped, or out of range. Whatever the request,
//!
//! - the server answers, and never with a `5xx` other than a `/ready` that is
//!   not ready;
//! - a refusal is a `4xx`, and a JSON one carries the error envelope with the
//!   response's own request ID;
//! - no response names the directory the database lives in;
//! - a refused request, and any `GET`, writes nothing; and
//! - the audit chain still verifies afterwards.
//!
//! Each seed gets a fresh database, so a seed replays exactly; the seed
//! convention is `tests/common/rng.rs`'s.

mod common;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use common::{
    generate, openapi,
    rng::{Rng, cases},
};
use cr::{
    Assignment, Attribution, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode, utf8_percent_encode};
use serde_json::{Value as Json, json};
use tower::ServiceExt;

/// A database with a little of everything: a schema'd collection, a plain
/// one, a link, and a view, behind a router.
struct Fixture {
    _temporary: tempfile::TempDir,
    /// The directory that holds the database, which no response may name.
    private: String,
    root: PathBuf,
    app: Router,
    runtime: tokio::runtime::Runtime,
    /// The form token the HTML pages carry, so generated forms can get past
    /// the CSRF check to the decoding behind it.
    csrf: String,
}

#[derive(Debug)]
struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Json {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|error| panic!("not JSON ({error}): {}", self.text()))
    }
}

/// One generated request, kept as data so a failure can print it.
#[derive(Clone, Debug)]
struct Generated {
    method: Method,
    uri: String,
    headers: Vec<(&'static str, Vec<u8>)>,
    body: Vec<u8>,
}

fn open(root: &Path) -> Database {
    Database::discover(Some(root))
        .expect("the database opens")
        .with_attribution(Attribution::default())
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let private = temporary.path().to_string_lossy().into_owned();
        let root = temporary.path().join("db");
        Database::init(&root).unwrap();
        let database = open(&root);
        database
            .set_schema(
                "people",
                &json!({
                    "type": "object",
                    "required": ["name"],
                    "properties": {
                        "name": { "type": "string", "minLength": 1 },
                        "age": { "type": "integer", "minimum": 0 },
                        "stage": { "enum": ["open", "won"] }
                    }
                }),
                false,
            )
            .unwrap();
        let assign = |text: &str| text.parse::<Assignment>().unwrap();
        database
            .create(
                "items",
                "alpha",
                &[assign("stage=open"), assign("value=10")],
                "# Alpha\n",
            )
            .unwrap();
        database
            .create("items", "beta", &[assign("stage=won")], "")
            .unwrap();
        database
            .create("people", "ada", &[assign("name=Ada"), assign("age=36")], "")
            .unwrap();
        database
            .link("items", "alpha", "related", "items", "beta")
            .unwrap();
        database
            .create_view("board", Some("Board"), "items", Vec::new(), Vec::new(), 25)
            .unwrap();

        let app = router(database, ServerConfig::default()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut fixture = Self {
            _temporary: temporary,
            private,
            root,
            app,
            runtime,
            csrf: String::new(),
        };
        let home = fixture.send(&Generated {
            method: Method::GET,
            uri: "/board".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        });
        let page = home.text();
        let marker = "name=\"_csrf\" value=\"";
        let start = page.find(marker).expect("a page carries a form token") + marker.len();
        fixture.csrf = page[start..start + page[start..].find('"').unwrap()].to_owned();
        fixture
    }

    /// Send `request`, or return `None` if it is not a request `http` can
    /// represent at all, such as a URI with a space in it.
    fn try_send(&self, request: &Generated) -> Option<Answer> {
        let mut builder = Request::builder()
            .method(request.method.clone())
            .uri(request.uri.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(*name, value.as_slice());
        }
        let built = builder.body(Body::from(request.body.clone())).ok()?;
        Some(self.runtime.block_on(async {
            let response = self.app.clone().oneshot(built).await.unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec();
            Answer {
                status,
                headers,
                body,
            }
        }))
    }

    fn send(&self, request: &Generated) -> Answer {
        self.try_send(request)
            .unwrap_or_else(|| panic!("not a representable request: {request:?}"))
    }
}

/// Every file under `root`, with its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), files);
            } else {
                files.insert(entry.path(), fs::read(entry.path()).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, &mut files);
    files
}

// ---------------------------------------------------------------------------
// Generating requests
// ---------------------------------------------------------------------------

/// Names that exist in the fixture, names that do not, and names no
/// collection, record, relation, or view may have.
const SEGMENTS: &[&str] = &[
    "items", "people", "alpha", "beta", "ada", "board", "related", "stage", "name", "ghost",
    "users", "", ".", "..", ".cr", "records", "audit", "a b", "a/b", "a\\b", "é", "🙂", "\u{0}",
    "-", "_", "a.md", "$id", "CON", "~", "{id}", "null", "?", "#", "%", "+",
];

/// What a path segment must escape: everything but unreserved characters.
const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Names the fixture has, so that half of all requests reach real records.
const EXISTING: &[&str] = &[
    "items", "people", "alpha", "beta", "ada", "board", "related", "stage",
];

fn segment(rng: &mut Rng) -> String {
    let raw = match rng.below(12) {
        0 => generate::string(rng),
        1 => "x".repeat(rng.between(200, 400)),
        2..=6 => rng.pick(EXISTING).to_string(),
        _ => rng.pick(SEGMENTS).to_string(),
    };
    match rng.below(8) {
        // Every byte escaped, dots included.
        0 => percent_encode(raw.as_bytes(), NON_ALPHANUMERIC).to_string(),
        // Escapes that decode to nothing valid.
        1 => format!(
            "{}{}",
            utf8_percent_encode(&raw, SEGMENT),
            rng.pick(&["%", "%zz", "%FF", "%C3%28", "%2F", "%00", "%2e%2e"])
        ),
        _ => utf8_percent_encode(&raw, SEGMENT).to_string(),
    }
}

/// Every route, with the methods it answers and the body it expects.
#[derive(Clone, Copy, Debug)]
enum Shape {
    Empty,
    Create,
    Patch,
    Replace,
    Link,
    Save,
    Schema,
    Form,
}

/// The query parameters each family of routes reads.
const LIST: &[&str] = &[
    "where",
    "where_expr",
    "filter",
    "select",
    "sort",
    "direction",
    "limit",
    "offset",
];
const COUNT: &[&str] = &[
    "where",
    "where_expr",
    "filter",
    "by",
    "sum",
    "avg",
    "min",
    "max",
];
const PREVIEW: &[&str] = &["preview"];
const SCHEMA: &[&str] = &["preview", "allow_violations"];
const SELECT: &[&str] = &["select"];
const BACKLINKS: &[&str] = &[
    "from",
    "relation",
    "where",
    "where_expr",
    "filter",
    "select",
    "sort",
    "direction",
    "limit",
    "offset",
];
const TRAVERSE: &[&str] = &["relation", "depth", "expand", "select"];
const SEARCH: &[&str] = &[
    "q",
    "collection",
    "where",
    "where_expr",
    "filter",
    "select",
    "sort",
    "direction",
    "target",
    "field",
    "ignore_case",
    "regex",
    "limit",
    "offset",
];
const PAGE: &[&str] = &["limit", "offset"];
const CHECK: &[&str] = &["collection", "limit", "offset"];
const AUDIT_LOG: &[&str] = &["collection", "id", "agent", "session", "limit", "offset"];
const VERIFY: &[&str] = &["expected_head"];
const BROWSE: &[&str] = &["path", "sort_field", "sort_direction"];
const BROWSE_FILE: &[&str] = &["path", "from"];
const VIEW: &[&str] = &[
    "q",
    "filter_match",
    "filter_field",
    "filter_operator",
    "filter_value",
    "sort_field",
    "sort_direction",
    "after",
    "before",
    "offset",
];
const NONE: &[&str] = &[];

/// Every route: its path, the methods it answers, the body it expects, and
/// the query parameters it reads.
type Route = (
    &'static str,
    &'static [&'static str],
    Shape,
    &'static [&'static str],
);

const ROUTES: &[Route] = &[
    ("/api/v1/identity", &["GET"], Shape::Empty, NONE),
    ("/api/v1/collections", &["GET"], Shape::Empty, PAGE),
    (
        "/api/v1/collections/{c}/count",
        &["GET"],
        Shape::Empty,
        COUNT,
    ),
    (
        "/api/v1/collections/{c}/schema",
        &["GET", "PUT", "DELETE"],
        Shape::Schema,
        SCHEMA,
    ),
    (
        "/api/v1/collections/{c}/records",
        &["GET"],
        Shape::Empty,
        LIST,
    ),
    (
        "/api/v1/collections/{c}/records",
        &["POST"],
        Shape::Create,
        PREVIEW,
    ),
    (
        "/api/v1/collections/{c}/records/{r}",
        &["GET"],
        Shape::Empty,
        SELECT,
    ),
    (
        "/api/v1/collections/{c}/records/{r}",
        &["PATCH", "DELETE"],
        Shape::Patch,
        PREVIEW,
    ),
    (
        "/api/v1/collections/{c}/records/{r}",
        &["PUT"],
        Shape::Replace,
        PREVIEW,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/document",
        &["GET"],
        Shape::Empty,
        NONE,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/fields/{f}",
        &["GET"],
        Shape::Empty,
        NONE,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/links",
        &["POST"],
        Shape::Link,
        PREVIEW,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/links/{f}/{c}/{r}",
        &["DELETE"],
        Shape::Empty,
        PREVIEW,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/backlinks",
        &["GET"],
        Shape::Empty,
        BACKLINKS,
    ),
    (
        "/api/v1/collections/{c}/records/{r}/traverse",
        &["GET"],
        Shape::Empty,
        TRAVERSE,
    ),
    ("/api/v1/search", &["GET"], Shape::Empty, SEARCH),
    ("/api/v1/status", &["GET"], Shape::Empty, PAGE),
    ("/api/v1/check", &["GET"], Shape::Empty, CHECK),
    ("/api/v1/save", &["POST"], Shape::Save, PREVIEW),
    ("/api/v1/audit/log", &["GET"], Shape::Empty, AUDIT_LOG),
    ("/api/v1/audit/head", &["GET"], Shape::Empty, NONE),
    ("/api/v1/audit/verify", &["GET"], Shape::Empty, VERIFY),
    ("/api/v1/audit/baseline", &["POST"], Shape::Empty, NONE),
    ("/openapi.json", &["GET"], Shape::Empty, NONE),
    ("/health", &["GET"], Shape::Empty, NONE),
    ("/ready", &["GET"], Shape::Empty, NONE),
    ("/static/{f}", &["GET"], Shape::Empty, NONE),
    ("/", &["GET"], Shape::Empty, NONE),
    ("/audit", &["GET"], Shape::Empty, AUDIT_LOG),
    ("/users", &["GET"], Shape::Empty, NONE),
    ("/browse", &["GET"], Shape::Empty, BROWSE),
    ("/browse/edit", &["GET", "POST"], Shape::Form, BROWSE_FILE),
    ("/browse/delete", &["GET", "POST"], Shape::Form, BROWSE_FILE),
    ("/browse/pin", &["POST"], Shape::Form, NONE),
    ("/perspective", &["POST"], Shape::Form, NONE),
    ("/{v}", &["GET"], Shape::Empty, VIEW),
    ("/{v}/save-view", &["POST"], Shape::Form, NONE),
    ("/{v}/edit", &["GET", "POST"], Shape::Form, NONE),
    ("/{v}/delete", &["GET", "POST"], Shape::Form, NONE),
    ("/{v}/new", &["GET"], Shape::Empty, NONE),
    ("/{v}/records", &["POST"], Shape::Form, NONE),
    ("/{v}/records/{r}", &["GET", "POST"], Shape::Form, NONE),
    ("/{v}/records/{r}/move", &["POST"], Shape::Form, NONE),
    ("/{v}/records/{r}/relations", &["POST"], Shape::Form, NONE),
    (
        "/{v}/records/{r}/delete",
        &["GET", "POST"],
        Shape::Form,
        NONE,
    ),
];

/// Query parameter names: every one some route accepts, and a few none does.
const PARAMETERS: &[&str] = &[
    "limit",
    "offset",
    "where",
    "where_expr",
    "filter",
    "select",
    "sort",
    "direction",
    "preview",
    "allow_violations",
    "q",
    "collection",
    "target",
    "field",
    "ignore_case",
    "regex",
    "from",
    "relation",
    "depth",
    "expand",
    "by",
    "sum",
    "avg",
    "min",
    "max",
    "expected_head",
    "id",
    "agent",
    "session",
    "path",
    "sort_field",
    "sort_direction",
    "filter_field",
    "filter_operator",
    "filter_value",
    "filter_match",
    "after",
    "before",
    "unknown",
    "",
    "limit[]",
];

fn parameter_value(rng: &mut Rng) -> String {
    match rng.below(10) {
        0 => rng
            .pick(&[
                "0",
                "1",
                "-1",
                "18446744073709551616",
                "1e3",
                "",
                "true",
                "yes",
                "desc",
                "asc",
            ])
            .to_string(),
        1 => rng
            .pick(&[
                "stage = open",
                "NOT (value > 5 OR stage in [open, won])",
                "stage=open",
                "value>=10",
                "stage,value:desc",
                "$id,stage",
                "related",
                "document",
                "front_matter",
                "records/items/alpha.md",
                "../../etc/passwd",
                "(((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((((a = 1",
            ])
            .to_string(),
        2 => "(".repeat(rng.between(60, 5000)),
        3 => generate::noise(rng, 20),
        _ => generate::string(rng),
    }
}

/// A query string of the parameters a route reads, now and then with one it
/// does not, or with broken encoding.
fn query(rng: &mut Rng, reads: &[&'static str]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for _ in 0..rng.below(5) {
        let name = if reads.is_empty() || rng.chance(1, 5) {
            *rng.pick(PARAMETERS)
        } else {
            *rng.pick(reads)
        };
        serializer.append_pair(name, &parameter_value(rng));
    }
    let mut query = serializer.finish();
    if rng.chance(1, 5) {
        query.push_str(rng.pick(&["&", "&&", "=", "%", "%zz", "%FF", "+", "&limit", "&=x", "#"]));
    }
    query
}

/// A well-formed version that matches no record. `If-Match: *` is the
/// generated precondition that holds.
fn version(rng: &mut Rng) -> String {
    let hex: String = (0..64)
        .map(|_| char::from(b"0123456789abcdef"[rng.below(16)]))
        .collect();
    format!("sha256:{hex}")
}

fn headers(rng: &mut Rng, request: &mut Generated) {
    let text = |rng: &mut Rng| -> Vec<u8> {
        match rng.below(4) {
            0 => (0..rng.below(40)).map(|_| rng.next() as u8).collect(),
            1 => "x".repeat(rng.between(1000, 5000)).into_bytes(),
            _ => generate::string(rng).into_bytes(),
        }
    };
    let count = if rng.chance(1, 2) {
        0
    } else {
        rng.between(1, 4)
    };
    for _ in 0..count {
        let (name, value): (&'static str, Vec<u8>) = match rng.below(12) {
            0 => ("x-cr-actor", text(rng)),
            1 => (
                "x-cr-agent",
                rng.pick(&[
                    &b"claude-code"[..],
                    b"none",
                    br#"{"name":"claude-code","session":"s1"}"#,
                    br#"{"name":1}"#,
                    b"{",
                ])
                .to_vec(),
            ),
            2 => (
                "x-cr-authorization",
                rng.pick(&[
                    &b"direct"[..],
                    b"delegated",
                    b"bogus",
                    br#"{"mode":"interactive"}"#,
                ])
                .to_vec(),
            ),
            3 => (
                "x-cr-intent",
                rng.pick(&[
                    &br#"{"request":"tidy up"}"#[..],
                    concat!("{\"request\":\"\\", "u00e9\"}").as_bytes(),
                    "{\"request\":\"é\"}".as_bytes(),
                    b"[]",
                ])
                .to_vec(),
            ),
            4 => ("x-cr-approved-changes", version(rng).into_bytes()),
            5 => (
                "if-match",
                match rng.below(4) {
                    0 => b"*".to_vec(),
                    1 => format!("\"{}\"", version(rng)).into_bytes(),
                    2 => format!("W/\"{}\", \"x\"", version(rng)).into_bytes(),
                    _ => text(rng),
                },
            ),
            6 => (
                "idempotency-key",
                match rng.below(3) {
                    0 => rng
                        .pick(&[
                            &b"550e8400-e29b-41d4-a716-446655440000"[..],
                            b"1d94a86a-10af-4cc0-a255-1d451d52d6ff",
                        ])
                        .to_vec(),
                    _ => text(rng),
                },
            ),
            7 => ("cookie", [b"cr_perspective=".to_vec(), text(rng)].concat()),
            8 => ("authorization", [b"Bearer ".to_vec(), text(rng)].concat()),
            9 => (
                "content-type",
                rng.pick(&[
                    &b"application/json"[..],
                    b"text/plain",
                    b"application/x-www-form-urlencoded",
                    b"multipart/form-data; boundary=x",
                    b"application/json; charset=latin1",
                ])
                .to_vec(),
            ),
            10 => (
                "accept",
                rng.pick(&[
                    &b"text/html"[..],
                    b"application/json",
                    b"text/markdown",
                    b"*/*",
                ])
                .to_vec(),
            ),
            _ => ("hx-request", b"true".to_vec()),
        };
        request.headers.push((name, value));
    }
}

/// Front matter as JSON: generated values, plus now and then nesting at and
/// past the depth a record may have.
fn front_matter(rng: &mut Rng) -> Json {
    let mut object = serde_json::to_value(generate::mapping(rng, 2)).unwrap_or_else(|_| json!({}));
    if rng.chance(1, 6) {
        let mut value = json!("leaf");
        for _ in 1..*rng.pick(&[64, 65, 121, 126]) {
            value = json!({ "k": value });
        }
        object["deep"] = value;
    }
    if rng.chance(1, 6) {
        object["stage"] = json!(*rng.pick(&["open", "won", "a\nb\u{2028}", "a\n\n\u{2029}"]));
    }
    object
}

fn json_body(rng: &mut Rng, shape: Shape) -> Json {
    let record = |rng: &mut Rng| {
        format!(
            "{}/{}",
            rng.pick(&["items", "people", "ghost"]),
            rng.pick(&["alpha", "beta", "ada", "x"])
        )
    };
    match shape {
        Shape::Create => json!({
            "id": if rng.chance(1, 2) { format!("new{}", rng.below(100)) } else { rng.pick(SEGMENTS).to_string() },
            "front_matter": front_matter(rng),
            "markdown": generate::body(rng),
        }),
        Shape::Patch => json!({
            "front_matter": front_matter(rng),
            "remove": [rng.pick(&["stage", "value", "a..b", "", "deep.k"])],
            "markdown": generate::body(rng),
        }),
        Shape::Replace => json!({
            "front_matter": front_matter(rng),
            "markdown": generate::body(rng),
        }),
        Shape::Link => json!({
            "relation": rng.pick(SEGMENTS),
            "target_collection": rng.pick(&["items", "people", "ghost", ""]),
            "target_id": rng.pick(&["alpha", "beta", "ada", "x", ".."]),
        }),
        Shape::Save => json!({
            "records": [record(rng)],
            "all": rng.chance(1, 2),
            "message": generate::string(rng),
        }),
        Shape::Schema => collection_schema(rng),
        Shape::Empty | Shape::Form => json!({}),
    }
}

/// Damage a JSON document the way a client can: a wrong type, a stray field,
/// a missing one, truncation, nesting past the parser's limit, numbers out of
/// range, invalid UTF-8, or no document at all.
fn damage(rng: &mut Rng, value: Json) -> Vec<u8> {
    let mut value = value;
    match rng.below(12) {
        0 => {
            if let Some(object) = value.as_object_mut()
                && let Some(key) = object.keys().next().cloned()
            {
                object.remove(&key);
            }
        }
        1 => {
            if let Some(object) = value.as_object_mut()
                && let Some(key) = object.keys().next().cloned()
            {
                object.insert(
                    key,
                    rng.pick(&[
                        json!(1),
                        json!([]),
                        json!(null),
                        json!(true),
                        json!("x"),
                        json!({}),
                    ])
                    .clone(),
                );
            }
        }
        2 => value["unexpected"] = json!(1),
        3 => value = json!([value]),
        4 => {
            let depth = rng.between(100, 3000);
            return format!("{}1{}", "[".repeat(depth), "]".repeat(depth)).into_bytes();
        }
        5 => {
            let text = value.to_string();
            let cut = rng.below(text.len().max(1));
            return text.as_bytes()[..cut].to_vec();
        }
        6 => {
            let number = *rng.pick(&[
                "1e400",
                "-1e400",
                "18446744073709551616",
                "-0",
                "1.7976931348623157e309",
            ]);
            return value
                .to_string()
                .replacen("{", &format!("{{\"n\":{number},"), 1)
                .replace(",}", "}")
                .into_bytes();
        }
        7 => {
            let mut bytes = value.to_string().into_bytes();
            let at = rng.below(bytes.len() + 1);
            bytes.splice(at..at, [0xff, 0xfe]);
            return bytes;
        }
        8 => return br#"{"id":"\ud800","front_matter":{}}"#.to_vec(),
        9 => {
            return rng
                .pick(&[&b""[..], b"null", b"\xef\xbb\xbf{}", b"{} trailing"])
                .to_vec();
        }
        _ => {}
    }
    value.to_string().into_bytes()
}

const FORM_FIELDS: &[&str] = &[
    "_csrf",
    "name",
    "title",
    "filter_match",
    "filter_field",
    "filter_operator",
    "filter_value",
    "sort_field",
    "sort_direction",
    "column",
    "layout",
    "group_by",
    "expected_record_hash",
    "relation",
    "target",
    "path",
    "from",
    "contents",
    "expected_version",
    "principal",
    "id",
    "front_matter",
    "markdown",
    "field.stage",
    "structured",
    "x",
];

fn form_body(rng: &mut Rng, csrf: &str) -> Vec<u8> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    if rng.chance(2, 3) {
        serializer.append_pair("_csrf", csrf);
    }
    for _ in 0..rng.below(6) {
        let name = *rng.pick(FORM_FIELDS);
        let value = match name {
            "path" | "from" => rng
                .pick(&[
                    "records/items/alpha.md",
                    "records/items/new.md",
                    ".cr/config.yaml",
                    "../x",
                    "",
                    "records",
                ])
                .to_string(),
            "contents" => format!(
                "---\nstage: {}\n---\n{}",
                generate::string(rng),
                generate::body(rng)
            ),
            "front_matter" => serde_json::to_string(&front_matter(rng)).unwrap(),
            _ => parameter_value(rng),
        };
        serializer.append_pair(name, &value);
    }
    serializer.finish().into_bytes()
}

fn generated_request(rng: &mut Rng, csrf: &str) -> Generated {
    let (template, methods, shape, reads) = *rng.pick(ROUTES);
    let mut path = String::new();
    for part in template.split('/').skip(1) {
        path.push('/');
        if part.starts_with('{') {
            path.push_str(&segment(rng));
        } else {
            path.push_str(part);
        }
    }
    if rng.chance(1, 12) {
        path.push_str(rng.pick(&["/", "//", "/extra", "/.."]));
    }
    let mut uri = path;
    if rng.chance(2, 5) {
        uri.push('?');
        uri.push_str(&query(rng, reads));
    }
    let method = if rng.chance(1, 12) {
        rng.pick(&[
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ])
        .clone()
    } else {
        Method::from_bytes(rng.pick(methods).as_bytes()).unwrap()
    };
    let mut request = Generated {
        method: method.clone(),
        uri,
        headers: Vec::new(),
        body: Vec::new(),
    };
    let wants_body =
        !matches!(method, Method::GET | Method::HEAD | Method::DELETE) || rng.chance(1, 10);
    if wants_body {
        match shape {
            Shape::Form => {
                request.headers.push((
                    "content-type",
                    b"application/x-www-form-urlencoded".to_vec(),
                ));
                request.body = form_body(rng, csrf);
            }
            _ => {
                request
                    .headers
                    .push(("content-type", b"application/json".to_vec()));
                let body = json_body(rng, shape);
                request.body = if rng.chance(1, 4) {
                    damage(rng, body)
                } else {
                    body.to_string().into_bytes()
                };
            }
        }
    }
    headers(rng, &mut request);
    request
}

// ---------------------------------------------------------------------------
// The request properties
// ---------------------------------------------------------------------------

/// Check one answer against every property in the module comment.
fn assert_answer_is_acceptable(fixture: &Fixture, request: &Generated, answer: &Answer) {
    let context = || {
        format!(
            "{} {}\nheaders: {:?}\nbody: {}\n=> {} {}",
            request.method,
            request.uri,
            request
                .headers
                .iter()
                .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value)))
                .collect::<Vec<_>>(),
            String::from_utf8_lossy(&request.body[..request.body.len().min(400)]),
            answer.status,
            answer.text().chars().take(400).collect::<String>()
        )
    };
    // `/ready` answers 503 when the database is not ready; it is the one
    // route whose 5xx is an answer rather than a failure.
    let readiness =
        request.uri.starts_with("/ready") && answer.status == StatusCode::SERVICE_UNAVAILABLE;
    assert!(
        !answer.status.is_server_error() || readiness,
        "server error\n{}",
        context()
    );
    assert!(
        !answer.text().contains(&fixture.private),
        "the response names the database directory\n{}",
        context()
    );
    for (name, value) in &answer.headers {
        assert!(
            !String::from_utf8_lossy(value.as_bytes()).contains(&fixture.private),
            "header {name} names the database directory\n{}",
            context()
        );
    }
    // A `HEAD` answer has headers and no body, so it has no envelope either.
    if answer.status.is_client_error() && request.method != Method::HEAD {
        let content_type = answer
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if content_type.starts_with("application/json") {
            let envelope = answer.json();
            let error = &envelope["error"];
            assert!(
                error["code"].as_str().is_some_and(|code| !code.is_empty())
                    && error["message"]
                        .as_str()
                        .is_some_and(|message| !message.is_empty()),
                "a refusal without the error envelope\n{}",
                context()
            );
            assert_eq!(
                error["request_id"].as_str(),
                answer
                    .headers
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok()),
                "the envelope's request ID is not the response's\n{}",
                context()
            );
        } else {
            assert!(
                content_type.starts_with("text/html"),
                "a refusal that is neither JSON nor HTML ({content_type:?})\n{}",
                context()
            );
        }
    }
}

/// Generated requests are answered without a server error, refusals are
/// classified and write nothing, reads write nothing, no response names the
/// database directory, and the audit chain verifies throughout.
#[test]
fn generated_requests_are_refused_cleanly_and_refusals_write_nothing() {
    for mut case in cases(
        "generated_requests_are_refused_cleanly_and_refusals_write_nothing",
        30,
    ) {
        let rng = &mut case.rng;
        let fixture = Fixture::new();
        for _ in 0..30 {
            let request = generated_request(rng, &fixture.csrf);
            let before = snapshot(&fixture.root);
            let Some(answer) = fixture.try_send(&request) else {
                continue;
            };
            assert_answer_is_acceptable(&fixture, &request, &answer);
            let refused = answer.status.is_client_error();
            let read = matches!(request.method, Method::GET | Method::HEAD);
            if refused || read {
                assert!(
                    snapshot(&fixture.root) == before,
                    "{} {} => {} changed the database",
                    request.method,
                    request.uri,
                    answer.status
                );
            }
            if refused && !read {
                open(&fixture.root)
                    .audit_verify(None)
                    .unwrap_or_else(|error| {
                        panic!("{} {}: {error:#}", request.method, request.uri)
                    });
            }
        }
        open(&fixture.root)
            .audit_verify(None)
            .unwrap_or_else(|error| panic!("{error:#}"));
    }
}

fn get(uri: &str) -> Generated {
    Generated {
        method: Method::GET,
        uri: uri.to_owned(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}

fn post_json(uri: &str, body: &Json) -> Generated {
    Generated {
        method: Method::POST,
        uri: uri.to_owned(),
        headers: vec![("content-type", b"application/json".to_vec())],
        body: body.to_string().into_bytes(),
    }
}

/// Found by `generated_requests_are_refused_cleanly_and_refusals_write_nothing`
/// before the parser bounded its nesting: a thousand `(` overflowed the stack
/// of the thread parsing the filter, which aborts the whole process.
#[test]
fn a_filter_of_ten_thousand_parentheses_is_a_422_and_the_server_keeps_answering() {
    let fixture = Fixture::new();
    let filter = format!("{}stage = open{}", "(".repeat(10_000), ")".repeat(10_000));
    let uri = format!(
        "/api/v1/collections/items/records?{}",
        form_urlencoded::Serializer::new(String::new())
            .append_pair("filter", &filter)
            .finish()
    );
    let answer = fixture.send(&get(&uri));
    assert_eq!(answer.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answer.json()["error"]["code"], "validation_failed");
    assert_eq!(
        fixture
            .send(&get("/api/v1/collections/items/records"))
            .status,
        StatusCode::OK
    );
}

/// Found by `generated_requests_are_refused_cleanly_and_refusals_write_nothing`:
/// a name longer than a directory entry may be failed in the filesystem
/// unclassified, so every route that took one answered `500`.
#[test]
fn a_collection_or_record_named_with_300_bytes_is_a_422_not_a_500() {
    let fixture = Fixture::new();
    let long = "x".repeat(300);
    let before = snapshot(&fixture.root);
    for request in [
        get(&format!("/api/v1/collections/{long}/count")),
        get(&format!("/api/v1/collections/{long}/records")),
        get(&format!("/api/v1/collections/items/records/{long}")),
        post_json(
            "/api/v1/collections/items/records",
            &json!({ "id": long, "front_matter": {} }),
        ),
        post_json(
            &format!("/api/v1/collections/{long}/records"),
            &json!({ "id": "short", "front_matter": {} }),
        ),
        Generated {
            method: Method::PUT,
            uri: format!("/api/v1/collections/{long}/schema"),
            headers: vec![("content-type", b"application/json".to_vec())],
            body: b"{\"type\":\"object\"}".to_vec(),
        },
    ] {
        let answer = fixture.send(&request);
        assert_eq!(
            answer.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{} {}: {}",
            request.method,
            request.uri,
            answer.text()
        );
        assert!(
            answer.json()["error"]["message"]
                .as_str()
                .unwrap()
                .ends_with("has a name the filesystem cannot store, because it is too long or holds a NUL byte"),
            "{}",
            answer.text()
        );
    }
    assert!(snapshot(&fixture.root) == before);
}

/// Found by `generated_requests_are_refused_cleanly_and_refusals_write_nothing`:
/// axum's own path rejection answered in plain text, without the envelope or
/// the request ID a client quotes.
#[test]
fn a_path_segment_of_percent_ff_is_a_400_in_the_error_envelope() {
    let fixture = Fixture::new();
    for uri in [
        "/api/v1/collections/%FF/records",
        "/api/v1/collections/items/records/alpha%C3%28",
        "/board%FF",
        "/static/%FF",
    ] {
        let answer = fixture.send(&get(uri));
        assert_eq!(
            answer.status,
            StatusCode::BAD_REQUEST,
            "{uri}: {}",
            answer.text()
        );
        let envelope = answer.json();
        assert_eq!(envelope["error"]["code"], "invalid_path", "{uri}");
        assert_eq!(
            envelope["error"]["request_id"].as_str(),
            answer.headers["x-request-id"].to_str().ok()
        );
    }
}

/// Found by `generated_requests_are_refused_cleanly_and_refusals_write_nothing`
/// (seed 191 at `CR_PROPERTY_SCALE=20`): a patch reads the collection's schema
/// before it validates the collection name, and the filesystem layer refused
/// the NUL unclassified.
#[test]
fn a_patch_to_the_collection_percent_00_is_a_422_not_a_500() {
    let fixture = Fixture::new();
    let request = Generated {
        method: Method::PATCH,
        uri: "/api/v1/collections/%00/records/alpha".to_owned(),
        headers: vec![("content-type", b"application/json".to_vec())],
        body: br#"{"front_matter":{"stage":"won"}}"#.to_vec(),
    };
    let before = snapshot(&fixture.root);
    let answer = fixture.send(&request);
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.text()
    );
    assert_eq!(answer.json()["error"]["code"], "validation_failed");
    assert!(snapshot(&fixture.root) == before);
}

/// Front matter nested 121 levels deep fits in a JSON request, and used to be
/// written with an audit event too deep for the journal reader, after which
/// every request to the database failed. It is refused, and the database
/// keeps answering.
#[test]
fn a_create_nesting_front_matter_121_levels_deep_is_refused_and_the_database_stays_readable() {
    let fixture = Fixture::new();
    let mut value = json!("leaf");
    for _ in 1..121 {
        value = json!({ "k": value });
    }
    let answer = fixture.send(&post_json(
        "/api/v1/collections/items/records",
        &json!({ "id": "deep", "front_matter": { "deep": value } }),
    ));
    assert_eq!(
        answer.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        answer.text()
    );
    assert_eq!(
        answer.json()["error"]["message"],
        "front matter nests more than 64 levels deep"
    );
    assert_eq!(
        fixture
            .send(&get("/api/v1/collections/items/records"))
            .status,
        StatusCode::OK
    );
    open(&fixture.root).audit_verify(None).unwrap();
}

/// A value ending in a line separator after a line break was answered with
/// `500`, because the rendered record could not be read back. It is created;
/// the one form the emitter cannot write back exactly is a `422`.
#[test]
fn a_create_whose_value_ends_in_a_line_separator_is_not_a_500() {
    let fixture = Fixture::new();
    let created = fixture.send(&post_json(
        "/api/v1/collections/items/records",
        &json!({ "id": "separated", "front_matter": { "notes": "first\nsecond\u{2028}" } }),
    ));
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());
    assert_eq!(
        created.json()["front_matter"]["notes"],
        "first\nsecond\u{2028}"
    );

    let refused = fixture.send(&post_json(
        "/api/v1/collections/items/records",
        &json!({ "id": "unwritable", "front_matter": { "notes": "first\n\n\u{2028}" } }),
    ));
    assert_eq!(
        refused.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        refused.text()
    );
    open(&fixture.root).audit_verify(None).unwrap();
}

// ---------------------------------------------------------------------------
// The OpenAPI document
// ---------------------------------------------------------------------------

/// A property schema of any JSON Schema type, nested at most `depth` levels.
fn property_schema(rng: &mut Rng, depth: usize) -> Json {
    let mut schema = match rng.below(10) {
        0 => json!({ "type": "string", "minLength": rng.below(3), "maxLength": 40 }),
        1 => json!({ "type": "string", "enum": ["open", "won", "é", ""] }),
        2 => {
            json!({ "type": "string", "format": rng.pick(&["date", "email", "date-time", "uri"]) })
        }
        3 => json!({ "type": "integer", "minimum": 0 }),
        4 => json!({ "type": "number", "exclusiveMaximum": 1e300 }),
        5 => json!({ "type": "boolean" }),
        6 => json!({ "type": ["string", "null"] }),
        7 => json!({ "type": "array", "items": property_schema(rng, depth.saturating_sub(1)) }),
        8 if depth > 0 => object_schema(rng, depth - 1),
        _ => json!({ "enum": [1, "1", null, true, [], {}] }),
    };
    if rng.chance(1, 4) {
        schema["description"] = json!(generate::string(rng));
    }
    schema
}

fn object_schema(rng: &mut Rng, depth: usize) -> Json {
    let mut properties = serde_json::Map::new();
    for _ in 0..rng.below(5) {
        properties.insert(generate::string(rng), property_schema(rng, depth));
    }
    let required: Vec<&String> = properties.keys().filter(|_| rng.chance(1, 3)).collect();
    let mut schema = json!({ "type": "object", "properties": properties, "required": required });
    if rng.chance(1, 3) {
        schema["additionalProperties"] = json!(rng.chance(1, 2));
    }
    schema
}

/// A collection schema as a user might install one: usually an object
/// schema, sometimes `true` or `false`, sometimes with `x-cr-ui` ordering, and
/// sometimes with local definitions, which carry an `$id` so the embedded
/// schema is its own resource (see the ignored test below for the case
/// without).
fn collection_schema(rng: &mut Rng) -> Json {
    if rng.chance(1, 10) {
        return json!(rng.chance(1, 2));
    }
    let mut schema = object_schema(rng, 2);
    if rng.chance(1, 3) {
        let order: Vec<Json> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .map(|key| json!(key))
            .collect();
        schema["x-cr-ui"] = json!({ "order": order });
    }
    if rng.chance(1, 3) {
        let name = *rng.pick(&["stage", "a b", "é", "a/b", "a~b"]);
        let pointer = name.replace('~', "~0").replace('/', "~1");
        schema["$id"] = json!(format!("https://example.com/schemas/{}", rng.below(1000)));
        schema["$defs"] = json!({ name: property_schema(rng, 1) });
        schema["properties"]["defined"] =
            json!({ "$ref": format!("#/$defs/{}", utf8_percent_encode(&pointer, SEGMENT)) });
    }
    if rng.chance(1, 4) {
        schema["title"] = json!(generate::string(rng));
    }
    schema
}

const COLLECTION_NAMES: &[&str] = &[
    "deals", "people", "a-b", "a_b", "a.b", "A", "é", "日本", "x1", "users", "", "..", ".cr", "a b",
];

/// For generated collection schemas installed through the schema API, the
/// document is JSON, every reference in it resolves, every path's parameters
/// are unique and match its template, operation IDs are unique, and each
/// collection maps to exactly the schema it installed.
#[test]
fn the_openapi_document_stays_well_formed_for_generated_collection_schemas() {
    for mut case in cases(
        "the_openapi_document_stays_well_formed_for_generated_collection_schemas",
        30,
    ) {
        let rng = &mut case.rng;
        let fixture = Fixture::new();
        let mut installed = BTreeMap::new();
        for _ in 0..rng.between(1, 4) {
            let name = *rng.pick(COLLECTION_NAMES);
            let schema = collection_schema(rng);
            let uri = format!(
                "/api/v1/collections/{}/schema",
                utf8_percent_encode(name, SEGMENT)
            );
            let request = Generated {
                method: Method::PUT,
                uri,
                headers: vec![("content-type", b"application/json".to_vec())],
                body: schema.to_string().into_bytes(),
            };
            let answer = fixture.send(&request);
            assert_answer_is_acceptable(&fixture, &request, &answer);
            if answer.status.is_success() {
                installed.insert(name.to_owned(), schema);
            }
        }

        let answer = fixture.send(&get("/openapi.json"));
        assert_eq!(answer.status, StatusCode::OK);
        let document = answer.json();
        openapi::assert_references_resolve(&document);
        openapi::assert_operations_are_unambiguous(&document);

        let mapping = document["x-cr-collection-schemas"].as_object().unwrap();
        let mut components = std::collections::BTreeSet::new();
        for (name, schema) in &installed {
            let reference = mapping[name.as_str()].as_str().unwrap();
            assert!(
                components.insert(reference.to_owned()),
                "{reference} is shared"
            );
            let embedded = document
                .pointer(reference.strip_prefix('#').unwrap())
                .unwrap_or_else(|| panic!("{reference} does not resolve"));
            assert_eq!(embedded, schema, "collection {name:?}");
        }
    }
}

/// A collection schema with `$defs` and no `$id` is embedded verbatim, so its
/// `#/$defs/...` reference points at the root of the OpenAPI document, where
/// there are no `$defs`. JSON Schema tooling reading the document cannot
/// resolve it. See the `TODO.md` entry "Resolve collection schemas' local
/// references inside the OpenAPI document".
#[test]
#[ignore = "the OpenAPI document embeds collection schemas without rebasing their local references; see TODO.md"]
fn a_collection_schema_with_local_definitions_resolves_inside_the_openapi_document() {
    let fixture = Fixture::new();
    let request = Generated {
        method: Method::PUT,
        uri: "/api/v1/collections/deals/schema".to_owned(),
        headers: vec![("content-type", b"application/json".to_vec())],
        body: json!({
            "type": "object",
            "$defs": { "stage": { "enum": ["open", "won"] } },
            "properties": { "stage": { "$ref": "#/$defs/stage" } }
        })
        .to_string()
        .into_bytes(),
    };
    assert_eq!(fixture.send(&request).status, StatusCode::OK);
    let document = fixture.send(&get("/openapi.json")).json();
    openapi::assert_references_resolve(&document);
}
