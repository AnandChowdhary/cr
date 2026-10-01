//! The REST contract for bundle records: supporting files in create and patch
//! bodies, in every record response, and readable one at a time.

use std::fs;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    AccessResource, Database, Role, UserKind,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl TestResponse {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|error| {
            panic!(
                "response was not JSON: {error}\n{}",
                String::from_utf8_lossy(&self.body)
            )
        })
    }

    fn etag(&self) -> &str {
        self.headers[header::ETAG].to_str().unwrap()
    }
}

fn bundle_app() -> (TempDir, Router) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("bundles");
    Database::init(&root).unwrap();
    fs::write(
        root.join(".cr/config.yaml"),
        "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n",
    )
    .unwrap();
    let database = Database::discover(Some(&root)).unwrap();
    let app = router(database, ServerConfig::default()).unwrap();
    (temporary, app)
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    send_request(app, builder.body(Body::from(body)).unwrap()).await
}

async fn post_form(app: &Router, uri: &str, fields: &[(&str, &str)]) -> TestResponse {
    post_form_with_headers(app, uri, fields, &[]).await
}

async fn post_form_with_headers(
    app: &Router,
    uri: &str,
    fields: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        serializer.append_pair(name, value);
    }
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::from(serializer.finish())).unwrap();
    send_request(app, request).await
}

async fn send_request(app: &Router, request: Request<Body>) -> TestResponse {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    TestResponse {
        status,
        headers,
        body,
    }
}

fn hidden_field<'response>(response: &'response TestResponse, name: &str) -> &'response str {
    response
        .text()
        .split_once(&format!("name=\"{name}\" value=\""))
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
}

fn sha256(contents: &[u8]) -> String {
    let mut value = String::from("sha256:");
    for byte in Sha256::digest(contents) {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

const FONT: &[u8] = &[0x00, 0xff, 0x10, 0x80];

async fn create_skill(app: &Router) -> TestResponse {
    request(
        app,
        Method::POST,
        "/api/v1/collections/skills/records",
        Some(json!({
            "id": "pdf",
            "front_matter": { "name": "pdf", "description": "Fill PDF forms" },
            "markdown": "Run scripts/run.py.\n",
            "files": {
                "scripts/run.py": { "content": "print('hi')\n" },
                "fonts/body.ttf": { "content": "AP8QgA==", "encoding": "base64" }
            }
        })),
        &[],
    )
    .await
}

#[tokio::test]
async fn files_are_created_listed_and_read_back_byte_for_byte() {
    let (_temporary, app) = bundle_app();
    let created = create_skill(&app).await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.json());
    let record = created.json();
    assert_eq!(record["path"], "records/skills/pdf/SKILL.md");
    assert_eq!(
        record["files"],
        json!([
            { "path": "fonts/body.ttf", "hash": sha256(FONT) },
            { "path": "scripts/run.py", "hash": sha256(b"print('hi')\n") },
        ])
    );
    assert_eq!(
        created.etag(),
        format!("\"{}\"", record["version"].as_str().unwrap())
    );

    let font = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/fonts/body.ttf",
        None,
        &[],
    )
    .await;
    assert_eq!(font.status, StatusCode::OK);
    assert_eq!(font.body, FONT);
    assert_eq!(
        font.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert_eq!(font.etag(), created.etag());

    let fetched = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf",
        None,
        &[],
    )
    .await;
    assert_eq!(fetched.json()["files"], record["files"]);

    for (uri, status) in [
        (
            "/api/v1/collections/skills/records/pdf/files/missing.txt",
            StatusCode::NOT_FOUND,
        ),
        (
            "/api/v1/collections/skills/records/pdf/files/SKILL.md",
            StatusCode::NOT_FOUND,
        ),
        (
            "/api/v1/collections/skills/records/pdf/files/%2E%2E/%2E%2E/config.yaml",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let response = request(&app, Method::GET, uri, None, &[]).await;
        assert_eq!(response.status, status, "{uri}");
    }
}

#[tokio::test]
async fn a_patch_changes_files_under_the_record_s_version_in_one_event() {
    let (_temporary, app) = bundle_app();
    let created = create_skill(&app).await;
    let version = created.etag().to_owned();
    let patch = json!({
        "front_matter": { "description": "Fill and sign PDF forms" },
        "files": {
            "fonts/body.ttf": null,
            "scripts/run.py": { "content": "print('bye')\n" }
        }
    });

    let preview = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf?preview=true",
        Some(patch.clone()),
        &[("if-match", &version)],
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK);
    let preview = preview.json();
    assert_eq!(preview["files"][0]["operation"], "remove");
    assert_eq!(
        preview["files"][1]["diff"],
        "@@ -1 +1 @@\n-print('hi')\n+print('bye')\n"
    );

    let patched = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(patch.clone()),
        &[("if-match", &version)],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.json());
    assert_eq!(
        patched.json()["files"],
        json!([{ "path": "scripts/run.py", "hash": sha256(b"print('bye')\n") }])
    );

    let stale = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({ "files": { "notes.txt": { "content": "x" } } })),
        &[("if-match", &version)],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);

    let log = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?collection=skills&id=pdf&limit=1",
        None,
        &[],
    )
    .await
    .json();
    let event = &log["data"][0];
    assert_eq!(event["action"], "update");
    assert_eq!(event["version"], 4);
    assert_eq!(event["files"], preview["files"]);
}

#[tokio::test]
async fn file_requests_that_cannot_be_honoured_are_refused() {
    let (_temporary, app) = bundle_app();
    for (uri, body) in [
        (
            "/api/v1/collections/notes/records",
            json!({ "id": "one", "files": { "a.txt": { "content": "x" } } }),
        ),
        (
            "/api/v1/collections/skills/records",
            json!({ "id": "one", "files": { "a.bin": { "content": "!!", "encoding": "base64" } } }),
        ),
        (
            "/api/v1/collections/skills/records",
            json!({ "id": "one", "files": { "../escape": { "content": "x" } } }),
        ),
    ] {
        let response = request(&app, Method::POST, uri, Some(body.clone()), &[]).await;
        assert_eq!(
            response.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{body}: {}",
            response.json()
        );
    }
    let unknown = request(
        &app,
        Method::POST,
        "/api/v1/collections/skills/records",
        Some(json!({ "id": "one", "files": { "a.txt": { "content": "x", "mode": "755" } } })),
        &[],
    )
    .await;
    assert!(unknown.status.is_client_error());
}

#[tokio::test]
async fn the_record_page_lists_supporting_files_as_downloads() {
    let (_temporary, app) = bundle_app();
    create_skill(&app).await;
    let page = request(&app, Method::GET, "/skills/records/pdf", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let html = String::from_utf8(page.body).unwrap();
    assert!(html.contains(r#"id="files-heading""#), "{html}");
    assert!(
        html.contains(r#"href="/api/v1/collections/skills/records/pdf/files/scripts/run.py""#),
        "{html}"
    );
}

#[tokio::test]
async fn markdown_files_open_in_editors_and_other_files_remain_downloads() {
    let (temporary, app) = bundle_app();
    create_skill(&app).await;
    let database = Database::discover(Some(&temporary.path().join("bundles"))).unwrap();
    database
        .create_view(
            "project-docs",
            Some("Project docs"),
            "skills",
            vec![],
            vec![],
            50,
        )
        .unwrap();
    let text = "\n# Draft\n<script>alert('unsafe')</script>\n</textarea>\n";
    let patched = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {
            "references/draft & review.MD": {"content": text},
            "notes.markdown": {"content": "# Notes\n"}
        }})),
        &[],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    let page = request(&app, Method::GET, "/project-docs/records/pdf", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let uri = "/project-docs/records/pdf/files/references/draft%20%26%20review.MD";
    assert!(
        page.text().contains(
            "href=\"/project-docs/records/pdf/files/references/draft%20&amp;%20review.MD\""
        )
    );
    assert!(
        page.text()
            .contains("href=\"/project-docs/records/pdf/files/notes.markdown\"")
    );
    assert!(
        !page
            .text()
            .contains("/api/v1/collections/skills/records/pdf/files/references/")
    );
    assert!(page.text().contains(
        "href=\"/api/v1/collections/skills/records/pdf/files/fonts/body.ttf\" hx-boost=\"false\""
    ));
    assert!(page.text().contains(
        "href=\"/api/v1/collections/skills/records/pdf/files/scripts/run.py\" hx-boost=\"false\""
    ));

    for headers in [
        &[][..],
        &[("hx-request", "true"), ("hx-boosted", "true")][..],
    ] {
        let editor = request(&app, Method::GET, uri, None, headers).await;
        assert_eq!(editor.status, StatusCode::OK);
        assert!(
            editor.headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert!(editor.text().contains("data-file-editor=\"true\""));
        assert!(
            editor
                .text()
                .contains("<textarea id=\"record-file-editor\"")
        );
        assert!(editor.text().contains("class=\"cr-file-editor\">\n\n# Draft\n&lt;script&gt;alert('unsafe')&lt;/script&gt;\n&lt;/textarea&gt;\n</textarea>"));
        assert!(
            editor
                .text()
                .contains("href=\"/project-docs/records/pdf#files\"")
        );
        assert_eq!(
            hidden_field(&editor, "_expected_record_hash"),
            patched.etag().trim_matches('"')
        );
        assert!(!editor.text().contains("<script>alert('unsafe')</script>"));
    }
    let raw = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/references/draft%20%26%20review.MD",
        None,
        &[],
    )
    .await;
    assert_eq!(raw.status, StatusCode::OK);
    assert_eq!(raw.body, text.as_bytes());
    assert_eq!(
        raw.headers[header::CONTENT_TYPE],
        "application/octet-stream"
    );
}

#[tokio::test]
async fn markdown_file_saves_are_audited_without_changing_the_rest_of_the_record() {
    let (_temporary, app) = bundle_app();
    create_skill(&app).await;
    let patched = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {
            "draft.md": {"content": "# Draft\nOld text\n"},
            "windows.md": {"content": "# Windows\r\nOld text\r\n"}
        }})),
        &[],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    for (path, submitted, expected) in [
        ("draft.md", "# Draft\r\nNew text\r\n", "# Draft\nNew text\n"),
        (
            "windows.md",
            "# Windows\r\nNew text\r\n",
            "# Windows\r\nNew text\r\n",
        ),
    ] {
        let uri = format!("/skills/records/pdf/files/{path}");
        let editor = request(&app, Method::GET, &uri, None, &[]).await;
        let saved = post_form(
            &app,
            &uri,
            &[
                ("_csrf", hidden_field(&editor, "_csrf")),
                (
                    "_expected_record_hash",
                    hidden_field(&editor, "_expected_record_hash"),
                ),
                ("contents", submitted),
            ],
        )
        .await;
        assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.text());
        assert_eq!(saved.headers[header::LOCATION], uri);
        let raw = request(
            &app,
            Method::GET,
            &format!("/api/v1/collections/skills/records/pdf/files/{path}"),
            None,
            &[],
        )
        .await;
        assert_eq!(raw.body, expected.as_bytes());
        let history = request(
            &app,
            Method::GET,
            "/api/v1/audit/log?collection=skills&id=pdf&limit=1",
            None,
            &[],
        )
        .await
        .json();
        let event = &history["data"][0];
        assert_eq!(event["action"], "update");
        assert_eq!(event["source"], "api");
        assert_eq!(event["files"].as_array().unwrap().len(), 1);
        assert_eq!(event["files"][0]["path"], path);
    }
    let record = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf",
        None,
        &[],
    )
    .await
    .json();
    assert_eq!(
        record["front_matter"],
        json!({"name": "pdf", "description": "Fill PDF forms"})
    );
    assert_eq!(record["markdown"], "Run scripts/run.py.\n");
    let font = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/fonts/body.ttf",
        None,
        &[],
    )
    .await;
    assert_eq!(font.body, FONT);
    let script = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/scripts/run.py",
        None,
        &[],
    )
    .await;
    assert_eq!(script.body, b"print('hi')\n");
}

#[tokio::test]
async fn refused_markdown_file_saves_preserve_the_submitted_text() {
    let (_temporary, app) = bundle_app();
    create_skill(&app).await;
    request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {"draft.md": {"content": "# Draft\n"}}})),
        &[],
    )
    .await;
    let uri = "/skills/records/pdf/files/draft.md";
    let editor = request(&app, Method::GET, uri, None, &[]).await;
    let csrf = hidden_field(&editor, "_csrf");
    let version = hidden_field(&editor, "_expected_record_hash");
    let invalid_csrf = post_form(
        &app,
        uri,
        &[
            ("_csrf", "wrong"),
            ("_expected_record_hash", version),
            ("contents", "My <unsaved> changes"),
        ],
    )
    .await;
    assert_eq!(invalid_csrf.status, StatusCode::FORBIDDEN);
    assert!(
        invalid_csrf
            .text()
            .contains("My &lt;unsaved&gt; changes</textarea>")
    );
    let changed = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {"scripts/run.py": {"content": "Newer script\n"}}})),
        &[],
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK);
    let stale = post_form(
        &app,
        uri,
        &[
            ("_csrf", csrf),
            ("_expected_record_hash", version),
            ("contents", "My <unsaved> changes"),
        ],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert!(stale.text().contains("The file was not saved"));
    assert!(
        stale
            .text()
            .contains("My &lt;unsaved&gt; changes</textarea>")
    );
    assert_eq!(hidden_field(&stale, "_expected_record_hash"), version);
    let raw = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/draft.md",
        None,
        &[],
    )
    .await;
    assert_eq!(raw.body, b"# Draft\n");
    assert_eq!(raw.etag(), changed.etag());
}

#[tokio::test]
async fn record_file_editors_refuse_binary_oversized_missing_and_unsafe_files() {
    let (_temporary, app) = bundle_app();
    create_skill(&app).await;
    let patched = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {
            "binary.md": {"content": "AP8QgA==", "encoding": "base64"},
            "null.md": {"content": "hello\u{0000}world"},
            "large.md": {"content": "x".repeat(1024 * 1024 + 1)},
            "draft.md": {"content": "# Draft\n"}
        }})),
        &[],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.text());
    for (path, status) in [
        ("binary.md", StatusCode::UNPROCESSABLE_ENTITY),
        ("null.md", StatusCode::UNPROCESSABLE_ENTITY),
        ("large.md", StatusCode::UNPROCESSABLE_ENTITY),
        ("missing.md", StatusCode::NOT_FOUND),
        ("SKILL.md", StatusCode::NOT_FOUND),
        (
            "%2E%2E/%2E%2E/config.yaml",
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
    ] {
        let response = request(
            &app,
            Method::GET,
            &format!("/skills/records/pdf/files/{path}"),
            None,
            &[],
        )
        .await;
        assert_eq!(response.status, status, "{}", response.text());
        assert!(!response.text().contains("<textarea"));
    }
    let uri = "/skills/records/pdf/files/draft.md";
    let editor = request(&app, Method::GET, uri, None, &[]).await;
    let oversized = "x".repeat(1024 * 1024 + 1);
    let rejected = post_form(
        &app,
        uri,
        &[
            ("_csrf", hidden_field(&editor, "_csrf")),
            (
                "_expected_record_hash",
                hidden_field(&editor, "_expected_record_hash"),
            ),
            ("contents", &oversized),
        ],
    )
    .await;
    assert_eq!(rejected.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(rejected.text().contains(&oversized));
    let raw = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf/files/draft.md",
        None,
        &[],
    )
    .await;
    assert_eq!(raw.body, b"# Draft\n");
}

#[tokio::test]
async fn record_file_editors_follow_record_permissions_not_filesystem_owner_access() {
    let (temporary, app) = bundle_app();
    create_skill(&app).await;
    request(
        &app,
        Method::PATCH,
        "/api/v1/collections/skills/records/pdf",
        Some(json!({"files": {"draft.md": {"content": "# Draft\n"}}})),
        &[],
    )
    .await;
    let database = Database::discover(Some(&temporary.path().join("bundles")))
        .unwrap()
        .with_actor("owner@example.com")
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    for (principal, role) in [
        ("reader@example.com", Some(Role::Viewer)),
        ("editor@example.com", Some(Role::Editor)),
        ("stranger@example.com", None),
    ] {
        database
            .add_user(principal, principal, Some(principal), UserKind::Human)
            .unwrap();
        if let Some(role) = role {
            database
                .grant_access(principal, AccessResource::record("skills", "pdf"), role)
                .unwrap();
        }
    }
    let uri = "/skills/records/pdf/files/draft.md";
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let home = request(&app, Method::GET, "/", None, &[]).await;
    for (principal, editable) in [("reader@example.com", false), ("editor@example.com", true)] {
        let switched = post_form(
            &app,
            "/perspective",
            &[
                ("_csrf", hidden_field(&home, "_csrf")),
                ("principal", principal),
            ],
        )
        .await;
        assert_eq!(switched.status, StatusCode::SEE_OTHER);
        let cookie = switched.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let editor = request(&app, Method::GET, uri, None, &[("cookie", cookie)]).await;
        assert_eq!(editor.status, StatusCode::OK, "{}", editor.text());
        assert_eq!(editor.text().contains("autofocus readonly"), !editable);
        assert_eq!(editor.text().contains(">Save</button>"), editable);
        assert_eq!(
            editor.text().contains("data-file-editor=\"true\""),
            editable
        );
        let saved = post_form_with_headers(
            &app,
            uri,
            &[
                ("_csrf", hidden_field(&editor, "_csrf")),
                (
                    "_expected_record_hash",
                    hidden_field(&editor, "_expected_record_hash"),
                ),
                ("contents", "# Updated\n"),
            ],
            &[("cookie", cookie)],
        )
        .await;
        assert_eq!(
            saved.status,
            if editable {
                StatusCode::SEE_OTHER
            } else {
                StatusCode::FORBIDDEN
            },
            "{}",
            saved.text()
        );
    }
    let switched = post_form(
        &app,
        "/perspective",
        &[
            ("_csrf", hidden_field(&home, "_csrf")),
            ("principal", "stranger@example.com"),
        ],
    )
    .await;
    assert_eq!(switched.status, StatusCode::SEE_OTHER);
    let cookie = switched.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let denied = request(&app, Method::GET, uri, None, &[("cookie", cookie)]).await;
    assert_eq!(denied.status, StatusCode::NOT_FOUND, "{}", denied.text());
    assert!(!denied.text().contains("# Updated"));
    assert_eq!(
        database.read_file("skills", "pdf", "draft.md").unwrap().0,
        b"# Updated\n"
    );
}

/// A running server reads `.cr/config.yaml` for every request, as each command
/// does, so a collection declared as bundles after it started is not read as
/// empty. A configuration that stops loading leaves the last one that did.
#[tokio::test]
async fn a_running_server_follows_the_configuration_a_command_reads() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("bundles");
    Database::init(&root).unwrap();
    let app = router(
        Database::discover(Some(&root)).unwrap(),
        ServerConfig::default(),
    )
    .unwrap();

    // Another process declares the collection and writes a record to it.
    let config = root.join(".cr/config.yaml");
    fs::write(
        &config,
        "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n",
    )
    .unwrap();
    Database::discover(Some(&root))
        .unwrap()
        .create("skills", "pdf", &[], "Fill PDF forms.\n")
        .unwrap();
    assert!(root.join("records/skills/pdf/SKILL.md").is_file());

    let listed = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records",
        None,
        &[],
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.json()["pagination"]["total"], 1);
    let read = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records/pdf",
        None,
        &[],
    )
    .await;
    assert_eq!(read.status, StatusCode::OK, "{}", read.json());

    fs::write(&config, "version: 1\nsurprise: true\n").unwrap();
    let listed = request(
        &app,
        Method::GET,
        "/api/v1/collections/skills/records",
        None,
        &[],
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.json()["pagination"]["total"], 1);
    let ready = request(&app, Method::GET, "/ready", None, &[]).await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    let checks = ready.json()["checks"].as_array().unwrap().clone();
    assert!(
        checks.contains(&json!({ "name": "config", "ok": false, "code": "config_invalid" })),
        "{checks:?}"
    );
}
