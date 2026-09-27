//! The REST contract for bundle records: supporting files in create and patch
//! bodies, in every record response, and readable one at a time.

use std::fs;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    Database,
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
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
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
