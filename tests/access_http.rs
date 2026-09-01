use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    AccessResource, Assignment, AuditFilter, Database, Role, UserKind,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "Owner <owner@example.com>";

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
        serde_json::from_slice(&self.body).unwrap()
    }
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<String>,
    content_type: Option<&str>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body.unwrap_or_default())).unwrap())
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

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

fn csrf(html: &str) -> &str {
    html.split_once("name=\"_csrf\" value=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
}

fn perspective_cookie(response: &TestResponse) -> String {
    response.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split_once(';')
        .unwrap()
        .0
        .to_owned()
}

fn seeded_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name))
        .unwrap()
        .with_actor(OWNER)
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .create(
            "deals",
            "public",
            &[Assignment::from_str("stage=open").unwrap()],
            "Visible",
        )
        .unwrap();
    database
        .create(
            "deals",
            "secret",
            &[Assignment::from_str("stage=open").unwrap()],
            "Hidden",
        )
        .unwrap();
    for (id, name) in [
        ("reader@example.com", "Reader"),
        ("editor@example.com", "Editor"),
    ] {
        database
            .add_user(id, name, Some(id), UserKind::Human)
            .unwrap();
    }
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "public"),
            Role::Viewer,
        )
        .unwrap();
    database
        .grant_access(
            "editor@example.com",
            AccessResource::collection("deals"),
            Role::Editor,
        )
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn owner_switches_user_perspectives_and_the_ui_matches_each_policy() {
    let (_temporary, database) = seeded_database("perspective-ui");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let home = request(&app, Method::GET, "/", None, None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("aria-label=\"View as user\""));
    assert!(home.text().contains("Owner — owner"));
    assert!(home.text().contains("Reader — viewer · scoped"));
    assert!(!home.text().contains("records/users"));
    let csrf = csrf(home.text()).to_owned();

    let selected_reader = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "reader@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[],
    )
    .await;
    assert_eq!(selected_reader.status, StatusCode::SEE_OTHER);
    assert_eq!(selected_reader.headers[header::LOCATION], "/");
    let reader_cookie = perspective_cookie(&selected_reader);

    let reader_view = request(
        &app,
        Method::GET,
        "/deals",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(reader_view.status, StatusCode::OK);
    assert!(
        reader_view
            .text()
            .contains("Viewing as <strong>Reader</strong>")
    );
    assert!(reader_view.text().contains("public"));
    assert!(!reader_view.text().contains("secret"));
    assert!(!reader_view.text().contains("New record"));
    assert!(!reader_view.text().contains("Audit log"));
    assert_eq!(reader_view.headers[header::VARY], "Cookie");

    let reader_record = request(
        &app,
        Method::GET,
        "/deals/records/public",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(reader_record.status, StatusCode::OK);
    assert!(reader_record.text().contains("View public"));
    assert!(reader_record.text().contains("Read-only perspective"));
    assert!(!reader_record.text().contains("Save changes"));
    assert!(!reader_record.text().contains("Delete this record"));

    let secret = request(
        &app,
        Method::GET,
        "/deals/records/secret",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(secret.status, StatusCode::FORBIDDEN);

    let reader_identity = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await
    .json();
    assert_eq!(reader_identity["principal"], "reader@example.com");
    assert_eq!(
        reader_identity["impersonated_by"]["principal"],
        "owner@example.com"
    );

    let selected_editor = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "editor@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(selected_editor.status, StatusCode::SEE_OTHER);
    let editor_cookie = perspective_cookie(&selected_editor);

    let editor_view = request(
        &app,
        Method::GET,
        "/deals",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(editor_view.status, StatusCode::OK);
    assert!(editor_view.text().contains("public"));
    assert!(editor_view.text().contains("secret"));
    assert!(editor_view.text().contains("New record"));

    let editor_record = request(
        &app,
        Method::GET,
        "/deals/records/public",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert!(editor_record.text().contains("Edit public"));
    assert!(editor_record.text().contains("Save changes"));
    assert!(!editor_record.text().contains("Delete this record"));

    let updated = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/deals/records/public",
        Some(json!({ "front_matter": { "stage": "won" } }).to_string()),
        Some("application/json"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.json()["front_matter"]["stage"], "won");

    let history = database
        .audit_recent(10, AuditFilter::record("deals", "public"))
        .unwrap();
    let access = history[0].payload.access.as_ref().unwrap();
    assert_eq!(access.principal, "editor@example.com");
    assert_eq!(
        access.impersonated_by.as_ref().unwrap().principal,
        "owner@example.com"
    );
}

#[test]
fn rbac_console_requires_an_owner_and_a_loopback_bind() {
    let (_temporary, database) = seeded_database("perspective-boundary");
    let reader = database.impersonate("reader@example.com").unwrap();
    assert!(router(reader, ServerConfig::default()).is_err());

    let config = ServerConfig {
        bind: "0.0.0.0:3000".parse().unwrap(),
        ..ServerConfig::default()
    };
    let error = match router(database, config) {
        Ok(_) => panic!("an RBAC console must not bind beyond loopback"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("owner-only local console"));
}
