use std::{fs, str::FromStr};

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use cr::{
    server::{router, ServerConfig},
    Assignment, AuditAction, AuditSource, Database,
};
use http_body_util::BodyExt;
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
}

fn test_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    (temporary, database)
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<String>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
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
    let marker = "name=\"_csrf\" value=\"";
    let rest = html
        .split_once(marker)
        .unwrap_or_else(|| panic!("CSRF field missing from HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
}

#[tokio::test]
async fn automatic_and_saved_views_render_safe_filterable_paginated_tables() {
    let (_temporary, database) = test_database("views-render");
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=\"<script>alert('x')</script>\"").unwrap(),
                Assignment::from_str("status=open").unwrap(),
                Assignment::from_str("value=12000").unwrap(),
            ],
            "Enterprise renewal",
        )
        .unwrap();
    database
        .create(
            "deals",
            "beta",
            &[
                Assignment::from_str("name=Beta expansion").unwrap(),
                Assignment::from_str("status=won").unwrap(),
                Assignment::from_str("value=8000").unwrap(),
            ],
            "Closed last week",
        )
        .unwrap();
    database
        .create_view(
            "open-deals",
            Some("Open <deals>"),
            "deals",
            vec!["status=open".into()],
            vec!["name".into(), "status".into(), "value".into()],
            1,
        )
        .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let home = request(&app, Method::GET, "/", None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("Database views"));
    assert!(home.text().contains("href=\"/audit\""));
    assert!(home.text().contains("href=\"/deals\""));
    assert!(home.text().contains("href=\"/open-deals\""));

    let automatic = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(automatic.status, StatusCode::OK);
    assert!(automatic
        .text()
        .contains("https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"));
    assert!(automatic.text().contains("alpha"));
    assert!(automatic.text().contains("beta"));
    assert!(automatic.text().contains("href=\"/deals/records/alpha\""));
    assert!(automatic
        .text()
        .contains("&lt;script&gt;alert('x')&lt;/script&gt;"));
    assert!(!automatic.text().contains("<script>alert('x')</script>"));
    assert!(!automatic.text().to_lowercase().contains("react"));
    assert_eq!(automatic.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(automatic.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    let saved = request(&app, Method::GET, "/open-deals", None, &[]).await;
    assert_eq!(saved.status, StatusCode::OK);
    assert!(saved.text().contains("Open &lt;deals&gt;"));
    assert!(saved.text().contains("alpha"));
    assert!(!saved.text().contains("beta"));
    assert!(saved.text().contains("status=open"));

    let exact = request(
        &app,
        Method::GET,
        "/deals?filter_field=value&filter_value=8000",
        None,
        &[],
    )
    .await;
    assert_eq!(exact.status, StatusCode::OK);
    assert!(exact.text().contains("beta"));
    assert!(!exact.text().contains("alpha"));

    let searched = request(&app, Method::GET, "/deals?q=ENTERPRISE", None, &[]).await;
    assert_eq!(searched.status, StatusCode::OK);
    assert!(searched.text().contains("alpha"));
    assert!(!searched.text().contains("beta"));
    let browser_search = request(
        &app,
        Method::GET,
        "/deals?q=ENTERPRISE&filter_field=&filter_value=",
        None,
        &[],
    )
    .await;
    assert_eq!(browser_search.status, StatusCode::OK);
    assert!(browser_search.text().contains("alpha"));

    let first_page = request(&app, Method::GET, "/deals?limit=1", None, &[]).await;
    assert!(first_page.text().contains("alpha"));
    assert!(!first_page.text().contains("beta"));
    assert!(first_page.text().contains("limit=1&amp;offset=1"));
    let second_page = request(&app, Method::GET, "/deals?limit=1&offset=1", None, &[]).await;
    assert!(!second_page.text().contains("alpha"));
    assert!(second_page.text().contains("beta"));
}

#[tokio::test]
async fn html_forms_create_update_and_delete_through_validated_audited_database_methods() {
    let (_temporary, database) = test_database("views-forms");
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["status", "value"],
  "properties": {
    "status": { "enum": ["open", "won"] },
    "value": { "type": "number" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    database
        .create_view(
            "open-deals",
            Some("Open deals"),
            "deals",
            vec!["status=open".into()],
            vec!["status".into(), "value".into()],
            50,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let new_page = request(&app, Method::GET, "/open-deals/new", None, &[]).await;
    assert_eq!(new_page.status, StatusCode::OK);
    let token = csrf(new_page.text()).to_owned();
    let created = request(
        &app,
        Method::POST,
        "/open-deals/records",
        Some(form(&[
            ("_csrf", &token),
            ("id", "acme"),
            ("front_matter", "status: open\nvalue: 12500\n"),
            ("markdown", "First contact"),
        ])),
        &[("x-cr-actor", "sales@example.com")],
    )
    .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER);
    assert_eq!(
        created.headers[header::LOCATION],
        "/open-deals?notice=Record+created"
    );
    let record = database.get("deals", "acme").unwrap();
    assert_eq!(
        record.attributes["value"],
        yaml_serde::Value::Number(12500.into())
    );
    assert_eq!(record.body, "First contact");
    let audit = database
        .audit_recent(1, Some("deals"), Some("acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Create);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "sales@example.com");

    let edit_page = request(&app, Method::GET, "/open-deals/records/acme", None, &[]).await;
    assert_eq!(edit_page.status, StatusCode::OK);
    assert!(edit_page.text().contains("status: open"));
    assert!(edit_page.text().contains("value: 12500"));
    assert!(edit_page.text().contains("Audit history"));
    assert!(edit_page.text().contains("sales@example.com"));
    assert!(edit_page.text().contains("create"));
    assert!(edit_page
        .text()
        .contains("/audit?collection=deals&amp;id=acme"));
    let edit_token = csrf(edit_page.text()).to_owned();

    let invalid = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", &edit_token),
            ("front_matter", "status: lost\nvalue: 12500\n"),
            ("markdown", "Invalid attempt"),
        ])),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(invalid.text().contains("does not match schema"));
    assert_eq!(database.get("deals", "acme").unwrap().body, "First contact");
    assert_eq!(database.audit_recent(10, None, None).unwrap().len(), 1);

    let bad_csrf = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", "wrong"),
            ("front_matter", "status: won\nvalue: 13000\n"),
            ("markdown", "Won"),
        ])),
        &[],
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::FORBIDDEN);

    let updated = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", &edit_token),
            ("front_matter", "status: won\nvalue: 13000\nowner: jane\n"),
            ("markdown", "Closed won"),
        ])),
        &[],
    )
    .await;
    assert_eq!(updated.status, StatusCode::SEE_OTHER);
    let record = database.get("deals", "acme").unwrap();
    assert_eq!(record.attributes["status"], "won");
    assert_eq!(record.body, "Closed won");
    let audit = database
        .audit_recent(1, Some("deals"), Some("acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Update);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    let updated_page = request(&app, Method::GET, "/deals/records/acme", None, &[]).await;
    assert_eq!(updated_page.status, StatusCode::OK);
    assert!(updated_page.text().contains("replace"));
    assert!(updated_page.text().contains("/attributes/status"));
    assert!(updated_page.text().contains("Closed won"));
    let filtered = request(&app, Method::GET, "/open-deals", None, &[]).await;
    assert!(!filtered.text().contains("acme"));

    let delete_page = request(&app, Method::GET, "/open-deals/records/acme", None, &[]).await;
    let delete_token = csrf(delete_page.text()).to_owned();
    let deleted = request(
        &app,
        Method::POST,
        "/open-deals/records/acme/delete",
        Some(form(&[("_csrf", &delete_token)])),
        &[],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert!(database.get("deals", "acme").is_err());
    let audit = database
        .audit_recent(1, Some("deals"), Some("acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Delete);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn global_audit_view_renders_filters_and_paginates_field_changes() {
    let (_temporary, database) = test_database("global-audit-view");
    let attributed = database.clone().with_actor("sales@example.com").unwrap();
    attributed
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=Alpha renewal").unwrap(),
                Assignment::from_str("stage=proposal").unwrap(),
            ],
            "<script>alert('historical')</script>",
        )
        .unwrap();
    attributed
        .update(
            "deals",
            "alpha",
            &[Assignment::from_str("stage=won").unwrap()],
            Some("Closed won"),
        )
        .unwrap();
    attributed
        .create(
            "contacts",
            "beta",
            &[Assignment::from_str("name=Beta Buyer").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let global = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(global.status, StatusCode::OK);
    assert!(global.text().contains("Global audit log"));
    assert!(global.text().contains("contacts/beta"));
    assert!(global.text().contains("deals/alpha"));
    assert!(global.text().contains("sales@example.com"));
    assert!(global.text().contains("/attributes/stage"));
    assert!(global.text().contains("proposal"));
    assert!(global.text().contains("won"));
    assert!(global
        .text()
        .contains("&lt;script&gt;alert('historical')&lt;/script&gt;"));
    assert!(!global
        .text()
        .contains("<script>alert('historical')</script>"));
    assert!(
        global.text().find("contacts/beta").unwrap() < global.text().find("deals/alpha").unwrap()
    );

    let filtered = request(
        &app,
        Method::GET,
        "/audit?collection=deals&id=alpha",
        None,
        &[],
    )
    .await;
    assert_eq!(filtered.status, StatusCode::OK);
    assert!(filtered.text().contains("deals/alpha"));
    assert!(!filtered.text().contains("contacts/beta"));
    assert!(filtered.text().contains("value=\"deals\""));
    assert!(filtered.text().contains("value=\"alpha\""));

    let first_page = request(&app, Method::GET, "/audit?limit=1", None, &[]).await;
    assert_eq!(first_page.status, StatusCode::OK);
    assert!(first_page.text().contains("contacts/beta"));
    assert!(!first_page.text().contains("deals/alpha"));
    assert!(first_page.text().contains("limit=1&amp;offset=1"));
    let second_page = request(&app, Method::GET, "/audit?limit=1&offset=1", None, &[]).await;
    assert_eq!(second_page.status, StatusCode::OK);
    assert!(!second_page.text().contains("contacts/beta"));
    assert!(second_page.text().contains("deals/alpha"));

    let invalid = request(&app, Method::GET, "/audit?id=alpha", None, &[]).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert!(invalid.text().contains("collection is required"));
}

#[tokio::test]
async fn view_routes_respect_api_authentication_and_return_html_errors() {
    let (_temporary, database) = test_database("views-auth");
    database.create("deals", "one", &[], "").unwrap();
    let app = router(
        database,
        ServerConfig {
            api_token: Some("secret".into()),
            ..ServerConfig::default()
        },
    )
    .unwrap();

    let health = request(&app, Method::GET, "/health", None, &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    let unauthorized = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    assert!(unauthorized.text().contains("unauthorized"));
    let unauthorized_audit = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(unauthorized_audit.status, StatusCode::UNAUTHORIZED);

    let authorized = request(
        &app,
        Method::GET,
        "/deals",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(authorized.status, StatusCode::OK);
    assert!(authorized.text().starts_with("<!DOCTYPE html>"));

    let missing = request(
        &app,
        Method::GET,
        "/missing-view",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.text().contains("Request could not be completed"));

    let invalid_query = request(
        &app,
        Method::GET,
        "/deals?filter_field=status",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(invalid_query.status, StatusCode::BAD_REQUEST);
    assert!(invalid_query.text().contains("must be provided together"));
}
