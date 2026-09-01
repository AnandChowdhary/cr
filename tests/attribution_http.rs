//! Agent, authorization, and intent attribution over HTTP.
//!
//! The headers carry exactly the same trust boundary as `X-CR-Actor`: the
//! server records what a caller tells it and authenticates none of it. What the
//! tests below pin down is that the values arrive intact, that they are
//! recorded as `detected_from: header`, that a caller cannot claim `cr`'s own
//! `detected_from` field, and that the delegate is queryable afterwards.

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use cr::{
    server::{openapi_document, router, ServerConfig},
    Attribution, Database,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
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

    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }
}

/// A server whose starting attribution is empty regardless of where the test
/// runs, so a suite executed inside a coding agent asserts the same thing as one
/// executed in CI.
fn test_app(name: &str) -> (TempDir, Router, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join(name);
    let database = Database::init(&root)
        .unwrap()
        .with_attribution(Attribution::default());
    let app = router(
        database.clone(),
        ServerConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            max_page_size: 200,
            max_body_bytes: 8 * 1024 * 1024,
            api_token: None,
        },
    )
    .unwrap();
    (temporary, app, database)
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
    let payload = body.map(|value| value.to_string()).unwrap_or_default();
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(payload)).unwrap())
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

#[tokio::test]
async fn attribution_headers_are_recorded_beside_the_asserted_actor() {
    let (_temporary, app, _database) = test_app("http-attribution");
    let created = request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        Some(json!({ "id": "acme-renewal", "front_matter": { "status": "open" } })),
        &[
            ("X-CR-Actor", "Ada Lovelace <ada@example.com>"),
            (
                "X-CR-Agent",
                r#"{"id":"claude-code","model":"claude-opus-4-5","session":"6d1baa69","turn":"prompt_01HXZ"}"#,
            ),
            (
                "X-CR-Authorization",
                r#"{"mode":"delegated","grant":"acceptEdits","at":"2026-09-01T09:17:55Z"}"#,
            ),
            (
                "X-CR-Intent",
                r#"{"request":{"text":"add the acme renewal"},"rationale":{"text":"created deals/acme-renewal with status open"}}"#,
            ),
        ],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);

    let log = request(&app, Method::GET, "/api/v1/audit/log", None, &[]).await;
    let event = &log.json()["data"][0];
    assert_eq!(event["actor"], "Ada Lovelace <ada@example.com>");
    assert_eq!(event["source"], "api");
    assert_eq!(event["agent"]["id"], "claude-code");
    assert_eq!(event["agent"]["model"], "claude-opus-4-5");
    assert_eq!(event["agent"]["detected_from"], "header");
    assert_eq!(event["authorization"]["mode"], "delegated");
    assert_eq!(event["authorization"]["grant"], "acceptEdits");
    assert_eq!(event["intent"]["request"]["author"], "human");
    assert_eq!(event["intent"]["rationale"]["author"], "agent");

    let verification = request(&app, Method::GET, "/api/v1/audit/verify", None, &[]).await;
    assert_eq!(verification.status, StatusCode::OK);
    assert_eq!(verification.json()["entries"], 1);
}

#[tokio::test]
async fn a_request_cannot_claim_how_cr_came_to_believe_it() {
    let (_temporary, app, _database) = test_app("http-detected-from");
    let response = request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        Some(json!({ "id": "one", "front_matter": { "status": "open" } })),
        &[(
            "X-CR-Agent",
            r#"{"id":"claude-code","detected_from":"environment"}"#,
        )],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    let error = response.json();
    assert_eq!(error["error"]["code"], "validation_failed");
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("detected_from"));
    assert!(response.headers.contains_key("x-request-id"));
}

#[tokio::test]
async fn invalid_attribution_headers_are_rejected_without_internal_detail() {
    let (_temporary, app, database) = test_app("http-attribution-errors");
    let root = database.root().to_str().unwrap().to_owned();
    for (header, value, expected) in [
        ("X-CR-Agent", "", "agent cannot be empty"),
        ("X-CR-Authorization", "supervised", "must be direct"),
        ("X-CR-Intent", "not json", "JSON object"),
    ] {
        let response = request(
            &app,
            Method::POST,
            "/api/v1/collections/deals/records",
            Some(json!({ "id": "one", "front_matter": {} })),
            &[(header, value)],
        )
        .await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
        let message = response.json()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(&root), "{message}");
        assert!(!message.contains("os error"), "{message}");
    }

    // Header values are visible ASCII, so non-ASCII intent has to arrive as
    // JSON escapes. The refusal says so and names nothing internal.
    let response = request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        Some(json!({ "id": "one", "front_matter": {} })),
        &[("X-CR-Intent", "{\"request\":{\"text\":\"caf\u{e9}\"}}")],
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.json()["error"]["code"], "invalid_intent");
    assert!(response.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("visible ASCII"));

    // The escaped form is accepted and round-trips through the journal.
    let accepted = request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        Some(json!({ "id": "one", "front_matter": {} })),
        &[("X-CR-Intent", r#"{"request":{"text":"caf\u00e9 renewal"}}"#)],
    )
    .await;
    assert_eq!(accepted.status, StatusCode::CREATED);
    let log = request(&app, Method::GET, "/api/v1/audit/log", None, &[]).await;
    assert_eq!(
        log.json()["data"][0]["intent"]["request"]["text"],
        "café renewal"
    );
}

#[tokio::test]
async fn audit_history_is_filterable_by_agent_and_session_over_http() {
    let (_temporary, app, _database) = test_app("http-agent-filter");
    for (id, agent) in [
        ("one", None),
        ("two", Some(r#"{"id":"claude-code","session":"session-a"}"#)),
        (
            "three",
            Some(r#"{"id":"sub","session":"session-b","via":[{"id":"claude-code"}]}"#),
        ),
    ] {
        let headers: Vec<(&str, &str)> = agent
            .map(|agent| ("X-CR-Agent", agent))
            .into_iter()
            .collect();
        let response = request(
            &app,
            Method::POST,
            "/api/v1/collections/deals/records",
            Some(json!({ "id": id, "front_matter": { "status": "open" } })),
            &headers,
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);
    }

    let by_agent = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?agent=claude-code",
        None,
        &[],
    )
    .await;
    let matched: Vec<&str> = by_agent.json()["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["record"]["id"].as_str().unwrap().to_owned())
        .collect::<Vec<String>>()
        .iter()
        .map(|value| Box::leak(value.clone().into_boxed_str()) as &str)
        .collect();
    assert_eq!(matched, vec!["three", "two"]);

    let by_session = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?session=session-b",
        None,
        &[],
    )
    .await;
    assert_eq!(by_session.json()["data"].as_array().unwrap().len(), 1);
    assert_eq!(by_session.json()["data"][0]["record"]["id"], "three");

    let unmatched = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?agent=cursor-agent",
        None,
        &[],
    )
    .await;
    assert!(unmatched.json()["data"].as_array().unwrap().is_empty());

    let unknown = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?delegate=claude-code",
        None,
        &[],
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_identity_endpoint_previews_what_would_be_recorded() {
    let (_temporary, app, _database) = test_app("http-identity");
    let empty = request(&app, Method::GET, "/api/v1/identity", None, &[]).await;
    assert!(empty.json()["agent"].is_null());
    assert!(empty.json()["authorization"].is_null());
    assert!(empty.json()["intent"].is_null());

    let declared = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[
            ("X-CR-Actor", "Ada Lovelace <ada@example.com>"),
            ("X-CR-Agent", "claude-code"),
            ("X-CR-Authorization", "interactive"),
        ],
    )
    .await;
    let body = declared.json();
    assert_eq!(body["actor"], "Ada Lovelace <ada@example.com>");
    assert_eq!(body["agent"]["id"], "claude-code");
    assert_eq!(body["agent"]["detected_from"], "header");
    assert_eq!(body["authorization"]["mode"], "interactive");
}

#[tokio::test]
async fn the_html_history_names_the_agent_rather_than_only_the_human() {
    let (_temporary, app, _database) = test_app("http-attribution-html");
    request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        Some(json!({ "id": "acme-renewal", "front_matter": { "status": "open" } })),
        &[
            ("X-CR-Actor", "Ada Lovelace <ada@example.com>"),
            (
                "X-CR-Agent",
                r#"{"id":"claude-code","model":"claude-opus-4-5","session":"6d1baa69"}"#,
            ),
            ("X-CR-Authorization", r#"{"mode":"delegated","grant":"acceptEdits"}"#),
            (
                "X-CR-Intent",
                r#"{"request":{"text":"add the acme renewal"},"rationale":{"text":"created it with status open"}}"#,
            ),
        ],
    )
    .await;

    let page = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let text = page.text();
    assert!(text.contains("Ada Lovelace"));
    assert!(text.contains("claude-code"));
    assert!(text.contains("claude-opus-4-5"));
    assert!(text.contains("asserted, detected from header"));
    assert!(text.contains("Authorization"));
    assert!(text.contains("acceptEdits"));
    assert!(text.contains("add the acme renewal"));
    assert!(text.contains("created it with status open"));
    assert!(text.contains("Agent session"));

    let filtered = request(&app, Method::GET, "/audit?agent=claude-code", None, &[]).await;
    assert!(filtered.text().contains("acme-renewal"));
    let missing = request(&app, Method::GET, "/audit?agent=cursor-agent", None, &[]).await;
    assert!(missing
        .text()
        .contains("No audit events match this filter."));
}

#[test]
fn the_openapi_document_describes_the_attribution_contract() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("openapi")).unwrap();
    let document = openapi_document(&database, false).unwrap();

    let agent = &document["components"]["schemas"]["AuditAgent"];
    assert_eq!(agent["required"], json!(["id", "detected_from"]));
    assert_eq!(
        agent["properties"]["detected_from"]["enum"],
        json!(["environment", "flag", "header", "config"])
    );
    assert!(agent["properties"]["detected_from"]["description"]
        .as_str()
        .unwrap()
        .contains("No value means verified"));
    assert!(
        document["components"]["schemas"]["AuditAuthorization"]["properties"]["approved_changes"]
            ["description"]
            .as_str()
            .unwrap()
            .contains("does not yet verify")
    );

    let headers: Vec<&str> = document["paths"]["/api/v1/collections/{collection}/records"]["post"]
        ["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|parameter| parameter["name"].as_str())
        .collect();
    assert!(headers.contains(&"X-CR-Actor"));
    assert!(headers.contains(&"X-CR-Agent"));
    assert!(headers.contains(&"X-CR-Authorization"));
    assert!(headers.contains(&"X-CR-Intent"));

    let query: Vec<&str> = document["paths"]["/api/v1/audit/log"]["get"]["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|parameter| parameter["name"].as_str())
        .collect();
    assert!(query.contains(&"agent"));
    assert!(query.contains(&"session"));
}
