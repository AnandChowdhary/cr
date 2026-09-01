//! `GET /api/v1/check` — the HTTP form of the integrity report.

use std::fs;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use cr::{
    Database,
    server::{ServerConfig, openapi_document, router},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

fn test_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join(name);
    let database = Database::init(&root).unwrap();
    (temporary, database)
}

async fn get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(Method::GET).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&body).unwrap_or_else(|error| {
        panic!(
            "response was not JSON: {error}\n{}",
            String::from_utf8_lossy(&body)
        )
    });
    (status, json)
}

/// A database with one dangling relation and one unsaved direct edit.
fn broken() -> (TempDir, Database) {
    let (temporary, database) = test_database("check-http");
    database.create("companies", "acme", &[], "").unwrap();
    database.create("deals", "acme-renewal", &[], "").unwrap();
    database
        .link("deals", "acme-renewal", "company", "companies", "acme")
        .unwrap();
    fs::remove_file(database.root().join("records/companies/acme.md")).unwrap();
    (temporary, database)
}

#[tokio::test]
async fn a_clean_database_reports_an_empty_page_and_a_zeroed_summary() {
    let (_temporary, database) = test_database("check-http-clean");
    database.create("deals", "acme-renewal", &[], "").unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let (status, body) = get(&app, "/api/v1/check", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"], serde_json::json!([]));
    assert_eq!(body["summary"]["errors"], 0);
    assert_eq!(body["summary"]["warnings"], 0);
    assert_eq!(body["summary"]["records"], 1);
    assert_eq!(body["pagination"]["total"], 0);
    assert_eq!(body["collection"], Value::Null);
}

#[tokio::test]
async fn findings_are_returned_with_a_summary_and_a_success_status() {
    let (_temporary, database) = broken();
    let app = router(database, ServerConfig::default()).unwrap();

    // A broken database is not an HTTP error: the findings are the resource.
    let (status, body) = get(&app, "/api/v1/check", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["summary"]["errors"], 1);
    assert_eq!(body["summary"]["warnings"], 1);

    let kinds: Vec<_> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["dangling_link", "missing_record"]);
    assert_eq!(body["data"][0]["collection"], "deals");
    assert_eq!(body["data"][0]["id"], "acme-renewal");
    assert_eq!(body["data"][0]["target"], "companies/acme");
    assert_eq!(body["data"][0]["severity"], "error");
    assert_eq!(body["data"][1]["severity"], "warning");
}

#[tokio::test]
async fn the_summary_survives_pagination() {
    let (_temporary, database) = broken();
    let app = router(database, ServerConfig::default()).unwrap();

    let (status, body) = get(&app, "/api/v1/check?limit=1&offset=1", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["pagination"]["total"], 2);
    assert_eq!(body["pagination"]["has_more"], false);
    assert_eq!(body["pagination"]["previous_offset"], 0);
    // A caller reading only the second page still learns the database is broken.
    assert_eq!(body["summary"]["errors"], 1);
}

#[tokio::test]
async fn scope_and_unknown_parameters_follow_the_existing_query_contract() {
    let (_temporary, database) = broken();
    let app = router(database, ServerConfig::default()).unwrap();

    let (status, body) = get(&app, "/api/v1/check?collection=deals", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["collection"], "deals");
    assert_eq!(body["summary"]["records"], 1);
    assert_eq!(body["data"][0]["kind"], "dangling_link");

    let (status, body) = get(&app, "/api/v1/check?collection=typo", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");

    let (status, body) = get(&app, "/api/v1/check?colection=deals", &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_query");

    let (status, _) = get(&app, "/api/v1/check?limit=0", &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn checking_is_protected_by_the_same_bearer_token_as_every_other_route() {
    let (_temporary, database) = broken();
    let app = router(
        database,
        ServerConfig {
            api_token: Some("secret".to_owned()),
            ..ServerConfig::default()
        },
    )
    .unwrap();

    let (status, _) = get(&app, "/api/v1/check", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = get(&app, "/api/v1/check", &[("authorization", "Bearer secret")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["summary"]["errors"], 1);
}

#[tokio::test]
async fn checking_never_writes_through_the_http_route() {
    let (_temporary, database) = broken();
    let before = snapshot(database.root());
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let (status, _) = get(&app, "/api/v1/check", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get(&app, "/api/v1/check?collection=deals", &[]).await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(snapshot(database.root()), before);
}

#[test]
fn the_route_is_described_by_the_generated_openapi_document() {
    let (_temporary, database) = test_database("check-openapi");
    let document = openapi_document(&database, false).unwrap();
    let operation = &document["paths"]["/api/v1/check"]["get"];
    assert_eq!(operation["operationId"], "getCheckReport");
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/CheckReport"
    );
    let parameters: Vec<_> = operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|parameter| parameter["name"].as_str().unwrap())
        .collect();
    assert_eq!(parameters, vec!["collection", "limit", "offset"]);

    let report = &document["components"]["schemas"]["CheckReport"];
    assert_eq!(
        report["properties"]["summary"]["$ref"],
        "#/components/schemas/CheckSummary"
    );
    assert_eq!(
        report["properties"]["data"]["items"]["$ref"],
        "#/components/schemas/CheckFinding"
    );

    // Every kind the implementation can emit is enumerated in the document, so
    // the two cannot drift apart silently.
    let kinds: Vec<_> =
        document["components"]["schemas"]["CheckFinding"]["properties"]["kind"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kind| kind.as_str().unwrap().to_owned())
            .collect();
    for kind in [
        "dangling_link",
        "malformed_relation",
        "schema_violation",
        "unusable_schema",
        "invalid_record_name",
        "unreadable_record",
        "unaudited_record",
        "missing_record",
        "record_content_mismatch",
        "audit_chain_broken",
        "approval_mismatch",
        "interrupted_sync_run",
    ] {
        assert!(kinds.contains(&kind.to_owned()), "{kind} is undocumented");
    }
}

fn snapshot(root: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    collect(root, root, &mut files);
    files.sort();
    files
}

fn collect(
    root: &std::path::Path,
    directory: &std::path::Path,
    files: &mut Vec<(std::path::PathBuf, Vec<u8>)>,
) {
    for entry in fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect(root, &path, files);
        } else if entry.file_type().unwrap().is_file() {
            files.push((
                path.strip_prefix(root).unwrap().to_path_buf(),
                fs::read(&path).unwrap(),
            ));
        }
    }
}
