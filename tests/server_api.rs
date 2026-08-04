use std::fs;

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use cr::{
    server::{router, ServerConfig},
    Database,
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

fn test_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join(name);
    let database = Database::init(&root).unwrap();
    (temporary, database)
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.unwrap_or_default().to_owned()))
                .unwrap(),
        )
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

async fn json_request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> TestResponse {
    request(app, method, uri, Some(&body.to_string()), headers).await
}

#[tokio::test]
async fn rest_crud_search_relations_audit_and_pagination_share_database_semantics() {
    let (_temporary, database) = test_database("server-crud");
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["stage", "active"],
  "properties": {
    "stage": { "enum": ["open", "won"] },
    "active": { "type": "boolean" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        json!({
            "id": "alpha-renewal",
            "front_matter": {
                "stage": "won",
                "active": true,
                "value": 25000,
                "obsolete": "remove me"
            },
            "markdown": "Priority account. Follow up next week."
        }),
        &[("x-cr-actor", "alice@example.com")],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(
        created.headers[header::LOCATION],
        "/api/v1/collections/deals/records/alpha-renewal"
    );
    assert_eq!(created.json()["front_matter"]["stage"], "won");

    let duplicate = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        json!({
            "id": "alpha-renewal",
            "front_matter": { "stage": "won", "active": true }
        }),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(duplicate.json()["error"]["code"], "already_exists");

    for (id, stage, active, value) in [
        ("beta-expansion", "won", true, 15000),
        ("gamma-trial", "open", true, 5000),
    ] {
        let response = json_request(
            &app,
            Method::POST,
            "/api/v1/collections/deals/records",
            json!({
                "id": id,
                "front_matter": { "stage": stage, "active": active, "value": value },
                "markdown": format!("Notes for {id}")
            }),
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);
    }

    let listed = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records?where=stage%3Dwon&where=active%3Dtrue&limit=1&offset=1",
        None,
        &[],
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK);
    let listed = listed.json();
    assert_eq!(listed["data"].as_array().unwrap().len(), 1);
    assert_eq!(listed["data"][0]["path"], "records/deals/beta-expansion.md");
    assert_eq!(listed["data"][0]["front_matter"]["stage"], "won");
    assert!(listed["data"][0].get("markdown").is_none());
    assert_eq!(listed["pagination"]["total"], 2);
    assert_eq!(listed["pagination"]["returned"], 1);
    assert_eq!(listed["pagination"]["previous_offset"], 0);
    assert_eq!(listed["pagination"]["next_offset"], Value::Null);

    let compared = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records?where_expr=value%3E%3D15000",
        None,
        &[],
    )
    .await;
    assert_eq!(compared.status, StatusCode::OK);
    let compared = compared.json();
    assert_eq!(compared["pagination"]["total"], 2);
    assert_eq!(
        compared["data"][0]["path"],
        "records/deals/alpha-renewal.md"
    );
    assert_eq!(
        compared["data"][1]["path"],
        "records/deals/beta-expansion.md"
    );

    let invalid_expression = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records?where_expr=value",
        None,
        &[],
    )
    .await;
    assert_eq!(invalid_expression.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        invalid_expression.json()["error"]["code"],
        "validation_failed"
    );

    let patched = json_request(
        &app,
        Method::PATCH,
        "/api/v1/collections/deals/records/alpha-renewal",
        json!({
            "front_matter": { "owner": { "email": "sales@example.com" } },
            "remove": ["obsolete"],
            "markdown": "Updated notes: follow up tomorrow."
        }),
        &[("x-cr-actor", "bob@example.com")],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    let patched = patched.json();
    assert_eq!(
        patched["front_matter"]["owner"]["email"],
        "sales@example.com"
    );
    assert!(patched["front_matter"].get("obsolete").is_none());
    assert_eq!(patched["markdown"], "Updated notes: follow up tomorrow.");

    let invalid_patch = json_request(
        &app,
        Method::PATCH,
        "/api/v1/collections/deals/records/alpha-renewal",
        json!({ "front_matter": { "stage": "invalid" } }),
        &[],
    )
    .await;
    assert_eq!(invalid_patch.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_patch.json()["error"]["code"], "validation_failed");

    let fetched = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records/alpha-renewal",
        None,
        &[],
    )
    .await;
    assert_eq!(fetched.json()["front_matter"]["stage"], "won");

    let field = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records/alpha-renewal/fields/owner.email",
        None,
        &[],
    )
    .await;
    assert_eq!(field.json()["value"], "sales@example.com");

    let document = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records/alpha-renewal/document",
        None,
        &[],
    )
    .await;
    assert_eq!(document.status, StatusCode::OK);
    assert_eq!(
        document.headers[header::CONTENT_TYPE],
        "text/markdown; charset=utf-8"
    );
    assert!(document.text().starts_with("---\n"));
    assert!(document
        .text()
        .ends_with("Updated notes: follow up tomorrow."));

    let searched = request(
        &app,
        Method::GET,
        "/api/v1/search?q=FOLLOW%20UP&collection=deals&target=body&ignore_case=true&where_expr=value%3E%3D20000&limit=1",
        None,
        &[],
    )
    .await;
    assert_eq!(searched.status, StatusCode::OK);
    assert_eq!(
        searched.json()["data"][0]["path"],
        "records/deals/alpha-renewal.md"
    );

    let company = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/companies/records",
        json!({ "id": "acme", "front_matter": { "name": "Acme" } }),
        &[],
    )
    .await;
    assert_eq!(company.status, StatusCode::CREATED);
    let linked = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records/alpha-renewal/links",
        json!({
            "relation": "company",
            "target_collection": "companies",
            "target_id": "acme"
        }),
        &[("x-cr-actor", "carol@example.com")],
    )
    .await;
    assert_eq!(linked.status, StatusCode::OK);
    assert_eq!(
        linked.json()["front_matter"]["relations"]["company"][0]["id"],
        "acme"
    );

    let log = request(
        &app,
        Method::GET,
        "/api/v1/audit/log?collection=deals&id=alpha-renewal&limit=20",
        None,
        &[],
    )
    .await;
    assert_eq!(log.status, StatusCode::OK);
    let log = log.json();
    assert_eq!(log["data"].as_array().unwrap().len(), 3);
    assert_eq!(log["data"][0]["source"], "api");
    assert_eq!(log["data"][0]["actor"], "carol@example.com");
    assert_eq!(log["data"][1]["actor"], "bob@example.com");
    assert_eq!(log["pagination"]["total"], Value::Null);

    let verified = request(&app, Method::GET, "/api/v1/audit/verify", None, &[]).await;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.json()["records_checked"], 4);

    let deleted = request(
        &app,
        Method::DELETE,
        "/api/v1/collections/deals/records/alpha-renewal",
        None,
        &[("x-cr-actor", "admin@example.com")],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(deleted.json()["deleted"], true);
    let missing = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records/alpha-renewal",
        None,
        &[],
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.json()["error"]["code"], "not_found");
}

#[tokio::test]
async fn direct_edits_status_save_and_baseline_are_available_over_http() {
    let (_temporary, database) = test_database("server-direct-edits");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/deals/records",
        json!({
            "id": "renewal",
            "front_matter": { "stage": "open" },
            "markdown": "Initial notes."
        }),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);

    fs::write(
        database.root().join("records/deals/renewal.md"),
        "---\nstage: won\n---\nEdited outside HTTP and CLI.\n",
    )
    .unwrap();
    let dirty = request(&app, Method::GET, "/api/v1/status", None, &[]).await;
    assert_eq!(dirty.status, StatusCode::OK);
    assert_eq!(dirty.json()["data"][0]["status"], "modified");
    assert_eq!(dirty.json()["data"][0]["path"], "records/deals/renewal.md");

    let saved = json_request(
        &app,
        Method::POST,
        "/api/v1/save",
        json!({
            "records": ["deals/renewal"],
            "message": "Reviewed direct edit"
        }),
        &[("x-cr-actor", "editor@example.com")],
    )
    .await;
    assert_eq!(saved.status, StatusCode::OK);
    assert_eq!(saved.json()[0]["source"], "filesystem");
    assert_eq!(saved.json()[0]["actor"], "editor@example.com");
    assert_eq!(saved.json()[0]["message"], "Reviewed direct edit");
    assert!(request(&app, Method::GET, "/api/v1/status", None, &[])
        .await
        .json()["data"]
        .as_array()
        .unwrap()
        .is_empty());

    let (_legacy_temporary, legacy_database) = test_database("server-baseline");
    fs::create_dir_all(legacy_database.root().join("records/companies")).unwrap();
    fs::write(
        legacy_database.root().join("records/companies/acme.md"),
        "---\nname: Acme\n---\nLegacy notes.\n",
    )
    .unwrap();
    let legacy_app = router(legacy_database, ServerConfig::default()).unwrap();
    let baseline = request(
        &legacy_app,
        Method::POST,
        "/api/v1/audit/baseline",
        None,
        &[("x-cr-actor", "migration@example.com")],
    )
    .await;
    assert_eq!(baseline.status, StatusCode::OK);
    assert_eq!(baseline.json()["added"], 1);
    let log = request(
        &legacy_app,
        Method::GET,
        "/api/v1/audit/log?limit=1",
        None,
        &[],
    )
    .await;
    assert_eq!(log.json()["data"][0]["source"], "api");
    assert_eq!(log.json()["data"][0]["action"], "baseline");
}

#[tokio::test]
async fn concurrent_http_patches_are_serialized_without_losing_fields() {
    let (_temporary, database) = test_database("server-concurrency");
    let app = router(database, ServerConfig::default()).unwrap();
    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/items/records",
        json!({ "id": "shared", "front_matter": { "values": {} } }),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);

    let mut tasks = Vec::new();
    for index in 0..12 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            json_request(
                &app,
                Method::PATCH,
                "/api/v1/collections/items/records/shared",
                json!({ "front_matter": { "values": { format!("field_{index}"): index } } }),
                &[],
            )
            .await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().status, StatusCode::OK);
    }

    let fetched = request(
        &app,
        Method::GET,
        "/api/v1/collections/items/records/shared",
        None,
        &[],
    )
    .await
    .json();
    for index in 0..12 {
        assert_eq!(
            fetched["front_matter"]["values"][format!("field_{index}")],
            index
        );
    }
    let verified = request(&app, Method::GET, "/api/v1/audit/verify", None, &[]).await;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.json()["entries"], 13);
}

#[tokio::test]
async fn openapi_authentication_and_http_errors_are_structured() {
    let (_temporary, database) = test_database("server-openapi");
    fs::write(
        database.root().join(".cr/schemas/candidates.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["stage"],
  "properties": { "stage": { "enum": ["screening", "interview"] } }
}"#,
    )
    .unwrap();
    let config = ServerConfig {
        api_token: Some("secret-token".into()),
        max_body_bytes: 256,
        ..ServerConfig::default()
    };
    let app = router(database.clone(), config).unwrap();

    let health = request(&app, Method::GET, "/health", None, &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json()["status"], "ok");

    let unauthorized = request(&app, Method::GET, "/openapi.json", None, &[]).await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.json()["error"]["code"], "unauthorized");
    assert_eq!(
        unauthorized.headers[header::WWW_AUTHENTICATE],
        "Bearer realm=\"cr\""
    );

    let openapi = request(
        &app,
        Method::GET,
        "/openapi.json",
        None,
        &[("authorization", "Bearer secret-token")],
    )
    .await;
    assert_eq!(openapi.status, StatusCode::OK);
    let openapi = openapi.json();
    assert_eq!(openapi["openapi"], "3.1.1");
    assert_local_schema_references_resolve(&openapi, &openapi);
    assert!(
        openapi["components"]["schemas"]["AuditEntry"]["properties"]["source"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("sync"))
    );
    assert_eq!(openapi["security"][0]["bearerAuth"], json!([]));
    assert!(openapi["paths"]
        .get("/api/v1/collections/{collection}/records")
        .is_some());
    for path in ["/api/v1/collections/{collection}/records", "/api/v1/search"] {
        assert!(openapi["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .any(|parameter| parameter["name"] == "where_expr"));
    }
    let reference = openapi["x-cr-collection-schemas"]["candidates"]
        .as_str()
        .unwrap();
    let component = reference.rsplit('/').next().unwrap();
    assert_eq!(
        openapi["components"]["schemas"][component]["properties"]["stage"]["enum"],
        json!(["screening", "interview"])
    );

    fs::write(
        database.root().join(".cr/schemas/candidates.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": { "stage": { "enum": ["screening", "interview", "offer"] } }
}"#,
    )
    .unwrap();
    let refreshed = request(
        &app,
        Method::GET,
        "/openapi.json",
        None,
        &[("authorization", "Bearer secret-token")],
    )
    .await
    .json();
    assert_eq!(
        refreshed["components"]["schemas"][component]["properties"]["stage"]["enum"],
        json!(["screening", "interview", "offer"])
    );

    let invalid_json = request(
        &app,
        Method::POST,
        "/api/v1/collections/candidates/records",
        Some("{"),
        &[("authorization", "Bearer secret-token")],
    )
    .await;
    assert_eq!(invalid_json.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_json.json()["error"]["code"], "invalid_json");

    let invalid_query = request(
        &app,
        Method::GET,
        "/api/v1/collections/candidates/records?unknown=true",
        None,
        &[("authorization", "Bearer secret-token")],
    )
    .await;
    assert_eq!(invalid_query.status, StatusCode::BAD_REQUEST);
    assert_eq!(invalid_query.json()["error"]["code"], "invalid_query");

    let bad_page = request(
        &app,
        Method::GET,
        "/api/v1/collections/candidates/records?limit=0",
        None,
        &[("authorization", "Bearer secret-token")],
    )
    .await;
    assert_eq!(bad_page.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(bad_page.json()["error"]["code"], "validation_failed");

    let too_large = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/candidates/records",
        json!({
            "id": "large",
            "front_matter": { "stage": "screening" },
            "markdown": "x".repeat(512)
        }),
        &[("authorization", "Bearer secret-token")],
    )
    .await;
    assert_eq!(too_large.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(too_large.json()["error"]["code"], "payload_too_large");

    // Single-segment root paths are view names and are protected like the API.
    // An unmatched multi-segment path still exercises the JSON route fallback.
    let missing_route = request(&app, Method::GET, "/missing/route", None, &[]).await;
    assert_eq!(missing_route.status, StatusCode::NOT_FOUND);
    assert_eq!(missing_route.json()["error"]["code"], "route_not_found");

    let wrong_method = request(&app, Method::POST, "/health", None, &[]).await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(wrong_method.json()["error"]["code"], "method_not_allowed");
}

fn assert_local_schema_references_resolve(root: &Value, value: &Value) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if let Some(component) = reference.strip_prefix("#/components/schemas/") {
                    assert!(
                        root["components"]["schemas"].get(component).is_some(),
                        "unresolved OpenAPI schema reference: {reference}"
                    );
                }
            }
            for value in object.values() {
                assert_local_schema_references_resolve(root, value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_local_schema_references_resolve(root, value);
            }
        }
        _ => {}
    }
}
