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

    let sorted = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records?sort=value&direction=asc&limit=2",
        None,
        &[],
    )
    .await;
    assert_eq!(sorted.status, StatusCode::OK);
    let sorted = sorted.json();
    assert_eq!(sorted["pagination"]["total"], 3);
    assert_eq!(sorted["pagination"]["returned"], 2);
    assert_eq!(sorted["data"][0]["path"], "records/deals/gamma-trial.md");
    assert_eq!(sorted["data"][1]["path"], "records/deals/beta-expansion.md");

    let invalid_sort = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records?sort=owner..email",
        None,
        &[],
    )
    .await;
    assert_eq!(invalid_sort.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(invalid_sort.json()["error"]["code"], "validation_failed");

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
    assert!(
        document
            .text()
            .ends_with("Updated notes: follow up tomorrow.")
    );

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

    let sorted_search = request(
        &app,
        Method::GET,
        "/api/v1/search?q=Notes&collection=deals&sort=value&direction=asc",
        None,
        &[],
    )
    .await;
    assert_eq!(sorted_search.status, StatusCode::OK);
    let sorted_search = sorted_search.json();
    assert_eq!(
        sorted_search["data"][0]["path"],
        "records/deals/gamma-trial.md"
    );
    assert_eq!(
        sorted_search["data"][1]["path"],
        "records/deals/beta-expansion.md"
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
async fn record_etags_guard_conditional_and_whole_document_writes() {
    let (_temporary, database) = test_database("server-etags");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let uri = "/api/v1/collections/items/records/one";

    let created = json_request(
        &app,
        Method::POST,
        "/api/v1/collections/items/records",
        json!({
            "id": "one",
            "front_matter": { "stage": "open", "obsolete": true },
            "markdown": "First"
        }),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let first_version = created.json()["version"].as_str().unwrap().to_owned();
    let first_etag = created.headers[header::ETAG].to_str().unwrap().to_owned();
    assert_eq!(first_etag, format!("\"{first_version}\""));

    let fetched = request(&app, Method::GET, uri, None, &[]).await;
    assert_eq!(fetched.headers[header::ETAG], first_etag);
    assert_eq!(fetched.json()["version"], first_version);

    let patched = json_request(
        &app,
        Method::PATCH,
        uri,
        json!({ "front_matter": { "owner": "ada" } }),
        &[("if-match", &first_etag)],
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK);
    let second_version = patched.json()["version"].as_str().unwrap().to_owned();
    let second_etag = patched.headers[header::ETAG].to_str().unwrap().to_owned();
    assert_ne!(second_version, first_version);

    let stale = json_request(
        &app,
        Method::PATCH,
        uri,
        json!({ "front_matter": { "stage": "lost" } }),
        &[("if-match", &first_etag)],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(stale.json()["error"]["code"], "precondition_failed");
    assert!(
        !stale
            .text()
            .contains(database.root().to_string_lossy().as_ref())
    );

    let missing = json_request(
        &app,
        Method::PUT,
        uri,
        json!({ "front_matter": { "stage": "won" }, "markdown": "Won" }),
        &[],
    )
    .await;
    assert_eq!(missing.status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(missing.json()["error"]["code"], "precondition_required");

    let replacement = json!({ "front_matter": { "stage": "won" }, "markdown": "Won" });
    let preview = json_request(
        &app,
        Method::PUT,
        &format!("{uri}?preview=true"),
        replacement.clone(),
        &[("if-match", &second_etag)],
    )
    .await;
    assert_eq!(preview.status, StatusCode::OK);
    assert_eq!(preview.json()["preview"], true);
    let approved = preview.json()["digest"].as_str().unwrap().to_owned();
    assert_eq!(database.get("items", "one").unwrap().body, "First");

    let replaced = json_request(
        &app,
        Method::PUT,
        uri,
        replacement,
        &[
            ("if-match", &second_etag),
            ("x-cr-authorization", "interactive"),
            ("x-cr-approved-changes", &approved),
        ],
    )
    .await;
    assert_eq!(replaced.status, StatusCode::OK);
    assert_eq!(replaced.json()["front_matter"], json!({ "stage": "won" }));
    assert_eq!(replaced.json()["markdown"], "Won");
    assert!(replaced.json()["front_matter"].get("owner").is_none());
    assert!(replaced.json()["front_matter"].get("obsolete").is_none());
    assert_ne!(replaced.headers[header::ETAG], second_etag);

    let weak = json_request(
        &app,
        Method::PATCH,
        uri,
        json!({ "front_matter": { "stage": "weak" } }),
        &[(
            "if-match",
            &format!("W/{}", replaced.headers[header::ETAG].to_str().unwrap()),
        )],
    )
    .await;
    assert_eq!(weak.status, StatusCode::PRECONDITION_FAILED);

    for opaque in [r#""xyzzy""#, r#"W/"xyzzy""#, r#""foo,bar""#] {
        let nonmatching = json_request(
            &app,
            Method::PATCH,
            uri,
            json!({ "front_matter": { "stage": "opaque" } }),
            &[("if-match", opaque)],
        )
        .await;
        assert_eq!(
            nonmatching.status,
            StatusCode::PRECONDITION_FAILED,
            "valid opaque entity tag {opaque} must be evaluated, not rejected"
        );
        assert_eq!(nonmatching.json()["error"]["code"], "precondition_failed");
    }

    for invalid in ["*, *", r#"*, "xyzzy""#] {
        let malformed = json_request(
            &app,
            Method::PATCH,
            uri,
            json!({ "front_matter": { "stage": "invalid" } }),
            &[("if-match", invalid)],
        )
        .await;
        assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
        assert_eq!(malformed.json()["error"]["code"], "invalid_if_match");
    }
    let repeated_wildcard = json_request(
        &app,
        Method::PATCH,
        uri,
        json!({ "front_matter": { "stage": "invalid" } }),
        &[("if-match", "*"), ("if-match", "*")],
    )
    .await;
    assert_eq!(repeated_wildcard.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        repeated_wildcard.json()["error"]["code"],
        "invalid_if_match"
    );

    let absent = json_request(
        &app,
        Method::PATCH,
        "/api/v1/collections/items/records/missing",
        json!({ "front_matter": { "stage": "new" } }),
        &[("if-match", "*")],
    )
    .await;
    assert_eq!(absent.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(absent.json()["error"]["code"], "precondition_failed");

    let log = database
        .audit_recent(10, cr::AuditFilter::record("items", "one"))
        .unwrap();
    assert_eq!(
        log.len(),
        3,
        "stale and missing preconditions write no audit event"
    );
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
    assert!(
        request(&app, Method::GET, "/api/v1/status", None, &[])
            .await
            .json()["data"]
            .as_array()
            .unwrap()
            .is_empty()
    );

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
    assert_eq!(
        openapi["components"]["schemas"]["RecordSummary"]["properties"]["version"]["pattern"],
        "^sha256:[0-9a-f]{64}$"
    );
    assert!(
        openapi["components"]["schemas"]["RecordSummary"]["properties"]["version"]["description"]
            .as_str()
            .unwrap()
            .contains(r"cr:record:v1\0")
    );
    assert_eq!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["put"]["operationId"],
        "replaceRecord"
    );
    let put_parameters =
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["put"]["parameters"]
            .as_array()
            .unwrap();
    let if_match = put_parameters
        .iter()
        .find(|parameter| parameter["name"] == "If-Match")
        .expect("PUT documents If-Match");
    assert_eq!(if_match["required"], true);
    assert!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["put"]
            ["responses"]["200"]["headers"]["ETag"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["put"]
            ["responses"]["412"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["put"]
            ["responses"]["428"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["patch"]
            ["responses"]["412"]
            .is_object()
    );
    assert!(
        openapi["paths"]["/api/v1/collections/{collection}/records/{id}"]["patch"]["responses"]
            .get("428")
            .is_none()
    );
    assert!(
        openapi["paths"]["/api/v1/collections"]["get"]["responses"]
            .get("412")
            .is_none()
    );
    assert!(
        openapi["paths"]["/api/v1/collections"]["get"]["responses"]
            .get("428")
            .is_none()
    );
    assert!(
        openapi["components"]["schemas"]["AuditEntry"]["properties"]["source"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("sync"))
    );
    assert_eq!(openapi["security"][0]["bearerAuth"], json!([]));
    assert!(
        openapi["paths"]
            .get("/api/v1/collections/{collection}/records")
            .is_some()
    );
    for path in ["/api/v1/collections/{collection}/records", "/api/v1/search"] {
        let parameters = openapi["paths"][path]["get"]["parameters"]
            .as_array()
            .unwrap();
        for name in ["where_expr", "sort", "direction"] {
            assert!(parameters.iter().any(|parameter| parameter["name"] == name));
        }
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
            if let Some(reference) = object.get("$ref").and_then(Value::as_str)
                && let Some(component) = reference.strip_prefix("#/components/schemas/")
            {
                assert!(
                    root["components"]["schemas"].get(component).is_some(),
                    "unresolved OpenAPI schema reference: {reference}"
                );
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

/// One request that must produce one public status and error code: a label for
/// assertion messages, the expected status and code, then the method, URI,
/// body, and headers that produce it.
type ErrorCase = (
    &'static str,
    StatusCode,
    &'static str,
    Method,
    String,
    Option<String>,
    Vec<(&'static str, &'static str)>,
);

/// Every public error code the JSON API can return, with the status it must
/// carry and a request that produces it.
#[tokio::test]
async fn every_public_error_mapping_is_typed_redacted_and_correlated() {
    let (_temporary, database) = test_database("server-errors");
    let root = database.root().display().to_string();
    database.create("deals", "alpha", &[], "Alpha\n").unwrap();
    // A record path that is not a regular Markdown file, and one that is only
    // reachable through a symbolic link, are both refused as conflicting
    // durable state rather than followed.
    fs::create_dir(database.root().join("records/deals/broken.md")).unwrap();
    #[cfg(unix)]
    {
        let outside = database.root().join("outside.md");
        fs::write(&outside, "---\nstatus: leaked\n---\n").unwrap();
        std::os::unix::fs::symlink(&outside, database.root().join("records/deals/linked.md"))
            .unwrap();
        let elsewhere = database.root().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, database.root().join("records/escaped")).unwrap();
    }
    // Editing a record outside the audited path makes the next mutation stale.
    database.create("deals", "stale", &[], "Stale\n").unwrap();
    fs::write(
        database.root().join("records/deals/stale.md"),
        "---\nstatus: edited\n---\n",
    )
    .unwrap();

    let app = router(
        database,
        ServerConfig {
            api_token: Some("secret".into()),
            max_body_bytes: 256,
            ..ServerConfig::default()
        },
    )
    .unwrap();
    let authorization = ("authorization", "Bearer secret");

    #[allow(unused_mut)]
    let mut cases: Vec<ErrorCase> = vec![
        (
            "unauthorized",
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Method::GET,
            "/api/v1/collections".to_owned(),
            None,
            vec![],
        ),
        (
            "route_not_found",
            StatusCode::NOT_FOUND,
            "route_not_found",
            Method::GET,
            "/api/v1/nowhere".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "method_not_allowed",
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            Method::DELETE,
            "/api/v1/collections".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "missing record",
            StatusCode::NOT_FOUND,
            "not_found",
            Method::GET,
            "/api/v1/collections/deals/records/nope".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "missing field",
            StatusCode::NOT_FOUND,
            "not_found",
            Method::GET,
            "/api/v1/collections/deals/records/alpha/fields/nope".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "duplicate record",
            StatusCode::CONFLICT,
            "already_exists",
            Method::POST,
            "/api/v1/collections/deals/records".to_owned(),
            Some(json!({ "id": "alpha" }).to_string()),
            vec![authorization],
        ),
        (
            "record edited outside the audit log",
            StatusCode::CONFLICT,
            "conflict",
            Method::PATCH,
            "/api/v1/collections/deals/records/stale".to_owned(),
            Some(json!({ "front_matter": { "status": "won" } }).to_string()),
            vec![authorization],
        ),
        (
            "stale record precondition",
            StatusCode::PRECONDITION_FAILED,
            "precondition_failed",
            Method::PATCH,
            "/api/v1/collections/deals/records/alpha".to_owned(),
            Some(json!({ "front_matter": { "status": "won" } }).to_string()),
            vec![
                authorization,
                (
                    "if-match",
                    "\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
                ),
            ],
        ),
        (
            "missing whole replacement precondition",
            StatusCode::PRECONDITION_REQUIRED,
            "precondition_required",
            Method::PUT,
            "/api/v1/collections/deals/records/alpha".to_owned(),
            Some(json!({ "front_matter": {}, "markdown": "replacement" }).to_string()),
            vec![authorization],
        ),
        (
            "invalid expression",
            StatusCode::UNPROCESSABLE_ENTITY,
            "validation_failed",
            Method::GET,
            "/api/v1/collections/deals/records?where_expr=score".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "malformed JSON body",
            StatusCode::BAD_REQUEST,
            "invalid_json",
            Method::POST,
            "/api/v1/collections/deals/records".to_owned(),
            Some("{".to_owned()),
            vec![authorization],
        ),
        (
            "malformed query string",
            StatusCode::BAD_REQUEST,
            "invalid_query",
            Method::GET,
            "/api/v1/collections/deals/records?limit=many".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "non-UTF-8 actor",
            StatusCode::BAD_REQUEST,
            "invalid_actor",
            Method::GET,
            "/api/v1/identity".to_owned(),
            None,
            vec![authorization, ("x-cr-actor", "caf\u{e9}")],
        ),
        (
            "oversized body",
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            Method::POST,
            "/api/v1/collections/deals/records".to_owned(),
            Some(json!({ "id": "big", "markdown": "x".repeat(512) }).to_string()),
            vec![authorization],
        ),
        (
            "record file replaced by a directory",
            StatusCode::CONFLICT,
            "conflict",
            Method::GET,
            "/api/v1/collections/deals/records/broken".to_owned(),
            None,
            vec![authorization],
        ),
    ];

    // Symbolic links can only be planted where the platform has them.
    #[cfg(unix)]
    cases.extend([
        (
            "record reached through a symbolic link",
            StatusCode::CONFLICT,
            "conflict",
            Method::GET,
            "/api/v1/collections/deals/records/linked".to_owned(),
            None,
            vec![authorization],
        ),
        (
            "collection directory replaced by a symbolic link",
            StatusCode::CONFLICT,
            "conflict",
            Method::GET,
            "/api/v1/collections/escaped/records".to_owned(),
            None,
            vec![authorization],
        ),
    ]);

    for (label, status, code, method, uri, body, headers) in cases {
        let response = request(&app, method, &uri, body.as_deref(), &headers).await;
        assert_eq!(response.status, status, "{label}: {}", response.text());
        let payload = response.json();
        assert_eq!(payload["error"]["code"], code, "{label}");

        let message = payload["error"]["message"].as_str().unwrap();
        assert!(!message.is_empty(), "{label} has no message");
        assert!(!message.contains(&root), "{label} leaked the database root");
        assert!(!message.contains("os error"), "{label} leaked an OS error");
        assert!(
            !response.text().contains(&root),
            "{label} leaked the database root"
        );

        let request_id = payload["error"]["request_id"].as_str().unwrap();
        assert!(!request_id.is_empty(), "{label} has no request ID");
        assert_eq!(
            response.headers.get("x-request-id").unwrap(),
            request_id,
            "{label} header and body request IDs differ"
        );
    }
}

#[tokio::test]
async fn unexpected_failures_reveal_only_a_generic_message_and_a_request_id() {
    let (_temporary, database) = test_database("server-internal");
    let root = database.root().display().to_string();
    // A journal whose last line was lost is an internal inconsistency no caller
    // can act on, so it must stay unclassified and redacted.
    fs::write(
        database
            .root()
            .join(".cr/audit/segments/00000000000000000001.jsonl"),
        "{\"hash\":\"sha256:none\",\"payload\":{}}",
    )
    .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let response = request(&app, Method::GET, "/api/v1/audit/head", None, &[]).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    let payload = response.json();
    assert_eq!(payload["error"]["code"], "internal_error");
    let message = payload["error"]["message"].as_str().unwrap();
    assert!(message.contains("request ID"), "{message}");
    assert!(!message.contains(&root));
    assert!(!message.contains("truncated tail"));
    assert!(!payload["error"]["request_id"].as_str().unwrap().is_empty());

    // Successful responses carry the same correlation ID for access logs.
    let health = request(&app, Method::GET, "/health", None, &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    assert!(health.headers.contains_key("x-request-id"));
}

/// A record filename that cannot be an ID is the database's stored state being
/// unusable, not the request being wrong, so it is a `409 conflict` rather
/// than a `422` blaming a caller who asked for nothing unusual — and above all
/// not an unclassified `500`, which would hide the one sentence that says how
/// to fix it.
#[tokio::test]
async fn an_unusable_record_filename_is_a_classified_conflict_over_http() {
    let (_temporary, database) = test_database("server-unusable-record-name");
    database.create("deals", "acme", &[], "").unwrap();
    fs::write(
        database.root().join("records/deals/..md"),
        "---\nvalue: 1\n---\n",
    )
    .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let root = database.root().to_string_lossy().to_string();

    for uri in [
        "/api/v1/collections/deals/records",
        "/api/v1/search?q=acme",
        "/api/v1/status",
    ] {
        let response = request(&app, Method::GET, uri, None, &[]).await;
        assert_eq!(
            response.status,
            StatusCode::CONFLICT,
            "{uri}: {:?}",
            response.text()
        );
        assert_eq!(response.json()["error"]["code"], "conflict", "{uri}");
        let message = response.json()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(
            message.contains("collection 'deals'") && message.contains("'..md'"),
            "{uri} did not name the file and its collection: {message}"
        );
        assert!(
            message.contains("cannot be a record ID"),
            "{uri} did not say what is wrong: {message}"
        );
        assert!(
            !message.contains(&root) && !message.contains("records/deals"),
            "{uri} leaked a filesystem path: {message}"
        );
    }

    // The healthy record beside it is still addressable by name.
    let single = request(
        &app,
        Method::GET,
        "/api/v1/collections/deals/records/acme",
        None,
        &[],
    )
    .await;
    assert_eq!(single.status, StatusCode::OK);
}
