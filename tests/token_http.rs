use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use cr::{
    AccessResource, Assignment, AuditFilter, AuthenticationMethod, Database, Role, UserKind,
    UserStatus, UserUpdate,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "Owner <owner@example.com>";
const EDITOR: &str = "editor@example.com";

struct TestResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl TestResponse {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap().to_owned()
    }
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
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(
                    body.map(|body| body.to_string()).unwrap_or_default(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    TestResponse { status, body }
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
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
            "acme",
            &[Assignment::from_str("stage=open").unwrap()],
            "",
        )
        .unwrap();
    database
        .add_user(EDITOR, "Editor", Some(EDITOR), UserKind::Human)
        .unwrap();
    database
        .grant_access(EDITOR, AccessResource::collection("deals"), Role::Editor)
        .unwrap();
    (temporary, database)
}

fn issue(database: &Database, principal: &str) -> (String, String) {
    let (issued, _) = database.issue_token(principal, None, None).unwrap();
    (issued.token.to_string(), issued.stored.id)
}

#[tokio::test]
async fn a_principal_token_authenticates_its_principal_and_every_event_records_it() {
    let (_temporary, database) = seeded_database("token-authenticates");
    let (token, id) = issue(&database, EDITOR);
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let authorization = bearer(&token);

    let identity = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(identity.status, StatusCode::OK, "{}", identity.text());
    let identity = identity.json();
    assert_eq!(identity["principal"], EDITOR);
    assert_eq!(identity["actor"], "Editor <editor@example.com>");
    assert_eq!(identity["impersonated_by"], Value::Null);
    assert_eq!(
        identity["authentication"],
        json!({ "method": "token", "credential": id })
    );

    // The console's own identity carries no authentication.
    let console = request(&app, Method::GET, "/api/v1/identity", None, &[]).await;
    assert_eq!(console.json()["principal"], "owner@example.com");
    assert_eq!(console.json()["authentication"], Value::Null);

    let updated = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/deals/records/acme",
        Some(json!({ "front_matter": { "stage": "won" } })),
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());

    let entries = database
        .audit_recent(
            1,
            AuditFilter {
                collection: Some("deals"),
                id: Some("acme"),
                ..AuditFilter::default()
            },
        )
        .unwrap();
    let access = entries[0].payload.access.as_ref().unwrap();
    assert_eq!(entries[0].payload.actor, "Editor <editor@example.com>");
    assert_eq!(access.principal, EDITOR);
    assert!(access.impersonated_by.is_none());
    let authentication = access.authentication.as_ref().unwrap();
    assert_eq!(authentication.method, AuthenticationMethod::Token);
    assert_eq!(authentication.credential.as_deref(), Some(id.as_str()));
    database.audit_verify(None).unwrap();

    // The token's principal is its policy: an editor still cannot delete.
    let deleted = request(
        &app,
        Method::DELETE,
        "/api/v1/collections/deals/records/acme",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_token_cannot_be_redirected_to_another_principal() {
    let (_temporary, database) = seeded_database("token-bound");
    let (token, _) = issue(&database, EDITOR);
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let authorization = bearer(&token);

    // The console's perspective cookie is ignored: it selects a perspective for
    // the launching owner, and a token is not the launching owner.
    let cookie = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[
            ("authorization", &authorization),
            ("cookie", "cr_perspective=owner%40example.com"),
        ],
    )
    .await;
    assert_eq!(cookie.json()["principal"], EDITOR);

    // X-CR-Actor may restyle the same principal and nothing else.
    let restyled = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[
            ("authorization", &authorization),
            ("x-cr-actor", "E. Ditor <editor@example.com>"),
        ],
    )
    .await;
    assert_eq!(restyled.json()["actor"], "E. Ditor <editor@example.com>");
    assert_eq!(restyled.json()["principal"], EDITOR);
    let other = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization), ("x-cr-actor", OWNER)],
    )
    .await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);

    // Nor can a token-authenticated request switch the console's perspective.
    let switched = request(
        &app,
        Method::POST,
        "/perspective",
        None,
        &[
            ("authorization", &authorization),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
    )
    .await;
    assert_eq!(switched.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_token_that_fails_never_falls_back_to_the_console() {
    let (_temporary, database) = seeded_database("token-refused");
    let (revoked, revoked_id) = issue(&database, EDITOR);
    database.revoke_token(EDITOR, &revoked_id).unwrap();
    let (disabled, _) = issue(&database, EDITOR);
    database
        .update_user(
            EDITOR,
            UserUpdate {
                status: Some(UserStatus::Disabled),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let (live, _) = issue(&database, "owner@example.com");
    let (prefix, _) = live.rsplit_once('_').unwrap();
    let wrong_secret = format!("{prefix}_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    for token in [
        revoked.as_str(),
        disabled.as_str(),
        wrong_secret.as_str(),
        "crt_0123456789abcdef_unknown",
        "crt_malformed",
    ] {
        let authorization = bearer(token);
        let response = request(
            &app,
            Method::GET,
            "/api/v1/collections/deals/records/acme",
            None,
            &[("authorization", &authorization)],
        )
        .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{token}");
        assert_eq!(response.code(), "unauthorized");
        assert_eq!(
            response.json()["error"]["message"],
            "the principal token is not valid"
        );
    }
    let authorization = bearer(&live);
    let owner = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(owner.status, StatusCode::OK);
    assert_eq!(owner.json()["principal"], "owner@example.com");
}

#[tokio::test]
async fn a_verifier_written_into_a_user_file_directly_authenticates_nothing() {
    let (_temporary, database) = seeded_database("token-direct-edit");
    let (legitimate, _) = issue(&database, EDITOR);
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // Forge a token and plant its verifier in the owner's policy file, as
    // somebody who can write the Markdown but cannot append an audit event.
    let forged = "crt_00000000000000ff_forged-secret-that-nobody-issued";
    let mut digest = Sha256::new();
    digest.update(b"cr:access:token:v1\0");
    digest.update(forged.as_bytes());
    let hash: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let owner_path = database.root().join("records/users/owner@example.com.md");
    let owner_file = std::fs::read_to_string(&owner_path).unwrap();
    let planted = owner_file.replacen(
        "\n---\n",
        &format!(
            "\ntokens:\n- id: 00000000000000ff\n  hash: sha256:{hash}\n  created: 2026-01-01T00:00:00Z\n---\n"
        ),
        1,
    );
    assert_ne!(planted, owner_file);
    std::fs::write(&owner_path, planted).unwrap();

    let authorization = bearer(forged);
    let forged_response = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(forged_response.status, StatusCode::UNAUTHORIZED);

    // A legitimate token whose principal's file has drifted from its audited
    // policy is refused too, as a conflict rather than as a bad token.
    let editor_path = database.root().join("records/users/editor@example.com.md");
    let editor_file = std::fs::read_to_string(&editor_path).unwrap();
    std::fs::write(
        &editor_path,
        editor_file.replacen("name: Editor", "name: Editor In Chief", 1),
    )
    .unwrap();
    let authorization = bearer(&legitimate);
    let drifted = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(drifted.status, StatusCode::CONFLICT, "{}", drifted.text());
}

#[tokio::test]
async fn require_token_serves_only_authenticated_principals() {
    let (_temporary, database) = seeded_database("token-required");
    let (editor_token, _) = issue(&database, EDITOR);
    let (owner_token, _) = issue(&database, "owner@example.com");
    let config = ServerConfig {
        bind: "0.0.0.0:3000".parse().unwrap(),
        require_token: true,
        ..ServerConfig::default()
    };
    let app = router(database.clone(), config).unwrap();

    for path in ["/api/v1/identity", "/", "/users", "/audit", "/openapi.json"] {
        let response = request(&app, Method::GET, path, None, &[]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let health = request(&app, Method::GET, "/health", None, &[]).await;
    assert_eq!(health.status, StatusCode::OK);

    // A page for a token-authenticated principal offers nobody else to be.
    let authorization = bearer(&editor_token);
    let home = request(
        &app,
        Method::GET,
        "/",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(home.status, StatusCode::OK, "{}", home.text());
    assert!(!home.text().contains("action=\"/perspective\""));
    assert!(!home.text().contains("owner@example.com"));

    // Even an owner's token cannot reach the server's filesystem.
    let authorization = bearer(&owner_token);
    for path in ["/browse", "/browse/edit?path=/etc/hostname"] {
        let response = request(
            &app,
            Method::GET,
            path,
            None,
            &[("authorization", &authorization)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{path}");
    }
    let owner_home = request(
        &app,
        Method::GET,
        "/",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert!(!owner_home.text().contains("href=\"/browse\""));
}

#[tokio::test]
async fn require_token_is_refused_where_it_cannot_mean_anything() {
    let open = tempfile::tempdir().unwrap();
    let open = Database::init(open.path().join("open")).unwrap();
    let config = ServerConfig {
        require_token: true,
        ..ServerConfig::default()
    };
    let error = router(open.clone(), config).err().unwrap();
    assert!(error.to_string().contains("needs access control"));

    // On an open database a principal token is refused rather than ignored.
    let app = router(open, ServerConfig::default()).unwrap();
    let response = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", "Bearer crt_0123456789abcdef_secret")],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    let (_temporary, database) = seeded_database("token-required-shared");
    let config = ServerConfig {
        require_token: true,
        api_token: Some("shared".into()),
        ..ServerConfig::default()
    };
    let error = router(database.clone(), config).err().unwrap();
    assert!(error.to_string().contains("CR_API_TOKEN"));

    // Without --require-token an RBAC console still stays on loopback.
    let config = ServerConfig {
        bind: "0.0.0.0:3000".parse().unwrap(),
        ..ServerConfig::default()
    };
    assert!(router(database, config).is_err());
}

#[tokio::test]
async fn a_shared_api_token_and_principal_tokens_coexist() {
    let (_temporary, database) = seeded_database("token-shared");
    let (token, _) = issue(&database, EDITOR);
    let config = ServerConfig {
        api_token: Some("shared-secret".into()),
        ..ServerConfig::default()
    };
    let app = router(database, config).unwrap();

    let shared = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", "Bearer shared-secret")],
    )
    .await;
    assert_eq!(shared.json()["principal"], "owner@example.com");
    assert_eq!(shared.json()["authentication"], Value::Null);

    let authorization = bearer(&token);
    let principal = request(
        &app,
        Method::GET,
        "/api/v1/identity",
        None,
        &[("authorization", &authorization)],
    )
    .await;
    assert_eq!(principal.json()["principal"], EDITOR);

    for authorization in ["", "Bearer shared-secre", "Bearer shared-secret2"] {
        let response = request(
            &app,
            Method::GET,
            "/api/v1/identity",
            None,
            &[("authorization", authorization)],
        )
        .await;
        assert_eq!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{authorization:?}"
        );
    }
}
