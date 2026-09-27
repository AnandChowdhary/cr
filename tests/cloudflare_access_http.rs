//! `cr serve --cloudflare-access`: signing people in by the email in a
//! verified Cloudflare Access assertion.
//!
//! The team's key set is served by a small HTTP server on loopback, and the
//! assertions are signed with the two throwaway RSA keys under
//! `tests/fixtures/cloudflare_access`, exactly as Cloudflare signs its own.

use std::{
    io::{Read, Write},
    net::TcpListener,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cr::{
    AccessResource, Assignment, AuditFilter, AuthenticationMethod, Database, Role, UserKind,
    UserStatus, UserUpdate,
    cloudflare_access::CloudflareAccess,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use ring::{
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const TEAM: &str = "https://harmess.cloudflareaccess.com";
const AUDIENCE: &str = "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2";
const OWNER: &str = "Owner <owner@example.com>";
const EDITOR: &str = "editor@example.com";
const SUBJECT: &str = "7335d417-61da-459d-899c-0a01c76a2f94";
const ASSERTION: &str = "cf-access-jwt-assertion";

// ---------------------------------------------------------------------------
// Signing keys and assertions

struct Signer {
    key: RsaKeyPair,
    kid: &'static str,
}

impl Signer {
    fn team() -> Self {
        Self::load(
            include_bytes!("fixtures/cloudflare_access/team-key.der"),
            "team-key",
        )
    }

    fn other() -> Self {
        Self::load(
            include_bytes!("fixtures/cloudflare_access/other-key.der"),
            "other-key",
        )
    }

    fn load(pkcs1: &[u8], kid: &'static str) -> Self {
        Self {
            key: RsaKeyPair::from_der(pkcs1).unwrap(),
            kid,
        }
    }

    /// The same key published under another ID.
    fn with_kid(self, kid: &'static str) -> Self {
        Self { kid, ..self }
    }

    /// This key as a JSON Web Key, read out of its DER `RSAPublicKey`.
    fn jwk(&self) -> Value {
        let (tag, sequence, _) = der(self.key.public().as_ref());
        assert_eq!(tag, 0x30);
        let (_, n, rest) = der(sequence);
        let (_, e, _) = der(rest);
        let unsigned = |bytes: &[u8]| {
            let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
            URL_SAFE_NO_PAD.encode(&bytes[zeros..])
        };
        json!({
            "kid": self.kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "e": unsigned(e),
            "n": unsigned(n),
        })
    }

    fn sign_raw(&self, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .unwrap();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    fn sign(&self, claims: &Value) -> String {
        self.sign_raw(
            &json!({ "alg": "RS256", "kid": self.kid, "typ": "JWT" }),
            claims,
        )
    }

    /// An assertion Cloudflare would issue for `email`, adjusted by `change`.
    fn assertion_for(&self, email: &str, change: impl FnOnce(&mut Value)) -> String {
        let now = now();
        let mut claims = json!({
            "aud": [AUDIENCE],
            "email": email,
            "exp": now + 3600,
            "iat": now,
            "nbf": now,
            "iss": TEAM,
            "type": "app",
            "identity_nonce": "6ei69kawdKzMIAPF",
            "sub": SUBJECT,
            "country": "NL",
        });
        change(&mut claims);
        self.sign(&claims)
    }

    fn assertion(&self, email: &str) -> String {
        self.assertion_for(email, |_| {})
    }
}

/// One DER element: its tag, its contents, and whatever follows it.
fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let (length, header) = match input[1] {
        short if short < 0x80 => (usize::from(short), 2),
        0x81 => (usize::from(input[2]), 3),
        0x82 => (usize::from(u16::from_be_bytes([input[2], input[3]])), 4),
        other => panic!("unexpected DER length byte {other:#x}"),
    };
    (
        input[0],
        &input[header..header + length],
        &input[header + length..],
    )
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// The team's key set, served over plain HTTP on loopback

struct KeyServer {
    url: String,
    body: Arc<Mutex<String>>,
    fetches: Arc<AtomicUsize>,
}

impl KeyServer {
    fn start(keys: &[&Signer]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/cdn-cgi/access/certs",
            listener.local_addr().unwrap()
        );
        let body = Arc::new(Mutex::new(String::new()));
        let fetches = Arc::new(AtomicUsize::new(0));
        let server = Self { url, body, fetches };
        server.publish(keys);
        let (body, fetches) = (Arc::clone(&server.body), Arc::clone(&server.fetches));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&buffer[..read]),
                    }
                }
                fetches.fetch_add(1, Ordering::SeqCst);
                let body = body.lock().unwrap().clone();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        server
    }

    /// Serve these keys from now on, as Cloudflare does after a rotation.
    fn publish(&self, keys: &[&Signer]) {
        *self.body.lock().unwrap() = json!({
            "keys": keys.iter().map(|key| key.jwk()).collect::<Vec<_>>(),
            "public_cert": { "kid": keys.first().map(|key| key.kid), "cert": "-----BEGIN CERTIFICATE-----" },
        })
        .to_string();
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }

    fn access(&self) -> Arc<CloudflareAccess> {
        Arc::new(self.unshared_access())
    }

    fn unshared_access(&self) -> CloudflareAccess {
        CloudflareAccess::new("harmess", AUDIENCE)
            .unwrap()
            .with_certs_url(&self.url)
    }
}

/// Somewhere nothing listens.
fn unreachable_access() -> Arc<CloudflareAccess> {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    Arc::new(
        CloudflareAccess::new("harmess", AUDIENCE)
            .unwrap()
            .with_certs_url(format!("http://127.0.0.1:{port}/cdn-cgi/access/certs")),
    )
}

// ---------------------------------------------------------------------------
// Requests

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

    fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap().to_owned()
    }

    fn message(&self) -> String {
        self.json()["error"]["message"].as_str().unwrap().to_owned()
    }

    fn header(&self, name: header::HeaderName) -> String {
        self.headers
            .get_all(name)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<(&str, String)>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some((content_type, _)) = &body {
        builder = builder.header(header::CONTENT_TYPE, *content_type);
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(body.map(|(_, body)| body).unwrap_or_default()))
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

async fn get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
    request(app, Method::GET, uri, None, headers).await
}

fn json_body(value: Value) -> Option<(&'static str, String)> {
    Some(("application/json", value.to_string()))
}

fn form(fields: &[(&str, &str)]) -> Option<(&'static str, String)> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        serializer.append_pair(name, value);
    }
    Some(("application/x-www-form-urlencoded", serializer.finish()))
}

fn csrf(html: &str) -> &str {
    html.split_once("name=\"_csrf\" value=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
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

fn signed_in(access: Arc<CloudflareAccess>) -> ServerConfig {
    ServerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        cloudflare_access: Some(access),
        ..ServerConfig::default()
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_verified_assertion_signs_in_the_user_whose_email_it_names() {
    let (_temporary, database) = seeded_database("cloudflare-signs-in");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let app = router(database.clone(), signed_in(keys.access())).unwrap();
    // Case is the identity provider's business, not the user's.
    let assertion = team.assertion("Editor@Example.COM");

    let identity = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(identity.status, StatusCode::OK, "{}", identity.text());
    let identity = identity.json();
    assert_eq!(identity["principal"], EDITOR);
    assert_eq!(identity["actor"], "Editor <editor@example.com>");
    assert_eq!(identity["impersonated_by"], Value::Null);
    assert_eq!(
        identity["authentication"],
        json!({ "method": "cloudflare-access", "credential": SUBJECT })
    );

    let updated = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/deals/records/acme",
        json_body(json!({ "front_matter": { "stage": "won" } })),
        &[(ASSERTION, &assertion)],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());
    let entries = database
        .audit_recent(1, AuditFilter::record("deals", "acme"))
        .unwrap();
    let access = entries[0].payload.access.as_ref().unwrap();
    assert_eq!(entries[0].payload.actor, "Editor <editor@example.com>");
    assert_eq!(access.principal, EDITOR);
    let authentication = access.authentication.as_ref().unwrap();
    assert_eq!(
        authentication.method,
        AuthenticationMethod::CloudflareAccess
    );
    assert_eq!(authentication.credential.as_deref(), Some(SUBJECT));
    database.audit_verify(None).unwrap();

    // The web timeline says how the change was authenticated.
    let owner = team.assertion("owner@example.com");
    let audit = get(&app, "/audit", &[(ASSERTION, &owner)]).await;
    assert_eq!(audit.status, StatusCode::OK, "{}", audit.text());
    assert!(audit.text().contains("authenticated by Cloudflare Access"));

    // The user's grants still decide: an editor cannot delete.
    let deleted = request(
        &app,
        Method::DELETE,
        "/api/v1/collections/deals/records/acme",
        None,
        &[(ASSERTION, &assertion)],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::FORBIDDEN);

    // Only one fetch of the keys for all of that.
    assert_eq!(keys.fetches(), 1);
}

#[tokio::test]
async fn nothing_unsigned_or_signed_for_something_else_signs_anybody_in() {
    let (_temporary, database) = seeded_database("cloudflare-refuses");
    let team = Signer::team();
    let impostor = Signer::other().with_kid("team-key");
    let keys = KeyServer::start(&[&team]);
    let app = router(database, signed_in(keys.access())).unwrap();
    let genuine = team.assertion("owner@example.com");

    // What Cloudflare also sends, and anything on the machine could send.
    let unsigned = get(
        &app,
        "/api/v1/identity",
        &[
            ("cf-access-authenticated-user-email", "owner@example.com"),
            ("cookie", &format!("CF_Authorization={genuine}")),
        ],
    )
    .await;
    assert_eq!(unsigned.status, StatusCode::UNAUTHORIZED);
    assert_eq!(unsigned.message(), "sign in through Cloudflare Access");

    let now = now();
    let refused = [
        (
            impostor.assertion("owner@example.com"),
            "is not signed by the team's key",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims["iss"] = json!("https://elsewhere.cloudflareaccess.com");
            }),
            "was not issued by https://harmess.cloudflareaccess.com",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims["aud"] = json!(["another-application"]);
            }),
            "is for another Access application",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims["aud"] = json!(AUDIENCE.to_uppercase());
            }),
            "is for another Access application",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims["exp"] = json!(now - 120);
            }),
            "has expired",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims.as_object_mut().unwrap().remove("exp");
            }),
            "has no readable expiry",
        ),
        (
            team.assertion_for("owner@example.com", |claims| {
                claims["nbf"] = json!(now + 600);
            }),
            "is not valid yet",
        ),
        // A service token names a client, not a person.
        (
            team.assertion_for("", |claims| {
                let claims = claims.as_object_mut().unwrap();
                claims.remove("email");
                claims.insert("common_name".into(), json!("deploy.access"));
                claims.insert("sub".into(), json!(""));
            }),
            "names no email",
        ),
        (
            team.sign_raw(
                &json!({ "alg": "HS256", "kid": "team-key" }),
                &json!({ "email": "owner@example.com", "iss": TEAM, "aud": AUDIENCE }),
            ),
            "is not signed with RS256",
        ),
        (
            format!("{}.***", genuine.rsplit_once('.').unwrap().0),
            "has an unreadable signature",
        ),
        (
            format!("{}.", genuine.rsplit_once('.').unwrap().0),
            "is not signed by the team's key",
        ),
        (
            // The payload of one assertion under the signature of another.
            {
                let other = team.assertion(EDITOR);
                let (head, _) = genuine.rsplit_once('.').unwrap();
                format!("{head}.{}", other.rsplit_once('.').unwrap().1)
            },
            "is not signed by the team's key",
        ),
    ];
    for (assertion, reason) in refused {
        let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{reason}");
        assert_eq!(response.code(), "unauthorized", "{reason}");
        assert!(
            response.message().contains(reason),
            "{reason}: {}",
            response.message()
        );
        assert_eq!(
            response.header(header::WWW_AUTHENTICATE),
            "Bearer realm=\"cr\""
        );
    }

    // Two assertions are one too many to choose between.
    let mut builder = Request::builder().uri("/api/v1/identity");
    builder = builder
        .header(ASSERTION, &genuine)
        .header(ASSERTION, &genuine);
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // The genuine one still works, and nothing above fetched the keys twice.
    let accepted = get(&app, "/api/v1/identity", &[(ASSERTION, &genuine)]).await;
    assert_eq!(accepted.status, StatusCode::OK, "{}", accepted.text());
    assert_eq!(accepted.json()["principal"], "owner@example.com");
    assert_eq!(keys.fetches(), 1);
}

#[tokio::test]
async fn the_email_must_belong_to_exactly_one_active_user() {
    let (_temporary, database) = seeded_database("cloudflare-one-user");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    database
        .add_user(
            "former@example.com",
            "Former",
            Some("former@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .update_user(
            "former@example.com",
            UserUpdate {
                status: Some(UserStatus::Disabled),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    database
        .add_user("ada", "Ada", Some("ada@example.com"), UserKind::Human)
        .unwrap();
    database
        .add_user(
            "ada-2",
            "Ada Again",
            Some("ADA@example.com"),
            UserKind::Human,
        )
        .unwrap();
    let app = router(database.clone(), signed_in(keys.access())).unwrap();

    for email in [
        "nobody@example.com",
        "former@example.com",
        "ada@example.com",
        // Only ASCII letters fold; this is not editor@example.com.
        "edİtor@example.com",
    ] {
        let assertion = team.assertion(email);
        let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{email}");
        assert!(
            response
                .message()
                .contains("no single active cr user has that email"),
            "{email}: {}",
            response.message()
        );
    }

    // Clearing one of the two makes the other unambiguous.
    database
        .update_user(
            "ada-2",
            UserUpdate {
                email: Some(None),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let assertion = team.assertion("ada@example.com");
    let ada = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(ada.status, StatusCode::OK, "{}", ada.text());
    assert_eq!(ada.json()["principal"], "ada");

    // An address written into a user file by hand, with no audited change
    // behind it, signs nobody in; the drifted file is a conflict.
    let editor_path = database.root().join("records/users/editor@example.com.md");
    let editor_file = std::fs::read_to_string(&editor_path).unwrap();
    std::fs::write(
        &editor_path,
        editor_file.replacen("email: editor@example.com", "email: mallory@example.com", 1),
    )
    .unwrap();
    let assertion = team.assertion("mallory@example.com");
    let planted = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(
        planted.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        planted.text()
    );
    let assertion = team.assertion(EDITOR);
    let drifted = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(drifted.status, StatusCode::CONFLICT, "{}", drifted.text());
}

#[tokio::test]
async fn keys_are_cached_and_fetched_again_only_for_a_key_they_lack() {
    let (_temporary, database) = seeded_database("cloudflare-rotation");
    let team = Signer::team();
    let rotated = Signer::other();
    let keys = KeyServer::start(&[&team]);
    // Cloudflare rotates every few weeks, not within one test's ten seconds.
    let rotating = keys
        .unshared_access()
        .with_min_fetch_interval(Duration::ZERO);
    let app = router(database.clone(), signed_in(Arc::new(rotating))).unwrap();

    for _ in 0..3 {
        let assertion = team.assertion(EDITOR);
        let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    }
    assert_eq!(keys.fetches(), 1);

    // Cloudflare rotates: the new key signs, and the first assertion under it
    // makes the server fetch the set again.
    keys.publish(&[&rotated, &team]);
    let assertion = rotated.assertion(EDITOR);
    let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(keys.fetches(), 2);

    // At the real interval, a key ID nobody publishes costs no fetch so soon
    // after the last one: made-up IDs cannot make the server a client
    // hammering Cloudflare.
    let app = router(database, signed_in(keys.access())).unwrap();
    let assertion = team.assertion(EDITOR);
    let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.text());
    assert_eq!(keys.fetches(), 3);
    let unknown = Signer::other().with_kid("made-up");
    for _ in 0..3 {
        let assertion = unknown.assertion(EDITOR);
        let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert!(
            response
                .message()
                .contains("is signed by a key the team does not publish"),
            "{}",
            response.message()
        );
    }
    assert_eq!(keys.fetches(), 3);
}

#[tokio::test]
async fn keys_that_cannot_be_fetched_are_the_servers_fault_not_the_callers() {
    let (_temporary, database) = seeded_database("cloudflare-unreachable");
    let team = Signer::team();
    let app = router(database, signed_in(unreachable_access())).unwrap();

    let assertion = team.assertion(EDITOR);
    let response = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(
        response.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        response.text()
    );
    assert_eq!(response.code(), "authentication_unavailable");
    // What went wrong is for the server log, not the caller.
    assert!(!response.text().contains("127.0.0.1"));

    let health = get(&app, "/health", &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    let ready = get(&app, "/ready", &[]).await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    let check = ready.json()["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["name"] == "cloudflare_access")
        .cloned()
        .unwrap();
    assert_eq!(check["ok"], false);
    assert_eq!(check["code"], "cloudflare_access_keys_unavailable");
    assert!(!ready.text().contains("127.0.0.1"));
}

#[tokio::test]
async fn health_and_readiness_need_no_sign_in_and_nothing_else_is_open() {
    let (_temporary, database) = seeded_database("cloudflare-probes");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let app = router(database, signed_in(keys.access())).unwrap();

    let health = get(&app, "/health", &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json(), json!({ "status": "ok" }));

    // A router nobody started fetches nothing until asked; the first probe
    // starts the fetch, as it starts the journal's first walk, and a later
    // one finds both done.
    let mut ready = get(&app, "/ready", &[]).await;
    for _ in 0..200 {
        if ready.status == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        ready = get(&app, "/ready", &[]).await;
    }
    assert_eq!(ready.status, StatusCode::OK, "{}", ready.text());
    assert_eq!(ready.json()["status"], "ready");
    assert_eq!(keys.fetches(), 1);

    for path in ["/openapi.json", "/api/v1/identity", "/audit", "/users"] {
        let refused = get(&app, path, &[]).await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let assertion = team.assertion(EDITOR);
    let openapi = get(&app, "/openapi.json", &[(ASSERTION, &assertion)]).await;
    assert_eq!(openapi.status, StatusCode::OK, "{}", openapi.text());
    let document = openapi.json();
    assert_eq!(
        document["components"]["securitySchemes"]["cloudflareAccess"]["name"],
        "Cf-Access-Jwt-Assertion"
    );
    // Principal tokens are not a way in to this server, so not described.
    assert_eq!(document["security"], json!([{ "cloudflareAccess": [] }]));
}

#[tokio::test]
async fn principal_tokens_are_accepted_only_with_require_token_as_well() {
    let (_temporary, database) = seeded_database("cloudflare-and-tokens");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let (issued, _) = database.issue_token(EDITOR, None, None).unwrap();
    let bearer = format!("Bearer {}", issued.token.as_str());
    let token_id = issued.stored.id.clone();

    // Cloudflare Access alone: everybody comes through the login.
    let alone = router(database.clone(), signed_in(keys.access())).unwrap();
    let refused = get(&alone, "/api/v1/identity", &[("authorization", &bearer)]).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert!(refused.message().contains("--require-token"));
    // Not even beside an assertion that would have signed somebody in.
    let assertion = team.assertion("owner@example.com");
    let both = get(
        &alone,
        "/api/v1/identity",
        &[("authorization", &bearer), (ASSERTION, &assertion)],
    )
    .await;
    assert_eq!(both.status, StatusCode::UNAUTHORIZED);

    let config = ServerConfig {
        require_token: true,
        ..signed_in(keys.access())
    };
    let app = router(database.clone(), config).unwrap();
    let person = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert_eq!(person.json()["principal"], "owner@example.com");
    assert_eq!(
        person.json()["authentication"]["method"],
        "cloudflare-access"
    );

    // A script behind Access carries its service token's assertion, which
    // names nobody, and the principal token that names it.
    let service = team.assertion_for("", |claims| {
        let claims = claims.as_object_mut().unwrap();
        claims.remove("email");
        claims.insert("common_name".into(), json!("deploy.access"));
    });
    for headers in [
        vec![("authorization", bearer.as_str())],
        vec![("authorization", bearer.as_str()), (ASSERTION, &service)],
        vec![("authorization", bearer.as_str()), (ASSERTION, &assertion)],
    ] {
        let script = get(&app, "/api/v1/identity", &headers).await;
        assert_eq!(script.status, StatusCode::OK, "{}", script.text());
        assert_eq!(script.json()["principal"], EDITOR);
        assert_eq!(
            script.json()["authentication"],
            json!({ "method": "token", "credential": token_id })
        );
    }
    // A token that fails is refused, whatever assertion comes with it.
    let revoked = get(
        &app,
        "/api/v1/identity",
        &[
            ("authorization", "Bearer crt_0123456789abcdef_unknown"),
            (ASSERTION, &assertion),
        ],
    )
    .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);

    let neither = get(&app, "/api/v1/identity", &[]).await;
    assert_eq!(neither.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        neither.message(),
        "sign in through Cloudflare Access, or provide a principal token as a Bearer token"
    );
    let openapi = get(&app, "/openapi.json", &[("authorization", &bearer)]).await;
    assert_eq!(
        openapi.json()["security"],
        json!([{ "bearerAuth": [] }, { "cloudflareAccess": [] }])
    );
}

#[tokio::test]
async fn a_signed_in_browser_cannot_be_made_to_write_by_another_site() {
    let (_temporary, database) = seeded_database("cloudflare-cross-site");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let app = router(database.clone(), signed_in(keys.access())).unwrap();
    let owner = team.assertion("owner@example.com");
    let patch = || json_body(json!({ "front_matter": { "stage": "lost" } }));

    for (name, value) in [
        ("sec-fetch-site", "cross-site"),
        // Another application on the same domain is still another origin.
        ("sec-fetch-site", "same-site"),
        ("sec-fetch-site", "none"),
        ("origin", "https://evil.example"),
        ("origin", "null"),
    ] {
        let refused = request(
            &app,
            Method::PATCH,
            "/api/v1/collections/deals/records/acme",
            patch(),
            &[
                (ASSERTION, &owner),
                ("host", "cr.harmess.com"),
                (name, value),
            ],
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{name}: {value}");
        assert_eq!(refused.code(), "cross_site_request");
    }
    // Including the one route that changes data with no body at all, which a
    // plain cross-site form could otherwise post.
    let baseline = request(
        &app,
        Method::POST,
        "/api/v1/audit/baseline",
        None,
        &[(ASSERTION, &owner), ("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(baseline.status, StatusCode::FORBIDDEN);
    assert_eq!(
        database.get("deals", "acme").unwrap().attributes["stage"],
        "open"
    );

    // Reading is not writing: a link from elsewhere still opens the page.
    let linked = get(
        &app,
        "/api/v1/identity",
        &[(ASSERTION, &owner), ("sec-fetch-site", "cross-site")],
    )
    .await;
    assert_eq!(linked.status, StatusCode::OK);

    for headers in [
        vec![("sec-fetch-site", "same-origin")],
        vec![
            ("origin", "https://cr.harmess.com"),
            ("host", "cr.harmess.com"),
        ],
        // A script, not a browser.
        vec![],
    ] {
        let mut headers = headers;
        headers.push((ASSERTION, &owner));
        let accepted = request(
            &app,
            Method::PATCH,
            "/api/v1/collections/deals/records/acme",
            patch(),
            &headers,
        )
        .await;
        assert_eq!(
            accepted.status,
            StatusCode::OK,
            "{headers:?}: {}",
            accepted.text()
        );
    }
}

#[tokio::test]
async fn each_signed_in_person_has_their_own_form_token_and_no_console() {
    let (_temporary, database) = seeded_database("cloudflare-forms");
    database
        .create_view("deals", Some("Deals"), "deals", Vec::new(), Vec::new(), 25)
        .unwrap();
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let app = router(database.clone(), signed_in(keys.access())).unwrap();
    let owner = team.assertion("owner@example.com");
    let editor = team.assertion(EDITOR);

    let owner_page = get(&app, "/deals/records/acme", &[(ASSERTION, &owner)]).await;
    assert_eq!(owner_page.status, StatusCode::OK, "{}", owner_page.text());
    let editor_page = get(&app, "/deals/records/acme", &[(ASSERTION, &editor)]).await;
    assert_eq!(editor_page.status, StatusCode::OK, "{}", editor_page.text());
    let owner_csrf = csrf(owner_page.text()).to_owned();
    let editor_csrf = csrf(editor_page.text()).to_owned();
    assert_ne!(owner_csrf, editor_csrf);
    // One person's token is the same on every page, and on the next sign-in.
    let again = team.assertion("owner@example.com");
    let new_record = get(&app, "/deals/new", &[(ASSERTION, &again)]).await;
    assert_eq!(new_record.status, StatusCode::OK, "{}", new_record.text());
    assert_eq!(csrf(new_record.text()), owner_csrf);

    // Nobody is offered anybody else to be, or the server's files.
    for page in [&owner_page, &editor_page] {
        assert!(!page.text().contains("action=\"/perspective\""));
        assert!(!page.text().contains("href=\"/browse\""));
    }
    let browse = get(&app, "/browse", &[(ASSERTION, &owner)]).await;
    assert_eq!(browse.status, StatusCode::FORBIDDEN);

    // A form carrying one person's token is refused for another, so a page
    // the editor wrote with the editor's own token in it cannot make the
    // owner's browser delete anything.
    let version = database.get("deals", "acme").unwrap().version;
    let forged = request(
        &app,
        Method::POST,
        "/deals/records/acme/delete",
        form(&[("_csrf", &editor_csrf), ("_expected_record_hash", &version)]),
        &[(ASSERTION, &owner), ("sec-fetch-site", "same-origin")],
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN, "{}", forged.text());
    assert!(forged.text().contains("reload the form"));
    assert!(database.get("deals", "acme").is_ok());

    let deleted = request(
        &app,
        Method::POST,
        "/deals/records/acme/delete",
        form(&[("_csrf", &owner_csrf), ("_expected_record_hash", &version)]),
        &[(ASSERTION, &owner), ("sec-fetch-site", "same-origin")],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.text());
    assert!(database.get("deals", "acme").is_err());
}

#[tokio::test]
async fn a_browser_that_cannot_sign_in_is_shown_a_page() {
    let (_temporary, database) = seeded_database("cloudflare-page");
    let team = Signer::team();
    let keys = KeyServer::start(&[&team]);
    let app = router(database, signed_in(keys.access())).unwrap();

    let assertion = team.assertion("stranger@example.com");
    let page = get(&app, "/", &[(ASSERTION, &assertion)]).await;
    assert_eq!(page.status, StatusCode::UNAUTHORIZED);
    assert!(page.header(header::CONTENT_TYPE).starts_with("text/html"));
    assert!(page.text().contains("stranger@example.com"));
    assert_eq!(page.header(header::WWW_AUTHENTICATE), "Bearer realm=\"cr\"");

    // The API keeps its envelope.
    let api = get(&app, "/api/v1/identity", &[(ASSERTION, &assertion)]).await;
    assert!(
        api.header(header::CONTENT_TYPE)
            .starts_with("application/json")
    );
    assert_eq!(api.code(), "unauthorized");

    // What a signed-in person sees depends on the assertion, and a cache is
    // told so.
    let assertion = team.assertion(EDITOR);
    let home = get(&app, "/", &[(ASSERTION, &assertion)]).await;
    assert_eq!(home.status, StatusCode::OK, "{}", home.text());
    assert!(
        home.header(header::VARY)
            .contains("Cf-Access-Jwt-Assertion")
    );
    assert_eq!(home.header(header::CACHE_CONTROL), "no-store");
}

#[tokio::test]
async fn cloudflare_access_is_refused_where_it_cannot_mean_anything() {
    let open = tempfile::tempdir().unwrap();
    let open = Database::init(open.path().join("open")).unwrap();
    let error = router(open, signed_in(unreachable_access())).err().unwrap();
    assert!(error.to_string().contains("--cloudflare-access"));
    assert!(error.to_string().contains("needs access control"));

    let (_temporary, database) = seeded_database("cloudflare-refused");
    let config = ServerConfig {
        api_token: Some("shared".into()),
        ..signed_in(unreachable_access())
    };
    let error = router(database.clone(), config).err().unwrap();
    assert!(error.to_string().contains("CR_API_TOKEN"));

    // No console, so no loopback rule, and no owner has to launch it.
    let config = ServerConfig {
        bind: "0.0.0.0:3000".parse().unwrap(),
        ..signed_in(unreachable_access())
    };
    assert!(router(database.clone(), config).is_ok());
    let unregistered = Database::discover(Some(database.root())).unwrap();
    assert!(router(unregistered, signed_in(unreachable_access())).is_ok());
}
