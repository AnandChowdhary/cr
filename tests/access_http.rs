use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    AccessDecisionBasis, AccessResource, Assignment, AuditFilter, CollectionAccessPolicy, Database,
    RecordVisibility, Role, UserKind,
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
async fn rest_reads_and_writes_enforce_record_owned_visibility() {
    let (temporary, database) = seeded_database("record-owned-api");
    database
        .set_record_access_policy("secrets", CollectionAccessPolicy::record_owned())
        .unwrap();
    for principal in ["reader@example.com", "editor@example.com"] {
        database
            .grant_access(
                principal,
                AccessResource::collection("secrets"),
                Role::Editor,
            )
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let home = request(&app, Method::GET, "/", None, None, &[]).await;
    let csrf = csrf(home.text()).to_owned();
    let editor = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "editor@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[],
    )
    .await;
    let editor_cookie = perspective_cookie(&editor);
    let reader = request(
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
    let reader_cookie = perspective_cookie(&reader);

    let created = request(
        &app,
        Method::POST,
        "/api/v1/collections/secrets/records",
        Some(json!({ "id": "deploy", "front_matter": { "service": "github" } }).to_string()),
        Some("application/json"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.text());

    let private = request(
        &app,
        Method::GET,
        "/api/v1/collections/secrets/records/deploy",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(private.status, StatusCode::FORBIDDEN);

    database
        .impersonate("editor@example.com")
        .unwrap()
        .set_record_visibility("secrets", "deploy", RecordVisibility::Shared)
        .unwrap();
    let shared = request(
        &app,
        Method::GET,
        "/api/v1/collections/secrets/records/deploy",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(shared.status, StatusCode::OK, "{}", shared.text());
    assert_eq!(shared.json()["front_matter"]["service"], "github");
    drop(temporary);
}

#[tokio::test]
async fn users_table_folds_grants_after_the_first_three() {
    let (_temporary, database) = seeded_database("users-grant-fold");
    for resource in [
        AccessResource::collection("notes"),
        AccessResource::collection("tasks"),
        AccessResource::record("deals", "secret"),
    ] {
        database
            .grant_access("reader@example.com", resource, Role::Viewer)
            .unwrap();
    }
    let app = router(database, ServerConfig::default()).unwrap();

    let users = request(&app, Method::GET, "/users", None, None, &[]).await;
    assert_eq!(users.status, StatusCode::OK, "{}", users.text());
    let page = users.text();
    let table = &page[page.find("<tbody").unwrap()..];
    let row = &table[table.find("reader@example.com").unwrap()..];
    let row = &row[..row.find("</tr>").unwrap()];
    // Sorted by resource, the collections come first and a record folds away,
    // still in the page for the reader who opens it.
    let fold = row.find("<details class=\"cr-access-more\">").unwrap();
    assert!(row.contains(">+1</span>"), "{row}");
    assert!(row[..fold].contains("viewer · collection:notes"));
    assert!(row[..fold].contains("viewer · collection:tasks"));
    assert!(row[..fold].contains("viewer · record:deals/public"));
    assert!(row[fold..].contains("viewer · record:deals/secret"));
    // A principal with three grants or fewer has nothing to fold.
    let editor = &table[table.find("editor@example.com").unwrap()..];
    assert!(!editor[..editor.find("</tr>").unwrap()].contains("cr-access-more"));
}

#[tokio::test]
async fn internal_user_records_are_readable_without_any_web_mutation() {
    let (_temporary, database) = seeded_database("internal-users");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let owner = request(&app, Method::GET, "/users", None, None, &[]).await;
    assert_eq!(owner.status, StatusCode::OK, "{}", owner.text());
    assert!(owner.text().contains("owner@example.com"));
    assert!(owner.text().contains("reader@example.com"));
    assert!(owner.text().contains("editor@example.com"));
    assert!(owner.text().contains("owner · database"));
    assert!(owner.text().contains("editor · collection:deals"));
    assert!(owner.text().contains("viewer · record:deals/public"));
    // Read-only means no create, edit, or delete affordance at all.
    assert!(owner.text().contains("read-only"));
    assert!(!owner.text().contains("New record"));
    assert!(!owner.text().contains("Save changes"));
    assert!(!owner.text().contains("Delete record…"));
    assert!(!owner.text().contains("href=\"/users/records"));
    let owner_files = request(&app, Method::GET, "/browse", None, None, &[]).await;
    assert_eq!(owner_files.status, StatusCode::OK, "{}", owner_files.text());
    assert!(owner_files.text().contains("<span>All files</span></h1>"));

    // `users` is not a view, so the record routes never reach it.
    let record = request(
        &app,
        Method::GET,
        "/users/records/reader@example.com",
        None,
        None,
        &[],
    )
    .await;
    assert_eq!(record.status, StatusCode::NOT_FOUND);

    let home = request(&app, Method::GET, "/", None, None, &[]).await;
    let csrf = csrf(home.text()).to_owned();
    let selected_editor = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "editor@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[],
    )
    .await;
    let editor_cookie = perspective_cookie(&selected_editor);

    // Editing records is not reading access policy: the section is hidden and
    // the page itself stays refused.
    let editor_home = request(
        &app,
        Method::GET,
        "/",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(editor_home.status, StatusCode::OK);
    assert!(!editor_home.text().contains("href=\"/users\""));
    assert!(!editor_home.text().contains("href=\"/browse\""));
    let editor_users = request(
        &app,
        Method::GET,
        "/users",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(editor_users.status, StatusCode::FORBIDDEN);
    let editor_files = request(
        &app,
        Method::GET,
        "/browse",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(editor_files.status, StatusCode::FORBIDDEN);

    database
        .grant_access(
            "editor@example.com",
            AccessResource::Database,
            Role::AccessManager,
        )
        .unwrap();
    let managed = request(
        &app,
        Method::GET,
        "/users",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(managed.status, StatusCode::OK, "{}", managed.text());
    assert!(managed.text().contains("reader@example.com"));
    let manager_files = request(
        &app,
        Method::GET,
        "/browse",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(manager_files.status, StatusCode::FORBIDDEN);

    // Pins are the owner's map of this host: an access manager sees none of
    // them and cannot add one.
    database.pin("/etc", Some("Owner's pinned place")).unwrap();
    let manager_home = request(
        &app,
        Method::GET,
        "/",
        None,
        None,
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert!(!manager_home.text().contains("Owner's pinned place"));
    assert!(!manager_home.text().contains("All files"));
    let manager_pin = request(
        &app,
        Method::POST,
        "/browse/pin",
        Some(form(&[
            ("_csrf", &csrf),
            ("path", "/tmp"),
            ("from", "/tmp"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(manager_pin.status, StatusCode::FORBIDDEN);
    assert_eq!(database.pins().unwrap().len(), 1);

    // Nor may an access manager open, save, or delete a file.
    let file = database.root().join("notes.txt");
    std::fs::write(&file, "owner's notes").unwrap();
    let file_path = file.to_str().unwrap();
    let encoded = form(&[("path", file_path)]);
    for (method, uri, body) in [
        (Method::GET, format!("/browse/edit?{encoded}"), None),
        (
            Method::POST,
            "/browse/edit".to_owned(),
            Some(form(&[
                ("_csrf", &csrf),
                ("path", file_path),
                ("from", file_path),
                ("_expected_version", "sha256:0"),
                ("contents", "overwritten"),
            ])),
        ),
        (Method::GET, format!("/browse/delete?{encoded}"), None),
        (
            Method::POST,
            "/browse/delete".to_owned(),
            Some(form(&[("_csrf", &csrf), ("path", file_path)])),
        ),
    ] {
        let content_type = body
            .is_some()
            .then_some("application/x-www-form-urlencoded");
        let response = request(
            &app,
            method,
            &uri,
            body,
            content_type,
            &[("cookie", &editor_cookie)],
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{uri}");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "owner's notes");
}

#[tokio::test]
async fn owner_switches_user_perspectives_and_the_ui_matches_each_policy() {
    let (_temporary, database) = seeded_database("perspective-ui");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // The counts are part of what the policy decides, so ask for the index
    // with them rendered in rather than left for the page to fetch.
    let home = request(&app, Method::GET, "/?summary=inline", None, None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("aria-label=\"View as user\""));
    assert!(home.text().contains("Owner — owner"));
    assert!(home.text().contains("Reader — viewer · scoped"));
    // The reserved `users` collection is internal: it stays out of collection
    // navigation and the view index, and is offered separately instead.
    let (navigation, _) = home
        .text()
        .split_once("cr-sidebar-label\">Internal<")
        .unwrap();
    assert!(!navigation.contains("href=\"/users\""));
    let (index, _) = home
        .text()
        .split_once("aria-label=\"Internal records\"")
        .unwrap();
    assert!(!index.contains("records/users"));
    assert!(home.text().contains("href=\"/users\""));
    // The owner can read both deals, and the index counts both.
    assert!(index.contains("<span class=\"cr-view-count\">2<"));
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

    // A count is information too: the reader holds a grant on one deal, so the
    // index must not reveal that the collection has another.
    let reader_home = request(
        &app,
        Method::GET,
        "/?summary=inline",
        None,
        None,
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(reader_home.status, StatusCode::OK);
    assert!(
        reader_home
            .text()
            .contains("<span class=\"cr-view-count\">1<")
    );
    assert!(!reader_home.text().contains("cr-view-count\">2<"));
    // The owner is told how to fill an empty Saved views section; a reader,
    // who cannot save views, is not offered what they cannot do.
    assert!(home.text().contains(r#"<p class="cr-sidebar-hint">"#));
    assert!(
        !reader_home
            .text()
            .contains(r#"<p class="cr-sidebar-hint">"#)
    );

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
    // The perspective is a cookie, so the same URL renders different records
    // for different principals and `Vary` has to say `Cookie`. It says more
    // than that: an HTML answer also varies on the htmx headers that choose
    // between a document and a fragment (`tests/fragment_seam_http.rs`), and
    // `Cookie` arriving from the authorization layer must be appended to that
    // list rather than replace it.
    assert_eq!(
        reader_view.headers[header::VARY],
        "Cookie, HX-Request, HX-Target, HX-History-Restore-Request"
    );
    // One `Vary` header, not two: both layers have something to add and the
    // second one to run finds `Cookie` already listed.
    assert_eq!(reader_view.headers.get_all(header::VARY).iter().count(), 1);

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
    // A record with no name is called by its ID.
    assert!(
        reader_record
            .text()
            .contains(r#"<h1 class="cr-page-title"><span>public</span></h1>"#)
    );
    assert!(reader_record.text().contains("Read-only perspective"));
    assert!(!reader_record.text().contains("Save changes"));
    assert!(!reader_record.text().contains("Delete record…"));

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
    assert!(
        editor_record
            .text()
            .contains(r#"<h1 class="cr-page-title"><span>public</span></h1>"#)
    );
    assert!(editor_record.text().contains("Save changes"));
    assert!(!editor_record.text().contains("Delete record…"));

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

#[tokio::test]
async fn user_profile_patches_follow_editor_grants_and_self_name_updates() {
    let (_temporary, database) = seeded_database("user-profile-api");
    database
        .grant_access(
            "editor@example.com",
            AccessResource::collection("users"),
            Role::Editor,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let home = request(&app, Method::GET, "/", None, None, &[]).await;
    let csrf = csrf(home.text()).to_owned();
    let selected_editor = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "editor@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[],
    )
    .await;
    let editor_cookie = perspective_cookie(&selected_editor);

    let profile = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/users/records/reader@example.com",
        Some(json!({ "front_matter": { "profile": { "source": "slack" } } }).to_string()),
        Some("application/json"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(profile.status, StatusCode::OK, "{}", profile.text());
    assert_eq!(profile.json()["front_matter"]["profile"]["source"], "slack");

    let reserved = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/users/records/reader@example.com",
        Some(
            json!({
                "front_matter": {
                    "name": "Editor chose this",
                    "profile": { "should_not_land": true }
                }
            })
            .to_string(),
        ),
        Some("application/json"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    assert_eq!(reserved.status, StatusCode::FORBIDDEN);
    assert_eq!(reserved.json()["error"]["code"], "forbidden");
    assert!(
        database
            .user("reader@example.com")
            .unwrap()
            .profile
            .get("should_not_land")
            .is_none()
    );

    let selected_reader = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &csrf),
            ("principal", "reader@example.com"),
        ])),
        Some("application/x-www-form-urlencoded"),
        &[("cookie", &editor_cookie)],
    )
    .await;
    let reader_cookie = perspective_cookie(&selected_reader);
    let self_update = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/users/records/reader@example.com",
        Some(
            json!({
                "front_matter": {
                    "name": "Preferred Reader",
                    "profile": { "timezone": "Europe/Amsterdam" }
                }
            })
            .to_string(),
        ),
        Some("application/json"),
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(self_update.status, StatusCode::OK, "{}", self_update.text());

    let email = request(
        &app,
        Method::PATCH,
        "/api/v1/collections/users/records/reader@example.com",
        Some(json!({ "front_matter": { "email": "changed@example.com" } }).to_string()),
        Some("application/json"),
        &[("cookie", &reader_cookie)],
    )
    .await;
    assert_eq!(email.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(email.json()["error"]["code"], "validation_failed");

    let reader = database.user("reader@example.com").unwrap();
    assert_eq!(reader.name, "Preferred Reader");
    assert_eq!(reader.email.as_deref(), Some("reader@example.com"));
    assert_eq!(
        reader.profile["timezone"],
        yaml_serde::Value::String("Europe/Amsterdam".into())
    );
    let history = database
        .audit_recent(1, AuditFilter::record("users", "reader@example.com"))
        .unwrap();
    let access = history[0].payload.access.as_ref().unwrap();
    assert_eq!(access.basis, AccessDecisionBasis::SelfService);
    assert_eq!(
        access.impersonated_by.as_ref().unwrap().principal,
        "owner@example.com"
    );
}

#[tokio::test]
async fn only_an_owner_may_edit_or_delete_a_saved_view() {
    let (_temporary, database) = seeded_database("perspective-saved-views");
    database
        .create_view(
            "open-deals",
            Some("Open deals"),
            "deals",
            vec!["stage=open".into()],
            vec![],
            25,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let owner_view = request(&app, Method::GET, "/open-deals", None, None, &[]).await;
    assert_eq!(owner_view.status, StatusCode::OK);
    assert!(owner_view.text().contains("id=\"cr-view-edit\""));
    let owner_editor = request(&app, Method::GET, "/open-deals/edit", None, None, &[]).await;
    assert_eq!(owner_editor.status, StatusCode::OK);
    let csrf = csrf(owner_editor.text()).to_owned();

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
    let reader_cookie = perspective_cookie(&selected_reader);
    let reader = [("cookie", reader_cookie.as_str())];

    let reader_view = request(&app, Method::GET, "/open-deals", None, None, &reader).await;
    assert_eq!(reader_view.status, StatusCode::OK);
    assert!(!reader_view.text().contains("id=\"cr-view-edit\""));
    assert!(!reader_view.text().contains("id=\"cr-view-save-state\""));
    for (method, uri, body) in [
        (Method::GET, "/open-deals/edit", None),
        (Method::GET, "/open-deals/delete", None),
        (
            Method::POST,
            "/open-deals/edit",
            Some(form(&[
                ("_csrf", &csrf),
                ("title", "Taken over"),
                ("sort_field", "$id"),
                ("page_size", "25"),
            ])),
        ),
        (
            Method::POST,
            "/open-deals/delete",
            Some(form(&[("_csrf", &csrf)])),
        ),
    ] {
        let refused = request(
            &app,
            method.clone(),
            uri,
            body,
            Some("application/x-www-form-urlencoded"),
            &reader,
        )
        .await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{method} {uri}");
    }
    assert_eq!(database.view("open-deals").unwrap().title, "Open deals");
}
