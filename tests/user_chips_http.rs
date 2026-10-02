//! Wherever the web UI shows a person — a relation to a user, an audit actor,
//! the registry — it shows a tiny avatar of their initials and their name,
//! rather than their principal ID.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use cr::{
    AccessResource, Assignment, Database, Role, UserKind,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "Owner <owner@example.com>";
const ADA: &str = "ada@example.com";
const EDITOR: &str = "editor@example.com";

async fn page(app: &Router, uri: &str, headers: &[(&str, &str)]) -> String {
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
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(status, StatusCode::OK, "{uri}: {body}");
    body
}

/// A deal whose `owner` relation is Ada, who is a registered user, and an
/// editor of deals who may not read the user registry.
fn seeded_database() -> (TempDir, Database, String) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("people"))
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
            &[
                Assignment::from_str("name=Acme renewal").unwrap(),
                Assignment::from_str("stage=open").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .add_user(ADA, "Ada Lovelace", Some(ADA), UserKind::Human)
        .unwrap();
    database
        .add_user(EDITOR, "Editor", Some(EDITOR), UserKind::Human)
        .unwrap();
    database
        .grant_access(EDITOR, AccessResource::collection("deals"), Role::Editor)
        .unwrap();
    database
        .link("deals", "acme", "owner", "users", ADA)
        .unwrap();
    let (issued, _) = database.issue_token(EDITOR, None, None).unwrap();
    (
        temporary,
        database,
        format!("Bearer {}", issued.token.as_str()),
    )
}

#[tokio::test]
async fn a_relation_to_a_user_shows_the_person() {
    let (_temporary, database, editor) = seeded_database();
    let app = router(database, ServerConfig::default()).unwrap();

    let owner_page = page(&app, "/deals/records/acme?relations=true", &[]).await;
    assert!(
        owner_page.contains(
            "<span class=\"cr-relation-target\"><span class=\"cr-user\" title=\"ada@example.com\"><span class=\"cr-avatar cr-avatar-"
        ),
        "{owner_page}"
    );
    assert!(owner_page.contains(
        "aria-hidden=\"true\">AL</span><span class=\"cr-user-name\">Ada Lovelace</span>"
    ));

    // An editor of deals may not read the registry, so the relation shows only
    // the ID it states — still as a person, and never the name.
    let editor_page = page(
        &app,
        "/deals/records/acme?relations=true",
        &[("authorization", &editor)],
    )
    .await;
    assert!(
        editor_page.contains("<span class=\"cr-relation-missing\" title=\"Missing, or not visible to this perspective\"><span class=\"cr-user\">"),
        "{editor_page}"
    );
    assert!(editor_page.contains("<span class=\"cr-user-name\">ada@example.com</span>"));
    assert!(!editor_page.contains("Ada Lovelace"));
}

#[tokio::test]
async fn audit_actors_and_the_users_they_changed_show_the_person() {
    let (_temporary, database, _) = seeded_database();
    let app = router(database, ServerConfig::default()).unwrap();

    // The record's activity names who changed it, with the recorded actor in
    // the tooltip.
    let record = page(&app, "/deals/records/acme?relations=true", &[]).await;
    assert!(
        record.contains("<span class=\"cr-user\" title=\"Owner &lt;owner@example.com&gt;\">"),
        "{record}"
    );
    assert!(record.contains("<span class=\"cr-user-name\">Owner</span>"));

    // The audit log: every actor, and an event on a user's own record, which
    // names the user rather than `users/<id>`.
    let audit = page(&app, "/audit", &[]).await;
    assert!(audit.contains(
        "by <span class=\"font-medium text-gray-700\"><span class=\"cr-user\" title=\"Owner &lt;owner@example.com&gt;\">"
    ));
    assert!(
        audit.contains("<span class=\"cr-user\" title=\"users/ada@example.com\">"),
        "{audit}"
    );
    assert!(audit.contains("<span class=\"cr-user-name\">Ada Lovelace</span>"));
    // A deal is still its reference.
    assert!(audit.contains(">deals/acme</a>"));
}

#[tokio::test]
async fn the_registry_leads_with_the_person_and_keeps_their_id() {
    let (_temporary, database, _) = seeded_database();
    let app = router(database, ServerConfig::default()).unwrap();

    let users = page(&app, "/users", &[]).await;
    assert!(users.contains(">User</th>"));
    assert!(!users.contains(">Principal</th>"));
    assert!(users.contains("<span class=\"cr-user-name\">Ada Lovelace</span>"));
    assert!(users.contains("<span class=\"cr-user-id\">ada@example.com</span>"));
}
