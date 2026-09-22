//! Deleting a record is asked about by the server, not by a script.
//!
//! The record page used to carry a form whose `onsubmit` called
//! `window.confirm`, and the guard was worth less than it looked: an inline
//! handler is JavaScript, so a browser with JavaScript switched off — the
//! configuration every other HTTP suite in this repository stands in for —
//! deleted the record on the first click with nothing asked at all. Replacing
//! that handler with htmx's `hx-confirm`, which phase 5 of
//! `.context/htmx-plan.md` proposed, would have preserved the hole exactly: it
//! is also JavaScript, and it would merely have changed which script had to be
//! missing.
//!
//! So the confirmation moved to the server. `GET` on the delete path renders a
//! page that names the record, the collection and what survives in the audit
//! log, and offers Delete and Cancel; `POST` on the same path is the write, with
//! the contract it has always had — the same two fields, the same `303`, the
//! same `412` for a version that moved, the same audit event. That is what these
//! tests are for. Three properties matter:
//!
//! **Nothing deletes without the question having been asked.** There is no
//! longer any markup that writes on one click: the record page links, and only
//! the confirmation page carries a form, a token and a version.
//!
//! **The question is asked of everyone.** These tests send no htmx headers, so
//! they are the browser-with-no-JavaScript path, and it is the path where the
//! old confirmation did not exist. It exists here.
//!
//! **Declining is a navigation, not a cancelled event.** Cancel is a link back
//! to the record; following it writes nothing, because a `GET` never could.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    AccessResource, Assignment, AuditAction, AuditFilter, Database, Role, UserKind,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

const OWNER: &str = "Owner <owner@example.com>";

/// The path both halves of the interaction use, which is the point: one URL, and
/// the method decides whether it asks or writes.
const DELETE_PATH: &str = "/deals/records/acme/delete";
const RECORD_PATH: &str = "/deals/records/acme";

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl TestResponse {
    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap())
            .unwrap_or_default()
    }
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

async fn get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
    request(app, Method::GET, uri, None, headers).await
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

/// The value of a hidden input, read out of the page the server actually
/// rendered rather than computed here: the whole question is whether the
/// confirmation page hands the reader everything the write needs.
fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split_once(marker.as_str())
        .unwrap_or_else(|| panic!("no hidden {name} field in:\n{html}"))
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}

/// The form the confirmation page renders, filled in, ready to post.
async fn confirmation_form(app: &Router, cookie: &[(&str, &str)]) -> String {
    let page = get(app, DELETE_PATH, cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    form(&[
        ("_csrf", &hidden(&page.body, "_csrf")),
        (
            "_expected_record_hash",
            &hidden(&page.body, "_expected_record_hash"),
        ),
    ])
}

fn database_with_a_deal(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    database
        .create(
            "deals",
            "acme",
            &[
                Assignment::from_str("name=Acme").unwrap(),
                Assignment::from_str("stage=open").unwrap(),
            ],
            "Renewal",
        )
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn the_record_page_links_to_the_confirmation_and_can_write_nothing_itself() {
    let (_temporary, database) = database_with_a_deal("delete-link");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = get(&app, RECORD_PATH, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body
            .contains(&format!("<a href=\"{DELETE_PATH}\" class=")),
        "the record page does not link to the confirmation"
    );

    // The old markup, absent in both its parts. No form on this page posts to
    // the delete path any more, so there is nothing here a single click can
    // submit; and the inline handler is gone, which is what `script-src 'self'`
    // was waiting for. The edit form's own `_expected_record_hash` stays, because
    // that one is the update's optimistic-concurrency check and is unrelated.
    assert!(
        !page.body.contains(&format!("action=\"{DELETE_PATH}\"")),
        "the record page still carries a form that deletes"
    );
    assert!(
        !page.body.contains("onsubmit="),
        "an inline handler survives"
    );
    assert!(database.get("deals", "acme").is_ok());
}

#[tokio::test]
async fn the_confirmation_page_asks_with_no_javascript_at_all() {
    let (_temporary, database) = database_with_a_deal("delete-confirm");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // No htmx header anywhere in this file, which is the point of it: this is
    // exactly what a browser with scripting disabled receives.
    let page = get(&app, DELETE_PATH, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.starts_with("<!DOCTYPE html>"));
    assert!(page.body.contains("<title>Delete acme · cr</title>"));
    assert!(page.body.contains("Delete this record?"));

    // More than `window.confirm` could say: which record, out of which
    // collection, and what remains afterwards.
    assert!(page.body.contains("acme"));
    assert!(page.body.contains("deals"));
    assert!(page.body.contains("tamper-evident audit log"));

    // The form is here and only here, with both fields the write requires and
    // native submission, because a refusal is a rendered error document that
    // htmx would not swap into a boosted `POST`.
    assert!(
        page.body
            .contains(&format!("<form method=\"post\" action=\"{DELETE_PATH}\"")),
        "the confirmation page carries no form: {}",
        page.body
    );
    assert!(page.body.contains("hx-boost=\"false\""));
    assert!(!hidden(&page.body, "_csrf").is_empty());
    assert!(!hidden(&page.body, "_expected_record_hash").is_empty());

    // Cancel is a link to the record, so declining is a navigation that cannot
    // write and needs no handler to prevent one.
    assert!(
        page.body.contains(&format!(
            "<a href=\"{RECORD_PATH}\" class=\"cr-button\">Cancel</a>"
        )),
        "the confirmation page offers no way out: {}",
        page.body
    );

    // Rendering the question wrote nothing.
    assert!(database.get("deals", "acme").is_ok());
    assert!(
        database
            .audit_recent(1, AuditFilter::record("deals", "acme"))
            .unwrap()[0]
            .payload
            .action
            == AuditAction::Create
    );
}

#[tokio::test]
async fn declining_leaves_the_record_and_confirming_deletes_it() {
    let (_temporary, database) = database_with_a_deal("delete-decline");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // Declining: follow Cancel back to the record. Nothing is cancelled in the
    // sense a dialog cancels something — no request to delete was ever made.
    let submission = confirmation_form(&app, &[]).await;
    let cancelled = get(&app, RECORD_PATH, &[]).await;
    assert_eq!(cancelled.status, StatusCode::OK);
    assert!(database.get("deals", "acme").is_ok());

    // Confirming: the unchanged `POST` contract, answered with the redirect it
    // has always been answered with.
    let deleted = request(&app, Method::POST, DELETE_PATH, Some(submission), &[]).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert_eq!(
        deleted.header(header::LOCATION),
        "/deals?notice=Record+deleted"
    );
    assert!(database.get("deals", "acme").is_err());
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Delete);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_record_that_moved_while_the_question_was_open_is_refused() {
    let (_temporary, database) = database_with_a_deal("delete-stale");
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // The version travels from the confirmation page rather than from the record
    // page, which narrows this window without closing it — so the window still
    // has to be closed by the write. Someone edits the record after the question
    // was rendered and before it was answered.
    let submission = confirmation_form(&app, &[]).await;
    database
        .update(
            "deals",
            "acme",
            &[Assignment::from_str("stage=won").unwrap()],
            None,
        )
        .unwrap();

    let refused = request(&app, Method::POST, DELETE_PATH, Some(submission), &[]).await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert!(database.get("deals", "acme").is_ok());
}

#[tokio::test]
async fn a_missing_record_is_not_offered_for_deletion() {
    let (_temporary, database) = database_with_a_deal("delete-missing");
    let app = router(database, ServerConfig::default()).unwrap();

    // Answering with a confirmation page whose only possible outcome is a
    // failure would be a worse answer than the failure.
    let missing = get(&app, "/deals/records/nothing/delete", &[]).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    let no_view = get(&app, "/absent/records/acme/delete", &[]).await;
    assert_eq!(no_view.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_principal_who_may_not_delete_is_refused_the_question_too() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("delete-access"))
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
            "Renewal",
        )
        .unwrap();
    database
        .add_user(
            "reader@example.com",
            "Reader",
            Some("reader@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "acme"),
            Role::Viewer,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // The confirmation checks the permission itself rather than trusting that
    // the reader arrived from a page that rendered the link: a viewer can read
    // the record, so they can type this URL.
    let home = get(&app, "/", &[]).await;
    let token = hidden(&home.body, "_csrf");
    let switched = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", &token),
            ("principal", "reader@example.com"),
        ])),
        &[],
    )
    .await;
    let cookie = switched.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split_once(';')
        .unwrap()
        .0
        .to_owned();
    let as_reader: &[(&str, &str)] = &[("cookie", &cookie)];

    let record = get(&app, RECORD_PATH, as_reader).await;
    assert_eq!(record.status, StatusCode::OK);
    assert!(
        !record.body.contains(&format!("href=\"{DELETE_PATH}\"")),
        "a viewer is offered a delete link"
    );
    let question = get(&app, DELETE_PATH, as_reader).await;
    assert_eq!(question.status, StatusCode::FORBIDDEN);
    assert!(database.get("deals", "acme").is_ok());
}
