//! The form experience: a refused write answers with the form, not an error page.
//!
//! Phase 3 of `.context/htmx-plan.md`, and the roadmap's *"Preserve submitted
//! form values on validation errors"*. A create or update the database refused
//! used to become the generic error page, which meant navigating back to recover
//! — and a browser does not reliably restore a `<textarea>` full of typed YAML,
//! so "navigate back" often meant "type it all again".
//!
//! Four properties are load bearing here, and each of them is a way for this to
//! be wrong rather than merely unfinished.
//!
//! The first is that nothing is lost. Every assertion about a re-rendered form
//! below compares against the *submitted* text and not against what the server
//! made of it: a rejected `12500.50` has to come back as `12500.50`, a YAML
//! mapping has to come back with its keys in the order they were typed, and the
//! Markdown body has to come back whole.
//!
//! The second is that the refusal is still a refusal. Nothing is written, no
//! audit event is recorded, the status is the status of the failure rather than a
//! flat `422`, and a stale `_expected_record_hash` still loses to the record that
//! moved underneath it — keeping the version it lost with, so the next click
//! cannot silently overwrite the writer who won.
//!
//! The third is that both clients get one answer. A browser with JavaScript off
//! posts the form and receives a whole document with a status; htmx posts the
//! same form and receives the same markup as the form region alone. The rest of
//! this HTTP suite never sends an htmx header, so it is the no-JavaScript
//! regression suite, and the tests below assert the two answers are the same
//! markup rather than two renderings that happen to agree today.
//!
//! The fourth is that success has a shape htmx can act on: `303 See Other` for a
//! plain post, `204 No Content` with `HX-Location` for an htmx one, because an
//! `XMLHttpRequest` follows a redirect invisibly and htmx would otherwise push
//! the posted path into the address bar.

use std::{fs, str::FromStr};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    Assignment, AuditFilter, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// The id of the record form, which is also the region name a submission puts in
/// `HX-Target`. Spelled out rather than imported because it is a contract with
/// the markup: the page states it in an `id`, the client repeats it in a header,
/// and a test sharing a constant with the server could not notice a rename break
/// that agreement.
const RECORD_FORM_REGION: &str = "cr-record-form";

/// The headers htmx sends when it submits the record form: the request label, the
/// URL it is on, and the `HX-Target` taken from the `id` of the element it is
/// about to replace, which for this form is the form itself.
const HTMX: [(&str, &str); 3] = [
    ("hx-request", "true"),
    ("hx-current-url", "http://127.0.0.1/deals/new"),
    ("hx-target", RECORD_FORM_REGION),
];

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl TestResponse {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap())
            .unwrap_or_default()
    }

    /// The body with this response's request ID replaced, so two answers to two
    /// requests can be compared as markup. The ID is the one thing that is
    /// legitimately different every time, and it is in the body because somebody
    /// reading a refusal has to be able to quote it.
    fn without_request_id(&self) -> String {
        self.body
            .replace(self.header("x-request-id"), "<request-id>")
    }
}

fn test_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    (temporary, database)
}

/// A collection whose schema can fail in more than one way: a declared object
/// field, a declared enum, a declared list, and room for attributes the schema
/// does not mention.
fn deals_database(name: &str) -> (TempDir, Database) {
    let (temporary, database) = test_database(name);
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name", "stage", "value"],
  "properties": {
    "name": { "type": "string", "minLength": 1 },
    "stage": { "enum": ["discovery", "won"] },
    "value": { "type": "number", "minimum": 0 },
    "relations": { "type": "object" },
    "reviewers": { "type": "array", "items": { "enum": ["ada", "grace"] } }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
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
    let body = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
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

fn expected_record_hash(html: &str) -> &str {
    let marker = "name=\"_expected_record_hash\" value=\"";
    let rest = html
        .split_once(marker)
        .unwrap_or_else(|| panic!("record version field missing from HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
}

/// One complete creation, with `relations` left to the caller because it is the
/// one declared field a browser cannot validate on its own: there is no native
/// rule for "this textarea has to contain a mapping".
///
/// Two of the values are chosen so that a reparsed round trip would come back
/// changed: `12500.50` prints as `12500.5`, and a mapping written `owner` before
/// `region` comes back alphabetized once it has been through the parser.
fn submission(token: &str, relations: &str) -> String {
    form(&[
        ("_csrf", token),
        ("_form_mode", "structured"),
        ("id", "acme-pilot"),
        ("attribute.name", "Acme pilot"),
        ("attribute.stage", "discovery"),
        ("attribute.value", "12500.50"),
        ("attribute.reviewers", "grace"),
        ("attribute.relations", relations),
        ("_additional_attributes", "owner: ada\nregion: emea\n"),
        (
            "markdown",
            "# Notes\n\n  indented, *typed*, worth keeping.\n",
        ),
    ])
}

/// Every value the reader typed, as it has to come back in the re-rendered form.
fn assert_nothing_was_lost(html: &str) {
    assert!(
        html.contains(r#"name="id" value="acme-pilot""#),
        "the record ID was not preserved:\n{html}"
    );
    assert!(
        html.contains(r#"value="Acme pilot""#),
        "a text field was not preserved:\n{html}"
    );
    assert!(
        html.contains(r#"value="discovery" checked"#),
        "the chosen option was not preserved:\n{html}"
    );
    assert!(
        html.contains(r#"value="grace" checked"#),
        "the ticked checkbox was not preserved:\n{html}"
    );
    assert!(
        !html.contains(r#"value="ada" checked"#),
        "a checkbox nobody ticked came back ticked:\n{html}"
    );
    // The submitted text, not a reparsed round trip of it.
    assert!(
        html.contains(r#"value="12500.50""#),
        "the submitted number was normalized:\n{html}"
    );
    assert!(
        html.contains("owner: ada\nregion: emea\n</textarea>"),
        "the additional-attributes YAML was not preserved verbatim:\n{html}"
    );
    assert!(
        html.contains("# Notes\n\n  indented, *typed*, worth keeping.\n</textarea>"),
        "the Markdown body was not preserved verbatim:\n{html}"
    );
    // The box that holds the YAML is open, because a collapsed disclosure would
    // hide both the text and anything said about it.
    assert!(
        html.contains(r#"class="cr-form-more" open>"#),
        "the additional-attributes box came back collapsed:\n{html}"
    );
}

/// The two properties a refused mutation has always had, and the two this phase
/// must not spend.
fn assert_nothing_was_written(database: &Database, collection: &str, id: &str) {
    assert!(
        database.get(collection, id).is_err(),
        "a refused creation wrote a record"
    );
    assert!(
        database
            .audit_recent(10, AuditFilter::record(collection, id))
            .unwrap()
            .is_empty(),
        "a refused creation recorded an audit event"
    );
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_refused_creation_answers_a_plain_post_with_the_whole_form_filled_in() {
    let (_temporary, database) = deals_database("refused-create");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();

    let refused = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "hello there")),
        &[],
    )
    .await;

    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        refused.body.starts_with("<!DOCTYPE html>"),
        "a plain post got something other than a document"
    );
    assert!(
        refused.body.contains("cr-sidebar"),
        "a plain post got a page with no navigation"
    );
    assert!(refused.body.contains("This record was not created."));
    assert!(refused.body.contains("does not match schema"));
    assert!(
        refused
            .body
            .contains("Nothing was written and no audit event was recorded.")
    );
    assert_nothing_was_lost(&refused.body);
    assert_nothing_was_written(&database, "deals", "acme-pilot");
}

#[tokio::test]
async fn a_refusal_names_the_field_it_is_about_where_the_schema_locates_one() {
    let (_temporary, database) = deals_database("refused-fields");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();

    let refused = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "hello there")),
        &[],
    )
    .await;
    let html = &refused.body;

    // The schema's own words, beside the control the value was typed into.
    let before_control = html
        .split_once(r#"id="field-relations""#)
        .expect("the relations control is rendered")
        .0;
    assert!(
        before_control.contains("is not of type") && before_control.contains("object"),
        "the diagnostic is not beside the control it is about:\n{html}"
    );
    // And stated to a screen reader, not only in red.
    assert!(
        html.contains(
            r#"name="attribute.relations" rows="5" spellcheck="false" aria-invalid="true""#
        ),
        "the refused control is not marked invalid:\n{html}"
    );
    assert_eq!(
        html.matches(r#"aria-invalid="true""#).count(),
        1,
        "a field nobody complained about was marked invalid:\n{html}"
    );
    assert_nothing_was_written(&database, "deals", "acme-pilot");
}

#[tokio::test]
async fn a_refusal_the_schema_cannot_locate_stays_a_message_on_the_box_it_came_from() {
    // No schema at all: the collection accepts any front matter, so the free-text
    // box is the only control there is and the refusal belongs to it.
    let (_temporary, database) = test_database("refused-thin-schema");
    database
        .create(
            "items",
            "one",
            &[Assignment::from_str("stage=open").unwrap()],
            "First",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/items/records/one", None, &[]).await;
    let token = csrf(&page.body).to_owned();
    let version = expected_record_hash(&page.body).to_owned();

    let refused = request(
        &app,
        Method::POST,
        "/items/records/one",
        Some(form(&[
            ("_csrf", &token),
            ("_expected_record_hash", &version),
            ("front_matter", "stage: open\n  broken: ["),
            ("markdown", "Body worth keeping"),
        ])),
        &[],
    )
    .await;

    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert!(refused.body.contains("This record was not saved."));
    assert!(refused.body.contains("front matter is not a YAML object"));
    let before_control = refused
        .body
        .split_once(r#"name="front_matter""#)
        .expect("the front matter control is rendered")
        .0;
    assert!(
        before_control.contains("front matter is not a YAML object"),
        "the message is not beside the control it is about:\n{}",
        refused.body
    );
    assert!(
        refused.body.contains("stage: open\n  broken: [</textarea>"),
        "the typed YAML was not preserved verbatim:\n{}",
        refused.body
    );
    assert!(
        refused.body.contains("Body worth keeping</textarea>"),
        "the Markdown body was not preserved:\n{}",
        refused.body
    );
    assert_eq!(database.get("items", "one").unwrap().body, "First");
    assert_eq!(
        database
            .audit_recent(10, AuditFilter::record("items", "one"))
            .unwrap()
            .len(),
        1
    );
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn an_htmx_submission_is_answered_with_the_form_region_alone() {
    let (_temporary, database) = deals_database("refused-fragment");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();

    let document = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "hello there")),
        &[],
    )
    .await;
    let fragment = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "hello there")),
        &HTMX,
    )
    .await;

    assert_eq!(fragment.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        fragment
            .body
            .starts_with(&format!(r#"<form id="{RECORD_FORM_REGION}""#)),
        "the fragment is not rooted at the element it replaces:\n{}",
        fragment.body
    );
    assert!(fragment.body.ends_with("</form>"));
    assert!(!fragment.body.contains("<!DOCTYPE"));
    assert!(!fragment.body.contains("cr-sidebar"));
    assert!(!fragment.body.contains("<title>"));
    // The same markup, not a second rendering of it. The request ID is the one
    // thing two answers to two requests may legitimately differ in, and it is
    // exactly what is normalized away here.
    assert!(
        document
            .without_request_id()
            .contains(&fragment.without_request_id()),
        "the fragment is not the document's own form:\n{}",
        fragment.body
    );
    assert_nothing_was_lost(&fragment.body);

    // htmx ignores the body of a response that is not a success unless something
    // says otherwise, and this header is that something. The push is refused
    // because the posted path is not a page: `/deals/records` answers no `GET`.
    assert_eq!(fragment.header("cr-form-invalid"), "true");
    assert_eq!(fragment.header("hx-push-url"), "false");
    assert_eq!(
        fragment.header("vary"),
        "Cookie, HX-Request, HX-Target, HX-History-Restore-Request"
    );
    assert_eq!(fragment.header("cache-control"), "no-store");
    assert_nothing_was_written(&database, "deals", "acme-pilot");
}

#[tokio::test]
async fn a_successful_submission_redirects_a_browser_and_relocates_htmx() {
    let (_temporary, database) = deals_database("accepted-create");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();

    let plain = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "{}")),
        &[],
    )
    .await;
    assert_eq!(plain.status, StatusCode::SEE_OTHER);
    assert_eq!(plain.header("location"), "/deals?notice=Record+created");
    assert_eq!(plain.header("cr-form-invalid"), "");

    // The record stores the value the text parses to; only the form keeps the
    // text. Both are properties of this change, and they are not the same one.
    let record = database.get("deals", "acme-pilot").unwrap();
    assert_eq!(record.attributes["value"], 12500.5);
    assert_eq!(record.attributes["owner"], "ada");
    assert_eq!(
        record.body,
        "# Notes\n\n  indented, *typed*, worth keeping.\n"
    );

    let edit = request(&app, Method::GET, "/deals/records/acme-pilot", None, &[]).await;
    let edit_token = csrf(&edit.body).to_owned();
    let version = expected_record_hash(&edit.body).to_owned();
    let boosted = request(
        &app,
        Method::POST,
        "/deals/records/acme-pilot",
        Some(form(&[
            ("_csrf", &edit_token),
            ("_expected_record_hash", &version),
            ("_form_mode", "structured"),
            ("attribute.name", "Acme pilot"),
            ("attribute.stage", "won"),
            ("attribute.value", "12500.50"),
            ("attribute.relations", "{}"),
            ("_additional_attributes", "owner: ada\n"),
            ("markdown", "Closed."),
        ])),
        &HTMX,
    )
    .await;
    // An `XMLHttpRequest` follows a `303` invisibly, so htmx is handed the
    // destination as a path it can navigate to instead.
    assert_eq!(boosted.status, StatusCode::NO_CONTENT);
    assert_eq!(
        boosted.header("hx-location"),
        "/deals?notice=Record+updated"
    );
    assert!(boosted.body.is_empty());
    assert_eq!(
        database.get("deals", "acme-pilot").unwrap().attributes["stage"],
        "won"
    );
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_stale_version_keeps_the_submitted_values_and_the_version_it_lost_with() {
    let (_temporary, database) = test_database("refused-stale");
    database
        .create(
            "items",
            "one",
            &[Assignment::from_str("stage=open").unwrap()],
            "First",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/items/records/one", None, &[]).await;
    let token = csrf(&page.body).to_owned();
    let stale_version = expected_record_hash(&page.body).to_owned();

    // Somebody else saves while this form is open.
    database
        .update(
            "items",
            "one",
            &[Assignment::from_str("stage=won").unwrap()],
            Some("Newer notes"),
        )
        .unwrap();

    let refused = request(
        &app,
        Method::POST,
        "/items/records/one",
        Some(form(&[
            ("_csrf", &token),
            ("_expected_record_hash", &stale_version),
            ("front_matter", "stage: lost\n"),
            ("markdown", "Old notes worth keeping"),
        ])),
        &[],
    )
    .await;

    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);
    assert!(
        refused
            .body
            .contains("record items/one changed since the expected version")
    );
    assert!(refused.body.contains("stage: lost\n</textarea>"));
    assert!(refused.body.contains("Old notes worth keeping</textarea>"));
    // The version that lost, not the version that won. Handing back the current
    // one would turn "somebody else changed this record" into a form that
    // overwrites their change on the next click.
    assert_eq!(expected_record_hash(&refused.body), stale_version);
    assert_ne!(database.get("items", "one").unwrap().version, stale_version);

    let record = database.get("items", "one").unwrap();
    assert_eq!(record.attributes["stage"], "won");
    assert_eq!(record.body, "Newer notes");
    assert_eq!(
        database
            .audit_recent(10, AuditFilter::record("items", "one"))
            .unwrap()
            .len(),
        2
    );
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_taken_record_id_is_reported_on_the_field_that_names_it() {
    let (_temporary, database) = deals_database("refused-taken-id");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();
    let created = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "{}")),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER);
    let before = database.audit_recent(10, AuditFilter::all()).unwrap().len();

    let refused = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "{}")),
        &[],
    )
    .await;

    // The status of the refusal, not a flat `422`: the same conflict the JSON
    // API answers for the same request.
    assert_eq!(refused.status, StatusCode::CONFLICT);
    let before_control = refused
        .body
        .split_once(r#"id="record-id""#)
        .expect("the record ID control is rendered")
        .0;
    assert!(
        before_control.contains("record deals/acme-pilot already exists"),
        "the conflict is not reported beside the field that caused it:\n{}",
        refused.body
    );
    assert_nothing_was_lost(&refused.body);
    assert_eq!(
        database.audit_recent(10, AuditFilter::all()).unwrap().len(),
        before,
        "a refused creation recorded an audit event"
    );
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_refused_form_can_be_corrected_and_submitted_again() {
    let (_temporary, database) = deals_database("refused-then-fixed");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();
    let refused = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(&token, "hello there")),
        &HTMX,
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);

    // What comes back is a working form: its CSRF token is current, so correcting
    // the one field that was wrong and pressing the button again is the whole of
    // the recovery.
    let corrected = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission(csrf(&refused.body), "owner: ada")),
        &HTMX,
    )
    .await;
    assert_eq!(corrected.status, StatusCode::NO_CONTENT);
    assert_eq!(
        corrected.header("hx-location"),
        "/deals?notice=Record+created"
    );
    let record = database.get("deals", "acme-pilot").unwrap();
    assert_eq!(record.attributes["relations"]["owner"], "ada");
    assert_eq!(record.attributes["value"], 12500.5);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn a_body_that_is_not_the_rendered_form_still_gets_the_error_page() {
    // The boundary of the re-render. A field this server never emits is a broken
    // or tampering client rather than somebody's typing, and there is nothing to
    // preserve because nothing in the body says what was typed. A wrong CSRF
    // token is refused before anything else happens, and the form it came from is
    // by definition not one this server rendered.
    let (_temporary, database) = deals_database("refused-tampered");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/new", None, &[]).await;
    let token = csrf(&page.body).to_owned();

    let tampered = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(form(&[
            ("_csrf", &token),
            ("id", "acme-pilot"),
            ("front_matter", "name: Acme\n"),
            ("markdown", ""),
            ("surprise", "1"),
        ])),
        &HTMX,
    )
    .await;
    assert_eq!(tampered.status, StatusCode::BAD_REQUEST);
    assert_eq!(tampered.header("cr-form-invalid"), "");
    assert!(tampered.body.contains("Request could not be completed"));
    assert!(!tampered.body.contains(r#"id="cr-record-form""#));

    let wrong_token = request(
        &app,
        Method::POST,
        "/deals/records",
        Some(submission("not-the-token", "{}")),
        &HTMX,
    )
    .await;
    assert_eq!(wrong_token.status, StatusCode::FORBIDDEN);
    assert_nothing_was_written(&database, "deals", "acme-pilot");
}

/// A record in a collection with no schema, holding one value of every kind the
/// fields form tells apart, plus a Markdown body that starts with a blank line.
fn schemaless_database(name: &str) -> (TempDir, Database) {
    let (temporary, database) = test_database(name);
    let assignments = [
        "name=Jane Doe",
        "postcode=\"02139\"",
        "bio=\"line one\\nline two\"",
        "ranking=3",
        "reviewed=false",
        "missing=null",
        "tags=[a, b]",
        "joined=2026-09-02",
        "website=https://example.com/jane",
        "homepage=javascript:alert(1)",
    ]
    .map(|assignment| Assignment::from_str(assignment).unwrap());
    database
        .create(
            "people",
            "jane",
            &assignments,
            "\nNotes after a blank line.\n",
        )
        .unwrap();
    (temporary, database)
}

/// The fields form for [`schemaless_database`]'s record as a browser submits
/// it untouched: every control in document order, with each `<textarea>`'s
/// line breaks sent as CRLF.
fn untouched_fields_form(token: &str, version: &str) -> Vec<(String, String)> {
    [
        ("_csrf", token),
        ("_expected_record_hash", version),
        ("_form_mode", "fields"),
        ("_field.name", "text"),
        ("attribute.name", "Jane Doe"),
        ("_field.postcode", "text"),
        ("attribute.postcode", "02139"),
        ("_field.bio", "text"),
        ("attribute.bio", "line one\r\nline two"),
        ("_field.ranking", "number"),
        ("attribute.ranking", "3"),
        ("_field.reviewed", "boolean"),
        ("attribute.reviewed", "false"),
        ("_field.missing", "empty"),
        ("attribute.missing", ""),
        ("_field.tags", "yaml"),
        ("attribute.tags", "- a\r\n- b"),
        ("_field.joined", "text"),
        ("attribute.joined", "2026-09-02"),
        ("_field.website", "text"),
        ("attribute.website", "https://example.com/jane"),
        ("_field.homepage", "text"),
        ("attribute.homepage", "javascript:alert(1)"),
        ("markdown", "\r\nNotes after a blank line.\r\n"),
    ]
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .to_vec()
}

fn with_values(mut fields: Vec<(String, String)>, changes: &[(&str, &str)]) -> String {
    for (name, value) in changes {
        let field = fields
            .iter_mut()
            .find(|(field, _)| field == name)
            .unwrap_or_else(|| panic!("no form field {name}"));
        field.1 = (*value).to_owned();
    }
    let pairs = fields
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    form(&pairs)
}

#[tokio::test]
async fn a_record_without_a_schema_is_edited_one_field_at_a_time() {
    let (_temporary, database) = schemaless_database("fields-render");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/people/records/jane", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let html = &page.body;

    assert!(html.contains(r#"name="_form_mode" value="fields""#));
    assert!(!html.contains(r#"name="front_matter""#));
    // One control per field, labelled readably, each saying how it is read back.
    for (key, kind) in [
        ("name", "text"),
        ("postcode", "text"),
        ("bio", "text"),
        ("ranking", "number"),
        ("reviewed", "boolean"),
        ("missing", "empty"),
        ("tags", "yaml"),
        ("joined", "text"),
    ] {
        assert!(
            html.contains(&format!(r#"name="_field.{key}" value="{kind}""#)),
            "{key} is not a {kind} field:\n{html}"
        );
    }
    assert!(
        html.contains(r#"<label for="field-postcode" class="cr-field-label">Postcode</label>"#)
    );
    assert!(html.contains(r#"type="text" name="attribute.postcode" value="02139""#));
    assert!(html.contains(r#"type="number" step="any" name="attribute.ranking" value="3""#));
    // True or false is a pair of buttons. The record's value made it a
    // boolean, so there is no "Not set" to fall back to.
    assert!(html.contains(r#"type="radio" name="attribute.reviewed" value="false" checked"#));
    assert!(!html.contains(r#"name="attribute.reviewed" value="""#));
    // A calendar date gets a date picker.
    assert!(html.contains(r#"type="date" name="attribute.joined" value="2026-09-02""#));
    // A web address can be opened from the form; nothing else becomes a link.
    assert!(html.contains(
        r#"<a href="https://example.com/jane" target="_blank" rel="noopener noreferrer""#
    ));
    assert!(!html.contains(r#"href="javascript:"#));
    // A string with a line break is edited in a box that keeps it.
    assert!(html.contains(r#"<textarea id="field-bio" name="attribute.bio""#));
    assert!(html.contains(">line one\nline two</textarea>"));
    // The parser drops the first line feed of a `<textarea>`, so a body that
    // starts with one is given a second for it to drop.
    assert!(html.contains(">\n\nNotes after a blank line.\n</textarea>"));
    assert!(html.contains(r#"href="/people/records/jane?editor=yaml""#));

    let yaml = request(
        &app,
        Method::GET,
        "/people/records/jane?editor=yaml",
        None,
        &[],
    )
    .await;
    assert_eq!(yaml.status, StatusCode::OK);
    assert!(yaml.body.contains(r#"name="front_matter""#));
    assert!(!yaml.body.contains(r#"name="_form_mode""#));
    assert!(
        yaml.body
            .contains(r#"href="/people/records/jane" class="cr-form-link">Edit as form</a>"#)
    );
}

#[tokio::test]
async fn saving_the_fields_form_untouched_changes_nothing() {
    let (_temporary, database) = schemaless_database("fields-untouched");
    let before = database.get("people", "jane").unwrap();
    let file = database.root().join("records/people/jane.md");
    let bytes = fs::read(&file).unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/people/records/jane", None, &[]).await;

    let saved = request(
        &app,
        Method::POST,
        "/people/records/jane",
        Some(with_values(
            untouched_fields_form(csrf(&page.body), expected_record_hash(&page.body)),
            &[],
        )),
        &[],
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let after = database.get("people", "jane").unwrap();
    assert_eq!(after.attributes, before.attributes);
    assert_eq!(after.body, before.body);
    assert_eq!(fs::read(&file).unwrap(), bytes);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn an_edited_field_keeps_the_type_it_had() {
    let (_temporary, database) = schemaless_database("fields-typed");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/people/records/jane", None, &[]).await;

    let saved = request(
        &app,
        Method::POST,
        "/people/records/jane",
        Some(with_values(
            untouched_fields_form(csrf(&page.body), expected_record_hash(&page.body)),
            &[
                // Digits typed into a text field are still text,
                ("attribute.postcode", "02140"),
                // a number field takes any number,
                ("attribute.ranking", "4.5"),
                // "Not set" is null rather than a missing field,
                ("attribute.reviewed", ""),
                // an empty text field is an empty string,
                ("attribute.name", ""),
                // and anything typed into an empty field is text.
                ("attribute.missing", "true"),
                ("attribute.tags", "[c]"),
            ],
        )),
        &[],
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let record = database.get("people", "jane").unwrap();
    assert_eq!(record.attributes["postcode"], "02140");
    assert_eq!(record.attributes["ranking"], 4.5);
    assert!(record.attributes["reviewed"].is_null());
    assert_eq!(record.attributes["name"], "");
    assert_eq!(record.attributes["missing"], "true");
    assert_eq!(record.attributes["tags"][0], "c");
    assert_eq!(record.attributes["tags"].as_sequence().unwrap().len(), 1);
    assert_eq!(record.attributes["bio"], "line one\nline two");
    // The order the record kept its fields in is the order it still keeps them.
    let keys = record
        .attributes
        .keys()
        .map(|key| key.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        [
            "name", "postcode", "bio", "ranking", "reviewed", "missing", "tags", "joined",
            "website", "homepage"
        ]
    );
}

#[tokio::test]
async fn a_refused_fields_form_comes_back_as_the_fields_form() {
    let (_temporary, database) = schemaless_database("fields-refused");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/people/records/jane", None, &[]).await;

    let refused = request(
        &app,
        Method::POST,
        "/people/records/jane",
        Some(with_values(
            untouched_fields_form(csrf(&page.body), expected_record_hash(&page.body)),
            &[("attribute.ranking", "high"), ("attribute.name", "Janet")],
        )),
        &[],
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let html = &refused.body;
    assert!(html.contains("This record was not saved."));
    assert!(html.contains(r#"name="_form_mode" value="fields""#));
    let before_control = html
        .split_once(r#"id="field-ranking""#)
        .expect("the ranking control is rendered")
        .0;
    assert!(
        before_control.contains("attribute 'ranking' must be a number"),
        "the message is not beside the control it is about:\n{html}"
    );
    assert!(html.contains(r#"name="attribute.name" value="Janet""#));
    assert!(html.contains(r#"name="_field.tags" value="yaml""#));
    assert_eq!(
        database.get("people", "jane").unwrap().attributes["name"],
        "Jane Doe"
    );

    // A field type the form never renders is a broken client, not a typo.
    let tampered = request(
        &app,
        Method::POST,
        "/people/records/jane",
        Some(with_values(
            untouched_fields_form(csrf(&page.body), expected_record_hash(&page.body)),
            &[("_field.ranking", "integer")],
        )),
        &[],
    )
    .await;
    assert_eq!(tampered.status, StatusCode::BAD_REQUEST);
    assert!(!tampered.body.contains(r#"id="cr-record-form""#));
    database.audit_verify(None).unwrap();
}
