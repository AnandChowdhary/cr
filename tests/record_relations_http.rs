//! The record page as a place to follow and change relations, and the rest of
//! what makes it read like the record rather than like its file.
//!
//! **Relations are links, both ways.** A record page lists what the record
//! links to, by name and linked to its page, and what links to it. A related
//! record this perspective cannot read, or that no longer exists, is shown only
//! by the `collection/id` the relation states, which is no more than the record
//! being viewed already says.
//!
//! **Linking is the audited operation it is everywhere else.** The panel's
//! forms run `link` and `unlink` with the page's version as their
//! precondition, and the record form carries the stored relations through
//! untouched, so saving the form cannot undo a link.
//!
//! **A record is called by its name**, and **tables read like the form**: the
//! headings are the form's labels, an enum reads as the form's option, and an
//! amount carries its unit.

use std::fs;
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

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl TestResponse {
    fn location(&self) -> &str {
        self.headers[header::LOCATION].to_str().unwrap()
    }
}

async fn request(
    app: &Router,
    method: Method,
    uri: &str,
    body: Option<String>,
    cookie: Option<&str>,
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
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

/// The value of the first input named `name` in `html`.
fn input_value<'a>(html: &'a str, name: &str) -> &'a str {
    let marker = format!("name=\"{name}\" value=\"");
    html.split_once(marker.as_str())
        .unwrap_or_else(|| panic!("no input named {name} in HTML:\n{html}"))
        .1
        .split_once('"')
        .unwrap()
        .0
}

/// A deal that links to a company that exists and a contact that does not,
/// and a second deal that links to the same company, under a schema that
/// declares `relations`, an enum, and two amounts.
fn crm(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "name": { "type": "string" },
    "stage": { "enum": ["discovery", "negotiation"] },
    "value": { "type": "integer", "x-cr-unit": { "field": "currency" } },
    "currency": { "enum": ["USD", "EUR"] },
    "probability": { "type": "integer", "x-cr-unit": "%" },
    "founded": { "type": "integer" },
    "expected_close": { "type": "string", "title": "Close date" },
    "relations": { "type": "object" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    for (collection, id, name) in [
        ("companies", "acme", "Acme Corporation"),
        ("contacts", "priya", "Priya Shah"),
    ] {
        database
            .create(
                collection,
                id,
                &[Assignment::from_str(&format!("name={name}")).unwrap()],
                "",
            )
            .unwrap();
    }
    database
        .create(
            "deals",
            "renewal",
            &[
                Assignment::from_str("name=Acme annual renewal").unwrap(),
                Assignment::from_str("stage=negotiation").unwrap(),
                Assignment::from_str("value=125000").unwrap(),
                Assignment::from_str("currency=USD").unwrap(),
                Assignment::from_str("probability=80").unwrap(),
                Assignment::from_str("founded=2019").unwrap(),
                Assignment::from_str("expected_close=2026-09-30").unwrap(),
                Assignment::from_str(
                    "relations.primary_contact=[{collection: contacts, id: ghost}]",
                )
                .unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .link("deals", "renewal", "company", "companies", "acme")
        .unwrap();
    database
        .create(
            "deals",
            "pilot",
            &[
                Assignment::from_str("name=Acme pilot").unwrap(),
                Assignment::from_str("stage=discovery").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .link("deals", "pilot", "company", "companies", "acme")
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn a_record_page_links_what_it_relates_to_and_lists_what_relates_to_it() {
    let (_temporary, database) = crm("relations-page");
    let app = router(database, ServerConfig::default()).unwrap();

    let deal = request(&app, Method::GET, "/deals/records/renewal", None, None).await;
    assert_eq!(deal.status, StatusCode::OK);
    let relations = deal
        .body
        .split_once(r#"id="relations""#)
        .unwrap()
        .1
        .split_once("</section>")
        .unwrap()
        .0;
    // The company exists and is readable: named and linked to its page.
    assert!(
        relations.contains(
            r#"href="/companies/records/acme" class="cr-relation-target">Acme Corporation</a>"#
        ),
        "{relations}"
    );
    assert!(relations.contains(">Company<"));
    // The contact does not exist: shown by the reference alone, with no link.
    assert!(relations.contains(">contacts/ghost</span>"), "{relations}");
    assert!(!relations.contains("/contacts/records/ghost"));
    // Both can be removed, and a new link made, against this version.
    let version = input_value(&deal.body, "_expected_record_hash");
    assert_eq!(
        relations
            .matches(r#"action="/deals/records/renewal/relations/remove""#)
            .count(),
        2
    );
    assert!(relations.contains(r#"action="/deals/records/renewal/relations""#));
    assert!(relations.contains(&format!(
        r#"name="_expected_record_hash" value="{version}""#
    )));
    // Suggestions for the link form: the names in use and readable records.
    assert!(relations.contains(r#"<option value="company">"#));
    assert!(relations.contains(r#"<option value="contacts/priya">Priya Shah · Contacts</option>"#));

    // The record form carries the stored relations through rather than asking
    // for them as YAML.
    let form = deal.body.split_once(r#"id="cr-record-form""#).unwrap().1;
    assert!(form.contains(r#"<input type="hidden" name="attribute.relations" value=""#));
    assert!(!form.contains(r#"<textarea id="field-relations""#));

    // The other end lists both deals that link to it.
    let company = request(&app, Method::GET, "/companies/records/acme", None, None).await;
    let linked_from = company.body.split_once("Linked from").unwrap().1;
    assert!(
        linked_from
            .contains(r#"href="/deals/records/pilot" class="cr-relation-target">Acme pilot</a>"#)
    );
    assert!(linked_from.contains(
        r#"href="/deals/records/renewal" class="cr-relation-target">Acme annual renewal</a>"#
    ));
    assert!(linked_from.contains("Deals · Company"));
}

#[tokio::test]
async fn linking_and_unlinking_are_audited_and_refused_against_a_stale_page() {
    let (_temporary, database) = crm("relations-change");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/records/renewal", None, None).await;
    let csrf = input_value(&page.body, "_csrf").to_owned();
    let stale = input_value(&page.body, "_expected_record_hash").to_owned();

    let linked = request(
        &app,
        Method::POST,
        "/deals/records/renewal/relations",
        Some(form(&[
            ("_csrf", &csrf),
            ("_expected_record_hash", &stale),
            ("relation", " champion "),
            ("target", "contacts/priya"),
        ])),
        None,
    )
    .await;
    assert_eq!(linked.status, StatusCode::SEE_OTHER, "{}", linked.body);
    assert_eq!(
        linked.location(),
        "/deals/records/renewal?notice=Linked+Priya+Shah+as+champion"
    );
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "renewal"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Link);
    let after = request(&app, Method::GET, linked.location(), None, None).await;
    assert!(after.body.contains(r#"data-notice="true""#));
    assert!(after.body.contains("Linked Priya Shah as champion"));
    assert!(
        after.body.contains(
            r#"href="/contacts/records/priya" class="cr-relation-target">Priya Shah</a>"#
        )
    );

    // The page the first link was made from is now stale, and a second change
    // made from it is refused rather than applied to a record nobody has seen.
    let refused = request(
        &app,
        Method::POST,
        "/deals/records/renewal/relations/remove",
        Some(form(&[
            ("_csrf", &csrf),
            ("_expected_record_hash", &stale),
            ("relation", "company"),
            ("target", "companies/acme"),
        ])),
        None,
    )
    .await;
    assert_eq!(refused.status, StatusCode::PRECONDITION_FAILED);

    let current = input_value(&after.body, "_expected_record_hash").to_owned();
    let unlinked = request(
        &app,
        Method::POST,
        "/deals/records/renewal/relations/remove",
        Some(form(&[
            ("_csrf", &csrf),
            ("_expected_record_hash", &current),
            ("relation", "company"),
            ("target", "companies/acme"),
        ])),
        None,
    )
    .await;
    assert_eq!(unlinked.status, StatusCode::SEE_OTHER, "{}", unlinked.body);
    assert!(
        unlinked
            .location()
            .contains("Removed+the+company+link+to+Acme+Corporation")
    );
    let record = database.get("deals", "renewal").unwrap();
    let relations = serde_json::to_value(&record.attributes["relations"]).unwrap();
    assert!(relations.get("company").is_none(), "{relations}");
    assert!(relations.get("champion").is_some(), "{relations}");

    // A target that is not `collection/id`, and a forged token, write nothing.
    for (token, target) in [(csrf.as_str(), "priya"), ("forged", "contacts/priya")] {
        let current = database.get("deals", "renewal").unwrap().version;
        let refused = request(
            &app,
            Method::POST,
            "/deals/records/renewal/relations",
            Some(form(&[
                ("_csrf", token),
                ("_expected_record_hash", &current),
                ("relation", "advisor"),
                ("target", target),
            ])),
            None,
        )
        .await;
        assert!(
            refused.status.is_client_error(),
            "{target}: {}",
            refused.status
        );
        assert_eq!(database.get("deals", "renewal").unwrap().version, current);
    }
}

#[tokio::test]
async fn saving_the_record_form_keeps_its_relations() {
    let (_temporary, database) = crm("relations-save");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = request(&app, Method::GET, "/deals/records/renewal", None, None).await;
    let before = database.get("deals", "renewal").unwrap();

    let saved = request(
        &app,
        Method::POST,
        "/deals/records/renewal",
        Some(form(&[
            ("_csrf", input_value(&page.body, "_csrf")),
            (
                "_expected_record_hash",
                input_value(&page.body, "_expected_record_hash"),
            ),
            ("_form_mode", "structured"),
            ("attribute.name", "Acme renewal, renamed"),
            ("attribute.stage", "negotiation"),
            ("attribute.value", "125000"),
            ("attribute.currency", "USD"),
            ("attribute.probability", "80"),
            ("attribute.founded", "2019"),
            ("attribute.expected_close", "2026-09-30"),
            (
                "attribute.relations",
                &html_unescape(input_value(&page.body, "attribute.relations")),
            ),
            ("_additional_attributes", ""),
            ("markdown", ""),
        ])),
        None,
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let after = database.get("deals", "renewal").unwrap();
    assert_eq!(
        after.attributes["name"].as_str(),
        Some("Acme renewal, renamed")
    );
    assert_eq!(
        after.attributes["relations"],
        before.attributes["relations"]
    );
}

/// The escapes Maud writes into an attribute value, undone as a browser would.
fn html_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

#[tokio::test]
async fn a_reader_sees_only_readable_relations_and_cannot_change_them() {
    let (_temporary, database) = crm("relations-reader");
    let database = database.with_actor(OWNER).unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user("reader@example.com", "Reader", None, UserKind::Human)
        .unwrap();
    // The reader may see the company and one of the two deals linking to it.
    for resource in [
        AccessResource::record("companies", "acme"),
        AccessResource::record("deals", "pilot"),
    ] {
        database
            .grant_access("reader@example.com", resource, Role::Viewer)
            .unwrap();
    }
    let app = router(database, ServerConfig::default()).unwrap();
    let home = request(&app, Method::GET, "/", None, None).await;
    let switched = request(
        &app,
        Method::POST,
        "/perspective",
        Some(form(&[
            ("_csrf", input_value(&home.body, "_csrf")),
            ("principal", "reader@example.com"),
        ])),
        None,
    )
    .await;
    let cookie = switched.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split_once(';')
        .unwrap()
        .0
        .to_owned();

    let company = request(
        &app,
        Method::GET,
        "/companies/records/acme",
        None,
        Some(&cookie),
    )
    .await;
    assert_eq!(company.status, StatusCode::OK);
    let relations = company.body.split_once(r#"id="relations""#).unwrap().1;
    assert!(relations.contains("Acme pilot"));
    // The deal the reader cannot see is not disclosed by linking to what they can.
    assert!(!relations.contains("renewal"), "{relations}");
    assert!(!relations.contains("Acme annual renewal"));
    // And nothing here can change a relation.
    assert!(!relations.contains("/relations\""));
    assert!(!relations.contains("Link a record"));
}

#[tokio::test]
async fn records_are_named_and_tables_read_like_the_form() {
    let (_temporary, database) = crm("relations-display");
    let app = router(database, ServerConfig::default()).unwrap();

    let deal = request(&app, Method::GET, "/deals/records/renewal", None, None).await;
    assert!(
        deal.body
            .contains("<title>Acme annual renewal · cr</title>")
    );
    assert!(
        deal.body
            .contains(r#"<h1 class="cr-title">Acme annual renewal</h1>"#)
    );
    assert!(deal.body.contains(r#"<p class="cr-path mt-1">renewal</p>"#));
    // A record with no name keeps its ID, once.
    let table = request(&app, Method::GET, "/deals", None, None).await;
    assert_eq!(table.status, StatusCode::OK);
    // Headings are the form's labels: a schema title, or the key made readable.
    assert!(table.body.contains(">Close date<"));
    assert!(table.body.contains(">Probability<"));
    assert!(!table.body.contains(">expected_close<"));
    // An enum reads as the form's option does, as a badge.
    assert!(
        table
            .body
            .contains(r#"<span class="cr-pill">Negotiation</span></a>"#)
    );
    // An amount is grouped and carries its unit, read from the record when the
    // schema says so, and a number with no unit is left exactly as stored.
    assert!(
        table.body.contains(">125,000\u{a0}USD</a>"),
        "{}",
        table.body
    );
    assert!(table.body.contains(">80%</a>"));
    assert!(table.body.contains(">2019</a>"));
    // Times are relative, with the exact instant kept in the markup.
    assert!(table.body.contains(r#"class="cr-time">just now</time>"#));
    assert!(table.body.contains(r#" UTC" class="cr-time""#));
}
