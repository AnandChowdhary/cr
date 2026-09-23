//! The view index names every view before it counts any of them.
//!
//! `/` is the page a server's address opens, and every number on it — how many
//! records each view shows, when the newest of them changed, the total in the
//! heading — comes from reading every record of every collection. So the
//! document a browser is sent renders the rows with placeholders where the
//! numbers go, and the region holding the rows asks for itself again once htmx
//! has processed it, at `/?summary=inline`, which answers that request with the
//! rows counted. The same URL without htmx headers is the whole document with
//! the numbers in it, which is what a `<noscript>` link offers a browser that
//! will never ask for the region.
//!
//! Four properties are held here:
//!
//! * the document a browser navigates to counts nothing, and says how to get
//!   the counts both with a script and without one;
//! * the region is cut from the counted document verbatim, and the total it
//!   carries out of band is that document's pill plus one attribute, so the
//!   page a script completes and the page `<noscript>` links to cannot differ;
//! * the counted region carries no trigger, or it would ask for itself forever;
//! * a stray parameter does not break the landing page, while a `summary` the
//!   server does not understand is refused rather than guessed at.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    Assignment, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// Spelled out rather than imported, for the reason
/// `tests/fragment_seam_http.rs` gives: the server writes these into markup and
/// a client repeats them back, so a test sharing the constants could not
/// notice a rename breaking the agreement.
const VIEW_INDEX_REGION: &str = "cr-view-index";
const VIEW_INDEX_TOTAL_ID: &str = "cr-view-index-total";
const SUMMARY_URL: &str = "/?summary=inline";
const PLACEHOLDER: &str = "<span class=\"text-gray-400\" aria-hidden=\"true\">…</span>";

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
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
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

/// The request htmx makes when the deferred region loads: an htmx request,
/// from the index, naming the region it will replace.
async fn load_region(app: &Router) -> TestResponse {
    get(
        app,
        SUMMARY_URL,
        &[
            ("hx-request", "true"),
            ("hx-current-url", "http://127.0.0.1/"),
            ("hx-target", VIEW_INDEX_REGION),
        ],
    )
    .await
}

/// Three deals, two of them open, and a saved view of the open ones, so a count
/// has to be the records a view matches rather than the size of its collection.
fn database_with_views(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    for (id, status) in [("alpha", "open"), ("beta", "open"), ("gamma", "won")] {
        database
            .create(
                "deals",
                id,
                &[Assignment::from_str(&format!("status={status}")).unwrap()],
                "",
            )
            .unwrap();
    }
    database
        .create_view(
            "open-deals",
            Some("Open deals"),
            "deals",
            vec!["status=open".into()],
            vec![],
            10,
        )
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn the_document_names_every_view_and_leaves_the_counting_to_the_page() {
    let (_temporary, database) = database_with_views("index-deferred");
    let app = router(database, ServerConfig::default()).unwrap();

    let document = get(&app, "/", &[]).await;
    assert_eq!(document.status, StatusCode::OK);
    let body = &document.body;
    assert!(body.contains("<h2 class=\"truncate\">Deals</h2>"));
    assert!(body.contains("<h2 class=\"truncate\">Open deals</h2>"));

    // The region says it is incomplete, and asks for its numbers on load.
    let region = body
        .split_once(&format!(
            "<div id=\"{VIEW_INDEX_REGION}\" aria-busy=\"true\" hx-get=\"{SUMMARY_URL}\" hx-trigger=\"load\" hx-swap=\"outerHTML\">"
        ))
        .expect("the index region does not ask for its numbers")
        .1;
    assert_eq!(region.matches(PLACEHOLDER).count(), 2, "one per view");
    // A counted row states its unit ("3 records", "updated …"); a placeholder
    // has none.
    assert!(!region.contains("cr-view-unit"), "a view was counted");
    assert!(!region.contains("<time"), "a last change was looked up");

    // The heading's total is present to be patched, and hidden until it is.
    assert!(body.contains(&format!(
        "<span id=\"{VIEW_INDEX_TOTAL_ID}\" hidden></span>"
    )));
    assert!(!body.contains(">3 records<"));
    // Without a script nothing will ask, so the document offers the page that
    // has the numbers in it.
    assert!(body.contains(&format!(
        "<noscript><a href=\"{SUMMARY_URL}\" class=\"cr-pill\">Count records</a></noscript>"
    )));

    // Asking for the default explicitly is the same document.
    let deferred = get(&app, "/?summary=deferred", &[]).await;
    assert_eq!(deferred.body, document.body);
}

#[tokio::test]
async fn the_region_is_the_counted_document_cut_down() {
    let (_temporary, database) = database_with_views("index-region");
    let app = router(database, ServerConfig::default()).unwrap();

    let counted = get(&app, SUMMARY_URL, &[]).await;
    assert_eq!(counted.status, StatusCode::OK);
    let region = load_region(&app).await;
    assert_eq!(region.status, StatusCode::OK);
    // A response that depends on `HX-Target` has to say so, or a cache could
    // hand the region to a browser that asked for the page.
    let vary = region.headers[header::VARY]
        .to_str()
        .unwrap()
        .to_lowercase();
    assert!(vary.contains("hx-target"), "{vary}");

    let (title, rest) = region
        .body
        .strip_prefix("<title>")
        .and_then(|body| body.split_once("</title>"))
        .expect("the region does not lead with a title");
    assert_eq!(title, "Database views · cr");
    let total_at = rest
        .find(&format!("<span id=\"{VIEW_INDEX_TOTAL_ID}\""))
        .expect("the region carries no total");
    let (rows, total) = rest.split_at(total_at);

    assert!(rows.starts_with(&format!("<div id=\"{VIEW_INDEX_REGION}\">")));
    assert!(
        !rows.contains("hx-trigger"),
        "the counted region asks again"
    );
    assert!(!rows.contains("aria-busy"));
    assert!(!rows.contains(PLACEHOLDER));
    assert!(
        counted.body.contains(rows),
        "the region is not the counted document's region"
    );
    assert!(rows.contains("cr-view-count\">3<"));
    assert!(rows.contains("cr-view-count\">2<"));
    assert!(rows.contains("<time datetime="));

    assert!(total.contains(" hx-swap-oob=\"true\""), "{total}");
    assert!(total.contains(">3 records<"), "{total}");
    assert!(
        counted
            .body
            .contains(&total.replace(" hx-swap-oob=\"true\"", "")),
        "the patched total is not the counted document's total"
    );
    // The counted document is complete, so it offers nothing to fetch.
    assert!(!counted.body.contains("<noscript>"));
    assert!(!counted.body.contains(PLACEHOLDER));
}

#[tokio::test]
async fn an_empty_database_has_nothing_to_count() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("index-empty")).unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let document = get(&app, "/", &[]).await;
    assert_eq!(document.status, StatusCode::OK);
    assert!(document.body.contains("No collections yet"));
    assert!(
        document
            .body
            .contains(&format!("<div id=\"{VIEW_INDEX_REGION}\"></div>"))
    );
    assert!(!document.body.contains("hx-trigger=\"load\""));
    assert!(!document.body.contains("Count records"));
}

#[tokio::test]
async fn the_landing_page_ignores_stray_parameters_but_not_a_wrong_summary() {
    let (_temporary, database) = database_with_views("index-query");
    let app = router(database, ServerConfig::default()).unwrap();

    let bookmarked = get(&app, "/?utm_source=newsletter", &[]).await;
    assert_eq!(bookmarked.status, StatusCode::OK);
    assert!(bookmarked.body.contains("hx-trigger=\"load\""));

    let unknown = get(&app, "/?summary=everything", &[]).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}
