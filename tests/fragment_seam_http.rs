//! The fragment seam: one URL, one handler, two envelopes.
//!
//! Phase 1 gave the HTML UI boosted navigation, which swaps the body of a whole
//! document and so needed no server change at all. Phase 2 of
//! `.context/htmx-plan.md` lets a request ask for less than a document: an htmx
//! request that names a region the route renders in `HX-Target` is answered with
//! that region's markup and nothing else, so a later phase can turn a page,
//! re-sort a column or apply a filter without re-rendering the sidebar.
//!
//! Three properties are load bearing here, and each of them is a way for the
//! seam to be wrong rather than merely unfinished.
//!
//! The first is that the fragment is the *same* markup, not a second rendering
//! of it: every test below asserts the fragment appears verbatim inside the
//! document the same URL answers a browser with. A second renderer would be a
//! second place for "what may this principal see" to be decided.
//!
//! Phase 4 added one thing to that envelope and one thing beside it, and both
//! are checked here rather than assumed. Every fragment now leads with a
//! `<title>` element, because htmx lifts a top-level title out of a response,
//! applies it to `document.title` and removes it before swapping — it is the only
//! way a fragment can name the state it produces, and `split_fragment` below is
//! where this suite accounts for it. A view's results fragment additionally
//! carries the two heading elements a change of result set changes, marked
//! `hx-swap-oob`; `tests/targeted_swap_http.rs` owns the assertions about them,
//! and the property this file keeps is that stripping that marker leaves markup
//! the document contains verbatim.
//!
//! The second is that nothing gets a fragment by accident. A browser address
//! bar, a `curl`, a feed reader, JavaScript switched off and the rest of this
//! HTTP suite all send no htmx headers and all still get exactly the page they
//! got before this commit. A back or forward restore does not get one either,
//! because a restore swaps into `<body>`, where a fragment would quietly delete
//! the navigation.
//!
//! The third is that the negotiation is declared. A response whose body depends
//! on a request header no cache was told about is a cache-poisoning bug, and the
//! failure it produces — a browser handed a headless fragment for a page it
//! asked for — is invisible until someone puts a proxy in front of `cr serve`.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    Assignment, Database, SortDirection, UserKind, ViewLayout,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// The id of the `<main>` element every page's content fills, which is the
/// region any route can answer with, and the id of a view's results region,
/// which only the view route can. Spelled out rather than imported because they
/// are a contract with the markup: a page states them in `id` attributes and a
/// client repeats them in `HX-Target`, so a test that shared a constant with the
/// server could not notice a rename breaking that agreement.
const CONTENT_REGION: &str = "main-content";
const VIEW_TABLE_REGION: &str = "cr-view-table";

/// Every page the HTML UI renders without access control configured: the view
/// index, a table, a Kanban board, a create form, an edit form, and the audit
/// log. The same list `tests/boosted_navigation_http.rs` boosts.
const PAGES: [&str; 6] = [
    "/",
    "/deals",
    "/pipeline",
    "/deals/new",
    "/deals/records/alpha",
    "/audit",
];

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

/// Ask for one region of a page with the headers htmx sends when it does: the
/// request label, the current URL it sends with everything, and the `HX-Target`
/// naming the element it is about to swap.
async fn fragment(app: &Router, uri: &str, region: &str) -> TestResponse {
    get(
        app,
        uri,
        &[
            ("hx-request", "true"),
            ("hx-current-url", "http://127.0.0.1/"),
            ("hx-target", region),
        ],
    )
    .await
}

/// Split a fragment into the title htmx applies to the tab and the markup it
/// swaps into the page.
///
/// A fragment leads with a `<title>` element, which is envelope rather than
/// content: htmx lifts a top-level title out of a response, sets `document.title`
/// from it and removes it before swapping anything, so the element never reaches
/// the DOM. It is there because htmx offers no title response header, so a
/// fragment that omitted it would leave the tab naming whatever state the reader
/// was in before — and because the URL a swap pushes is bookmarkable, the tab and
/// the URL have to agree.
fn split_fragment(uri: &str, body: &str) -> (String, String) {
    let (title, rest) = body
        .strip_prefix("<title>")
        .and_then(|body| body.split_once("</title>"))
        .unwrap_or_else(|| panic!("{uri} fragment does not lead with a title element: {body}"));
    (title.to_owned(), rest.to_owned())
}

/// The title a whole document states in its `<head>`, so the two envelopes can be
/// held to naming the same state.
fn document_title(uri: &str, body: &str) -> String {
    let (_, rest) = body
        .split_once("<title>")
        .unwrap_or_else(|| panic!("{uri} document has no title"));
    rest.split_once("</title>").unwrap().0.to_owned()
}

/// A document with no shell around it: the markup below belongs to the page
/// layout, so a fragment containing any of it would be a fragment that had been
/// swapped a whole document's worth of furniture into one element. `<title>` is
/// in the list because `split_fragment` has already taken the one a fragment is
/// allowed — a second would be shell that leaked.
fn assert_is_a_fragment(uri: &str, body: &str) {
    for shell in [
        "<!DOCTYPE",
        "<html",
        // `<head>` rather than `<head`, which every page bar's `<header>`
        // would match.
        "<head>",
        "<title",
        "<body",
        "<script",
        "cr-sidebar",
        "cr-mobile-header",
        "id=\"cr-progress\"",
        "cr-skip-link",
        "hx-boost=\"true\"",
    ] {
        assert!(
            !body.contains(shell),
            "{uri} fragment carries the shell: {shell}"
        );
    }
    assert!(!body.is_empty(), "{uri} fragment is empty");
}

fn database_with_a_board(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    for (id, stage) in [("alpha", "qualification"), ("beta", "won")] {
        database
            .create(
                "deals",
                id,
                &[
                    Assignment::from_str(&format!("name={id}")).unwrap(),
                    Assignment::from_str(&format!("stage={stage}")).unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    database
        .create_view_with_options(
            "pipeline",
            Some("Sales pipeline"),
            "deals",
            vec![],
            vec![],
            vec![],
            vec!["name".into(), "stage".into()],
            50,
            ViewLayout::Kanban,
            Some("stage".into()),
            None,
            SortDirection::Asc,
        )
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn a_targeted_request_gets_the_content_region_and_a_browser_gets_the_page_around_it() {
    let (_temporary, database) = database_with_a_board("seam-content");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let document = get(&app, uri, &[]).await;
        let region = fragment(&app, uri, CONTENT_REGION).await;
        assert_eq!(document.status, StatusCode::OK, "{uri}");
        assert_eq!(region.status, document.status, "{uri}");
        assert!(document.body.starts_with("<!DOCTYPE html>"), "{uri}");
        let (title, content) = split_fragment(uri, &region.body);
        assert_is_a_fragment(uri, &content);

        // Both envelopes name the same state, from one renderer. A fragment
        // cannot be corrected out of band — htmx has no title response header —
        // so a drift here is a tab that names the page the reader left.
        assert_eq!(title, document_title(uri, &document.body), "{uri}");

        // The load-bearing assertion of this whole phase: the fragment is not a
        // second rendering of the page, it is the contents of the one element
        // the document already puts it in. `tabindex="-1">` is the end of that
        // element's opening tag, so this pins the boundary as well as the bytes.
        assert!(
            document
                .body
                .contains(&format!("tabindex=\"-1\">{content}</main>")),
            "{uri} fragment is not exactly the content of <main>"
        );

        // Same representation rules for both envelopes: HTML, not sniffable,
        // never stored, and honest about what it varies on.
        assert_eq!(
            region.header(header::CONTENT_TYPE),
            "text/html; charset=utf-8",
            "{uri}"
        );
        assert_eq!(region.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
        assert_eq!(region.header(header::CACHE_CONTROL), "no-store", "{uri}");
    }
}

#[tokio::test]
async fn a_view_answers_its_results_region_without_the_controls_that_surround_it() {
    let (_temporary, database) = database_with_a_board("seam-results");
    let app = router(database, ServerConfig::default()).unwrap();

    // The table layout. This is the region phase 4 swaps for pagination, sort,
    // filter and search, so what must not be in it is as important as what is:
    // the heading, the search box and the filter panel stay on the page, which
    // is the point — a filter panel that is not re-rendered is a filter panel
    // that stays open across an apply.
    let table = fragment(&app, "/deals", VIEW_TABLE_REGION).await;
    assert_eq!(table.status, StatusCode::OK);
    let (_, table_content) = split_fragment("/deals", &table.body);
    let table_region = results_region(&table_content);
    assert_is_a_fragment("/deals", table_region);
    assert!(
        table_region.starts_with(&format!("<div id=\"{VIEW_TABLE_REGION}\">")),
        "results fragment is not rooted at the region it replaces: {}",
        &table_region[..table_region.len().min(120)]
    );
    assert!(table_region.ends_with("</div>"));
    assert!(table_region.contains("cr-table-shell"));
    assert!(table_region.contains("/deals/records/alpha"));
    assert!(table_region.contains("Showing 1–2 of 2"));
    for surrounding in [
        "cr-page-heading",
        "data-filter-builder",
        "Save as view",
        "New record",
        "Breadcrumb",
    ] {
        assert!(
            !table_region.contains(surrounding),
            "results fragment carries a control from outside the region: {surrounding}"
        );
    }

    // One id, both layouts. The controls that target it are shared by tables
    // and boards, so a Kanban view has to answer the same request with its own
    // results — the grouping caption and the board — rather than with nothing.
    let board = fragment(&app, "/pipeline", VIEW_TABLE_REGION).await;
    assert_eq!(board.status, StatusCode::OK);
    let (_, board_content) = split_fragment("/pipeline", &board.body);
    let board_region = results_region(&board_content);
    assert_is_a_fragment("/pipeline", board_region);
    assert!(board_region.contains("data-kanban-board"));
    assert!(board_region.contains("data-kanban-lane"));
    assert!(!board_region.contains("data-filter-builder"));

    // Both are regions of the page a browser gets, and the results region is
    // inside the content region, so each fragment is a substring of the larger
    // answer. That is what makes "same handler, same data, two envelopes" a
    // property rather than a description.
    let content = fragment(&app, "/deals", CONTENT_REGION).await;
    let (_, content_markup) = split_fragment("/deals", &content.body);
    let document = get(&app, "/deals", &[]).await;
    assert!(content_markup.contains(table_region));
    assert!(document.body.contains(table_region));
    assert!(document.body.len() > content_markup.len());
    assert!(content_markup.len() > table_region.len());
}

/// The results region of a results fragment, without the out-of-band elements
/// that travel behind it.
///
/// A swap of the region changes two things the heading states — the record count
/// and the badge counting applied filters — so the answer carries both, marked for
/// htmx to patch into place by id. They are the only markup in the fragment that
/// is not the region, they come after it, and each of them is the document's own
/// element with `hx-swap-oob="true"` added; `tests/targeted_swap_http.rs` asserts
/// that relationship. Here they are only in the way.
fn results_region(content: &str) -> &str {
    content
        .split_once(" hx-swap-oob=\"true\"")
        .map(|(before, _)| before.rsplit_once('<').expect("an element to patch").0)
        .unwrap_or(content)
}

#[tokio::test]
async fn a_route_only_answers_for_regions_it_renders() {
    let (_temporary, database) = database_with_a_board("seam-unknown-region");
    let app = router(database, ServerConfig::default()).unwrap();

    // `/audit` renders no results region, so a request that claims to be
    // swapping one is answered with the document. Refusing in this direction is
    // deliberate: a document arriving where a fragment was expected is a
    // visibly wrong page, while a fragment arriving where a document was
    // expected is a page that has silently lost its navigation.
    let audit = fragment(&app, "/audit", VIEW_TABLE_REGION).await;
    assert!(audit.body.starts_with("<!DOCTYPE html>"));
    assert_eq!(audit.body, get(&app, "/audit", &[]).await.body);

    // Ids that exist in the layout but are not regions the server composes:
    // htmx names whatever element it is about to swap, and only the two ids the
    // server renders content for mean anything.
    for region in ["cr-shell", "cr-progress", "main", "", "cr-view-table-"] {
        let answer = fragment(&app, "/deals", region).await;
        assert!(
            answer.body.starts_with("<!DOCTYPE html>"),
            "{region} was answered with a fragment"
        );
    }
}

#[tokio::test]
async fn nothing_short_of_an_htmx_request_naming_a_region_gets_a_fragment() {
    let (_temporary, database) = database_with_a_board("seam-plain");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let document = get(&app, uri, &[]).await;
        for headers in [
            // A browser address bar, `curl`, and every other test in this suite.
            vec![],
            // A stale `HX-Target` with no request label. Impossible from a
            // browser, trivial from a command line, and it must not be enough.
            vec![("hx-target", CONTENT_REGION)],
            // htmx spells the label `true`; anything else is not htmx asking.
            vec![("hx-request", "false"), ("hx-target", CONTENT_REGION)],
            vec![("hx-request", "1"), ("hx-target", CONTENT_REGION)],
            // A boosted navigation, which is what phase 1 ships: htmx targets
            // `<body>`, `<body>` has no id, so there is no `HX-Target` and the
            // answer is the whole document it is about to swap into place.
            vec![
                ("hx-request", "true"),
                ("hx-boosted", "true"),
                ("hx-current-url", "http://127.0.0.1/"),
            ],
        ] {
            let answer = get(&app, uri, &headers).await;
            assert_eq!(answer.status, document.status, "{uri} {headers:?}");
            assert_eq!(
                answer.body, document.body,
                "{uri} answers {headers:?} with something other than the page"
            );
        }
    }
}

/// `cr.js` sets `htmx.config.historyRestoreAsHxRequest` to `false`, so a back or
/// forward restore is not labelled as an htmx request in the first place, and
/// htmx sends no `HX-Target` on one either. The server nevertheless refuses a
/// fragment to any request carrying `HX-History-Restore-Request`, because a
/// restore replaces the contents of `<body>` with whatever it receives: a
/// fragment there deletes the sidebar, the progress bar and the skip link, and
/// the next navigation has nothing to boost from. Three independent reasons for
/// one answer is the right number when the failure is silent and the check is a
/// header lookup — and it means whoever turns that configuration back on does
/// not also have to know that the server depended on it.
#[tokio::test]
async fn a_history_restore_is_never_answered_with_a_fragment() {
    let (_temporary, database) = database_with_a_board("seam-history");
    let app = router(database, ServerConfig::default()).unwrap();

    assert!(
        UI_SCRIPT.contains("historyRestoreAsHxRequest = false"),
        "cr.js no longer switches off the htmx-request label on history restores"
    );

    for uri in PAGES {
        for region in [CONTENT_REGION, VIEW_TABLE_REGION] {
            let restore = get(
                &app,
                uri,
                &[
                    ("hx-request", "true"),
                    ("hx-history-restore-request", "true"),
                    ("hx-current-url", "http://127.0.0.1/"),
                    ("hx-target", region),
                ],
            )
            .await;
            assert_eq!(
                restore.body,
                get(&app, uri, &[]).await.body,
                "{uri} answers a history restore targeting {region} with a fragment"
            );
        }
    }
}

const UI_SCRIPT: &str = include_str!("../src/static/cr.js");

#[tokio::test]
async fn html_answers_declare_every_header_their_representation_depends_on() {
    let (_temporary, database) = database_with_a_board("seam-vary");
    let app = router(database, ServerConfig::default()).unwrap();

    // `Cookie` because the perspective switcher is a cookie, and the three htmx
    // headers because they are exactly what `Representation::requested` reads.
    // All four on every HTML answer, in one header, whether or not access
    // control is configured: this database has none, and the list is a property
    // of the route rather than of the deployment.
    const EXPECTED: &str = "Cookie, HX-Request, HX-Target, HX-History-Restore-Request";
    for uri in PAGES {
        let document = get(&app, uri, &[]).await;
        assert_eq!(document.header(header::VARY), EXPECTED, "{uri}");
        assert_eq!(document.headers.get_all(header::VARY).iter().count(), 1);
        let region = fragment(&app, uri, CONTENT_REGION).await;
        assert_eq!(region.header(header::VARY), EXPECTED, "{uri}");
    }

    // The rendered error page is an HTML answer too, and it is the one a shared
    // cache is most likely to be holding for a URL that has since changed.
    let missing = get(&app, "/deals/records/nonexistent", &[]).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.header(header::VARY), EXPECTED);

    // The JSON API is not part of the seam and says only what it varies on: it
    // renders no regions, so naming htmx headers there would be noise. Without
    // access control it varies on nothing at all, exactly as before.
    let api = get(&app, "/api/v1/collections", &[]).await;
    assert_eq!(api.status, StatusCode::OK);
    assert_eq!(api.header(header::VARY), "");
}

#[tokio::test]
async fn the_seam_survives_access_control_without_widening_what_a_perspective_sees() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("seam-access"))
        .unwrap()
        .with_actor("Owner <owner@example.com>")
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user("reader@example.com", "Reader", None, UserKind::Human)
        .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    // The authorization layer adds `Cookie` to a list an HTML answer has
    // already written, so it has to append: an `insert` there would delete the
    // htmx names and leave a cache free to hand a fragment to a browser.
    let document = get(&app, "/", &[]).await;
    assert_eq!(document.status, StatusCode::OK);
    assert_eq!(
        document.header(header::VARY),
        "Cookie, HX-Request, HX-Target, HX-History-Restore-Request"
    );
    assert_eq!(document.headers.get_all(header::VARY).iter().count(), 1);
    assert_eq!(document.header(header::CACHE_CONTROL), "no-store");

    // The fragment is the same markup the same principal's document contains,
    // so the perspective banner and the users link are decided in one place.
    let region = fragment(&app, "/", CONTENT_REGION).await;
    assert_eq!(region.status, StatusCode::OK);
    let (_, content) = split_fragment("/", &region.body);
    assert_is_a_fragment("/", &content);
    assert!(
        document
            .body
            .contains(&format!("tabindex=\"-1\">{content}</main>"))
    );
    // The sidebar is shell, so the perspective switcher it carries is not in
    // the fragment. Phase 4 targets regions, not the shell, which is why that
    // is the correct answer rather than a gap.
    assert!(document.body.contains("aria-label=\"View as user\""));
    assert!(!content.contains("aria-label=\"View as user\""));
}
