//! One live region per page, outside everything that gets swapped.
//!
//! Phases 1 to 4 replaced navigation and table interaction with swaps, and a
//! swap is silent: the rows behind an open filter panel become different rows
//! with no reload, no focus change and nothing said. Announcing that is what a
//! live region is for, and it only works under a condition the swaps themselves
//! make easy to break — an assistive technology announces a region because it is
//! watching *that element*, so a region delivered inside a fragment is a region
//! created and filled in one step, which is the case nothing is specified to
//! announce.
//!
//! Hence one region, rendered by the shell, outside `main-content`,
//! `cr-view-table` and `cr-record-form` alike, and patched rather than replaced.
//! Four properties are asserted here:
//!
//! **It is on every page, and it is empty.** Arriving somewhere is not a change
//! to announce; the page is the announcement. A region that already held a
//! sentence would also make the next swap's identical sentence indistinguishable
//! from nothing having happened.
//!
//! **It is outside every region a fragment can replace.** Stated positionally —
//! before `<main>` — because that is the property, not the attribute.
//!
//! **A results swap patches its contents, not the element.**
//! `hx-swap-oob="innerHTML"` rather than the `"true"` the heading's two
//! passengers use.
//!
//! **A whole document never carries the patch.** An out-of-band marker in a
//! document would be applied by the next boosted navigation and the element
//! would then be missing from the page that arrived.
//!
//! The sentence itself is asserted against the pager in
//! `tests/targeted_swap_http.rs`, where the fragment is already taken apart.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use cr::{
    Assignment, Database, SortDirection, ViewLayout,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// The contract with the markup, spelled out rather than imported for the reason
/// `tests/fragment_seam_http.rs` gives: the server writes these into `id`
/// attributes and htmx repeats them back, so a test sharing the constants could
/// not notice a rename breaking the agreement.
const ANNOUNCE_REGION: &str = "cr-announce";
const CONTENT_REGION: &str = "main-content";
const VIEW_TABLE_REGION: &str = "cr-view-table";

/// The region exactly as a document must contain it: named, hidden, a status
/// region by role and by explicit `aria-live`, and holding nothing.
const EMPTY_REGION: &str = r#"<div id="cr-announce" class="cr-visually-hidden" role="status" aria-live="polite" aria-atomic="true"></div>"#;

const UI_SCRIPT: &str = include_str!("../src/static/cr.js");
const STYLES_MARKER: &str = ".cr-visually-hidden {";

/// Every shape of page the shell renders, so the region cannot be present on the
/// pages someone remembered and absent from the rest.
const PAGES: [&str; 6] = [
    "/",
    "/deals",
    "/pipeline",
    "/deals/new",
    "/deals/records/alpha",
    "/audit",
];

async fn get(app: &Router, uri: &str, headers: &[(&str, &str)]) -> (StatusCode, String) {
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
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// Ask for a region with the headers htmx sends when a control that names one is
/// activated.
async fn swap(app: &Router, uri: &str, region: &str) -> String {
    get(
        app,
        uri,
        &[
            ("hx-request", "true"),
            ("hx-boosted", "true"),
            ("hx-current-url", "http://127.0.0.1/deals"),
            ("hx-target", region),
        ],
    )
    .await
    .1
}

fn database_with_deals(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    for (id, stage) in [
        ("alpha", "qualification"),
        ("beta", "won"),
        ("gamma", "won"),
    ] {
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
            2,
            ViewLayout::Kanban,
            Some("stage".into()),
            None,
            SortDirection::Asc,
        )
        .unwrap();
    (temporary, database)
}

#[tokio::test]
async fn every_page_carries_one_empty_live_region_above_its_content() {
    let (_temporary, database) = database_with_deals("live-region-pages");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let (status, html) = get(&app, uri, &[]).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(html.contains(EMPTY_REGION), "{uri} renders no live region");

        // Exactly one. Two live regions on a page is two candidates for one
        // announcement, which is how a reader hears something twice or hears
        // the wrong one; it is also why the success banner and the
        // impersonation strip carry no `role="status"` of their own.
        assert_eq!(
            html.matches(&format!("id=\"{ANNOUNCE_REGION}\"")).count(),
            1,
            "{uri} renders more than one live region"
        );
        assert_eq!(
            html.matches("role=\"status\"").count(),
            1,
            "{uri} has a live region other than the one the shell renders"
        );

        // Outside every region a fragment can replace, stated as position: the
        // shell renders it before `<main>`, so no swap of `main-content` or of
        // anything inside it can destroy the element being watched.
        let region_at = html.find(&format!("id=\"{ANNOUNCE_REGION}\"")).unwrap();
        let content_at = html.find(&format!("id=\"{CONTENT_REGION}\"")).unwrap();
        assert!(
            region_at < content_at,
            "{uri} puts the live region inside the content it announces about"
        );
    }

    // Hidden from the layout by the server's own stylesheet rather than by
    // Tailwind's `sr-only`. This is the one element whose styling is load
    // bearing for correctness: with the utility stylesheet unavailable every
    // other element degrades to unstyled but readable, and this one would
    // degrade to a duplicate sentence in the middle of the page.
    let (_, home) = get(&app, "/", &[]).await;
    assert!(
        home.contains(STYLES_MARKER),
        "the inline stylesheet does not define the class that hides the region"
    );
}

#[tokio::test]
async fn a_results_swap_patches_the_regions_contents_and_leaves_the_element() {
    let (_temporary, database) = database_with_deals("live-region-swap");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in ["/deals?limit=2", "/pipeline?limit=2"] {
        let fragment = swap(&app, uri, VIEW_TABLE_REGION).await;
        // `innerHTML`, not `true`. `true` replaces the element, and replacing
        // the node an assistive technology is watching with an identical one
        // carrying text is precisely how a live region goes quiet.
        assert!(
            fragment.contains(&format!(
                "<div id=\"{ANNOUNCE_REGION}\" hx-swap-oob=\"innerHTML\">"
            )),
            "{uri} does not patch the live region's contents: {fragment}"
        );
        assert!(
            fragment.contains("Showing records 1 to 2 of 3"),
            "{uri} announces something other than what is on screen: {fragment}"
        );
        // The patch is a passenger, not the answer: it must not be inside the
        // region being swapped, or it would be destroyed by the very swap it
        // is reporting.
        let region_at = fragment
            .find(&format!("<div id=\"{VIEW_TABLE_REGION}\">"))
            .unwrap();
        let patch_at = fragment.find(&format!("id=\"{ANNOUNCE_REGION}\"")).unwrap();
        assert!(region_at < patch_at, "{uri} nests the patch in the region");
    }

    // An emptied page says so rather than saying "showing 0 to 0", which is a
    // sentence about positions when the fact is that there is nothing there.
    let empty = swap(&app, "/deals?q=nothing-matches-this", VIEW_TABLE_REGION).await;
    assert!(
        empty.contains(&format!(
            "<div id=\"{ANNOUNCE_REGION}\" hx-swap-oob=\"innerHTML\">No records match</div>"
        )),
        "an empty result set is announced as a range: {empty}"
    );
}

#[tokio::test]
async fn a_content_fragment_carries_no_announcement_and_no_second_region() {
    let (_temporary, database) = database_with_deals("live-region-content");
    let app = router(database, ServerConfig::default()).unwrap();

    // `main-content` is a region of every page and the seam's other answer. It
    // must not carry the live region — that would deliver a fresh element on
    // every swap, which is the failure this whole design avoids — and it has
    // nothing to announce, because a navigation is announced by arriving.
    for uri in ["/deals", "/audit", "/deals/records/alpha"] {
        let fragment = swap(&app, uri, CONTENT_REGION).await;
        assert!(!fragment.starts_with("<!DOCTYPE"), "{uri}");
        assert!(
            !fragment.contains(ANNOUNCE_REGION),
            "{uri} ships a live region inside a content fragment"
        );
    }
}

#[tokio::test]
async fn a_whole_document_never_carries_the_patch() {
    let (_temporary, database) = database_with_deals("live-region-document");
    let app = router(database, ServerConfig::default()).unwrap();

    // The same URLs a swap asks for, answered to a browser. An out-of-band
    // marker here would be acted on by the next boosted navigation: htmx would
    // patch the element into place and then remove it from the incoming
    // markup, so the page would arrive with the region missing.
    for uri in ["/deals?limit=2", "/pipeline?limit=2", "/deals?q=gamma"] {
        let (status, html) = get(&app, uri, &[]).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        assert!(html.contains(EMPTY_REGION), "{uri}");
        assert!(
            !html.contains("hx-swap-oob"),
            "{uri} marks an element out of band in a whole document"
        );
    }
}

#[tokio::test]
async fn the_success_notice_is_plain_markup_that_the_script_announces() {
    let (_temporary, database) = database_with_deals("live-region-notice");
    let app = router(database, ServerConfig::default()).unwrap();

    // The banner a successful mutation redirects to. It arrives *with* the
    // page, which is the one case a live region does not reliably announce —
    // the element and its contents are inserted together — so it is plain
    // markup and `cr.js` copies its text into the region the shell already
    // rendered, one task later, where it is an ordinary mutation of a watched
    // element.
    let (status, html) = get(&app, "/deals?notice=Record+deleted", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("data-notice=\"true\""));
    assert!(html.contains("Record deleted"));
    assert!(
        html.contains(EMPTY_REGION),
        "the notice pre-fills the region"
    );

    // With JavaScript off there is no announcement and none is needed: the
    // reader has just been navigated to a new document and this is the first
    // thing in it. The script is the only thing that turns it into one.
    assert!(
        UI_SCRIPT.contains("[data-notice]") && UI_SCRIPT.contains("getElementById('cr-announce')"),
        "cr.js no longer announces the notice"
    );
}
