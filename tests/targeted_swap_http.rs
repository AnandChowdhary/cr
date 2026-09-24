//! In-place table interaction: a view's own controls replace its results rather
//! than the page around them.
//!
//! Phase 2 of `.context/htmx-plan.md` built the seam — one URL, one handler, a
//! whole document or the `cr-view-table` region depending on what the request
//! asked for — and shipped it with nothing asking. Phase 4 is the first caller:
//! the cursor links, the column sort links, the search box and the filter panel's
//! "Apply" all name that region, so a page turn, a re-sort, a search and an
//! apply leave the sidebar, the heading and — the visible win — an open filter
//! panel exactly where they were.
//!
//! Five properties are load bearing, and this file is where each of them is a
//! test rather than a claim.
//!
//! **Every control is still an ordinary link or form.** The `hx-` attributes are
//! additions to markup that already worked: a sort link keeps its `href`, the
//! filter form keeps `method="get"` and its `action`, and with JavaScript off, or
//! before the deferred script has run, the very same click navigates. This suite
//! sends htmx headers deliberately; every other HTTP suite sends none and is the
//! regression test for that path.
//!
//! **Every state stays shareable.** `hx-push-url="true"` puts the request's own
//! URL in the address bar, and the assertion that makes that meaningful is that
//! the region a swap receives is the region the same URL's *document* contains —
//! so what a reader copies out of the address bar is what a stranger with no
//! JavaScript is served.
//!
//! **The heading keeps up.** Two facts about the result set live outside the
//! region: the "*n* records" pill and the badge counting applied conditions. A
//! results fragment carries both as out-of-band elements, which are the document's
//! own markup plus one attribute — asserted here by stripping the attribute and
//! finding the remainder in the document verbatim.
//!
//! **The swap says what it did.** These four controls change which records are
//! on screen and nothing else, which is invisible to a reader who was not
//! looking at the table — after a filter apply, focus correctly stays on "Apply
//! view" and the rows behind it silently become different rows. The fragment
//! therefore carries a third out-of-band passenger: one sentence into the page's
//! live region, patched as `innerHTML` so the element an assistive technology is
//! watching survives the swap. It states the same range the pager prints, which
//! is asserted here by taking the numbers out of both.
//!
//! **Back and forward still get documents.** `cr.js` sets `historyCacheSize` to
//! zero, so every restore is a real request, and a restore swaps into `<body>`:
//! answering one with a region would delete the navigation.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
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
/// attributes and a client repeats them back in `HX-Target`, so a test that
/// shared the constants could not notice a rename breaking the agreement.
const VIEW_TABLE_REGION: &str = "cr-view-table";
const VIEW_COUNT_ID: &str = "cr-view-count";
const VIEW_FILTER_SUMMARY_ID: &str = "cr-view-filter-summary";
const ANNOUNCE_REGION: &str = "cr-announce";

/// The three attributes a targeted control carries, and the two swap styles.
///
/// `outerHTML` because the answer includes the region's own root element rather
/// than its children — a boosted element would otherwise default to `innerHTML`
/// and nest the region inside itself. The `show:` half decides whether the page
/// scrolls: a control inside the region (a cursor, a column heading) changes which
/// rows are on screen and puts the top of them at the top of the viewport, the way
/// the full reload it replaces did; a control above the region (search, apply)
/// must move nothing, because scrolling the results up would push the filter panel
/// that submitted them off the screen.
const TARGET_ATTRIBUTE: &str = "hx-target=\"#cr-view-table\"";
const SWAP_FROM_INSIDE: &str = "hx-swap=\"outerHTML show:top\"";
const SWAP_IN_PLACE: &str = "hx-swap=\"outerHTML show:none\"";
const PUSH_URL: &str = "hx-push-url=\"true\"";

const UI_SCRIPT: &str = include_str!("../src/static/cr.js");

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

/// Ask for the results region with the headers htmx sends when one of these
/// controls is activated: the request label, the URL the reader is on, and the id
/// of the element about to be replaced.
async fn swap(app: &Router, uri: &str) -> TestResponse {
    get(
        app,
        uri,
        &[
            ("hx-request", "true"),
            ("hx-boosted", "true"),
            ("hx-current-url", "http://127.0.0.1/deals"),
            ("hx-target", VIEW_TABLE_REGION),
        ],
    )
    .await
}

/// A results answer, taken apart: the title htmx applies to the tab, the region it
/// swaps, the out-of-band elements it patches into the heading, and the sentence
/// it patches into the page's live region.
struct Results {
    title: String,
    region: String,
    count: String,
    summary: String,
    announcement: String,
}

/// Split a results fragment into its five pieces, checking the shape as it goes.
///
/// The shape is the contract, so this panics rather than returning an option: a
/// fragment that had lost its title, its root element or one of its passengers
/// would otherwise make every assertion below vacuously true.
fn results(uri: &str, body: &str) -> Results {
    let (title, rest) = body
        .strip_prefix("<title>")
        .and_then(|body| body.split_once("</title>"))
        .unwrap_or_else(|| panic!("{uri} does not lead with a title element: {body}"));
    let count_at = rest
        .find(&format!("<span id=\"{VIEW_COUNT_ID}\""))
        .unwrap_or_else(|| panic!("{uri} carries no record-count patch"));
    let (region, rest) = rest.split_at(count_at);
    let summary_at = rest
        .find(&format!("<summary id=\"{VIEW_FILTER_SUMMARY_ID}\""))
        .unwrap_or_else(|| panic!("{uri} carries no filter-summary patch"));
    let (count, rest) = rest.split_at(summary_at);
    let announcement_at = rest
        .find(&format!("<div id=\"{ANNOUNCE_REGION}\""))
        .unwrap_or_else(|| panic!("{uri} carries no announcement"));
    let (summary, announcement) = rest.split_at(announcement_at);
    assert!(
        region.starts_with(&format!("<div id=\"{VIEW_TABLE_REGION}\">"))
            && region.ends_with("</div>"),
        "{uri} is not rooted at the region it replaces: {region:.120}"
    );
    for (name, patch) in [("record count", count), ("filter summary", summary)] {
        assert!(
            patch.contains(" hx-swap-oob=\"true\""),
            "{uri} sends the {name} without marking it out of band: {patch}"
        );
    }
    // `innerHTML`, not `true`, and the distinction is the whole reason the
    // announcement is a separate passenger: `true` replaces the element, and a
    // live region announces because an assistive technology is watching the node
    // it was given. Replacing that node with a new one carrying text is how a
    // region goes quiet, so this patch changes the contents of the region the
    // shell rendered and leaves the element — and the watcher — alone.
    assert!(
        announcement.contains(" hx-swap-oob=\"innerHTML\""),
        "{uri} replaces the live region instead of its contents: {announcement}"
    );
    Results {
        title: title.to_owned(),
        region: region.to_owned(),
        count: count.to_owned(),
        summary: summary.to_owned(),
        announcement: announcement.to_owned(),
    }
}

/// The value of an attribute on the element with the given id, so a test can
/// follow the link the page actually rendered instead of composing a URL the
/// server might no longer produce.
fn attribute(body: &str, id: &str, name: &str) -> String {
    let element = body
        .split_once(&format!("id=\"{id}\""))
        .unwrap_or_else(|| panic!("no element has id {id}"))
        .1;
    let value = element
        .split_once(&format!("{name}=\""))
        .expect("attribute")
        .1
        .split_once('"')
        .expect("closing quote")
        .0;
    value.replace("&amp;", "&")
}

/// The markup between two landmarks, so an assertion about the rows or the cards
/// is not quietly satisfied by the pager that follows them — the pager is exactly
/// what carries the attributes some of these tests are checking are absent.
fn between<'a>(body: &'a str, from: &str, to: &str) -> &'a str {
    let after = body.split_once(from).expect("opening landmark").1;
    after.split_once(to).expect("closing landmark").0
}

/// Five deals in one collection and a Kanban view over them, which is enough to
/// page with `limit=2`, to sort on a field that is not the id, to filter to a
/// subset and to search for one record by name.
fn database_with_deals(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    for (id, stage, value) in [
        ("alpha", "qualification", "1000"),
        ("beta", "won", "2000"),
        ("gamma", "won", "3000"),
        ("delta", "qualification", "4000"),
        ("epsilon", "lost", "5000"),
    ] {
        database
            .create(
                "deals",
                id,
                &[
                    Assignment::from_str(&format!("name={id}")).unwrap(),
                    Assignment::from_str(&format!("stage={stage}")).unwrap(),
                    Assignment::from_str(&format!("value={value}")).unwrap(),
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

/// The four URLs a reader reaches by using a view's controls, each one built by
/// following the markup the previous answer rendered where a cursor is involved.
async fn control_urls(app: &Router) -> Vec<(&'static str, String)> {
    let first = get(app, "/deals?limit=2", &[]).await;
    vec![
        ("next page", attribute(&first.body, "cr-page-next", "href")),
        (
            "column sort",
            attribute(&first.body, "cr-sort-3", "href"),
        ),
        (
            "filter apply",
            "/deals?filter_match=all&filter_field=stage&filter_operator=eq&filter_value=won&limit=2"
                .to_owned(),
        ),
        ("search", "/deals?q=gamma&filter_match=all&limit=2".to_owned()),
    ]
}

#[tokio::test]
async fn every_control_that_only_changes_the_results_targets_the_results_region() {
    let (_temporary, database) = database_with_deals("swap-markup");
    let app = router(database, ServerConfig::default()).unwrap();
    let page = get(&app, "/deals?limit=2", &[]).await.body;

    // The search box and "Apply" are two submit buttons on one `<form>`, so
    // one set of attributes covers both — and it is the form that must not scroll,
    // because the panel the reader applied from hangs below it.
    assert!(page.contains(&format!(
        "<form method=\"get\" action=\"/deals\" {TARGET_ATTRIBUTE} {SWAP_IN_PLACE} {PUSH_URL} data-filter-builder=\"true\""
    )));

    // Every column heading and every cursor, and each of them with an id, because
    // an `outerHTML` swap destroys the element the reader activated: htmx puts
    // focus back by looking that id up, and without one a keyboard or screen
    // reader user is returned to the top of the document by every page turn.
    for id in ["cr-sort-0", "cr-sort-3", "cr-page-next"] {
        let href = attribute(&page, id, "href");
        assert!(href.starts_with("/deals?"), "{id} lost its href: {href}");
        assert!(
            page.contains(&format!("{TARGET_ATTRIBUTE} {SWAP_FROM_INSIDE} {PUSH_URL}")),
            "{id} does not target the results region"
        );
    }
    let targeted = page.matches(TARGET_ATTRIBUTE).count();
    assert_eq!(
        targeted,
        page.matches(PUSH_URL).count(),
        "a control targets the region without pushing its URL, or the reverse"
    );
    assert_eq!(
        targeted,
        page.matches(SWAP_FROM_INSIDE).count() + page.matches(SWAP_IN_PLACE).count(),
        "a control targets the region without saying how to swap it"
    );

    // Deliberate exclusions. "Reset" empties the panel, and swapping only the
    // results would leave the discarded conditions on screen above rows that no
    // longer reflect them, so it stays a whole page. A record link leaves the view
    // entirely, which is what `hx-boost` on `<body>` already handles.
    assert!(page.contains("<a href=\"/deals\" class=\"cr-button\">Reset</a>"));
    let rows = between(&page, "<tbody", "</tbody>");
    assert!(rows.contains("/deals/records/"));
    assert!(
        !rows.contains("hx-target"),
        "a record link replaces the table instead of opening the record"
    );
}

#[tokio::test]
async fn each_control_answers_with_the_results_region_and_the_heading_it_changes() {
    let (_temporary, database) = database_with_deals("swap-fragments");
    let app = router(database, ServerConfig::default()).unwrap();

    for (control, uri) in control_urls(&app).await {
        let fragment = swap(&app, &uri).await;
        let document = get(&app, &uri, &[]).await;
        assert_eq!(fragment.status, StatusCode::OK, "{control}");
        assert_eq!(document.status, StatusCode::OK, "{control}");
        let answer = results(&uri, &fragment.body);

        // The shareability property, stated as an equality rather than a promise:
        // the region a swap installs is the region the same URL's document
        // contains, so the URL `hx-push-url` leaves in the address bar renders
        // the same state for a reader with no JavaScript at all.
        assert!(
            document.body.contains(&answer.region),
            "{control} swaps a region the same URL's document does not contain"
        );

        // The out-of-band passengers are the document's own elements with one
        // attribute added. Asserting it this way is what stops them drifting:
        // there is one renderer, and the only difference between its two outputs
        // is the marker that tells htmx to patch rather than to swap.
        for (name, patch) in [("count", &answer.count), ("summary", &answer.summary)] {
            let stripped = patch.replace(" hx-swap-oob=\"true\"", "");
            assert!(
                document.body.contains(&stripped),
                "{control} patches the heading's {name} with markup the page does not have: {stripped}"
            );
        }

        // The announcement and the footer are one fact in two renderings: the
        // pager prints "Showing 1–2 of 5" for the eye and the live region is
        // told "Showing records 1 to 2 of 5", which is the same three numbers
        // spelled for a voice. Asserting the numbers rather than the sentence is
        // what keeps the two from drifting without pinning either's wording.
        let spoken = between(&answer.announcement, "\">", "</div>");
        let printed = between(&answer.region, "Showing ", "</p>");
        let (range, total) = printed.split_once(" of ").expect("pager states a total");
        let (first, last) = range.split_once('–').expect("pager states a range");
        assert_eq!(
            spoken,
            format!("Showing records {first} to {last} of {total}"),
            "{control} tells the live region something the pager does not say"
        );

        // The tab follows the swap because the fragment says what to call the
        // state. Nothing here changes it — every one of these URLs is the same
        // view with a different query — and that is the point: the title is sent
        // so that the day one of them is not, the tab is still right.
        assert!(
            document
                .body
                .contains(&format!("<title>{}</title>", answer.title)),
            "{control} names a state the document does not"
        );

        // Same representation rules as a whole page, including the list of
        // request headers the body depends on: two htmx requests for one URL with
        // different targets get different bodies.
        assert_eq!(
            fragment.header(header::VARY),
            "Cookie, HX-Request, HX-Target, HX-History-Restore-Request",
            "{control}"
        );
        assert_eq!(
            fragment.header(header::CACHE_CONTROL),
            "no-store",
            "{control}"
        );
    }

    // Each control really does change the results, so the assertions above are
    // about four different answers rather than four copies of one.
    let regions = futures_of_regions(&app).await;
    for (index, (control, region)) in regions.iter().enumerate() {
        for (other, other_region) in regions.iter().skip(index + 1) {
            assert_ne!(region, other_region, "{control} and {other} agree");
        }
    }
}

/// The region each control answers with, so they can be compared against each
/// other. Kept out of the test body because the loop above reads better without
/// four bindings threaded through it.
async fn futures_of_regions(app: &Router) -> Vec<(&'static str, String)> {
    let mut regions = Vec::new();
    for (control, uri) in control_urls(app).await {
        let fragment = swap(app, &uri).await;
        regions.push((control, results(&uri, &fragment.body).region));
    }
    regions
}

#[tokio::test]
async fn the_same_urls_answer_a_browser_with_a_whole_page_and_no_patches() {
    let (_temporary, database) = database_with_deals("swap-no-js");
    let app = router(database, ServerConfig::default()).unwrap();

    for (control, uri) in control_urls(&app).await {
        let document = get(&app, &uri, &[]).await;
        assert_eq!(document.status, StatusCode::OK, "{control}");
        assert!(document.body.starts_with("<!DOCTYPE html>"), "{control}");
        // The shell the swap deliberately leaves alone is all present when the
        // same URL is navigated to rather than swapped into.
        for shell in [
            "cr-sidebar",
            "cr-page-bar",
            "data-filter-builder=\"true\"",
            "data-filter-panel=\"true\"",
            "hx-boost=\"true\"",
            // Present and empty. Arriving on a page is not a change to
            // announce, and a region that already held a sentence when the
            // reader got here would either be read out unprompted or make the
            // next swap's identical sentence look like no change at all.
            r#"<div id="cr-announce" class="cr-visually-hidden" role="status" aria-live="polite" aria-atomic="true"></div>"#,
        ] {
            assert!(document.body.contains(shell), "{control} lost {shell}");
        }
        // An out-of-band marker in a *document* would be acted on the next time a
        // boosted navigation swapped it into the body: htmx would patch the
        // element into place and then remove it from the incoming markup, so the
        // page would arrive with the element missing.
        assert!(
            !document.body.contains("hx-swap-oob"),
            "{control} marks an element out of band in a whole document"
        );
    }
}

#[tokio::test]
async fn back_and_forward_through_swapped_states_get_documents() {
    let (_temporary, database) = database_with_deals("swap-history");
    let app = router(database, ServerConfig::default()).unwrap();

    assert!(
        UI_SCRIPT.contains("historyCacheSize = 0"),
        "cr.js no longer refuses to write rendered pages into sessionStorage"
    );

    // With no history cache every back and forward is a real request, and htmx
    // swaps its answer into `<body>` whatever the answer claims to be. A region
    // there would delete the sidebar, the progress bar and the skip link, and the
    // next navigation would have nothing left to boost from — so a restore of a
    // URL a swap pushed has to get the page, even though the same URL answered a
    // region a moment earlier.
    for (control, uri) in control_urls(&app).await {
        let restore = get(
            &app,
            &uri,
            &[
                ("hx-request", "true"),
                ("hx-history-restore-request", "true"),
                ("hx-current-url", "http://127.0.0.1/deals"),
                ("hx-target", VIEW_TABLE_REGION),
            ],
        )
        .await;
        assert_eq!(
            restore.body,
            get(&app, &uri, &[]).await.body,
            "restoring {control} gets something other than the page"
        );
    }
}

#[tokio::test]
async fn a_kanban_board_is_paged_and_filtered_by_the_same_controls() {
    let (_temporary, database) = database_with_deals("swap-kanban");
    let app = router(database, ServerConfig::default()).unwrap();

    // One region id, two layouts: a board is searched and filtered by the same
    // controls a table is, so the board has to be a valid answer to the same
    // request. It is not paged; a lane holding more than it shows offers more,
    // and that link swaps the board as the pager swaps a table's page.
    let page = get(&app, "/pipeline?limit=1", &[]).await;
    assert!(page.body.contains("data-kanban-board"));
    let next = attribute(&page.body, "cr-lane-more-1", "href");
    assert!(next.contains("limit=2"));
    let answer = results(&next, &swap(&app, &next).await.body);
    assert!(answer.region.contains("data-kanban-lane"));
    assert!(!answer.region.contains("cr-table-shell"));
    assert!(get(&app, &next, &[]).await.body.contains(&answer.region));

    // Moving a card is deliberately not one of these controls. The board is the
    // region and a page turn already swaps it, but a move is a `POST` whose
    // successful answer is a redirect, and only the rendered move form could use a
    // second success shape that returned markup — the drag-and-drop equivalent in
    // `cr.js` submits with `form.submit()`, which fires no submit event and so is
    // never an htmx request. Giving the form a swap the drop cannot have is the
    // asymmetry `UNBOOSTED` exists to prevent.
    let board = between(&page.body, "data-kanban-board", "data-board-summary");
    assert!(board.contains("/move\" hx-boost=\"false\""));
    for card in board.split("<article").skip(1) {
        let card = &card[..card.find("</article>").unwrap()];
        assert!(
            !card.contains("hx-target"),
            "a card gained a targeted swap its drag-and-drop twin cannot make"
        );
    }
}

#[tokio::test]
async fn a_failed_swap_leaves_the_table_alone_instead_of_pasting_an_error_page_into_it() {
    let (_temporary, database) = database_with_deals("swap-errors");
    let app = router(database, ServerConfig::default()).unwrap();

    // htmx does not swap a failed response unless something says to, and the one
    // clause in `cr.js` that says so for a `GET` now checks the target as well as
    // the boost: these controls are boosted elements that override `hx-target`, and
    // htmx keeps calling their requests boosted, so "boosted" alone stopped meaning
    // "replacing the whole body" the moment they shipped. Without the second
    // condition a re-sort of a view someone has just deleted would paste a whole
    // rendered error document — doctype, sidebar and all — inside the table.
    assert!(
        UI_SCRIPT.contains("boosted && target === document.body && requestConfig.verb === 'get'"),
        "cr.js no longer distinguishes a whole-page boost from a targeted swap"
    );

    // Nor is a failed `GET` left doing nothing, which is what htmx does with one:
    // it becomes the page load it stands in for, so the reader gets the error
    // page where a click without JavaScript would have put it. The same clause
    // is what keeps these controls working behind an authenticating proxy —
    // Cloudflare Access, say — whose expired session redirects every request to
    // a sign-in page on another origin: a page load follows that redirect and
    // comes back signed in, and an htmx request fails without a response
    // (`htmx:sendError`). See `loadInstead` in `cr.js`.
    assert!(
        UI_SCRIPT.contains(
            "!event.detail.shouldSwap && xhr.status >= 400 && requestConfig.verb === 'get'"
        ),
        "cr.js leaves a refused GET doing nothing"
    );
    assert!(
        UI_SCRIPT.contains("document.addEventListener('htmx:sendError'")
            && UI_SCRIPT.contains("detail.pathInfo?.finalRequestPath"),
        "cr.js leaves a GET that got no response doing nothing"
    );

    // The error page itself is outside the seam, so a targeted request that fails
    // is answered with a document that htmx will refuse to swap rather than with
    // something that would look at home in a table cell.
    let missing = swap(&app, "/deals?sort_field=name&after=deleted-record").await;
    assert_eq!(missing.status, StatusCode::OK);
    let gone = swap(&app, "/nonexistent-view?sort_field=name").await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
    assert!(gone.body.starts_with("<!DOCTYPE html>"));
    assert!(!gone.body.contains("hx-swap-oob"));
}
