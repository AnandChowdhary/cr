//! Boosted navigation: the markup contract, and the absence of a server one.
//!
//! `hx-boost="true"` on `<body>` turns every same-origin link and form into an
//! htmx request whose response replaces the body's contents, so a navigation
//! stops discarding the parsed stylesheet and the running scripts. That is
//! entirely a client-side change, and these tests exist to keep it one.
//!
//! Two properties are load bearing. The first is that the opt-outs are where
//! they have to be: every mutating form and every link that leaves the HTML UI
//! for a JSON representation says `hx-boost="false"`, because htmx would change
//! how a `303` or a rendered error page behaves and phase 3 of
//! `.context/htmx-plan.md` is where that contract is redesigned. The second is
//! that no handler learned anything: an htmx request and a plain browser
//! request get byte-identical answers, which is what makes the rest of the HTTP
//! suite — which never sends an htmx header — a real no-JavaScript regression
//! suite. Phase 2 deliberately breaks that second property, and the assertion
//! below is where it has to say so.

use std::str::FromStr;

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use cr::{
    Assignment, Database, SortDirection, UserKind, ViewLayout,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tempfile::TempDir;
use tower::ServiceExt;

/// Every page the HTML UI renders without access control configured, which is
/// every shape of document the boost has to work on: the view index, a table, a
/// Kanban board, a create form, an edit form with its delete control, and the
/// audit log.
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

/// Every opening tag of the given name in a document, as raw text including the
/// closing `>`.
///
/// Crude on purpose, and safe here because Maud escapes `>` inside attribute
/// values: the first `>` after the tag name really is the end of the tag. What
/// this buys is an assertion over *every* form and *every* anchor a page
/// renders, rather than the handful someone thought to name, so a new mutating
/// form cannot be added without deciding whether it is boosted.
fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let opening = format!("<{name} ");
    html.match_indices(opening.as_str())
        .map(|(start, _)| {
            let rest = &html[start..];
            &rest[..rest.find('>').expect("unterminated tag") + 1]
        })
        .collect()
}

fn database_with_a_board(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=Alpha").unwrap(),
                Assignment::from_str("stage=qualification").unwrap(),
            ],
            "",
        )
        .unwrap();
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
async fn every_page_boosts_its_body_and_renders_the_progress_indicator() {
    let (_temporary, database) = database_with_a_board("boost-body");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let (status, html) = get(&app, uri, &[]).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        // On the body rather than on each link: a boost declared once cannot be
        // forgotten on a link added later, and it is the body that gets swapped.
        assert!(
            html.contains(r##"hx-boost="true" hx-indicator="#cr-progress""##),
            "{uri} does not boost its body"
        );
        // The indicator lives inside the region the swap replaces, which is
        // fine: the request that replaced it has by definition finished, and
        // every page renders a fresh one.
        assert!(
            html.contains(r#"<div id="cr-progress" class="cr-progress" aria-hidden="true">"#),
            "{uri} renders no progress indicator"
        );
        // No inline handler and no inline `<script>`: phase 0 moved the last of
        // those out so `script-src 'self'` stays reachable, and a boost must not
        // reintroduce one. `onsubmit`/`onchange` on two controls predate this
        // work and are tracked in `TODO.md`.
        assert!(
            !html.contains("hx-on:"),
            "{uri} uses an inline hx-on handler"
        );
        assert!(
            !html.contains("hx-on-"),
            "{uri} uses an inline hx-on handler"
        );
        assert!(!html.contains("onclick="), "{uri} uses an inline onclick");
    }
}

#[tokio::test]
async fn every_mutating_form_stays_a_native_browser_submission() {
    let (_temporary, database) = database_with_a_board("boost-forms");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let (_, html) = get(&app, uri, &[]).await;
        for tag in tags(&html, "form") {
            // A `POST` answers `303 See Other`, or a rendered error page with a
            // non-2xx status that htmx would refuse to swap. Neither shape is
            // something htmx can act on until phase 3 redefines it, so every
            // mutation is left to the browser exactly as it behaves today.
            if tag.contains(r#"method="post""#) {
                assert!(
                    tag.contains(r#"hx-boost="false""#),
                    "{uri} boosts a mutating form: {tag}"
                );
            }
            // The read-only forms are the opposite case, and the reason the
            // boost is worth having: search, the filter panel and the audit
            // filters are `GET`s whose response is a page, so htmx swaps them
            // in and pushes the same shareable URL the form would have produced.
            if tag.contains(r#"method="get""#) {
                assert!(
                    !tag.contains("hx-boost"),
                    "{uri} opts a read-only form out of boosting for no reason: {tag}"
                );
            }
        }
    }

    // Both ways of moving a Kanban card are the same native POST: the drop
    // handler in `cr.js` builds and submits a form, and `form.submit()` fires no
    // submit event for htmx to intercept.
    let (_, board) = get(&app, "/pipeline", &[]).await;
    assert!(board.contains(r#"action="/pipeline/records/alpha/move""#));
    assert!(board.contains("data-kanban-lane"));
}

#[tokio::test]
async fn links_that_leave_the_html_ui_are_not_boosted() {
    let (_temporary, database) = database_with_a_board("boost-links");
    let app = router(database, ServerConfig::default()).unwrap();

    let mut json_links = 0;
    let mut html_links = 0;
    for uri in PAGES {
        let (_, html) = get(&app, uri, &[]).await;
        for tag in tags(&html, "a") {
            let leaves_the_ui =
                tag.contains(r#"href="/openapi.json""#) || tag.contains(r#"href="/api/v1/"#);
            if leaves_the_ui {
                json_links += 1;
                // Boosting these would swap an OpenAPI document into the page
                // body as text. They exist to leave the UI for a raw
                // representation, which is what the `↗` beside them promises.
                assert!(
                    tag.contains(r#"hx-boost="false""#),
                    "{uri} boosts a link to a JSON representation: {tag}"
                );
            } else {
                html_links += 1;
                assert!(
                    !tag.contains("hx-boost"),
                    "{uri} opts an in-app link out of boosting: {tag}"
                );
            }
        }
    }
    // Guards the loop above against passing because it found nothing: the
    // sidebar's OpenAPI link, both mobile navigations, and the JSON-API buttons
    // on `/audit` are all in `PAGES`.
    assert!(json_links >= 4, "found only {json_links} JSON links");
    assert!(html_links > 20, "found only {html_links} in-app links");
}

#[tokio::test]
async fn the_perspective_switcher_is_not_boosted() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("boost-perspective"))
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

    let (status, html) = get(&app, "/", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains(r#"aria-label="View as user""#));
    // The switcher posts and is answered with `303 See Other` back to the page
    // it was on. An `XMLHttpRequest` follows that redirect invisibly, so htmx
    // would swap the right page in while pushing `/perspective` into the address
    // bar. It is also submitted by `form.submit()` from an `onchange`, which
    // fires no submit event, so htmx would not see it either way — the
    // attribute makes the opt-out a decision rather than an accident.
    let switcher = tags(&html, "form")
        .into_iter()
        .find(|tag| tag.contains(r#"action="/perspective""#))
        .expect("no perspective form");
    assert!(switcher.contains(r#"hx-boost="false""#), "{switcher}");
}

#[tokio::test]
async fn the_progress_indicator_is_driven_by_htmx_classes_and_honours_reduced_motion() {
    let (_temporary, database) = database_with_a_board("boost-progress");
    let app = router(database, ServerConfig::default()).unwrap();
    let (_, html) = get(&app, "/", &[]).await;

    // htmx adds `htmx-request` to whatever `hx-indicator` names for exactly as
    // long as a request is in flight, and the sheet animates from nothing else,
    // so the bar is inert markup rather than a second mechanism to keep in step.
    assert!(html.contains(".cr-progress.htmx-request { opacity: 1; }"));
    assert!(html.contains("animation: cr-progress"));
    // htmx also ships a `<style>` element for its own `htmx-indicator` class,
    // which `cr.js` switches off. Nothing here uses that class, and an injected
    // inline style is one more obstacle to a strict content security policy.
    assert!(!html.contains("htmx-indicator"));

    // Reduced motion keeps the feedback and drops the movement: with no
    // animation the bar rests at its full width, so it is a plain static strip
    // for as long as the navigation is waiting. Stated rather than left to the
    // sheet's blanket `animation-duration: 0.01ms` rule, which would collapse
    // the growth by accident.
    let (_, reduced) = html
        .split_once("@media (prefers-reduced-motion: reduce) {")
        .unwrap();
    assert!(reduced.contains(".cr-progress.htmx-request::after { animation: none; }"));
}

#[tokio::test]
async fn an_htmx_request_and_a_browser_request_get_the_same_answer() {
    let (_temporary, database) = database_with_a_board("boost-no-seam");
    let app = router(database, ServerConfig::default()).unwrap();

    for uri in PAGES {
        let (plain_status, plain) = get(&app, uri, &[]).await;
        let (boosted_status, boosted) = get(
            &app,
            uri,
            &[
                ("hx-request", "true"),
                ("hx-boosted", "true"),
                ("hx-current-url", "http://127.0.0.1/"),
                ("hx-target", "cr-shell"),
            ],
        )
        .await;
        // Byte for byte. Phase 1 added no representation to negotiate, which is
        // why the rest of this suite — which never sends these headers — still
        // exercises the code every browser runs. Phase 2 introduces the fragment
        // seam and has to change this assertion, and add `HX-Request` to `Vary`
        // in the same commit, because a response that varies on a header a cache
        // is not told about is a cache-poisoning bug.
        assert_eq!(plain_status, boosted_status, "{uri}");
        assert_eq!(plain, boosted, "{uri} answers an htmx request differently");
        assert!(plain.starts_with("<!DOCTYPE html>"), "{uri}");
    }
}
