//! The embedded UI asset route.
//!
//! The scripts that enhance the filter panel, the save-view control, and the
//! Kanban board used to be Rust string constants inlined into every page that
//! needed them. They are now one file compiled into the binary and served from
//! `/static/<name>`, alongside a vendored copy of htmx. These tests pin the
//! properties that move made load bearing: each URL is content addressed so it
//! can be cached forever, the route reaches nothing but the constants it was
//! compiled with, rendered pages link both files rather than carrying script
//! bodies around, and the htmx we serve is a named release whose exact bytes
//! cannot change without a test failing.

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

struct TestResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl TestResponse {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).unwrap()
    }

    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(name)
            .map(|value| value.to_str().unwrap())
            .unwrap_or_default()
    }
}

async fn request(app: &Router, uri: &str, headers: &[(&str, &str)]) -> TestResponse {
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

/// `cr.js`'s URL is a pure content address with no version in it, so tests read
/// it out of a rendered page rather than hardcoding a digest that every edit to
/// the script would invalidate. htmx names a release as well as a digest and is
/// asserted literally instead, below.
fn asset_path(html: &str, prefix: &str) -> String {
    let needle = format!("<script src=\"/static/{prefix}");
    let rest = html
        .split_once(needle.as_str())
        .unwrap_or_else(|| panic!("no {prefix} script link in HTML:\n{html}"))
        .1;
    format!("/static/{prefix}{}", rest.split_once('"').unwrap().0)
}

/// The vendored release, as it appears in the served file name.
///
/// Spelled out rather than derived: the point of a content-addressed name is
/// that these exact bytes are what every browser caches for a year under this
/// exact URL, so re-pinning htmx has to be a commit that changes a failing
/// assertion. `sha256sum src/static/htmx-2.0.10.min.js` is the whole digest
/// this truncates, and `src/server.rs` records it beside `HTMX_SCRIPT`.
const HTMX_ASSET: &str = "/static/htmx-2.0.10-71ea67185bfa8c98.min.js";

/// The bytes the binary compiles in, read the same way `src/server.rs` reads
/// them, so the assertions below compare what is served against what is
/// committed rather than against a copy of it.
const HTMX_SOURCE: &str = include_str!("../src/static/htmx-2.0.10.min.js");

/// Committed beside the script because a vendored dependency whose terms a
/// reader has to leave the tree to find is worse than one they can read in
/// place. 0BSD imposes no condition on redistribution, so this file is a
/// courtesy rather than compliance — which is exactly why a test has to keep it
/// from being deleted as dead weight.
const HTMX_LICENSE: &str = include_str!("../src/static/htmx-2.0.10.LICENSE.txt");

fn kanban_database(name: &str) -> (TempDir, Database) {
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
async fn the_ui_script_is_served_from_a_content_addressed_immutable_url() {
    let (_temporary, database) = kanban_database("static-asset");
    let app = router(database, ServerConfig::default()).unwrap();

    let home = request(&app, "/", &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    let path = asset_path(home.text(), "cr-");
    assert!(
        path.starts_with("/static/cr-") && path.ends_with(".js"),
        "unexpected asset path {path}"
    );
    // A digest, not a version number: the cache lifetime below is only safe
    // because editing the script necessarily changes this name.
    let digest = path
        .trim_start_matches("/static/cr-")
        .trim_end_matches(".js");
    assert_eq!(digest.len(), 16);
    assert!(
        digest
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );

    let asset = request(&app, &path, &[]).await;
    assert_eq!(asset.status, StatusCode::OK);
    assert_eq!(
        asset.header(header::CONTENT_TYPE),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        asset.header(header::CACHE_CONTROL),
        "public, max-age=31536000, immutable"
    );
    // The three enhancements that used to be separate inline blocks.
    assert!(asset.text().contains("[data-filter-builder]"));
    assert!(asset.text().contains("[data-view-layout]"));
    assert!(asset.text().contains("[data-kanban-board]"));
}

#[tokio::test]
async fn the_asset_route_cannot_be_walked_outside_the_binary() {
    let (_temporary, database) = kanban_database("static-traversal");
    let app = router(database, ServerConfig::default()).unwrap();
    let real = asset_path(request(&app, "/", &[]).await.text(), "cr-");

    // The handler matches request names against constants it was compiled
    // with and never touches the filesystem, so none of these can name a file:
    // there is no directory for a `..`, an absolute path, or a planted
    // symbolic link to be resolved against in the first place.
    for uri in [
        "/static/../Cargo.toml",
        "/static/..%2FCargo.toml",
        "/static/%2e%2e%2f%2e%2e%2fCargo.toml",
        "/static/%2Fetc%2Fpasswd",
        "/static/src%2Fstatic%2Fcr.js",
        "/static/cr.js",
        "/static/htmx.min.js",
        "/static/htmx-2.0.10.min.js",
        "/static/htmx-2.0.10.LICENSE.txt",
        "/static/",
        &format!("{real}%00"),
        &format!("{real}.map"),
    ] {
        let response = request(&app, uri, &[]).await;
        assert_ne!(response.status, StatusCode::OK, "{uri} was served");
        assert!(
            !response.text().contains("[package]") && !response.text().contains("root:"),
            "{uri} disclosed file contents"
        );
    }

    let missing = request(&app, "/static/cr-0000000000000000.js", &[]).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.text().contains("route_not_found"));

    // The real name still resolves, so the refusals above are the match
    // rejecting unknown names rather than the route being broken.
    assert_eq!(request(&app, &real, &[]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn rendered_pages_link_the_asset_instead_of_inlining_script_bodies() {
    let (_temporary, database) = kanban_database("static-pages");
    let app = router(database, ServerConfig::default()).unwrap();
    let path = asset_path(request(&app, "/", &[]).await.text(), "cr-");
    let link = format!("<script src=\"{path}\" defer></script>");
    let htmx_link = format!("<script src=\"{HTMX_ASSET}\" defer></script>");

    for uri in ["/", "/deals", "/pipeline", "/deals/new", "/audit"] {
        let page = request(&app, uri, &[]).await;
        assert_eq!(page.status, StatusCode::OK, "{uri}");
        assert!(page.text().contains(&link), "{uri} does not link the asset");
        assert!(page.text().contains(&htmx_link), "{uri} does not link htmx");
        // `defer` preserves the old execution point: the blocks used to be
        // emitted after the markup they enhance, so they ran against a parsed
        // document, which is exactly when a deferred script runs.
        assert!(
            page.text().find(&link).unwrap() < page.text().find("<body").unwrap(),
            "{uri} does not link the asset from the head"
        );
        // Both are deferred, so they run in document order, and `cr.js` sets
        // htmx configuration that htmx must already have defined. Linking htmx
        // second would leave `window.htmx` undefined when `cr.js` runs and
        // every one of those settings would silently keep its default.
        assert!(
            page.text().find(&htmx_link).unwrap() < page.text().find(&link).unwrap(),
            "{uri} links htmx after the script that configures it"
        );
        for body in [
            "document.querySelector('[data-filter-builder]')",
            "document.querySelectorAll('[data-view-layout]')",
            "document.querySelector('[data-kanban-board]')",
        ] {
            assert!(!page.text().contains(body), "{uri} still inlines {body}");
        }
    }

    // The markup the script binds to is untouched by the move.
    let board = request(&app, "/pipeline", &[]).await;
    assert!(board.text().contains("data-kanban-board=\"true\""));
    assert!(board.text().contains("draggable=\"true\""));
    let table = request(&app, "/deals", &[]).await;
    assert!(table.text().contains("data-filter-builder=\"true\""));
    assert!(table.text().contains("data-view-layout=\"true\""));
}

#[tokio::test]
async fn htmx_is_served_from_the_binary_at_the_exact_vendored_release() {
    let (_temporary, database) = kanban_database("static-htmx");
    let app = router(database, ServerConfig::default()).unwrap();

    // The whole point of vendoring: this URL, and therefore these bytes, are
    // what the pages ask for. Asserting the name literally is what makes
    // re-pinning htmx a deliberate act — new bytes produce a new digest, which
    // produces a new name, which fails here until someone updates it.
    assert_eq!(
        asset_path(request(&app, "/", &[]).await.text(), "htmx-"),
        HTMX_ASSET
    );

    let asset = request(&app, HTMX_ASSET, &[]).await;
    assert_eq!(asset.status, StatusCode::OK);
    assert_eq!(
        asset.header(header::CONTENT_TYPE),
        "text/javascript; charset=utf-8"
    );
    assert_eq!(
        asset.header(header::CACHE_CONTROL),
        "public, max-age=31536000, immutable"
    );
    // Served verbatim: no transformation, no header injected into the file, no
    // build step between the committed bytes and the browser.
    assert_eq!(asset.text(), HTMX_SOURCE);
    // htmx's own idea of which release this is, so a file renamed to a version
    // it is not cannot pass. The digest in the URL pins the bytes; this pins
    // the claim the name makes about them.
    assert!(asset.text().contains("version:\"2.0.10\""));
    // No CDN and no npm tree: the bytes come from `include_str!`, so they are in
    // the binary and the UI works with no network at all.
    assert!(asset.body.len() > 40_000, "htmx looks truncated");

    // 0BSD grants redistribution with no conditions attached, so nothing has to
    // be reproduced anywhere for this to be lawful. The text is committed so a
    // reader can check that for themselves without leaving the tree.
    assert!(HTMX_LICENSE.contains("Zero-Clause BSD"));
    assert!(HTMX_LICENSE.contains("Permission to use, copy, modify, and/or distribute"));
}

#[tokio::test]
async fn the_asset_stays_reachable_when_an_api_token_guards_every_other_route() {
    let (_temporary, database) = kanban_database("static-token");
    let config = ServerConfig {
        api_token: Some("secret-token".into()),
        ..ServerConfig::default()
    };
    let app = router(database, config).unwrap();

    let page = request(&app, "/", &[("authorization", "Bearer secret-token")]).await;
    assert_eq!(page.status, StatusCode::OK);
    let path = asset_path(page.text(), "cr-");
    assert_eq!(
        request(&app, "/", &[]).await.status,
        StatusCode::UNAUTHORIZED
    );

    // A `<script src>` cannot carry a bearer header, so an authenticated asset
    // route would leave the UI without its script in exactly the deployments
    // that set a token. The asset carries no database data, so it is public
    // for the same reason `/health` is.
    let asset = request(&app, &path, &[]).await;
    assert_eq!(asset.status, StatusCode::OK);
    assert_eq!(
        asset.header(header::CACHE_CONTROL),
        "public, max-age=31536000, immutable"
    );
}
