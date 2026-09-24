//! The shell's colour scheme and motion, asserted against what pages send.
//!
//! **Dark mode follows the system.** A page says it supports both schemes, in
//! its `<meta>` and in the sheet, so the browser renders native controls to
//! match, and every colour token the sheet declares has a dark value.
//!
//! **Every colour a utility reads has a dark value.** The utilities are
//! recoloured by redefining the custom properties they resolve through — the
//! sheet's own grey scale, and Tailwind's `--color-*` for every other hue —
//! rather than with a `dark:` variant beside each of them, so a utility that
//! reads a property the dark block leaves alone stays its light colour on a
//! dark page. The failure is quiet, pale text on a pale chip in the middle of
//! a dark page, which is why it is asserted against the stylesheet the server
//! actually serves rather than remembered.
//!
//! **The sheet's rules paint only with tokens.** A literal colour in a rule is
//! a colour with no dark value, and one more grey outside the scale.
//!
//! **Hover and focus states change instantly.** Nothing but the navigation
//! progress bar declares a transition, whether in the sheet or as a utility.

use std::collections::BTreeSet;
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
use regex::Regex;
use tempfile::TempDir;
use tower::ServiceExt;

const DARK_SCHEME: &str = "@media (prefers-color-scheme: dark) {";

/// Every shape of page the shell renders, the error page included.
const PAGES: [(&str, StatusCode); 8] = [
    ("/", StatusCode::OK),
    ("/deals", StatusCode::OK),
    ("/pipeline", StatusCode::OK),
    ("/deals/new", StatusCode::OK),
    ("/deals/records/alpha", StatusCode::OK),
    ("/deals/records/alpha/delete", StatusCode::OK),
    ("/audit", StatusCode::OK),
    ("/no-such-view", StatusCode::NOT_FOUND),
];

async fn get(app: &Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

fn app_with_a_board(name: &str) -> (TempDir, Router) {
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
    (
        temporary,
        router(database, ServerConfig::default()).unwrap(),
    )
}

/// Every page's HTML, each checked for the status it should answer with.
async fn rendered_pages(app: &Router) -> Vec<(&'static str, String)> {
    let mut pages = Vec::new();
    for (uri, expected) in PAGES {
        let (status, html) = get(app, uri).await;
        assert_eq!(status, expected, "{uri}");
        pages.push((uri, html));
    }
    pages
}

/// The server's own stylesheet, which every document inlines in its `<head>`,
/// with its comments removed so that prose cannot pass for a declaration.
fn stylesheet(html: &str) -> String {
    let (_, rest) = html.split_once("<style>").expect("no inline stylesheet");
    let sheet = rest.split_once("</style>").unwrap().0;
    Regex::new(r"(?s)/\*.*?\*/")
        .unwrap()
        .replace_all(sheet, "")
        .into_owned()
}

/// The light palette, the sheet's first `:root`.
fn light_palette(sheet: &str) -> &str {
    let (_, rest) = sheet.split_once(":root {").expect("no light palette");
    rest.split_once("\n}\n").unwrap().0
}

/// The dark palette: from its media query to the brace that closes it, which
/// is the first one at the start of a line — the `:root` inside is indented.
fn dark_palette(sheet: &str) -> &str {
    let (_, rest) = sheet.split_once(DARK_SCHEME).expect("no dark palette");
    rest.split_once("\n}\n").unwrap().0
}

/// The compiled utility stylesheet a page links, fetched from the server.
async fn utility_stylesheet(app: &Router, html: &str) -> String {
    let (_, rest) = html
        .split_once(r#"<link rel="stylesheet" href=""#)
        .expect("no linked stylesheet");
    let (status, css) = get(app, rest.split_once('"').unwrap().0).await;
    assert_eq!(status, StatusCode::OK);
    css
}

/// Every utility in a page's `class` attributes, with any variant prefix
/// (`hover:`, `sm:`) removed.
fn utilities(html: &str) -> BTreeSet<String> {
    let attribute = Regex::new(r#"class="([^"]*)""#).unwrap();
    attribute
        .captures_iter(html)
        .flat_map(|captures| {
            captures[1]
                .split_whitespace()
                .map(|class| class.rsplit(':').next().unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[tokio::test]
async fn every_page_follows_the_system_colour_scheme() {
    let (_temporary, app) = app_with_a_board("scheme-meta");
    let token = Regex::new(r"(--cr-[a-z0-9-]+):").unwrap();
    for (uri, html) in rendered_pages(&app).await {
        // In the document as well as in the sheet, so the browser paints a dark
        // canvas before it has parsed a stylesheet rather than flashing white.
        assert!(
            html.contains(r#"<meta name="color-scheme" content="light dark">"#),
            "{uri}"
        );
        for scheme in ["light", "dark"] {
            assert!(
                html.contains(&format!(
                    r#"<meta name="theme-color" media="(prefers-color-scheme: {scheme})""#
                )),
                "{uri} has no {scheme} theme colour"
            );
        }

        let sheet = stylesheet(&html);
        assert!(sheet.contains("color-scheme: light dark;"), "{uri}");
        let dark = dark_palette(&sheet);
        for captures in token.captures_iter(light_palette(&sheet)) {
            let name = &captures[1];
            // The tokens that are not colours.
            if ["--cr-radius", "--cr-emoji", "--cr-sidebar-width"].contains(&name) {
                continue;
            }
            assert!(
                dark.contains(&format!("{name}:")),
                "{name} has no dark value"
            );
        }
    }
}

#[tokio::test]
async fn every_colour_a_utility_reads_has_a_dark_value() {
    let (_temporary, app) = app_with_a_board("scheme-palette");
    let (_, home) = get(&app, "/").await;
    let dark = dark_palette(&stylesheet(&home)).to_owned();
    let css = utility_stylesheet(&app, &home).await;

    let reads = Regex::new(r"var\((--(?:color|cr)-[a-z0-9-]+)\)").unwrap();
    let properties: BTreeSet<&str> = reads
        .captures_iter(&css)
        .map(|captures| captures.get(1).unwrap().as_str())
        .collect();
    // A grey, so the stylesheet is known to read the palette at all, and a
    // utility only `cr.js` asks for — the card being dragged — so it is known
    // to have been compiled from both files that write markup.
    assert!(
        properties.contains("--cr-gray-500"),
        "the stylesheet reads none of the expected colours: {properties:?}"
    );
    assert!(
        css.contains(".opacity-50 {"),
        "the stylesheet was not compiled from cr.js"
    );

    for property in properties {
        // The middle of a mapped scale is the one shade that keeps its value.
        // It still has to belong to a scale the dark palette maps: a 500 of any
        // other hue — a `slate`, say — is a colour from outside the palette.
        if let Some(hue) = property
            .strip_prefix("--color-")
            .and_then(|shade| shade.strip_suffix("-500"))
        {
            assert!(
                dark.contains(&format!("--color-{hue}-50:")),
                "`{property}` is from a hue the dark palette does not map"
            );
            continue;
        }
        assert!(
            dark.contains(&format!("{property}:")),
            "`{property}` keeps its light value on a dark page"
        );
    }
}

#[tokio::test]
async fn the_sheets_rules_paint_only_with_tokens() {
    let (_temporary, app) = app_with_a_board("scheme-tokens");
    let (_, home) = get(&app, "/").await;
    let sheet = stylesheet(&home);
    // Everything after the dark palette, which follows the light one.
    let (_, rules) = sheet.split_once(DARK_SCHEME).unwrap();
    let (_, rules) = rules.split_once("\n}\n").unwrap();

    let declaration = Regex::new(r"([a-z-]+)\s*:\s*([^;{}]+)").unwrap();
    let literal = Regex::new(
        r"#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?|oklch|oklab|lab|lch|hwb)\(|(?:^|[\s,(])(?:white|black)(?:$|[\s,)])",
    )
    .unwrap();
    for captures in declaration.captures_iter(rules) {
        let (property, value) = (&captures[1], &captures[2]);
        // A shadow is the one exception: a faint black that a dark canvas
        // swallows rather than a colour that needs a dark value of its own.
        if property == "box-shadow" {
            continue;
        }
        assert!(
            !literal.is_match(value),
            "`{property}: {value}` paints with a literal colour instead of a token"
        );
    }
}

#[tokio::test]
async fn hover_and_focus_states_change_without_animating() {
    let (_temporary, app) = app_with_a_board("scheme-motion");
    let declaration = Regex::new(r"[{;\s]transition(?:-[a-z]+)?\s*:").unwrap();
    for (uri, html) in rendered_pages(&app).await {
        let sheet = stylesheet(&html);
        // Reduced motion may say anything about transitions; it only ever takes
        // them away.
        let (moving, _) = sheet
            .split_once("@media (prefers-reduced-motion: reduce) {")
            .unwrap();
        for found in declaration.find_iter(moving) {
            let opened = moving[..found.end()].rfind('{').unwrap();
            let selector_start = moving[..opened].rfind('}').map_or(0, |at| at + 1);
            let selector = moving[selector_start..opened].trim();
            assert_eq!(
                selector, ".cr-progress",
                "{uri}: `{selector}` animates a state change"
            );
        }

        for utility in utilities(&html) {
            assert!(
                !["transition", "duration-", "ease-", "delay-", "animate-"]
                    .iter()
                    .any(|prefix| utility.starts_with(prefix)),
                "{uri}: `{utility}` animates a state change"
            );
        }
    }
}
