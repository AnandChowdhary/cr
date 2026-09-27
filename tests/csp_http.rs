//! The content security policy, and the markup that lets every page keep it.
//!
//! Every HTML answer carries one policy, which allows this origin and nothing
//! inline. It is a second line of defence behind the templates' escaping, and a
//! policy that breaks the page the day the markup needs something it refuses —
//! an inline `<style>`, a `style=` attribute, an `onchange=`, a `data:` icon —
//! is one somebody loosens. So the policy and the markup are asserted together.
//!
//! **Every HTML answer carries the policy**: whole documents, the error page,
//! the regions htmx asks for, and a refused form, with access control off and
//! on. The value is compared literally and directive by directive, so loosening
//! it is a change to this file.
//!
//! **No page needs anything the policy refuses.** Every tag of every page is
//! read: no `<style>` element, no `style` attribute, no event handler
//! attribute, no `<script>` without a `src`, no `javascript:` or `data:` URL, no
//! `<base>`, no plugin or frame, and nothing a page loads, submits to or asks
//! htmx to fetch that is not a path on this origin. Every stylesheet, script
//! and icon a page links is then fetched, so none of them is a name the server
//! does not answer. The fixtures write markup into a record, a view title and
//! a file, so this is also a check that none of it comes back as markup.
//!
//! **htmx stays inside it too.** It injects a `<style>` element unless told
//! not to, and evaluates JavaScript written in attributes for `hx-on`, trigger
//! filters and `js:` values. `cr.js` switches both off, and no page uses any of
//! those attributes.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
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
use regex::Regex;
use tempfile::TempDir;
use tower::ServiceExt;

/// The policy, spelled out rather than imported, so that changing it in
/// `src/server.rs` fails here until someone has decided to change it here too.
const POLICY: &str = "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// Markup the policy exists to neutralise, written into the database wherever
/// the fixtures can put text. Escaping means it never reaches a page as markup,
/// which the tag checks below confirm by reading every tag and finding none of
/// it.
const HOSTILE: &str = r#"<style>body{display:none}</style><script>alert(1)</script><img src="data:," onerror="alert(1)" style="color:red">"#;

/// Every whole document the UI renders without access control, and the status
/// each should answer with.
const DOCUMENTS: [(&str, StatusCode); 11] = [
    ("/", StatusCode::OK),
    ("/?summary=inline", StatusCode::OK),
    ("/deals", StatusCode::OK),
    ("/pipeline", StatusCode::OK),
    ("/pipeline/edit", StatusCode::OK),
    ("/pipeline/delete", StatusCode::OK),
    ("/deals/new", StatusCode::OK),
    ("/deals/records/alpha", StatusCode::OK),
    ("/deals/records/alpha/delete", StatusCode::OK),
    ("/audit", StatusCode::OK),
    ("/no-such-view", StatusCode::NOT_FOUND),
];

/// The regions htmx asks for by name, each from a page that renders it.
const FRAGMENTS: [(&str, &str); 4] = [
    ("/?summary=inline", "cr-view-index"),
    ("/deals", "cr-view-table"),
    ("/deals/new", "cr-record-form"),
    ("/deals/records/alpha", "main-content"),
];

/// Pages only access control renders: the perspective switcher on every one,
/// the users registry, and the owner's file browser.
const ACCESS_CONTROLLED_DOCUMENTS: [&str; 5] = ["/", "/deals", "/users", "/audit", "/browse"];

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Answer {
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
    headers: &[(&str, &str)],
    form: Option<String>,
) -> Answer {
    let mut builder = Request::builder().method(method).uri(uri);
    if form.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(form.unwrap_or_default())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

async fn get(app: &Router, uri: &str) -> Answer {
    request(app, Method::GET, uri, &[], None).await
}

/// Ask for a region with the headers htmx sends for a control that names one.
async fn fragment(app: &Router, uri: &str, region: &str) -> Answer {
    request(
        app,
        Method::GET,
        uri,
        &[
            ("hx-request", "true"),
            ("hx-current-url", "http://127.0.0.1/"),
            ("hx-target", region),
        ],
        None,
    )
    .await
}

fn open_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=Alpha <b onclick=alert(1)>deal</b>").unwrap(),
                Assignment::from_str("stage=qualification").unwrap(),
            ],
            HOSTILE,
        )
        .unwrap();
    database
        .create_view_with_options(
            "pipeline",
            Some(HOSTILE),
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

/// A database under access control, launched by its owner, with a second user
/// for the perspective switcher to offer and a file for the browser to open.
fn access_controlled_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name))
        .unwrap()
        .with_actor("Owner <owner@example.com>")
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user("reader@example.com", "Reader", None, UserKind::Human)
        .unwrap();
    database
        .create(
            "deals",
            "alpha",
            &[Assignment::from_str("name=Alpha").unwrap()],
            HOSTILE,
        )
        .unwrap();
    let notes = database.root().join("notes");
    fs::create_dir(&notes).unwrap();
    fs::write(notes.join("hostile.html"), HOSTILE).unwrap();
    (temporary, database)
}

/// A file browser route for `path`, opened from the directory holding it when
/// the route acts on the file rather than showing it.
fn with_path(route: &str, path: &Path) -> String {
    let mut query = form_urlencoded::Serializer::new(String::new());
    query.append_pair("path", path.to_str().unwrap());
    if route != "/browse" {
        query.append_pair("from", path.parent().unwrap().to_str().unwrap());
    }
    format!("{route}?{}", query.finish())
}

fn csrf(html: &str) -> &str {
    let marker = "name=\"_csrf\" value=\"";
    let rest = html
        .split_once(marker)
        .unwrap_or_else(|| panic!("no CSRF field in HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
}

/// A policy as its directives, each with its sources in order.
fn directives(policy: &str) -> BTreeMap<&str, Vec<&str>> {
    policy
        .split(';')
        .map(str::trim)
        .filter(|directive| !directive.is_empty())
        .map(|directive| {
            let mut parts = directive.split_whitespace();
            (parts.next().unwrap(), parts.collect())
        })
        .collect()
}

fn assert_policy(context: &str, answer: &Answer) {
    assert!(
        answer.header(header::CONTENT_TYPE).starts_with("text/html"),
        "{context} is not HTML"
    );
    let policy = answer.header(header::CONTENT_SECURITY_POLICY);
    assert_eq!(policy, POLICY, "{context}");
    assert_eq!(
        answer
            .headers
            .get_all(header::CONTENT_SECURITY_POLICY)
            .iter()
            .count(),
        1,
        "{context} sends more than one policy, and a browser enforces them all"
    );
}

/// One opening tag: its name, its attributes, and where it ends in the page.
struct Tag<'a> {
    text: &'a str,
    name: String,
    attributes: Vec<(String, Option<String>)>,
    end: usize,
}

impl Tag<'_> {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(attribute, _)| attribute == name)
            .and_then(|(_, value)| value.as_deref())
    }
}

/// Every opening tag in a page.
///
/// Crude on purpose, and exact here for the reason `tests/boosted_navigation_http.rs`
/// gives: Maud escapes `<`, `>` and `"` in text and in attribute values, and
/// always quotes a value with `"`, so a `<` followed by a letter is a tag, the
/// next `>` ends it, and every value is one `"`-delimited run. Anything the
/// database holds reaches a page as `&lt;` and is not a tag at all, which is
/// the property the hostile fixture text puts to the test.
fn tags(html: &str) -> Vec<Tag<'_>> {
    let opening = Regex::new(r"<([a-zA-Z][a-zA-Z0-9-]*)").unwrap();
    let attribute = Regex::new(r#"([^\s="'<>/]+)(?:="([^"]*)")?"#).unwrap();
    opening
        .captures_iter(html)
        .map(|captures| {
            let start = captures.get(0).unwrap().start();
            let end = start + html[start..].find('>').expect("unterminated tag") + 1;
            let text = &html[start..end];
            let name = captures[1].to_ascii_lowercase();
            let rest = &html[captures.get(1).unwrap().end()..end - 1];
            let attributes = attribute
                .captures_iter(rest)
                .map(|found| {
                    (
                        found[1].to_ascii_lowercase(),
                        found.get(2).map(|value| value.as_str().to_owned()),
                    )
                })
                .collect();
            Tag {
                text,
                name,
                attributes,
                end,
            }
        })
        .collect()
}

/// A URL that resolves against this origin: a path, a query, or a fragment,
/// never a scheme or a protocol-relative host.
fn same_origin(url: &str) -> bool {
    (url.starts_with('/') && !url.starts_with("//")) || url.starts_with('?') || url.starts_with('#')
}

/// Assert that a page needs nothing the policy refuses, and return every
/// resource it links so the caller can fetch them.
fn assert_within_policy(uri: &str, html: &str) -> BTreeSet<String> {
    let mut linked = BTreeSet::new();
    let found = tags(html);
    // Guards everything below against passing because it read nothing.
    assert!(found.len() > 20, "{uri}: found only {} tags", found.len());
    for tag in &found {
        let text = tag.text;
        assert!(
            ![
                "style", "base", "object", "embed", "applet", "iframe", "frame"
            ]
            .contains(&tag.name.as_str()),
            "{uri}: `{text}` needs something the policy refuses"
        );
        for (name, value) in &tag.attributes {
            // `style-src 'self'` covers attributes as well as elements.
            assert_ne!(name, "style", "{uri}: an inline style in `{text}`");
            // Every event handler attribute is `on` and the event, and no
            // other attribute begins that way; `hx-on` is htmx's spelling.
            assert!(
                !name.starts_with("on") && !name.starts_with("hx-on"),
                "{uri}: an inline handler in `{text}`"
            );
            let Some(value) = value else { continue };
            let value = value.trim().to_ascii_lowercase();
            assert!(
                !value.starts_with("javascript:"),
                "{uri}: a javascript: URL in `{text}`"
            );
            if ["src", "href", "action", "formaction", "srcset", "poster"].contains(&name.as_str())
            {
                assert!(
                    !value.starts_with("data:"),
                    "{uri}: a data: URL in `{text}`"
                );
            }
            // htmx's requests are fetches like any other, held to `'self'`.
            if ["hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete"].contains(&name.as_str()) {
                assert!(same_origin(&value), "{uri}: `{text}` leaves this origin");
            }
            // The attributes htmx evaluates as JavaScript.
            assert!(
                !name.starts_with("hx-vars"),
                "{uri}: `{text}` asks htmx to evaluate an expression"
            );
            if name == "hx-vals" {
                assert!(
                    !value.starts_with("js:") && !value.starts_with("javascript:"),
                    "{uri}: `{text}` asks htmx to evaluate an expression"
                );
            }
            if name == "hx-trigger" {
                assert!(
                    !value.contains('['),
                    "{uri}: `{text}` has a trigger filter, which htmx evaluates"
                );
            }
        }
        match tag.name.as_str() {
            "script" => {
                let source = tag
                    .attribute("src")
                    .unwrap_or_else(|| panic!("{uri}: an inline script, `{text}`"));
                assert!(
                    html[tag.end..].starts_with("</script>"),
                    "{uri}: `{text}` has a body as well as a source"
                );
                assert!(same_origin(source), "{uri}: `{text}` loads from elsewhere");
                linked.insert(source.to_owned());
            }
            "link" => {
                let target = tag.attribute("href").unwrap_or_default();
                assert!(same_origin(target), "{uri}: `{text}` loads from elsewhere");
                linked.insert(target.to_owned());
            }
            "form" => {
                // A form with no `action` submits to the page it is on.
                if let Some(action) = tag.attribute("action") {
                    assert!(same_origin(action), "{uri}: `{text}` submits elsewhere");
                }
            }
            "img" | "video" | "audio" | "source" | "track" => {
                let source = tag.attribute("src").unwrap_or_default();
                assert!(same_origin(source), "{uri}: `{text}` loads from elsewhere");
            }
            _ => {}
        }
    }
    linked
}

/// Fetch everything the pages link, and check each one is served.
async fn assert_served(app: &Router, linked: &BTreeSet<String>) {
    // Two scripts, two stylesheets and the icon, at least.
    assert!(linked.len() >= 5, "{linked:?}");
    for path in linked {
        let answer = get(app, path).await;
        assert_eq!(
            answer.status,
            StatusCode::OK,
            "{path} is linked but not served"
        );
    }
    assert!(
        linked.iter().any(|path| path.ends_with(".svg")),
        "no page links its icon: {linked:?}"
    );
}

#[tokio::test]
async fn the_policy_allows_this_origin_and_nothing_inline() {
    let policy = directives(POLICY);
    let expected: BTreeMap<&str, Vec<&str>> = [
        ("default-src", vec!["'self'"]),
        ("object-src", vec!["'none'"]),
        ("base-uri", vec!["'none'"]),
        ("form-action", vec!["'self'"]),
        ("frame-ancestors", vec!["'none'"]),
    ]
    .into_iter()
    .collect();
    assert_eq!(policy, expected);
    // Nothing overrides the fallback for scripts, styles or images, so each of
    // them is `'self'` and nothing else: no inline source, no `eval`, no
    // `data:`, no other origin.
    for sources in policy.values() {
        for source in sources {
            assert!(
                ["'self'", "'none'"].contains(source),
                "`{source}` widens the policy"
            );
        }
    }
}

#[tokio::test]
async fn every_html_answer_carries_the_policy() {
    let (_temporary, database) = open_database("csp-open");
    let app = router(database, ServerConfig::default()).unwrap();

    for (uri, expected) in DOCUMENTS {
        let answer = get(&app, uri).await;
        assert_eq!(answer.status, expected, "{uri}");
        assert_policy(uri, &answer);
    }
    for (uri, region) in FRAGMENTS {
        let answer = fragment(&app, uri, region).await;
        assert_eq!(answer.status, StatusCode::OK, "{uri} {region}");
        assert!(
            !answer.body.starts_with("<!DOCTYPE"),
            "{uri} answered {region} with a document"
        );
        assert_policy(&format!("{uri} {region}"), &answer);
    }

    // A refused form is the form again, under the status of the refusal.
    let page = get(&app, "/deals/new").await;
    let submission = form_urlencoded::Serializer::new(String::new())
        .append_pair("_csrf", csrf(&page.body))
        .append_pair("id", "alpha")
        .append_pair("front_matter", "name: Taken\n")
        .append_pair("markdown", "")
        .finish();
    let refused = request(&app, Method::POST, "/deals/records", &[], Some(submission)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{}", refused.body);
    assert_eq!(refused.header("cr-form-invalid".parse().unwrap()), "true");
    assert_policy("a refused form", &refused);
    assert_within_policy("a refused form", &refused.body);
}

#[tokio::test]
async fn no_page_needs_anything_the_policy_refuses() {
    let (_temporary, database) = open_database("csp-markup");
    let app = router(database, ServerConfig::default()).unwrap();

    let mut linked = BTreeSet::new();
    for (uri, _) in DOCUMENTS {
        let answer = get(&app, uri).await;
        linked.extend(assert_within_policy(uri, &answer.body));
    }
    // The hostile text reached the pages it was written into, as text.
    let record = get(&app, "/deals/records/alpha").await;
    assert!(
        record
            .body
            .contains("&lt;style&gt;body{display:none}&lt;/style&gt;")
    );
    let board = get(&app, "/pipeline").await;
    assert!(board.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));

    for (uri, region) in FRAGMENTS {
        let answer = fragment(&app, uri, region).await;
        // A fragment is swapped into a page that already has the policy, so its
        // markup is held to it too. It has no head, so it links nothing.
        let context = format!("{uri} {region}");
        assert!(assert_within_policy(&context, &answer.body).is_empty());
    }
    assert_served(&app, &linked).await;
}

#[tokio::test]
async fn pages_under_access_control_keep_the_policy_too() {
    let (_temporary, database) = access_controlled_database("csp-access");
    let root = database.root().to_path_buf();
    let app = router(database, ServerConfig::default()).unwrap();

    let file = root.join("notes").join("hostile.html");
    let mut uris: Vec<String> = ACCESS_CONTROLLED_DOCUMENTS
        .iter()
        .map(|uri| (*uri).to_owned())
        .collect();
    uris.push(with_path("/browse", &file));
    uris.push(with_path("/browse/edit", &file));
    uris.push(with_path("/browse/delete", &file));

    let mut linked = BTreeSet::new();
    for uri in &uris {
        let answer = get(&app, uri).await;
        assert_eq!(answer.status, StatusCode::OK, "{uri}: {}", answer.body);
        assert_policy(uri, &answer);
        linked.extend(assert_within_policy(uri, &answer.body));
        // The perspective switcher is on every one of these pages, and it is
        // what used to carry the last inline handler.
        assert!(answer.body.contains(r#"action="/perspective""#), "{uri}");
    }
    let preview = get(&app, &with_path("/browse", &file)).await;
    assert!(
        preview
            .body
            .contains("&lt;script&gt;alert(1)&lt;/script&gt;")
    );
    assert_served(&app, &linked).await;
}

#[tokio::test]
async fn htmx_is_configured_to_need_neither_inline_style_nor_eval() {
    let (_temporary, database) = open_database("csp-htmx");
    let app = router(database, ServerConfig::default()).unwrap();
    let home = get(&app, "/").await;
    let script = home
        .body
        .split(r#"<script src=""#)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|source| source.starts_with("/static/cr-"))
        .expect("the page links cr.js");
    let script = get(&app, script).await.body;
    // htmx would otherwise append a `<style>` element to the head for its
    // `htmx-indicator` class, which the policy refuses.
    assert!(script.contains("window.htmx.config.includeIndicatorStyles = false;"));
    // The policy grants no `'unsafe-eval'`; htmx is told so, so a trigger
    // filter or `hx-on` added later fails with htmx's own error.
    assert!(script.contains("window.htmx.config.allowEval = false;"));
    // Both are set before htmx reads them: `cr.js` runs after htmx, which
    // applies its configuration on DOMContentLoaded.
    let htmx_at = home.body.find(r#"<script src="/static/htmx-"#).unwrap();
    let script_at = home.body.find(r#"<script src="/static/cr-"#).unwrap();
    assert!(htmx_at < script_at);
}
