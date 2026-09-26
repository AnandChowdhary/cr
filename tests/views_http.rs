use std::{fs, path::Path, str::FromStr};

use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use cr::{
    Assignment, AuditAction, AuditFilter, AuditSource, Database, ViewLayout, ViewPredicateMatch,
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
}

fn test_database(name: &str) -> (TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name)).unwrap();
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

fn form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

fn browse_uri(path: &Path) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("path", path.to_str().unwrap());
    format!("/browse?{}", serializer.finish())
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

#[tokio::test]
async fn stale_browser_forms_cannot_overwrite_a_newer_record() {
    let (_temporary, database) = test_database("stale-browser-form");
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
    let token = csrf(page.text()).to_owned();
    let version = expected_record_hash(page.text()).to_owned();

    database
        .update(
            "items",
            "one",
            &[Assignment::from_str("stage=won").unwrap()],
            Some("Newer notes"),
        )
        .unwrap();
    let stale = request(
        &app,
        Method::POST,
        "/items/records/one",
        Some(form(&[
            ("_csrf", &token),
            ("_expected_record_hash", &version),
            ("front_matter", "stage: lost\n"),
            ("markdown", "Old notes"),
        ])),
        &[],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert!(
        stale
            .text()
            .contains("record items/one changed since the expected version")
    );
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
}

#[tokio::test]
async fn automatic_and_saved_views_render_safe_filterable_paginated_tables() {
    let (_temporary, database) = test_database("views-render");
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=\"<script>alert('x')</script>\"").unwrap(),
                Assignment::from_str("status=open").unwrap(),
                Assignment::from_str("value=12000").unwrap(),
            ],
            "Enterprise renewal",
        )
        .unwrap();
    database
        .create(
            "deals",
            "beta",
            &[
                Assignment::from_str("name=Beta expansion").unwrap(),
                Assignment::from_str("status=won").unwrap(),
                Assignment::from_str("value=8000").unwrap(),
            ],
            "Closed last week",
        )
        .unwrap();
    database
        .create_view(
            "open-deals",
            Some("Open <deals>"),
            "deals",
            vec!["status=open".into()],
            vec!["name".into(), "status".into(), "value".into()],
            1,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let home = request(&app, Method::GET, "/", None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("Database views"));
    assert!(home.text().contains("href=\"/audit\""));
    assert!(home.text().contains("href=\"/deals\""));
    assert!(home.text().contains("href=\"/open-deals\""));
    assert!(home.text().contains("href=\"#main-content\""));
    assert!(home.text().contains("data-design-system=\"cr-workspace\""));
    assert!(home.text().contains("aria-label=\"Workspace navigation\""));
    assert!(home.text().contains("Collections"));
    assert!(home.text().contains("Saved views"));
    assert!(home.text().contains("aria-label=\"Views\""));

    let automatic = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(automatic.status, StatusCode::OK);
    assert!(
        automatic
            .text()
            .contains(r#"<link rel="stylesheet" href="/static/tailwind-"#)
    );
    assert!(automatic.text().contains("alpha"));
    assert!(automatic.text().contains("beta"));
    assert!(automatic.text().contains("href=\"/deals/records/alpha\""));
    assert!(automatic.text().contains("data-filter-builder=\"true\""));
    assert!(automatic.text().contains("data-view-search=\"true\""));
    assert!(automatic.text().contains("aria-label=\"Submit search\""));
    // The magnifier leads the box, drawn rather than typed as a glyph.
    assert!(automatic.text().contains(
        r#"class="absolute inset-y-1 left-1 inline-flex w-7 items-center justify-center rounded-md text-gray-400 hover:bg-gray-100 hover:text-blue-700"><svg aria-hidden="true" focusable="false""#
    ));
    assert!(
        automatic
            .text()
            .contains("h-8 w-full border bg-white pl-9 pr-3")
    );
    assert!(!automatic.text().contains("⌕"));
    assert!(automatic.text().contains("data-filter-disclosure=\"true\""));
    // The applied-condition count states itself on the disclosure's `<summary>`
    // rather than on the `<details>` around it, because the summary is the one
    // element of the filter panel a targeted apply re-renders — see
    // `tests/targeted_swap_http.rs`. An attribute on the `<details>` would be
    // describing a count it could no longer be corrected to.
    assert!(
        automatic
            .text()
            .contains("id=\"cr-view-filter-summary\" data-active-filters=\"0\"")
    );
    assert!(automatic.text().contains("data-filter-panel=\"true\""));
    let search_position = automatic.text().find("data-view-search=\"true\"").unwrap();
    let filter_position = automatic
        .text()
        .find("data-filter-disclosure=\"true\"")
        .unwrap();
    let new_record_position = automatic.text().find("href=\"/deals/new\"").unwrap();
    assert!(search_position < filter_position && filter_position < new_record_position);
    assert!(automatic.text().contains("+ Add filter"));
    // Each condition reads as a sentence, led by "Where" and joined by "and"
    // or "or"; the stylesheet shows the one word that fits.
    assert!(
        automatic
            .text()
            .contains(r#"<span class="cr-filter-join"><span class="cr-filter-join-where">Where</span><span class="cr-filter-join-all">and</span><span class="cr-filter-join-any">or</span></span>"#)
    );
    assert!(
        automatic
            .text()
            .contains(r#"name="filter_match" value="all" checked"#)
    );
    assert!(
        automatic
            .text()
            .contains(r#"name="filter_match" value="any">"#)
    );
    assert!(automatic.text().contains("aria-label=\"Sort by\""));
    assert!(automatic.text().contains("aria-label=\"Sort direction\""));
    assert!(automatic.text().contains("aria-label=\"Visible columns\""));
    assert!(automatic.text().contains("cr-sidebar-link is-active"));
    assert!(
        automatic
            .text()
            .contains("name=\"columns\" value=\"custom\"")
    );
    // The name is the first column, so like the ID it is not a choice here.
    assert!(!automatic.text().contains("name=\"column\" value=\"name\""));
    assert!(
        automatic
            .text()
            .contains("name=\"column\" value=\"status\" checked")
    );
    assert!(automatic.text().contains("Missing values stay last"));
    assert!(automatic.text().contains("Sort by Value ascending"));
    // A row lays out by the panel's width, not the window's, so the remove
    // control has its own column and cannot overlap the value.
    assert!(automatic.text().contains(r#"class="cr-filter-row""#));
    assert!(automatic.text().contains(
        r#"aria-label="Remove filter 1" title="Remove filter" class="cr-filter-remove""#
    ));
    assert!(automatic.text().contains(r#">Reset</a>"#));
    assert!(automatic.text().contains(r#">Apply</button>"#));
    assert!(
        automatic
            .text()
            .contains("&lt;script&gt;alert('x')&lt;/script&gt;")
    );
    assert!(!automatic.text().contains("<script>alert('x')</script>"));
    assert!(!automatic.text().to_lowercase().contains("react"));
    assert_eq!(automatic.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(automatic.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert!(automatic.text().contains("Save as view"));
    assert!(automatic.text().contains("Save current view"));
    assert!(automatic.text().contains("aria-label=\"Layout\""));
    assert!(automatic.text().contains("aria-label=\"Group Kanban by\""));
    assert!(automatic.text().contains("data-view-layout=\"true\""));

    let preset_source = request(
        &app,
        Method::GET,
        "/deals?filter_match=any&filter_field=status&filter_operator=eq&filter_value=won&filter_field=value&filter_operator=gte&filter_value=12000&sort_field=value&sort_direction=desc",
        None,
        &[],
    )
    .await;
    assert_eq!(preset_source.status, StatusCode::OK);
    let preset_token = csrf(preset_source.text()).to_owned();
    let preset_form = form(&[
        ("_csrf", &preset_token),
        ("name", "sales-focus"),
        ("title", "Sales focus"),
        ("filter_match", "any"),
        ("filter_field", "status"),
        ("filter_operator", "eq"),
        ("filter_value", "won"),
        ("filter_field", "value"),
        ("filter_operator", "gte"),
        ("filter_value", "12000"),
        ("sort_field", "value"),
        ("sort_direction", "desc"),
        ("column", "name"),
        ("column", "value"),
    ]);
    let preset_saved = request(
        &app,
        Method::POST,
        "/deals/save-view",
        Some(preset_form.clone()),
        &[],
    )
    .await;
    assert_eq!(preset_saved.status, StatusCode::SEE_OTHER);
    assert_eq!(
        preset_saved.headers[header::LOCATION],
        "/sales-focus?notice=View+saved"
    );
    let preset = database.view("sales-focus").unwrap();
    assert_eq!(preset.filter_groups.len(), 1);
    assert_eq!(preset.filter_groups[0].match_mode, ViewPredicateMatch::Any);
    assert_eq!(
        preset.filter_groups[0].expressions,
        ["status=won", "value>=12000"]
    );
    assert_eq!(preset.sort_by.as_deref(), Some("value"));
    assert_eq!(preset.sort_direction, cr::SortDirection::Desc);
    assert_eq!(preset.columns, ["name", "value"]);

    let browser_pipeline = request(
        &app,
        Method::POST,
        "/deals/save-view",
        Some(form(&[
            ("_csrf", &preset_token),
            ("name", "browser-pipeline"),
            ("title", "Browser pipeline"),
            ("filter_match", "all"),
            ("sort_direction", "asc"),
            ("column", "name"),
            ("column", "status"),
            ("column", "value"),
            ("layout", "kanban"),
            ("group_by", "status"),
        ])),
        &[],
    )
    .await;
    assert_eq!(browser_pipeline.status, StatusCode::SEE_OTHER);
    let browser_pipeline_definition = database.view("browser-pipeline").unwrap();
    assert_eq!(browser_pipeline_definition.layout, ViewLayout::Kanban);
    assert_eq!(
        browser_pipeline_definition.group_by.as_deref(),
        Some("status")
    );
    assert_eq!(
        browser_pipeline_definition.columns,
        ["name", "status", "value"]
    );
    let browser_pipeline_page = request(&app, Method::GET, "/browser-pipeline", None, &[]).await;
    assert_eq!(browser_pipeline_page.status, StatusCode::OK);
    assert!(browser_pipeline_page.text().contains("Grouped by"));
    assert!(
        browser_pipeline_page
            .text()
            .contains("data-kanban-board=\"true\"")
    );

    let missing_group = request(
        &app,
        Method::POST,
        "/deals/save-view",
        Some(form(&[
            ("_csrf", &preset_token),
            ("name", "invalid-browser-pipeline"),
            ("filter_match", "all"),
            ("sort_direction", "asc"),
            ("layout", "kanban"),
        ])),
        &[],
    )
    .await;
    assert_eq!(missing_group.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        missing_group
            .text()
            .contains("Kanban layout must provide group_by")
    );

    let preset_page = request(&app, Method::GET, "/sales-focus", None, &[]).await;
    assert_eq!(preset_page.status, StatusCode::OK);
    assert!(preset_page.text().contains("Any: "));
    assert!(preset_page.text().contains("status=won"));
    assert!(preset_page.text().contains("value&gt;=12000"));
    assert!(
        preset_page
            .text()
            .find("/sales-focus/records/alpha")
            .unwrap()
            < preset_page
                .text()
                .find("/sales-focus/records/beta")
                .unwrap()
    );

    let duplicate = request(
        &app,
        Method::POST,
        "/deals/save-view",
        Some(preset_form),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let cleared_sort = request(
        &app,
        Method::POST,
        "/open-deals/save-view",
        Some(form(&[
            ("_csrf", &preset_token),
            ("name", "open-deals-unsorted"),
            ("filter_match", "all"),
            ("sort_field", ""),
            ("sort_direction", "desc"),
        ])),
        &[],
    )
    .await;
    assert_eq!(cleared_sort.status, StatusCode::SEE_OTHER);
    let unsorted = database.view("open-deals-unsorted").unwrap();
    assert_eq!(unsorted.filters, ["status=open"]);
    assert_eq!(unsorted.sort_by, None);
    assert_eq!(unsorted.sort_direction, cr::SortDirection::Asc);

    let invalid_csrf = request(
        &app,
        Method::POST,
        "/deals/save-view",
        Some(form(&[
            ("_csrf", "wrong"),
            ("name", "unsafe-view"),
            ("filter_match", "all"),
            ("sort_direction", "asc"),
        ])),
        &[],
    )
    .await;
    assert_eq!(invalid_csrf.status, StatusCode::FORBIDDEN);
    assert!(database.view("unsafe-view").is_err());

    let sorted = request(
        &app,
        Method::GET,
        "/deals?sort_field=value&sort_direction=asc",
        None,
        &[],
    )
    .await;
    assert_eq!(sorted.status, StatusCode::OK);
    assert!(sorted.text().contains("value=\"value\" selected"));
    assert!(
        sorted
            .text()
            .contains("name=\"sort_direction\" value=\"asc\" checked")
    );
    assert!(sorted.text().contains("aria-sort=\"ascending\""));
    assert!(sorted.text().contains("Sort by Value descending"));
    assert!(
        sorted.text().find("/deals/records/beta").unwrap()
            < sorted.text().find("/deals/records/alpha").unwrap()
    );

    let sorted_page = request(
        &app,
        Method::GET,
        "/deals?sort_field=value&sort_direction=asc&limit=1",
        None,
        &[],
    )
    .await;
    assert!(sorted_page.text().contains("/deals/records/beta"));
    assert!(!sorted_page.text().contains("/deals/records/alpha"));
    assert!(
        sorted_page
            .text()
            .contains("sort_field=value&amp;sort_direction=asc&amp;limit=1&amp;after=beta")
    );

    let invalid_sort = request(
        &app,
        Method::GET,
        "/deals?sort_field=contact..country",
        None,
        &[],
    )
    .await;
    assert_eq!(invalid_sort.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(invalid_sort.text().contains("contains an empty segment"));

    let projected = request(
        &app,
        Method::GET,
        "/deals?columns=custom&column=name&column=value&limit=1",
        None,
        &[],
    )
    .await;
    assert_eq!(projected.status, StatusCode::OK);
    // The name is the first column rather than one of the chosen fields.
    assert!(projected.text().contains("1 shown"));
    assert!(projected.text().contains("Sort by Name ascending"));
    assert!(projected.text().contains("Sort by Value ascending"));
    assert!(!projected.text().contains("Sort by Status ascending"));
    assert!(projected.text().contains(
        "sort_field=name&amp;sort_direction=asc&amp;columns=custom&amp;column=name&amp;column=value"
    ));
    assert!(
        projected
            .text()
            .contains("columns=custom&amp;column=name&amp;column=value&amp;limit=1&amp;after=beta")
    );

    let empty_projection = request(&app, Method::GET, "/deals?columns=custom", None, &[]).await;
    assert_eq!(empty_projection.status, StatusCode::BAD_REQUEST);
    assert!(
        empty_projection
            .text()
            .contains("select at least one visible column")
    );

    let unknown_projection = request(
        &app,
        Method::GET,
        "/deals?columns=custom&column=unknown",
        None,
        &[],
    )
    .await;
    assert_eq!(unknown_projection.status, StatusCode::BAD_REQUEST);
    assert!(
        unknown_projection
            .text()
            .contains("column 'unknown' is not available")
    );

    let duplicate_projection = request(
        &app,
        Method::GET,
        "/deals?columns=custom&column=name&column=name",
        None,
        &[],
    )
    .await;
    assert_eq!(duplicate_projection.status, StatusCode::BAD_REQUEST);
    assert!(
        duplicate_projection
            .text()
            .contains("cannot be selected more than once")
    );

    let saved = request(&app, Method::GET, "/open-deals", None, &[]).await;
    assert_eq!(saved.status, StatusCode::OK);
    assert!(saved.text().contains("Open &lt;deals&gt;"));
    assert!(saved.text().contains("alpha"));
    assert!(!saved.text().contains("beta"));
    assert!(saved.text().contains("status=open"));

    let exact = request(
        &app,
        Method::GET,
        "/deals?filter_field=value&filter_value=8000",
        None,
        &[],
    )
    .await;
    assert_eq!(exact.status, StatusCode::OK);
    assert!(exact.text().contains("beta"));
    assert!(!exact.text().contains("alpha"));

    let combined = request(
        &app,
        Method::GET,
        "/deals?filter_field=status&filter_value=open&filter_field=value&filter_value=12000",
        None,
        &[],
    )
    .await;
    assert_eq!(combined.status, StatusCode::OK);
    assert!(combined.text().contains("alpha"));
    assert!(!combined.text().contains("beta"));
    assert_eq!(
        combined.text().matches("data-filter-row=\"true\"").count(),
        3
    );

    let greater_than = request(
        &app,
        Method::GET,
        "/deals?filter_field=value&filter_operator=gt&filter_value=10000",
        None,
        &[],
    )
    .await;
    assert_eq!(greater_than.status, StatusCode::OK);
    assert!(
        greater_than
            .text()
            .contains("id=\"cr-view-filter-summary\" data-active-filters=\"1\"")
    );
    assert!(greater_than.text().contains("value=\"gt\" selected"));
    assert!(greater_than.text().contains("alpha"));
    assert!(!greater_than.text().contains("beta"));

    let contains = request(
        &app,
        Method::GET,
        "/deals?filter_field=name&filter_operator=contains&filter_value=Beta",
        None,
        &[],
    )
    .await;
    assert_eq!(contains.status, StatusCode::OK);
    assert!(contains.text().contains("beta"));
    assert!(!contains.text().contains("href=\"/deals/records/alpha\""));

    let empty = request(
        &app,
        Method::GET,
        "/deals?filter_field=owner&filter_operator=is-empty&filter_value=",
        None,
        &[],
    )
    .await;
    assert_eq!(empty.status, StatusCode::OK);
    // "Owner is empty" needs no value, so the slot holds only the empty one
    // the form submits.
    assert!(empty.text().contains(
        r#"class="cr-filter-value"><input type="hidden" name="filter_value" data-filter-value="true" value=""></div>"#
    ));
    assert!(empty.text().contains("alpha"));
    assert!(empty.text().contains("beta"));

    let any = request(
        &app,
        Method::GET,
        "/deals?filter_match=any&filter_field=status&filter_operator=eq&filter_value=open&filter_field=value&filter_operator=gte&filter_value=8000",
        None,
        &[],
    )
    .await;
    assert_eq!(any.status, StatusCode::OK);
    assert!(any.text().contains("value=\"any\" checked"));
    assert!(any.text().contains("alpha"));
    assert!(any.text().contains("beta"));

    let saved_any = request(
        &app,
        Method::GET,
        "/open-deals?filter_match=any&filter_field=status&filter_value=won&filter_field=value&filter_value=12000",
        None,
        &[],
    )
    .await;
    assert_eq!(saved_any.status, StatusCode::OK);
    assert!(saved_any.text().contains("alpha"));
    assert!(!saved_any.text().contains("beta"));

    let any_first_page = request(
        &app,
        Method::GET,
        "/deals?filter_match=any&filter_field=status&filter_value=open&filter_field=value&filter_value=8000&limit=1",
        None,
        &[],
    )
    .await;
    assert!(
        any_first_page
            .text()
            .contains("filter_match=any&amp;filter_field=status")
    );
    assert!(any_first_page.text().contains("limit=1&amp;after=beta"));

    let invalid_match = request(&app, Method::GET, "/deals?filter_match=neither", None, &[]).await;
    assert_eq!(invalid_match.status, StatusCode::BAD_REQUEST);

    let searched = request(&app, Method::GET, "/deals?q=ENTERPRISE", None, &[]).await;
    assert_eq!(searched.status, StatusCode::OK);
    assert!(searched.text().contains("alpha"));
    assert!(!searched.text().contains("beta"));
    let browser_search = request(
        &app,
        Method::GET,
        "/deals?q=ENTERPRISE&filter_field=&filter_value=",
        None,
        &[],
    )
    .await;
    assert_eq!(browser_search.status, StatusCode::OK);
    assert!(browser_search.text().contains("alpha"));

    // Tables open newest first, and each page names the record the next one
    // continues after instead of an offset that a new record would shift.
    let first_page = request(&app, Method::GET, "/deals?limit=1", None, &[]).await;
    assert!(first_page.text().contains("/deals/records/beta"));
    assert!(!first_page.text().contains("/deals/records/alpha"));
    assert!(first_page.text().contains("limit=1&amp;after=beta"));
    let second_page = request(&app, Method::GET, "/deals?limit=1&after=beta", None, &[]).await;
    assert!(second_page.text().contains("/deals/records/alpha"));
    assert!(!second_page.text().contains("/deals/records/beta"));
    assert!(second_page.text().contains("limit=1&amp;before=alpha"));
    assert!(second_page.text().contains("Showing 2\u{2013}2 of 2"));
    // Links shared before cursors existed still resolve.
    let offset_page = request(&app, Method::GET, "/deals?limit=1&offset=1", None, &[]).await;
    assert!(offset_page.text().contains("/deals/records/alpha"));
    // A cursor naming a record that no longer matches starts over rather than
    // stranding the reader on an empty page.
    let stale = request(&app, Method::GET, "/deals?limit=1&after=removed", None, &[]).await;
    assert!(stale.text().contains("/deals/records/beta"));
}

#[tokio::test]
async fn kanban_views_render_schema_ordered_lanes_and_move_cards_through_audited_updates() {
    let (_temporary, database) = test_database("kanban-views");
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "x-cr-ui": { "order": ["name", "stage", "owner", "score"] },
  "required": ["name"],
  "properties": {
    "name": { "type": "string" },
    "stage": { "enum": ["qualification", "interview", "offer", "won", "lost"] },
    "owner": { "type": "string" },
    "score": { "type": "integer" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=\"<script>alert('x')</script>\"").unwrap(),
                Assignment::from_str("stage=qualification").unwrap(),
                Assignment::from_str("owner=Ana").unwrap(),
                Assignment::from_str("score=42").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "beta",
            &[
                Assignment::from_str("name=Beta").unwrap(),
                Assignment::from_str("stage=offer").unwrap(),
                Assignment::from_str("score=80").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "unassigned",
            &[
                Assignment::from_str("name=Unassigned").unwrap(),
                Assignment::from_str("score=50").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "excluded",
            &[
                Assignment::from_str("name=Excluded").unwrap(),
                Assignment::from_str("stage=offer").unwrap(),
                Assignment::from_str("score=20").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "gamma",
            &[
                Assignment::from_str("name=Gamma").unwrap(),
                Assignment::from_str("stage=offer").unwrap(),
                Assignment::from_str("score=60").unwrap(),
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
            vec!["score>=40".into()],
            vec![],
            vec!["name".into(), "owner".into(), "stage".into()],
            50,
            ViewLayout::Kanban,
            Some("stage".into()),
            Some("score".into()),
            cr::SortDirection::Asc,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let board = request(&app, Method::GET, "/pipeline", None, &[]).await;
    assert_eq!(board.status, StatusCode::OK);
    assert!(board.text().contains("Grouped by"));
    assert!(board.text().contains("data-kanban-board=\"true\""));
    // A board's lanes already split it by state, so it has no quick filters.
    assert!(!board.text().contains("data-quick-filter"));
    assert!(board.text().contains("draggable=\"true\""));
    // The drag-and-drop enhancement moved to the embedded asset the page
    // links; `tests/static_assets_http.rs` asserts the script it serves.
    assert!(board.text().contains("<script src=\"/static/cr-"));
    assert!(!board.text().contains("form.submit()"));
    assert!(board.text().contains("Move alpha to"));
    assert!(board.text().contains("score&gt;=40"));
    assert!(!board.text().contains("/pipeline/records/excluded"));
    assert!(board.text().contains("value=\"score\" selected"));
    assert!(
        board
            .text()
            .contains("name=\"sort_direction\" value=\"asc\" checked")
    );
    assert!(board.text().contains("Unassigned"));
    assert!(
        board
            .text()
            .contains("&lt;script&gt;alert('x')&lt;/script&gt;")
    );
    assert!(!board.text().contains("<script>alert('x')</script>"));
    // Lanes are named as the form names the options: readably.
    let qualification = board.text().find(">Qualification<").unwrap();
    let interview = board.text().find(">Interview<").unwrap();
    let offer = board.text().find(">Offer<").unwrap();
    let won = board.text().find(">Won<").unwrap();
    let lost = board.text().find(">Lost<").unwrap();
    assert!(qualification < interview && interview < offer && offer < won && won < lost);
    assert!(
        board.text().find("/pipeline/records/gamma").unwrap()
            < board.text().find("/pipeline/records/beta").unwrap()
    );

    let inherited_board = request(
        &app,
        Method::POST,
        "/pipeline/save-view",
        Some(form(&[
            ("_csrf", csrf(board.text())),
            ("name", "pipeline-copy"),
            ("filter_match", "all"),
            ("sort_direction", "asc"),
        ])),
        &[],
    )
    .await;
    assert_eq!(inherited_board.status, StatusCode::SEE_OTHER);
    let inherited_definition = database.view("pipeline-copy").unwrap();
    assert_eq!(inherited_definition.layout, ViewLayout::Kanban);
    assert_eq!(inherited_definition.group_by.as_deref(), Some("stage"));

    let projected_board = request(
        &app,
        Method::GET,
        "/pipeline?columns=custom&column=name",
        None,
        &[],
    )
    .await;
    assert_eq!(projected_board.status, StatusCode::OK);
    assert!(projected_board.text().contains("0 shown"));
    // The name is each card's heading, so it is not repeated as a detail.
    assert!(!projected_board.text().contains(">Name</dt>"));
    assert!(
        projected_board
            .text()
            .contains(r#"class="cr-card-title">Beta</a>"#)
    );
    assert!(!projected_board.text().contains(">Owner</dt>"));
    assert!(!projected_board.text().contains(">Score</dt>"));

    let typed_filter = request(
        &app,
        Method::GET,
        "/pipeline?filter_field=stage&filter_value=offer",
        None,
        &[],
    )
    .await;
    assert_eq!(typed_filter.status, StatusCode::OK);
    assert!(typed_filter.text().contains("value=\"stage\" selected"));
    assert!(
        typed_filter
            .text()
            .contains("name=\"filter_value\" data-filter-value=\"true\"")
    );
    assert!(
        typed_filter
            .text()
            .contains("value=\"offer\" selected>Offer</option>")
    );
    assert!(typed_filter.text().contains("beta"));
    assert!(!typed_filter.text().contains("alpha"));

    let numeric_filter = request(
        &app,
        Method::GET,
        "/pipeline?filter_field=score&filter_operator=gte&filter_value=80",
        None,
        &[],
    )
    .await;
    assert_eq!(numeric_filter.status, StatusCode::OK);
    assert!(numeric_filter.text().contains("value=\"gte\" selected"));
    assert!(numeric_filter.text().contains("type=\"number\" step=\"1\""));
    assert!(numeric_filter.text().contains("beta"));
    assert!(!numeric_filter.text().contains("alpha"));

    let sorted_lane = request(
        &app,
        Method::GET,
        "/pipeline?sort_field=score&sort_direction=desc",
        None,
        &[],
    )
    .await;
    assert_eq!(sorted_lane.status, StatusCode::OK);
    assert!(
        sorted_lane.text().find("/pipeline/records/beta").unwrap()
            < sorted_lane.text().find("/pipeline/records/gamma").unwrap()
    );

    let cleared_sort = request(&app, Method::GET, "/pipeline?sort_field=", None, &[]).await;
    assert_eq!(cleared_sort.status, StatusCode::OK);
    assert!(cleared_sort.text().contains("value=\"\" selected"));

    let token = csrf(board.text()).to_owned();
    let target = r#"{"kind":"value","value":"interview"}"#;
    let moved = request(
        &app,
        Method::POST,
        "/pipeline/records/alpha/move",
        Some(form(&[("_csrf", &token), ("target", target)])),
        &[("x-cr-actor", "pipeline@example.com")],
    )
    .await;
    assert_eq!(moved.status, StatusCode::SEE_OTHER);
    assert_eq!(
        moved.headers[header::LOCATION],
        "/pipeline?notice=Card+moved"
    );
    assert_eq!(
        database.get("deals", "alpha").unwrap().attributes["stage"],
        "interview"
    );
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "alpha"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Update);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "pipeline@example.com");

    let moved_board = request(&app, Method::GET, "/pipeline?notice=Card+moved", None, &[]).await;
    assert_eq!(moved_board.status, StatusCode::OK);
    assert!(moved_board.text().contains("Card moved"));
    let record_page = request(&app, Method::GET, "/pipeline/records/alpha", None, &[]).await;
    assert!(record_page.text().contains("/attributes/stage"));
    assert!(record_page.text().contains("qualification"));
    assert!(record_page.text().contains("interview"));

    let unset_target = r#"{"kind":"unset"}"#;
    let unassigned = request(
        &app,
        Method::POST,
        "/pipeline/records/beta/move",
        Some(form(&[("_csrf", &token), ("target", unset_target)])),
        &[("x-cr-actor", "pipeline@example.com")],
    )
    .await;
    assert_eq!(unassigned.status, StatusCode::SEE_OTHER);
    assert!(
        database
            .get("deals", "beta")
            .unwrap()
            .field("stage")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        database
            .audit_recent(1, AuditFilter::record("deals", "beta"))
            .unwrap()[0]
            .payload
            .action,
        AuditAction::Update
    );

    let invalid_target = r#"{"kind":"value","value":"not-a-stage"}"#;
    let invalid = request(
        &app,
        Method::POST,
        "/pipeline/records/alpha/move",
        Some(form(&[("_csrf", &token), ("target", invalid_target)])),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        database.get("deals", "alpha").unwrap().attributes["stage"],
        "interview"
    );

    let bad_csrf = request(
        &app,
        Method::POST,
        "/pipeline/records/alpha/move",
        Some(form(&[("_csrf", "wrong"), ("target", target)])),
        &[],
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::FORBIDDEN);

    let table_move = request(
        &app,
        Method::POST,
        "/deals/records/alpha/move",
        Some(form(&[("_csrf", &token), ("target", target)])),
        &[],
    )
    .await;
    assert_eq!(table_move.status, StatusCode::UNPROCESSABLE_ENTITY);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn kanban_cards_show_their_values_as_chips_without_labels_or_blanks() {
    let (_temporary, database) = test_database("views-kanban-cards");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": {
             "status": { "enum": ["queued", "done"] },
             "kind": { "enum": ["scheduled", "triggered"] },
             "owner": { "type": "string", "title": "Assignee" } } }"#,
    )
    .unwrap();
    let long = "triggered-inbound-rating-on-create-quiet-anik-majumdar-member-of-technical-staff-intern-4de0aaa0bd9f-3de67c9eb27d08b42c6feb79";
    database
        .create(
            "tasks",
            long,
            &[
                Assignment::from_str("title=Rate an applicant").unwrap(),
                Assignment::from_str("status=queued").unwrap(),
                Assignment::from_str("kind=triggered").unwrap(),
                Assignment::from_str("owner=anand").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "tasks",
            "untitled",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    database
        .create_view_with_layout(
            "board",
            Some("Board"),
            "tasks",
            vec![],
            vec!["kind".into(), "owner".into()],
            25,
            ViewLayout::Kanban,
            Some("status".into()),
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let board = request(&app, Method::GET, "/board", None, &[]).await;
    assert_eq!(board.status, StatusCode::OK);
    // The title, then the ID in one line, shortened in the middle.
    let (head, tail) = long.split_at(long.len() - 10);
    assert!(board.text().contains(&format!(
        r#"class="cr-card-title">Rate an applicant</a><p class="cr-card-id" title="{long}"><span class="truncate">{head}</span><span class="shrink-0">{tail}</span></p>"#
    )));
    // Values without labels: a state is its badge, anything else a chip, and
    // each says what it is to a screen reader and in its tooltip.
    assert!(board.text().contains(
        r#"<div class="cr-card-props"><span class="cr-card-prop-badge" title="Kind: Triggered"><span class="sr-only">Kind: </span><span class="cr-pill">Triggered</span></span><span class="cr-card-prop" title="Assignee: anand"><span class="sr-only">Assignee: </span>anand</span></div>"#
    ));
    assert!(!board.text().contains("<dt"));
    // A card without a title leads with its ID; one without values has no row
    // of empty ones.
    assert!(board.text().contains(r#"<a href="/board/records/untitled" class="cr-card-title cr-card-title-id"><span class="truncate">untitled</span></a>"#));
    let untitled = &board.text()[board.text().find("/board/records/untitled").unwrap()..];
    let untitled = &untitled[..untitled.find("</article>").unwrap()];
    assert!(!untitled.contains("cr-card-props"));
    assert!(!untitled.contains("—"));
    // The move control is there for the keyboard and touch, and quiet for a
    // pointer until the card is pointed at.
    assert!(
        board
            .text()
            .contains(r#"<details class="cr-kanban-move"><summary>Move…</summary>"#)
    );
    assert!(board.text().contains(".cr-kanban-card:not(:hover):not(:focus-within) .cr-kanban-move:not([open]) summary { opacity: 0; }"));
}

#[tokio::test]
async fn kanban_cards_show_the_values_that_tell_cards_apart_by_default() {
    let (_temporary, database) = test_database("views-kanban-defaults");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": {
             "status": { "enum": ["queued", "done"] },
             "kind": { "enum": ["scheduled", "triggered"] },
             "never_set": { "type": "string" } } }"#,
    )
    .unwrap();
    let tasks = [
        ("a", "queued", "triggered", "anik", "p1"),
        ("b", "queued", "scheduled", "khoi", "p2"),
        ("c", "done", "triggered", "priya", "p1"),
    ];
    for (id, status, kind, person, priority) in tasks {
        database
            .create(
                "tasks",
                id,
                &[
                    Assignment::from_str(&format!("title=Rate {person}")).unwrap(),
                    Assignment::from_str(&format!("status={status}")).unwrap(),
                    Assignment::from_str(&format!("kind={kind}")).unwrap(),
                    Assignment::from_str("asked_by=anand").unwrap(),
                    Assignment::from_str("attempts=0").unwrap(),
                    Assignment::from_str(&format!("person={person}")).unwrap(),
                    Assignment::from_str(
                        "prompt=\"Rate the inbound applicant against the rubric and draft a note.\"",
                    )
                    .unwrap(),
                    Assignment::from_str("claim.pid=1").unwrap(),
                    Assignment::from_str(&format!("priority={priority}")).unwrap(),
                    Assignment::from_str("region=eu").unwrap(),
                    Assignment::from_str(&format!("owner={person}-owner")).unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    database
        .create_view_with_layout(
            "board",
            Some("Board"),
            "tasks",
            vec![],
            vec![],
            25,
            ViewLayout::Kanban,
            Some("status".into()),
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let board = request(&app, Method::GET, "/board", None, &[]).await;
    assert_eq!(board.status, StatusCode::OK);
    let shown = |label: &str| board.text().contains(&format!(r#"title="{label}: "#));
    // The values that differ from card to card, four at most, in column order.
    for label in ["Kind", "Person", "Priority", "Owner"] {
        assert!(shown(label), "{label} is on the cards");
    }
    // Not the lane's own field, the same value everywhere, prose, an object,
    // a field nothing sets, or a fifth.
    for label in [
        "Status",
        "Asked By",
        "Attempts",
        "Region",
        "Prompt",
        "Claim",
        "Never Set",
    ] {
        assert!(!shown(label), "{label} is not on the cards");
    }
    assert!(board.text().contains("4 shown"));
    // Each card says when its record was made.
    let card = &board.text()[board.text().find("/board/records/a\"").unwrap()..];
    let card = &card[..card.find("</article>").unwrap()];
    assert!(card.contains(r#"<div class="cr-card-foot"><time datetime=""#));
    // A view that names its columns gets all of them.
    let chosen = request(
        &app,
        Method::GET,
        "/board?columns=custom&column=asked_by&column=attempts&column=region&column=prompt&column=kind",
        None,
        &[],
    )
    .await;
    for label in ["Asked By", "Attempts", "Region", "Prompt", "Kind"] {
        assert!(
            chosen.text().contains(&format!(r#"title="{label}: "#)),
            "{label} was chosen"
        );
    }
}

#[tokio::test]
async fn kanban_lanes_count_their_whole_lane_and_offer_more_of_it() {
    let (_temporary, database) = test_database("views-kanban-lanes");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": { "status": { "enum": ["queued", "done", "failed"] } } }"#,
    )
    .unwrap();
    // Five done, two queued, none failed, and one without a status.
    for (index, status) in ["done", "done", "queued", "done", "done", "queued", "done"]
        .into_iter()
        .enumerate()
    {
        database
            .create(
                "tasks",
                &format!("task-{index}"),
                &[Assignment::from_str(&format!("status={status}")).unwrap()],
                "",
            )
            .unwrap();
    }
    database.create("tasks", "loose", &[], "").unwrap();
    database
        .create_view_with_layout(
            "board",
            Some("Board"),
            "tasks",
            vec![],
            vec![],
            2,
            ViewLayout::Kanban,
            Some("status".into()),
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let board = request(&app, Method::GET, "/board", None, &[]).await;
    assert_eq!(board.status, StatusCode::OK);
    let lane = |label: &str| {
        let at = board.text().find(&format!("<h2>{label}</h2>")).unwrap();
        let rest = &board.text()[at..];
        rest[..rest.find("</section>").unwrap()].to_owned()
    };
    // Each lane counts every record it holds and shows up to the page size of
    // its own, rather than whatever share of one page fell into it.
    let done = lane("Done");
    assert!(done.contains(r#"<span class="cr-lane-count">5</span>"#));
    assert_eq!(done.matches("<article").count(), 2);
    let queued = lane("Queued");
    assert!(queued.contains(r#"<span class="cr-lane-count">2</span>"#));
    assert_eq!(queued.matches("<article").count(), 2);
    assert!(!queued.contains("cr-lane-more"));
    assert!(lane("Failed").contains(r#"<span class="cr-lane-count">0</span>"#));
    assert!(lane("Unassigned").contains(r#"<span class="cr-lane-count">1</span>"#));
    // More of every lane is one swap away.
    assert!(done.contains(
        r#"<a id="cr-lane-more-1" href="/board?filter_match=all&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=4" class="cr-lane-more""#
    ));
    assert!(done.contains(">Show 2 more</a>"));
    assert!(
        board.text().contains(
            r#"data-board-summary="true">Showing 5 of 8 records, up to 2 in each lane</p>"#
        )
    );
    // A board has no pager; its lanes are what page.
    assert!(!board.text().contains(r#"id="cr-page-next""#));
    let more = request(&app, Method::GET, "/board?limit=4", None, &[]).await;
    assert_eq!(more.text().matches("<article").count(), 7);
    // Past the most the server sends, a lane says how to reach the rest.
    let bounded = router(
        database.clone(),
        ServerConfig {
            max_page_size: 2,
            ..ServerConfig::default()
        },
    )
    .unwrap();
    let capped = request(&bounded, Method::GET, "/board", None, &[]).await;
    assert!(capped.text().contains(
        r#"<p class="cr-lane-more">3 more not shown; filter the board to reach them</p>"#
    ));

    // The lane's dot takes its state's colour.
    assert!(done.starts_with("<h2>Done</h2>"));
    assert!(board.text().contains(
        r#"<span class="cr-lane-dot cr-pill-positive" aria-hidden="true"></span><h2>Done</h2>"#
    ));
    assert!(board.text().contains(
        r#"<span class="cr-lane-dot cr-pill-negative" aria-hidden="true"></span><h2>Failed</h2>"#
    ));
    assert!(
        board
            .text()
            .contains(r#"<span class="cr-lane-dot" aria-hidden="true"></span><h2>Unassigned</h2>"#)
    );
}

#[tokio::test]
async fn a_kanban_board_fits_the_window_with_lanes_that_scroll_on_their_own() {
    let (_temporary, database) = test_database("views-kanban-layout");
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    database
        .create_view_with_layout(
            "board",
            Some("Board"),
            "tasks",
            vec![],
            vec![],
            25,
            ViewLayout::Kanban,
            Some("status".into()),
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let board = request(&app, Method::GET, "/board", None, &[]).await;
    assert_eq!(board.status, StatusCode::OK);
    assert!(board.text().contains(
        r#"<div class="cr-board-scroll"><div data-kanban-board="true" class="cr-board">"#
    ));
    assert!(
        board
            .text()
            .contains(r#"class="cr-kanban-lane"><div class="cr-lane-head">"#)
    );
    let sheet = board.text();
    let rule = |selector: &str| {
        let start = sheet
            .find(&format!("{selector} {{"))
            .unwrap_or_else(|| panic!("no {selector}"));
        &sheet[start..start + sheet[start..].find('}').unwrap()]
    };
    // A lane is no taller than the window leaves room for, and its cards
    // scroll inside it under its heading.
    assert!(rule(".cr-kanban-lane").contains("max-height: max(22rem, calc(100dvh - 10.5rem));"));
    assert!(rule(".cr-lane-cards").contains("overflow-y: auto;"));
    // Each lane's cards fade at its edges while there are more past them, on
    // the lane's own timeline, so a lane that fits shows no fade.
    assert!(rule(".cr-lane-cards").contains("scroll-timeline: --cr-lane-y block;"));
    let lane_fades = rule("  .cr-lane-cards::before,\n  .cr-lane-cards::after");
    assert!(
        lane_fades.contains("position: sticky;")
            && lane_fades.contains("opacity: 0;")
            && lane_fades.contains("flex: 0 0 auto;")
    );
    assert!(
        rule("  .cr-lane-cards::before").contains(
            "animation: cr-more-behind linear both;\n    animation-timeline: --cr-lane-y;"
        )
    );
    let lane_after = &sheet[sheet.rfind("  .cr-lane-cards::after {").unwrap()..];
    assert!(
        lane_after[..lane_after.find('}').unwrap()].contains(
            "animation: cr-more-ahead linear both;\n    animation-timeline: --cr-lane-y;"
        )
    );
    // The board scrolls sideways on its own timeline, and its edges fade only
    // while there is more board past them.
    assert!(rule(".cr-board-scroll").contains("scroll-timeline: --cr-board-x inline;"));
    let shared = rule("  .cr-board::before,\n  .cr-board::after");
    assert!(shared.contains("position: sticky;") && shared.contains("opacity: 0;"));
    assert!(
        rule("  .cr-board::before").contains(
            "animation: cr-more-behind linear both;\n    animation-timeline: --cr-board-x;"
        )
    );
    let after = &sheet[sheet.rfind("  .cr-board::after {").unwrap()..];
    assert!(
        after[..after.find('}').unwrap()].contains(
            "animation: cr-more-ahead linear both;\n    animation-timeline: --cr-board-x;"
        )
    );
    // The lane a dragged card would drop into is outlined, by an attribute the
    // sheet styles rather than a ring utility its lane rule would override.
    assert!(sheet.contains(
        ".cr-kanban-lane[data-drop-target] { outline: 2px solid var(--cr-accent); outline-offset: -1px; }"
    ));
    let script = sheet
        .split(r#"<script src=""#)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/static/cr-"))
        .expect("the page links cr.js");
    let script = request(&app, Method::GET, script, None, &[]).await;
    assert!(script.text().contains("lane.dataset.dropTarget = 'true';"));
    assert!(!script.text().contains("ring-blue-400"));
}

#[tokio::test]
async fn html_forms_create_update_and_delete_through_validated_audited_database_methods() {
    let (_temporary, database) = test_database("views-forms");
    fs::write(
        database.root().join(".cr/schemas/deals.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["status", "value"],
  "properties": {
    "status": { "enum": ["open", "won"] },
    "value": { "type": "number" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    database
        .create_view(
            "open-deals",
            Some("Open deals"),
            "deals",
            vec!["status=open".into()],
            vec!["status".into(), "value".into()],
            50,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let new_page = request(&app, Method::GET, "/open-deals/new", None, &[]).await;
    assert_eq!(new_page.status, StatusCode::OK);
    let token = csrf(new_page.text()).to_owned();
    let created = request(
        &app,
        Method::POST,
        "/open-deals/records",
        Some(form(&[
            ("_csrf", &token),
            ("id", "acme"),
            ("front_matter", "status: open\nvalue: 12500\n"),
            ("markdown", "First contact"),
        ])),
        &[("x-cr-actor", "sales@example.com")],
    )
    .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER);
    assert_eq!(
        created.headers[header::LOCATION],
        "/open-deals?notice=Record+created"
    );
    let record = database.get("deals", "acme").unwrap();
    assert_eq!(
        record.attributes["value"],
        yaml_serde::Value::Number(12500.into())
    );
    assert_eq!(record.body, "First contact");
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Create);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "sales@example.com");

    let edit_page = request(&app, Method::GET, "/open-deals/records/acme", None, &[]).await;
    assert!(edit_page.text().contains("class=\"cr-record-layout\""));
    assert!(
        edit_page
            .text()
            .contains("<h2 id=\"activity-heading\" class=\"cr-aside-heading\">Activity</h2>")
    );
    assert_eq!(edit_page.status, StatusCode::OK);
    assert!(
        edit_page
            .text()
            .contains("name=\"_form_mode\" value=\"structured\"")
    );
    assert!(edit_page.text().contains("name=\"attribute.status\""));
    // Two options are a row of buttons rather than a dropdown.
    assert!(
        edit_page
            .text()
            .contains("type=\"radio\" name=\"attribute.status\" value=\"open\" checked")
    );
    assert!(edit_page.text().contains("name=\"attribute.value\""));
    assert!(edit_page.text().contains("value=\"12500\""));
    assert!(edit_page.text().contains("All activity"));
    assert!(edit_page.text().contains("sales@example.com"));
    assert!(edit_page.text().contains("Created"));
    assert!(
        edit_page
            .text()
            .contains("/audit?collection=deals&amp;id=acme")
    );
    let edit_token = csrf(edit_page.text()).to_owned();
    let edit_version = expected_record_hash(edit_page.text()).to_owned();

    let invalid = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", &edit_token),
            ("_expected_record_hash", &edit_version),
            ("front_matter", "status: lost\nvalue: 12500\n"),
            ("markdown", "Invalid attempt"),
        ])),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(invalid.text().contains("does not match schema"));
    assert_eq!(database.get("deals", "acme").unwrap().body, "First contact");
    assert_eq!(
        database.audit_recent(10, AuditFilter::all()).unwrap().len(),
        1
    );

    let bad_csrf = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", "wrong"),
            ("_expected_record_hash", &edit_version),
            ("front_matter", "status: won\nvalue: 13000\n"),
            ("markdown", "Won"),
        ])),
        &[],
    )
    .await;
    assert_eq!(bad_csrf.status, StatusCode::FORBIDDEN);

    let updated = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", &edit_token),
            ("_expected_record_hash", &edit_version),
            ("front_matter", "status: won\nvalue: 13000\nowner: jane\n"),
            ("markdown", "Closed won"),
        ])),
        &[],
    )
    .await;
    assert_eq!(updated.status, StatusCode::SEE_OTHER);
    let record = database.get("deals", "acme").unwrap();
    assert_eq!(record.attributes["status"], "won");
    assert_eq!(record.body, "Closed won");
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Update);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    let updated_page = request(&app, Method::GET, "/deals/records/acme", None, &[]).await;
    assert_eq!(updated_page.status, StatusCode::OK);
    assert!(updated_page.text().contains("replace"));
    assert!(updated_page.text().contains("/attributes/status"));
    assert!(updated_page.text().contains("Closed won"));
    let filtered = request(&app, Method::GET, "/open-deals", None, &[]).await;
    assert!(!filtered.text().contains("acme"));

    let delete_page = request(&app, Method::GET, "/open-deals/records/acme", None, &[]).await;
    assert!(delete_page.text().contains(
        "href=\"/open-deals/records/acme/delete\" class=\"cr-button cr-button-danger\">Delete record…</a>"
    ));
    let delete_token = csrf(delete_page.text()).to_owned();
    let delete_version = expected_record_hash(delete_page.text()).to_owned();
    let deleted = request(
        &app,
        Method::POST,
        "/open-deals/records/acme/delete",
        Some(form(&[
            ("_csrf", &delete_token),
            ("_expected_record_hash", &delete_version),
        ])),
        &[],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert!(database.get("deals", "acme").is_err());
    let audit = database
        .audit_recent(1, AuditFilter::record("deals", "acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Delete);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn schema_driven_forms_render_typed_controls_and_preserve_typed_values() {
    let (_temporary, database) = test_database("structured-forms");
    fs::write(
        database.root().join(".cr/schemas/candidates.json"),
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "x-cr-ui": { "order": ["name", "email", "stage", "budget", "active", "tags"] },
  "required": ["name", "email", "stage", "budget"],
  "properties": {
    "name": {
      "type": "string",
      "title": "Candidate <name>",
      "description": "Displayed <script>alert('schema')</script> name",
      "minLength": 1
    },
    "email": { "type": "string", "format": "email", "description": "Primary email address" },
    "stage": { "enum": ["applied", "interview", "offer"] },
    "seniority": { "enum": ["junior", "mid", "senior", "staff"] },
    "budget": { "type": "number", "minimum": 0, "maximum": 1000000, "x-cr-unit": "USD" },
    "active": { "type": "boolean" },
    "tags": { "type": "array", "items": { "enum": ["rust", "remote", "referred"] } },
    "profile": { "type": "object" }
  },
  "additionalProperties": true
}"#,
    )
    .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let new_page = request(&app, Method::GET, "/candidates/new", None, &[]).await;
    assert_eq!(new_page.status, StatusCode::OK);
    assert!(
        new_page
            .text()
            .contains("name=\"_form_mode\" value=\"structured\"")
    );
    assert!(new_page.text().contains("Candidate &lt;name&gt;"));
    assert!(
        new_page
            .text()
            .contains("Displayed &lt;script&gt;alert('schema')&lt;/script&gt; name")
    );
    assert!(!new_page.text().contains("<script>alert('schema')</script>"));
    assert!(
        new_page
            .text()
            .contains("type=\"email\" name=\"attribute.email\"")
    );
    assert!(
        new_page
            .text()
            .contains("type=\"number\" step=\"any\" name=\"attribute.budget\"")
    );
    // Three options are a row of buttons; more than three are a dropdown.
    assert!(
        new_page
            .text()
            .contains("type=\"radio\" name=\"attribute.stage\" value=\"applied\" required")
    );
    assert!(
        new_page
            .text()
            .contains("select id=\"field-seniority\" name=\"attribute.seniority\"")
    );
    // A number's unit sits at the edge of its box.
    assert!(
        new_page
            .text()
            .contains("<span class=\"cr-input-unit\" aria-hidden=\"true\">USD</span>")
    );
    assert!(
        new_page
            .text()
            .contains("type=\"checkbox\" name=\"attribute.tags\"")
    );
    // A value with no control of its own is typed YAML, and says so.
    assert!(
        new_page
            .text()
            .contains("<span class=\"cr-field-hint\">YAML</span>")
    );
    // A new record has no "Edit as YAML" switch, so front matter the schema
    // does not declare has its own box.
    assert!(new_page.text().contains("name=\"_additional_attributes\""));
    assert!(new_page.text().contains("Other fields"));
    assert!(
        new_page.text().find("Candidate &lt;name&gt;").unwrap()
            < new_page.text().find("Primary email address").unwrap()
    );

    let token = csrf(new_page.text()).to_owned();
    let created = request(
        &app,
        Method::POST,
        "/candidates/records",
        Some(form(&[
            ("_csrf", &token),
            ("_form_mode", "structured"),
            ("id", "jane-doe"),
            ("attribute.name", "Jane Doe"),
            ("attribute.email", "jane@example.com"),
            ("attribute.stage", "interview"),
            ("attribute.budget", "125000.5"),
            ("attribute.active", "true"),
            ("attribute.tags", "rust"),
            ("attribute.tags", "remote"),
            ("attribute.profile", "team: platform\nlevel: senior"),
            ("_additional_attributes", "source: referral"),
            ("markdown", "# Jane\n\nStrong systems background."),
        ])),
        &[("x-cr-actor", "recruiter@example.com")],
    )
    .await;
    assert_eq!(created.status, StatusCode::SEE_OTHER);
    let record = database.get("candidates", "jane-doe").unwrap();
    assert_eq!(record.attributes["name"], "Jane Doe");
    assert_eq!(record.attributes["email"], "jane@example.com");
    assert_eq!(record.attributes["stage"], "interview");
    assert_eq!(record.attributes["active"], true);
    assert_eq!(record.attributes["tags"][0], "rust");
    assert_eq!(record.attributes["tags"][1], "remote");
    assert_eq!(record.attributes["profile"]["team"], "platform");
    assert_eq!(record.attributes["source"], "referral");
    assert_eq!(record.body, "# Jane\n\nStrong systems background.");
    let audit = database
        .audit_recent(1, AuditFilter::record("candidates", "jane-doe"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Create);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "recruiter@example.com");

    let edit_page = request(&app, Method::GET, "/candidates/records/jane-doe", None, &[]).await;
    assert_eq!(edit_page.status, StatusCode::OK);
    assert!(edit_page.text().contains("value=\"jane@example.com\""));
    assert!(
        edit_page
            .text()
            .contains("name=\"attribute.stage\" value=\"interview\" checked")
    );
    assert!(
        edit_page
            .text()
            .contains("name=\"attribute.tags\" value=\"rust\" checked")
    );
    assert!(edit_page.text().contains("source: referral"));
    let edit_version = expected_record_hash(edit_page.text()).to_owned();

    let invalid = request(
        &app,
        Method::POST,
        "/candidates/records/jane-doe",
        Some(form(&[
            ("_csrf", &token),
            ("_expected_record_hash", &edit_version),
            ("_form_mode", "structured"),
            ("attribute.name", "Jane Doe"),
            ("attribute.email", "jane@example.com"),
            ("attribute.stage", "offer"),
            ("attribute.budget", "-1"),
            ("attribute.active", "false"),
            ("attribute.profile", "{}"),
            ("_additional_attributes", "{}"),
            ("markdown", "Invalid update"),
        ])),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        database.get("candidates", "jane-doe").unwrap().body,
        "# Jane\n\nStrong systems background."
    );
    assert_eq!(
        database
            .audit_recent(10, AuditFilter::record("candidates", "jane-doe"))
            .unwrap()
            .len(),
        1
    );

    let unknown_option = request(
        &app,
        Method::POST,
        "/candidates/records/jane-doe",
        Some(form(&[
            ("_csrf", &token),
            ("_expected_record_hash", &edit_version),
            ("_form_mode", "structured"),
            ("attribute.name", "Jane Doe"),
            ("attribute.email", "jane@example.com"),
            ("attribute.stage", "hacked"),
            ("attribute.budget", "10"),
            ("_additional_attributes", "{}"),
            ("markdown", "Invalid option"),
        ])),
        &[],
    )
    .await;
    assert_eq!(unknown_option.status, StatusCode::BAD_REQUEST);
    database.audit_verify(None).unwrap();
}

#[tokio::test]
async fn global_audit_view_renders_filters_and_paginates_field_changes() {
    let (_temporary, database) = test_database("global-audit-view");
    let attributed = database.clone().with_actor("sales@example.com").unwrap();
    attributed
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=Alpha renewal").unwrap(),
                Assignment::from_str("stage=proposal").unwrap(),
            ],
            "<script>alert('historical')</script>",
        )
        .unwrap();
    attributed
        .update(
            "deals",
            "alpha",
            &[Assignment::from_str("stage=won").unwrap()],
            Some("Closed won"),
        )
        .unwrap();
    attributed
        .create(
            "contacts",
            "beta",
            &[Assignment::from_str("name=Beta Buyer").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let global = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(global.status, StatusCode::OK);
    assert!(global.text().contains("<span>Audit log</span></h1>"));
    assert!(global.text().contains("contacts/beta"));
    assert!(global.text().contains("deals/alpha"));
    assert!(global.text().contains("sales@example.com"));
    assert!(global.text().contains("/attributes/stage"));
    assert!(global.text().contains("proposal"));
    assert!(global.text().contains("won"));
    assert!(
        global
            .text()
            .contains("&lt;script&gt;alert('historical')&lt;/script&gt;")
    );
    assert!(
        !global
            .text()
            .contains("<script>alert('historical')</script>")
    );
    assert!(
        global.text().find("contacts/beta").unwrap() < global.text().find("deals/alpha").unwrap()
    );

    let filtered = request(
        &app,
        Method::GET,
        "/audit?collection=deals&id=alpha",
        None,
        &[],
    )
    .await;
    assert_eq!(filtered.status, StatusCode::OK);
    assert!(filtered.text().contains("deals/alpha"));
    assert!(!filtered.text().contains("contacts/beta"));
    assert!(filtered.text().contains("value=\"deals\""));
    assert!(filtered.text().contains("value=\"alpha\""));

    let first_page = request(&app, Method::GET, "/audit?limit=1", None, &[]).await;
    assert_eq!(first_page.status, StatusCode::OK);
    assert!(first_page.text().contains("contacts/beta"));
    assert!(!first_page.text().contains("deals/alpha"));
    assert!(first_page.text().contains("limit=1&amp;offset=1"));
    let second_page = request(&app, Method::GET, "/audit?limit=1&offset=1", None, &[]).await;
    assert_eq!(second_page.status, StatusCode::OK);
    assert!(!second_page.text().contains("contacts/beta"));
    assert!(second_page.text().contains("deals/alpha"));

    let invalid = request(&app, Method::GET, "/audit?id=alpha", None, &[]).await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert!(invalid.text().contains("collection is required"));
}

/// The first two table columns are derived from the audit journal, and a view
/// opens newest-first without anyone configuring a sort.
#[tokio::test]
async fn tables_show_audited_creation_and_update_times_and_open_newest_first() {
    let (_temporary, database) = test_database("views-activity");
    database
        .create(
            "deals",
            "alpha",
            &[Assignment::from_str("status=open").unwrap()],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "beta",
            &[Assignment::from_str("status=open").unwrap()],
            "",
        )
        .unwrap();
    // Written directly and never saved: no audited age to show.
    fs::write(
        database.root().join("records/deals/manual.md"),
        "---\nstatus: open\n---\n",
    )
    .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains(">Created<"));
    assert!(page.text().contains(">Updated<"));
    assert!(page.text().contains("<time datetime="));
    assert!(
        page.text()
            .contains("<option value=\"$created_at\" selected>")
    );
    // Newest first, with the unaudited record last in the ordering.
    let beta = page.text().find("/deals/records/beta").unwrap();
    let alpha = page.text().find("/deals/records/alpha").unwrap();
    let manual = page.text().find("/deals/records/manual").unwrap();
    assert!(beta < alpha && alpha < manual);
    assert!(page.text().contains("aria-sort=\"descending\""));

    // Changing a record moves it to the top of the update ordering without
    // disturbing the creation ordering.
    database
        .update(
            "deals",
            "alpha",
            &[Assignment::from_str("status=won").unwrap()],
            None,
        )
        .unwrap();
    let by_update = request(
        &app,
        Method::GET,
        "/deals?sort_field=%24updated_at&sort_direction=desc",
        None,
        &[],
    )
    .await;
    assert_eq!(by_update.status, StatusCode::OK);
    assert!(
        by_update.text().find("/deals/records/alpha").unwrap()
            < by_update.text().find("/deals/records/beta").unwrap()
    );
    let by_creation = request(&app, Method::GET, "/deals", None, &[]).await;
    assert!(
        by_creation.text().find("/deals/records/beta").unwrap()
            < by_creation.text().find("/deals/records/alpha").unwrap()
    );
}

#[tokio::test]
async fn long_record_ids_are_capped_and_shortened_in_the_middle_of_the_table() {
    let (_temporary, database) = test_database("views-long-ids");
    let long = "triggered-inbound-rating-on-create-quiet-anik-majumdar-member-of-technical-staff-intern-4de0aaa0bd9f-3de67c9eb27d08b42c6feb79";
    for id in [long, "acme-renewal"] {
        database
            .create(
                "tasks",
                id,
                &[Assignment::from_str("status=done").unwrap()],
                "",
            )
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    // The link is capped, keeps the last ten characters whole, and carries the
    // complete ID for hover. The halves are adjacent, so the text is the ID.
    let (head, tail) = long.split_at(long.len() - 10);
    assert!(page.text().contains(&format!(
        r#"<a href="/tasks/records/{long}" title="{long}" class="flex max-w-80 font-mono text-gray-600 hover:text-indigo-700 hover:underline"><span class="truncate">{head}</span><span class="shrink-0">{tail}</span></a>"#
    )));
    assert_eq!(tail, "b42c6feb79");
    // A short ID is never cut, so it is one span and needs no tooltip.
    assert!(page.text().contains(
        r#"<a href="/tasks/records/acme-renewal" class="flex max-w-80 font-mono text-gray-600 hover:text-indigo-700 hover:underline"><span class="truncate">acme-renewal</span></a>"#
    ));
}

#[tokio::test]
async fn the_records_table_scrolls_in_its_own_box_with_its_heading_and_edges_pinned() {
    let (_temporary, database) = test_database("views-pinned-edges");
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.text().contains(
            r#"<div class="cr-table-scroll"><table class="min-w-full text-left text-sm" data-date-groups="created" data-row-links="true">"#
        )
    );
    // The box is bounded, so the heading can stick to its top edge.
    for rule in [
        "max-height: max(20rem, calc(100dvh - 12.5rem));",
        ".cr-table-scroll thead th { position: sticky; top: 0;",
        ".cr-table-scroll tbody td:last-child:not([colspan]) { position: sticky; right: 0;",
        ".cr-table-scroll tbody td:first-child:not([colspan]) { position: sticky; left: 0;",
        "animation-timeline: --cr-table-x;",
    ] {
        assert!(page.text().contains(rule), "missing `{rule}`");
    }
    // Both hints start hidden. A table that fits has an inactive timeline,
    // and an animation on one has no effect, so without this they showed on
    // every table that did not scroll.
    for hint in ["animation: cr-more-ahead", "animation: cr-more-behind"] {
        // The table's rule, not the sidebar's, which shares the keyframes.
        let (at, _) = page
            .text()
            .match_indices(hint)
            .find(|(at, _)| {
                let rest = &page.text()[*at..];
                rest[..rest.find('}').unwrap()].contains("--cr-table-x")
            })
            .unwrap_or_else(|| panic!("no table rule animates `{hint}`"));
        let rule = &page.text()[..at];
        let rule = &rule[rule.rfind('{').unwrap()..];
        assert!(rule.contains("opacity: 0;"), "`{hint}` starts visible");
    }

    // The empty state spans every column and is not pinned to either edge.
    let empty = request(&app, Method::GET, "/tasks?q=nothing-matches", None, &[]).await;
    assert!(empty.text().contains("No records match this view."));
    assert!(empty.text().contains(r#"<td colspan=""#));
}

#[tokio::test]
async fn the_sidebar_list_scrolls_under_a_pinned_footer_with_faded_edges() {
    let (_temporary, database) = test_database("views-sidebar-fades");
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let sheet = page.text();
    let rule = |selector: &str| {
        let start = sheet
            .find(&format!("{selector} {{"))
            .unwrap_or_else(|| panic!("no rule for `{selector}`"));
        &sheet[start..start + sheet[start..].find('}').unwrap()]
    };
    // The list scrolls on its own, and the footer below it does not.
    assert!(rule(".cr-sidebar-nav").contains("overflow-y: auto;"));
    assert!(rule(".cr-sidebar-nav").contains("scroll-timeline: --cr-sidebar-y block;"));
    assert!(rule(".cr-sidebar-utility").contains("flex: 0 0 auto;"));
    // Both fades are pinned to the list's edges, start hidden, and are shown
    // by where the list is scrolled to.
    let shared = rule("  .cr-sidebar-nav::before,\n  .cr-sidebar-nav::after");
    assert!(shared.contains("position: sticky;") && shared.contains("opacity: 0;"));
    assert!(rule("  .cr-sidebar-nav::before").contains(
        "animation: cr-more-behind linear both;\n    animation-timeline: --cr-sidebar-y;"
    ));
    // The last rule for `::after`: the first is the one it shares with `::before`.
    let after = &sheet[sheet.rfind("  .cr-sidebar-nav::after {").unwrap()..];
    let after = &after[..after.find('}').unwrap()];
    assert!(after.contains(
        "animation: cr-more-ahead linear both;\n    animation-timeline: --cr-sidebar-y;"
    ));
}

#[tokio::test]
async fn navigation_lists_mark_the_current_page_and_keep_it_in_view() {
    let (_temporary, database) = test_database("views-nav-current");
    for collection in ["alpha", "tasks", "zeta"] {
        database
            .create(
                collection,
                "one",
                &[Assignment::from_str("status=done").unwrap()],
                "",
            )
            .unwrap();
    }
    database
        .create_view(
            "done",
            Some("Done tasks"),
            "tasks",
            vec!["status=done".into()],
            vec![],
            25,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/done", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    // Both lists say which entry is this page, the narrow screens' strip as
    // the sidebar already did, and only that one.
    assert!(
        page.text()
            .contains(r#"<a href="/done" class="is-active" aria-current="page">"#)
    );
    assert!(
        page.text()
            .contains(r#"<a href="/done" class="cr-sidebar-link is-active" aria-current="page""#)
    );
    assert_eq!(page.text().matches(r#"aria-current="page""#).count(), 2);
    // The browser keeps that entry in sight as the lists are re-rendered.
    let script = page
        .text()
        .split(r#"<script src=""#)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/static/cr-"))
        .expect("the page links cr.js");
    let script = request(&app, Method::GET, script, None, &[]).await;
    assert!(
        script
            .text()
            .contains("keepCurrentEntryInView('.cr-sidebar-nav', true);")
    );
    assert!(
        script
            .text()
            .contains("keepCurrentEntryInView('.cr-mobile-view-strip', false);")
    );
    assert!(script.text().contains("  enhanceNavigationLists();"));
}

#[tokio::test]
async fn header_controls_are_one_height() {
    let (_temporary, database) = test_database("views-control-height");
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    let sheet = page.text();
    let button = &sheet[sheet.find(".cr-button {").unwrap()..];
    let button = &button[..button.find('}').unwrap()];
    // A height, not a minimum, so a badge inside cannot stretch one button.
    assert!(button.contains("height: 32px;") && !button.contains("min-height"));
    assert!(sheet.contains(".cr-button .cr-pill { padding: 1px 6px; }"));
    // The search box among them is the same 2rem.
    assert!(sheet.contains(r#"data-view-search="true" class="h-8 w-full"#));
}

#[tokio::test]
async fn table_rows_keep_to_one_line_and_long_values_show_in_full_on_hover() {
    let (_temporary, database) = test_database("views-one-line");
    let prompt = "Rate the inbound applicant against the rubric and draft a note.";
    database
        .create(
            "tasks",
            "alpha",
            &[
                Assignment::from_str("asked_by=anand-chowdhary").unwrap(),
                Assignment::from_str(&format!("prompt={prompt:?}")).unwrap(),
                Assignment::from_str("claim.pid=0").unwrap(),
                Assignment::from_str("claim.owner=worker-with-a-rather-long-name-v1").unwrap(),
            ],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // An object is not a default column, so this table asks for it.
    let page = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=asked_by&column=prompt&column=claim",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    let cell = r#"class="block max-w-xs truncate""#;
    // A short value is one line with nothing to reveal.
    assert!(
        page.text()
            .contains(&format!(r#"<span {cell}>anand-chowdhary</span>"#))
    );
    // A long one may be cut at the cell's width, so hovering shows all of it.
    assert!(
        page.text()
            .contains(&format!(r#"<span title="{prompt}" {cell}>{prompt}</span>"#))
    );
    // A nested value runs together in the cell and keeps its lines on hover.
    assert!(page.text().contains(&format!(
        "<span title=\"pid: 0\nowner: worker-with-a-rather-long-name-v1\" {cell}>"
    )));
    assert!(!page.text().contains("line-clamp-2"));
}

#[tokio::test]
async fn the_pager_shows_the_page_number_and_offers_other_page_sizes() {
    let (_temporary, database) = test_database("views-page-sizes");
    for index in 0..30 {
        database
            .create(
                "tasks",
                &format!("task-{index:02}"),
                &[Assignment::from_str("status=done").unwrap()],
                "",
            )
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // Twenty-five rows unless something asks for another number.
    let first = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(first.status, StatusCode::OK);
    assert!(first.text().contains("<p>Showing 1\u{2013}25 of 30</p>"));
    assert!(first.text().contains(">Page 1 of 2</p>"));
    // Previous is drawn on the first page, unusable, so Next stays put.
    assert!(first.text().contains(
        r#"<span class="cr-button" data-disabled="true" aria-hidden="true">Previous</span>"#
    ));
    assert!(first.text().contains(r#"id="cr-page-next""#));
    // Each size is a link to the first page of the same view at that size, and
    // the current one says so.
    assert!(
        first
            .text()
            .contains(r#"role="group" aria-label="Rows per page""#)
    );
    assert!(first.text().contains(
        r#"href="/tasks?filter_match=all&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=10" aria-label="10 rows per page""#
    ));
    assert!(
        first
            .text()
            .contains(r#"aria-label="25 rows per page" aria-current="true""#)
    );
    assert!(first.text().contains(r#"aria-label="100 rows per page""#));

    let second = request(&app, Method::GET, "/tasks?limit=10&offset=10", None, &[]).await;
    assert!(second.text().contains(">Page 2 of 3</p>"));
    assert!(second.text().contains(r#"id="cr-page-previous""#));
    assert!(second.text().contains(r#"id="cr-page-next""#));
    assert!(
        !second
            .text()
            .contains(r#"<span class="cr-button" data-disabled"#)
    );

    let last = request(&app, Method::GET, "/tasks?limit=25&offset=25", None, &[]).await;
    assert!(last.text().contains(">Page 2 of 2</p>"));
    assert!(last.text().contains(
        r#"<span class="cr-button" data-disabled="true" aria-hidden="true">Next</span>"#
    ));

    // A size the server would refuse is never offered, and a size a view or
    // URL chose is offered beside the standard ones.
    let bounded = router(
        database.clone(),
        ServerConfig {
            max_page_size: 30,
            ..ServerConfig::default()
        },
    )
    .unwrap();
    let page = request(&bounded, Method::GET, "/tasks?limit=12", None, &[]).await;
    assert!(
        page.text()
            .contains(r#"aria-label="12 rows per page" aria-current="true""#)
    );
    assert!(page.text().contains(r#"aria-label="25 rows per page""#));
    assert!(!page.text().contains(r#"aria-label="50 rows per page""#));

    // One page of records that fit the smallest size needs neither control.
    let (_small_temporary, small) = test_database("views-one-page");
    small
        .create(
            "tasks",
            "only",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    let app = router(small, ServerConfig::default()).unwrap();
    let single = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert!(single.text().contains(">Page 1 of 1</p>"));
    assert!(!single.text().contains("Rows per page"));
    assert!(!single.text().contains("Previous"));
    assert!(!single.text().contains(r#"id="cr-page-next""#));
}

#[tokio::test]
async fn automatic_columns_follow_the_schema_then_the_order_records_are_written_in() {
    let (_temporary, database) = test_database("views-column-order");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{
          "type": "object",
          "x-cr-ui": { "order": ["title"] },
          "required": ["title", "status"],
          "properties": {
            "asked_by": { "type": "string" },
            "attempts": { "type": "integer" },
            "status": { "enum": ["queued", "done"] },
            "title": { "type": "string" },
            "zeta": { "type": "string" }
          }
        }"#,
    )
    .unwrap();
    // Written the way an agent writes them: the schema's fields in their own
    // order, then undeclared ones.
    for id in ["one", "two", "three", "four", "five"] {
        database
            .create(
                "tasks",
                id,
                &[
                    Assignment::from_str("status=queued").unwrap(),
                    Assignment::from_str("title=Rate an applicant").unwrap(),
                    Assignment::from_str("prompt=Rate them").unwrap(),
                    Assignment::from_str("attempts=0").unwrap(),
                    Assignment::from_str("asked_by=anand").unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    // One file written in another order does not move a column by itself.
    fs::write(
        database.root().join("records/tasks/odd.md"),
        "---\nasked_by: anand\ntitle: Odd\nstatus: done\nattempts: 1\nprompt: Rate\n---\n",
    )
    .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let at = |label: &str| {
        page.text()
            .find(&format!("aria-label=\"Sort by {label} ascending\""))
            .unwrap_or_else(|| panic!("no {label} column"))
    };
    // `x-cr-ui.order`, then `required` in its own order, then where the
    // records put the rest, then what only the schema declares.
    let order = ["Title", "Status", "Prompt", "Attempts", "Asked By", "Zeta"];
    for pair in order.windows(2) {
        assert!(at(pair[0]) < at(pair[1]), "{} before {}", pair[0], pair[1]);
    }

    // Without a schema the records' own order is the whole answer.
    for id in ["alpha", "beta"] {
        database
            .create(
                "notes",
                id,
                &[
                    Assignment::from_str("name=Note").unwrap(),
                    Assignment::from_str("stage=draft").unwrap(),
                    Assignment::from_str("author=anand").unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    let notes = request(&app, Method::GET, "/notes", None, &[]).await;
    let name = notes.text().find("Sort by Name ascending").unwrap();
    let stage = notes.text().find("Sort by Stage ascending").unwrap();
    let author = notes.text().find("Sort by Author ascending").unwrap();
    assert!(name < stage && stage < author);
}

#[tokio::test]
async fn a_table_leads_with_the_records_title_and_keeps_the_id_on_hover() {
    let (_temporary, database) = test_database("views-title-column");
    database
        .create(
            "deals",
            "acme-renewal",
            &[
                Assignment::from_str("name=Acme annual renewal").unwrap(),
                Assignment::from_str("stage=won").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "deals",
            "unnamed",
            &[Assignment::from_str("stage=lost").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    // The first column is the name, sorted by name, with the ID it replaces
    // in the tooltip.
    assert!(
        page.text()
            .contains(r#"aria-label="Sort by Name ascending""#)
    );
    assert!(!page.text().contains(r#"aria-label="Sort by record ID"#));
    assert!(page.text().contains(
        "<a href=\"/deals/records/acme-renewal\" title=\"Acme annual renewal\nacme-renewal\" class=\"flex max-w-80 font-semibold text-gray-900 hover:text-indigo-700 hover:underline\"><span class=\"truncate\">Acme annual renewal</span></a>"
    ));
    // Not repeated among the other columns.
    assert_eq!(page.text().matches("Sort by Name").count(), 1);
    assert!(!page.text().contains(">Acme annual renewal</a>"));
    // A record without one is shown by its ID.
    assert!(page.text().contains(
        r#"<a href="/deals/records/unnamed" class="flex max-w-80 font-mono text-gray-600 hover:text-indigo-700 hover:underline"><span class="truncate">unnamed</span></a>"#
    ));

    // A schema can name another field, and every page names the record by it.
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tickets.json"),
        r#"{ "type": "object", "x-cr-ui": { "title": "subject" },
             "properties": { "subject": { "type": "string", "title": "Subject line" },
                             "name": { "type": "string" } } }"#,
    )
    .unwrap();
    database
        .create(
            "tickets",
            "t-1",
            &[
                Assignment::from_str("name=Requester").unwrap(),
                Assignment::from_str("subject=Printer on fire").unwrap(),
            ],
            "",
        )
        .unwrap();
    let tickets = request(&app, Method::GET, "/tickets", None, &[]).await;
    assert!(
        tickets
            .text()
            .contains(r#"aria-label="Sort by Subject line ascending""#)
    );
    assert!(
        tickets
            .text()
            .contains(r#"<span class="truncate">Printer on fire</span>"#)
    );
    // `name` is an ordinary column here.
    assert!(
        tickets
            .text()
            .contains(r#"aria-label="Sort by Name ascending""#)
    );
    let record = request(&app, Method::GET, "/tickets/records/t-1", None, &[]).await;
    assert!(
        record
            .text()
            .contains("<title>Printer on fire · cr</title>")
    );
    let delete = request(&app, Method::GET, "/tickets/records/t-1/delete", None, &[]).await;
    assert!(delete.text().contains("Delete Printer on fire"));
}

#[tokio::test]
async fn automatic_tables_show_six_fields_and_leave_objects_to_the_picker() {
    let (_temporary, database) = test_database("views-default-columns");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object",
             "properties": { "reviews": { "type": "array", "items": { "type": "object" } } } }"#,
    )
    .unwrap();
    database
        .create(
            "tasks",
            "alpha",
            &[
                Assignment::from_str("title=Rate an applicant").unwrap(),
                Assignment::from_str("status=done").unwrap(),
                Assignment::from_str("capability.profile=worker-v1").unwrap(),
                Assignment::from_str("kind=triggered").unwrap(),
                Assignment::from_str("asked_by=anand").unwrap(),
                Assignment::from_str("attempts=0").unwrap(),
                Assignment::from_str("tags=[a, b]").unwrap(),
                Assignment::from_str("prompt=Rate them").unwrap(),
                Assignment::from_str("delivery=slack").unwrap(),
                Assignment::from_str("draft=none").unwrap(),
            ],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    let shown = |label: &str| page.text().contains(&format!("Sort by {label} ascending"));
    // The title leads, then the first six fields that are not objects: a list
    // of plain values is fine, and so is anything the schema does not call an
    // object.
    assert!(shown("Title"));
    for label in ["Status", "Kind", "Asked By", "Attempts", "Tags", "Prompt"] {
        assert!(shown(label), "{label} is a default column");
    }
    for label in ["Capability", "Reviews", "Delivery", "Draft"] {
        assert!(!shown(label), "{label} is not a default column");
    }
    assert!(page.text().contains("6 shown"));
    // Every field can still be chosen, objects included, the title aside.
    for field in ["capability", "reviews", "delivery", "draft"] {
        assert!(
            page.text()
                .contains(&format!(r#"name="column" value="{field}">"#)),
            "{field} is offered unchecked"
        );
    }
    assert!(!page.text().contains(r#"name="column" value="title""#));
    let chosen = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=capability",
        None,
        &[],
    )
    .await;
    assert!(chosen.text().contains("Sort by Capability ascending"));
}

#[tokio::test]
async fn object_values_are_summarised_as_a_badge_or_chips_rather_than_yaml() {
    let (_temporary, database) = test_database("views-object-summary");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object",
             "properties": { "review": { "type": "object",
                 "properties": { "verdict": { "enum": ["advance", "reject"] } } } } }"#,
    )
    .unwrap();
    database
        .create(
            "tasks",
            "alpha",
            &[
                Assignment::from_str("learning.attempts=0").unwrap(),
                Assignment::from_str("learning.status=in_progress").unwrap(),
                Assignment::from_str("learning.session=learning-alpha").unwrap(),
                Assignment::from_str("review.score=4").unwrap(),
                Assignment::from_str("review.verdict=advance").unwrap(),
                Assignment::from_str("capability.profile=worker-v1").unwrap(),
                Assignment::from_str("capability.region=eu").unwrap(),
                Assignment::from_str("capability.pool=batch").unwrap(),
                Assignment::from_str("capability.retries=0").unwrap(),
                Assignment::from_str("claim.pid=0").unwrap(),
                Assignment::from_str("claim.at=''").unwrap(),
                Assignment::from_str("history=[{at: one}, {at: two}]").unwrap(),
            ],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=learning&column=review&column=capability&column=claim&column=history",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    let cell = |content: &str| format!(r#"class="block max-w-xs truncate">{content}</span>"#);
    // A state is the whole summary, read like an enum.
    assert!(page.text().contains(&cell(
        r#"<span class="cr-pill cr-pill-active">In Progress</span>"#
    )));
    // So is the field the schema gives an enum.
    assert!(page.text().contains(&cell(
        r#"<span class="cr-pill cr-pill-positive">Advance</span>"#
    )));
    // Otherwise the first fields that hold something, and a count of the rest.
    let chip = |key: &str, value: &str| {
        format!(
            r#"<span class="mr-1 inline-flex items-baseline gap-1 rounded bg-gray-100 px-1.5 py-px text-xs"><span class="text-gray-500">{key}</span><span class="text-gray-700">{value}</span></span>"#
        )
    };
    assert!(page.text().contains(&cell(&format!(
        r#"{}{}<span class="text-xs text-gray-500">+1</span>"#,
        chip("profile", "worker-v1"),
        chip("region", "eu")
    ))));
    // Nothing but zeroes and empty strings is nothing.
    assert!(
        page.text()
            .contains(&cell(r#"<span class="text-gray-400">—</span>"#))
    );
    // A list of objects is counted.
    assert!(
        page.text()
            .contains(&cell(r#"<span class="text-gray-500">2 items</span>"#))
    );
    // The YAML is still there on hover.
    assert!(
        page.text()
            .contains("title=\"attempts: 0\nstatus: in_progress\nsession: learning-alpha\"")
    );
}

#[tokio::test]
async fn fields_inside_objects_can_be_chosen_as_columns_of_their_own() {
    let (_temporary, database) = test_database("views-nested-columns");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object",
             "properties": { "learning": { "type": "object", "properties": {
                 "status": { "enum": ["in_progress", "done"], "title": "Learning state" },
                 "notes": { "type": "string" } } } } }"#,
    )
    .unwrap();
    for (id, status, session) in [
        ("alpha", "done", "b-session"),
        ("beta", "in_progress", "a-session"),
    ] {
        database
            .create(
                "tasks",
                id,
                &[
                    Assignment::from_str("kind=triggered").unwrap(),
                    Assignment::from_str(&format!("learning.status={status}")).unwrap(),
                    Assignment::from_str(&format!("learning.session={session}")).unwrap(),
                    Assignment::from_str("learning.retry.at=never").unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    // Offered right after their object, in the records' order, then what only
    // the schema declares; a nested object is not.
    let offered = |field: &str| {
        page.text()
            .find(&format!(r#"name="column" value="{field}""#))
            .unwrap_or_else(|| panic!("{field} is not offered"))
    };
    assert!(offered("learning") < offered("learning.status"));
    assert!(offered("learning.status") < offered("learning.session"));
    assert!(offered("learning.session") < offered("learning.notes"));
    assert!(!page.text().contains(r#"value="learning.retry""#));
    assert!(!page.text().contains(r#"value="learning.retry.at""#));
    // Never a default column.
    assert!(!page.text().contains("Sort by Learning state"));

    // Chosen, it is a column like any other: labelled and read through the
    // schema, and sortable by its path.
    let chosen = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=learning.status&column=learning.session&sort_field=learning.session&sort_direction=asc",
        None,
        &[],
    )
    .await;
    assert_eq!(chosen.status, StatusCode::OK);
    assert!(chosen.text().contains("Sort by Learning state ascending"));
    assert!(
        chosen
            .text()
            .contains(r#"<span class="cr-pill cr-pill-active">In Progress</span></span>"#)
    );
    assert!(
        chosen.text().find("/tasks/records/beta").unwrap()
            < chosen.text().find("/tasks/records/alpha").unwrap()
    );
    // And filterable, with the schema's own control.
    assert!(
        chosen
            .text()
            .contains(r#"<option value="learning.status" data-filter-kind="select""#)
    );
    let filtered = request(
        &app,
        Method::GET,
        "/tasks?filter_field=learning.status&filter_operator=eq&filter_value=done",
        None,
        &[],
    )
    .await;
    assert!(filtered.text().contains("/tasks/records/alpha"));
    assert!(!filtered.text().contains("/tasks/records/beta"));
}

#[tokio::test]
async fn states_are_coloured_badges_by_what_they_say() {
    let (_temporary, database) = test_database("views-badges");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": {
             "stage": { "enum": ["in-progress", "failed", "queued", "proposal", "won"] },
             "labels": { "type": "array", "items": { "enum": ["urgent", "done"] } },
             "notes": { "type": "string" } } }"#,
    )
    .unwrap();
    let badge = |tone: &str, text: &str| match tone {
        "" => format!(r#"<span class="cr-pill">{text}</span>"#),
        tone => format!(r#"<span class="cr-pill cr-pill-{tone}">{text}</span>"#),
    };
    for (id, stage) in [
        ("a", "in-progress"),
        ("b", "failed"),
        ("c", "queued"),
        ("d", "proposal"),
        ("e", "won"),
    ] {
        database
            .create(
                "tasks",
                id,
                &[
                    Assignment::from_str(&format!("stage={stage}")).unwrap(),
                    Assignment::from_str("labels=[urgent, done]").unwrap(),
                    Assignment::from_str("status=done").unwrap(),
                    Assignment::from_str("notes=done").unwrap(),
                    Assignment::from_str("run.state=running").unwrap(),
                ],
                "",
            )
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=stage&column=labels&column=status&column=notes&column=run",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    // An enum's value is a badge coloured by what it says, and grey when the
    // word says nothing about how things went.
    assert!(page.text().contains(&badge("active", "In Progress")));
    assert!(page.text().contains(&badge("negative", "Failed")));
    assert!(page.text().contains(&badge("warn", "Queued")));
    assert!(page.text().contains(&badge("", "Proposal")));
    assert!(page.text().contains(&badge("positive", "Won")));
    // Each value of a list of enums is its own badge.
    assert!(page.text().contains(&format!(
        r#"<span class="mr-1">{}</span><span class="mr-1">{}</span>"#,
        badge("", "Urgent"),
        badge("positive", "Done")
    )));
    // A `status` or `state` field is one even without a schema, and so is an
    // object's state; any other text stays text.
    assert!(page.text().contains(&format!(
        r#"class="block max-w-xs truncate">{}</span>"#,
        badge("positive", "Done")
    )));
    assert!(page.text().contains(&badge("active", "Running")));
    assert!(
        page.text()
            .contains(r#"class="block max-w-xs truncate">done</span>"#)
    );
    // The tones have colours in both schemes.
    for tone in ["positive", "negative", "active", "warn"] {
        assert!(
            page.text()
                .contains(&format!(".cr-pill-{tone} {{ border-color: var("))
        );
    }
}

#[tokio::test]
async fn empty_values_read_as_a_quiet_dash_however_yaml_spells_them() {
    let (_temporary, database) = test_database("views-empty-values");
    database
        .create(
            "tasks",
            "alpha",
            &[
                Assignment::from_str("note=''").unwrap(),
                Assignment::from_str("owner=null").unwrap(),
                Assignment::from_str("tags=[]").unwrap(),
                Assignment::from_str("meta={}").unwrap(),
                Assignment::from_str("status=''").unwrap(),
                Assignment::from_str("count=0").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create(
            "tasks",
            "beta",
            &[Assignment::from_str("extra=here").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(
        &app,
        Method::GET,
        "/tasks?columns=custom&column=note&column=owner&column=tags&column=meta&column=status&column=count&column=extra",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    let dash = r#"class="block max-w-xs truncate"><span class="text-gray-400">—</span></span>"#;
    // Six empty cells on alpha and six missing ones on beta; an empty status
    // is not an empty badge, and zero is a value.
    assert_eq!(page.text().matches(dash).count(), 12);
    assert!(!page.text().contains("''"));
    assert!(!page.text().contains(">null<"));
    assert!(!page.text().contains(r#"<span class="cr-pill"></span>"#));
    assert!(
        page.text()
            .contains(r#"class="block max-w-xs truncate">0</span>"#)
    );
}

#[tokio::test]
async fn quick_filters_count_each_state_and_apply_it_in_one_click() {
    let (_temporary, database) = test_database("views-quick-filters");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": {
             "status": { "enum": ["queued", "running", "done", "failed"] },
             "kind": { "enum": ["scheduled", "triggered"] } } }"#,
    )
    .unwrap();
    let tasks = [
        ("a", Some("done"), "triggered"),
        ("b", Some("done"), "scheduled"),
        ("c", Some("done"), "triggered"),
        ("d", Some("failed"), "triggered"),
        ("e", Some("failed"), "scheduled"),
        ("f", Some("queued"), "triggered"),
        ("g", None, "triggered"),
    ];
    for (id, status, kind) in tasks {
        let mut assignments = vec![Assignment::from_str(&format!("kind={kind}")).unwrap()];
        if let Some(status) = status {
            assignments.push(Assignment::from_str(&format!("status={status}")).unwrap());
        }
        database.create("tasks", id, &assignments, "").unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let chip = |label: &str, count: usize, current: bool| {
        format!(
            r#"class="cr-quick-filter"{}>{label}<span class="cr-quick-filter-count">{count}</span></a>"#,
            if current {
                r#" aria-current="true""#
            } else {
                ""
            }
        )
    };

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.text()
            .contains(r#"<nav aria-label="Filter by Status" data-quick-filter="status""#)
    );
    // All, then the schema's order, values nothing has left out, then the
    // records with no status.
    let offered = [
        chip("All", 7, true),
        chip("Queued", 1, false),
        chip("Done", 3, false),
        chip("Failed", 2, false),
        chip("Not set", 1, false),
    ];
    let positions = offered
        .iter()
        .map(|chip| {
            page.text()
                .find(chip.as_str())
                .unwrap_or_else(|| panic!("missing {chip}"))
        })
        .collect::<Vec<_>>();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!page.text().contains(">Running<"));
    // A chip is the URL the filter panel would build.
    assert!(page.text().contains(
        "filter_match=all&amp;filter_field=status&amp;filter_operator=eq&amp;filter_value=failed&amp;sort_field"
    ));
    assert!(
        page.text()
            .contains("filter_field=status&amp;filter_operator=is-empty&amp;filter_value=&amp;")
    );

    // Applied, it is marked, and the other counts are still what each chip
    // would show, because a chip replaces the condition on its field.
    let failed = request(
        &app,
        Method::GET,
        "/tasks?filter_field=status&filter_operator=eq&filter_value=failed",
        None,
        &[],
    )
    .await;
    assert!(failed.text().contains(&chip("Failed", 2, true)));
    assert!(failed.text().contains(&chip("All", 7, false)));
    assert!(failed.text().contains(&chip("Done", 3, false)));
    assert!(failed.text().contains("Showing 1\u{2013}2 of 2"));
    // Its All chip clears the condition and nothing else.
    assert!(failed.text().contains(r#"<a href="/tasks?filter_match=all&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=25" class="cr-quick-filter">All"#));

    // Conditions on other fields narrow every count.
    let triggered = request(
        &app,
        Method::GET,
        "/tasks?filter_field=kind&filter_operator=eq&filter_value=triggered",
        None,
        &[],
    )
    .await;
    assert!(triggered.text().contains(&chip("All", 5, true)));
    assert!(triggered.text().contains(&chip("Done", 2, false)));
    assert!(triggered.text().contains(&chip("Failed", 1, false)));

    // Any-of matching with another field's condition has no honest count.
    let any = request(
        &app,
        Method::GET,
        "/tasks?filter_match=any&filter_field=kind&filter_operator=eq&filter_value=triggered",
        None,
        &[],
    )
    .await;
    assert!(!any.text().contains("data-quick-filter"));

    // A schemaless `status` gets them too, most frequent first.
    for (id, status) in [("x", "open"), ("y", "closed"), ("z", "closed")] {
        database
            .create(
                "issues",
                id,
                &[Assignment::from_str(&format!("status={status}")).unwrap()],
                "",
            )
            .unwrap();
    }
    let issues = request(&app, Method::GET, "/issues", None, &[]).await;
    assert!(
        issues.text().find(&chip("Closed", 2, false)).unwrap()
            < issues.text().find(&chip("Open", 1, false)).unwrap()
    );
}

#[tokio::test]
async fn applied_filters_are_chips_that_each_remove_their_condition() {
    let (_temporary, database) = test_database("views-filter-chips");
    fs::create_dir_all(database.root().join(".cr/schemas")).unwrap();
    fs::write(
        database.root().join(".cr/schemas/tasks.json"),
        r#"{ "type": "object", "properties": {
             "status": { "enum": ["done", "failed"] },
             "owner": { "type": "string", "title": "Assignee" } } }"#,
    )
    .unwrap();
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("status=failed").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let none = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert!(!none.text().contains("data-filter-chips"));

    let page = request(
        &app,
        Method::GET,
        "/tasks?q=alpha&filter_field=status&filter_operator=eq&filter_value=failed&filter_field=owner&filter_operator=is-empty&filter_value=",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.text().contains(r#"data-filter-chips="2""#));
    assert!(page.text().contains(">Filtered by<"));
    // In the panel's words, an enum's value as its option reads.
    assert!(
        page.text()
            .contains(r#"<span class="cr-active-filter">Status is Failed<a "#)
    );
    assert!(
        page.text()
            .contains(r#"<span class="cr-active-filter">Assignee is empty<a "#)
    );
    // Each removes its own condition and keeps the search and the rest.
    assert!(page.text().contains(
        r#"href="/tasks?q=alpha&amp;filter_match=all&amp;filter_field=owner&amp;filter_operator=is-empty&amp;filter_value=&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=25" aria-label="Remove filter: Status is Failed""#
    ));
    assert!(page.text().contains(
        r#"href="/tasks?q=alpha&amp;filter_match=all&amp;filter_field=status&amp;filter_operator=eq&amp;filter_value=failed&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=25" aria-label="Remove filter: Assignee is empty""#
    ));
    assert!(page.text().contains(
        r#"<a href="/tasks?q=alpha&amp;filter_match=all&amp;sort_field=%24created_at&amp;sort_direction=desc&amp;limit=25" class="text-xs text-gray-500 hover:text-gray-900 hover:underline">Clear filters</a>"#
    ));

    // One condition needs no second way to remove it; any-of says so.
    let one = request(
        &app,
        Method::GET,
        "/tasks?filter_field=status&filter_operator=ne&filter_value=done",
        None,
        &[],
    )
    .await;
    assert!(one.text().contains("Status is not Done<a "));
    assert!(!one.text().contains("Clear filters"));
    let any = request(
        &app,
        Method::GET,
        "/tasks?filter_match=any&filter_field=status&filter_operator=eq&filter_value=done&filter_field=owner&filter_operator=is-not-empty&filter_value=",
        None,
        &[],
    )
    .await;
    assert!(any.text().contains(">Any of<"));
}

#[tokio::test]
async fn a_table_ordered_by_time_is_marked_for_grouping_by_day() {
    let (_temporary, database) = test_database("views-date-groups");
    database
        .create(
            "tasks",
            "alpha",
            &[Assignment::from_str("name=Alpha").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // Newest first by default, so grouped by the day each was created.
    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert!(page.text().contains(r#"data-date-groups="created""#));
    assert!(page.text().contains(
        r#"<td class="whitespace-nowrap px-4 py-3" data-activity="created"><time datetime=""#
    ));
    assert!(page.text().contains(
        r#"<td class="whitespace-nowrap px-4 py-3" data-activity="updated"><time datetime=""#
    ));
    let updated = request(
        &app,
        Method::GET,
        "/tasks?sort_field=%24updated_at&sort_direction=asc",
        None,
        &[],
    )
    .await;
    assert!(updated.text().contains(r#"data-date-groups="updated""#));
    // Any other order has no days to group by.
    let by_name = request(&app, Method::GET, "/tasks?sort_field=name", None, &[]).await;
    assert!(!by_name.text().contains("data-date-groups"));

    // The browser does the grouping, in the reader's time zone.
    let script = page
        .text()
        .split(r#"<script src=""#)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/static/cr-"))
        .expect("the page links cr.js");
    let script = request(&app, Method::GET, script, None, &[]).await;
    assert!(script.text().contains("const enhanceDateGroups = () => {"));
    assert!(script.text().contains("enhanceDateGroups();"));
}

#[tokio::test]
async fn a_row_has_one_link_to_its_record_and_opens_it_from_anywhere() {
    let (_temporary, database) = test_database("views-row-links");
    database
        .create(
            "tasks",
            "alpha",
            &[
                Assignment::from_str("name=Alpha").unwrap(),
                Assignment::from_str("status=done").unwrap(),
                Assignment::from_str("owner=anand").unwrap(),
                Assignment::from_str("notes=Rate the applicant").unwrap(),
            ],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    // The title and the open action; the cells between are text.
    assert_eq!(
        page.text()
            .matches(r#"href="/tasks/records/alpha""#)
            .count(),
        2
    );
    assert!(
        page.text()
            .contains(r#"<span class="block max-w-xs truncate">anand</span>"#)
    );
    assert!(page.text().contains(r#"data-row-links="true""#));
    assert!(
        page.text()
            .contains(".cr-rows-open tbody tr:has(td a[href]) { cursor: pointer; }")
    );
    let script = page
        .text()
        .split(r#"<script src=""#)
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .find(|src| src.starts_with("/static/cr-"))
        .expect("the page links cr.js");
    let script = request(&app, Method::GET, script, None, &[]).await;
    assert!(script.text().contains("const enhanceRowLinks = () => {"));
    assert!(script.text().contains("enhanceRowLinks();"));
}

#[tokio::test]
async fn every_page_opens_with_one_compact_bar() {
    let (_temporary, database) = test_database("views-heading");
    database
        .create(
            "deals",
            "alpha",
            &[
                Assignment::from_str("name=Acme renewal").unwrap(),
                Assignment::from_str("stage=won").unwrap(),
            ],
            "",
        )
        .unwrap();
    database
        .create_view(
            "won",
            Some("Won deals"),
            "deals",
            vec!["stage=won".into()],
            vec![],
            25,
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // A view: the way back, then its title at the size of the text around it,
    // then how many records it shows, with its controls in the same bar.
    let automatic = request(&app, Method::GET, "/deals", None, &[]).await;
    assert!(automatic.text().contains(
        r#"<header class="cr-page-bar"><div class="cr-page-bar-title"><div class="cr-page-path"><nav aria-label="Breadcrumb" class="cr-crumbs"><a href="/"><span class="cr-crumb-label">Views</span></a><span class="cr-crumb-separator" aria-hidden="true">›</span></nav><h1 class="cr-page-title"><span class="cr-page-icon" aria-hidden="true">🗃️</span><span>Deals</span></h1></div><span class="cr-page-meta" data-view-summary="true"><span id="cr-view-count">1 record</span></span></div><div class="cr-page-actions">"#
    ));
    let bar = automatic
        .text()
        .split(r#"<header class="cr-page-bar">"#)
        .nth(1)
        .unwrap();
    let bar = &bar[..bar.find("</header>").unwrap()];
    for control in [
        r#"data-view-search="true""#,
        r#"id="cr-view-filter-summary""#,
        "Save as view",
        ">New record<",
    ] {
        assert!(bar.contains(control), "the bar lacks {control}");
    }
    // One heading per page, and none of the old display-sized furniture.
    assert_eq!(automatic.text().matches("<h1").count(), 1);
    for gone in ["cr-title", "cr-eyebrow", "cr-lede", "cr-page-heading"] {
        assert!(!automatic.text().contains(gone), "{gone} is still rendered");
    }

    // A saved view says which collection it reads, and lists its own filters
    // under the bar.
    let saved = request(&app, Method::GET, "/won", None, &[]).await;
    assert!(saved.text().contains(
        r#"data-view-summary="true">Saved view of <code class="font-mono text-gray-700">deals</code><span class="mx-1.5 text-gray-300" aria-hidden="true">·</span><span id="cr-view-count">1 record</span>"#
    ));
    assert!(saved.text().contains(
        r#"<div class="mb-3 flex flex-wrap items-center gap-1.5" data-view-filters="true"><code class="cr-filter-tag">stage=won</code>"#
    ));

    // A record: its view is a step back, its ID the quiet word after its name.
    let record = request(&app, Method::GET, "/deals/records/alpha", None, &[]).await;
    assert!(record.text().contains(
        r#"<a href="/deals"><span class="cr-page-icon" aria-hidden="true">🗃️</span><span class="cr-crumb-label">Deals</span></a><span class="cr-crumb-separator" aria-hidden="true">›</span></nav><h1 class="cr-page-title"><span>Acme renewal</span></h1></div><span class="cr-page-meta font-mono">alpha</span>"#
    ));
    assert_eq!(record.text().matches("<h1").count(), 1);
    // Its delete confirmation's question is the card's heading, not the page's.
    let delete = request(&app, Method::GET, "/deals/records/alpha/delete", None, &[]).await;
    assert!(
        delete
            .text()
            .contains(r#"<h1 class="cr-page-title"><span>Delete</span></h1>"#)
    );
    assert!(
        delete
            .text()
            .contains(r#"<h2 class="text-lg font-semibold text-red-900">Delete this record?</h2>"#)
    );
    assert_eq!(delete.text().matches("<h1").count(), 1);

    // The index and the audit log are bars too.
    let home = request(&app, Method::GET, "/?summary=inline", None, &[]).await;
    assert!(home.text().contains(r#"<span>All views</span></h1></div><span class="cr-page-meta">2 views<span id="cr-view-index-total"><span class="mx-1.5 text-gray-300" aria-hidden="true">·</span>1 record</span>"#));
    let audit = request(&app, Method::GET, "/audit", None, &[]).await;
    assert!(audit.text().contains("<span>Audit log</span></h1>"));
    assert_eq!(audit.text().matches("<h1").count(), 1);

    // On a phone only the nearest step back is kept, and the meta takes its
    // own line.
    assert!(
        automatic
            .text()
            .contains(".cr-crumbs > :nth-last-child(n+3) { display: none; }")
    );
}

#[tokio::test]
async fn an_empty_saved_views_section_says_how_to_fill_it() {
    let (_temporary, database) = test_database("views-nav-empty");
    database
        .create(
            "tasks",
            "one",
            &[Assignment::from_str("status=done").unwrap()],
            "",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let page = request(&app, Method::GET, "/tasks", None, &[]).await;
    assert!(page.text().contains(
        r#"<p class="cr-sidebar-label">Saved views</p><p class="cr-sidebar-hint">Use <strong>Save as view</strong> on any collection to keep it here.</p>"#
    ));
    // No collection is listed in either navigation list.
    let (navigation, _) = page.text().split_once("<main").unwrap();
    assert!(!navigation.contains(r#"href="/tasks""#));
}

#[tokio::test]
async fn the_view_index_labels_collections_and_counts_what_each_view_shows() {
    let (_temporary, database) = test_database("views-index");
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
    database.create("inbound-ratings", "one", &[], "").unwrap();
    database.create("zebras", "one", &[], "").unwrap();
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
    // A label sorts where it reads, not where its directory does.
    assert!(
        database
            .set_collection_label("zebras", Some("Animals"))
            .unwrap()
    );
    assert!(database.set_collection_icon("deals", Some("💼")).unwrap());
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // The document a browser is sent first leaves the numbers for the page to
    // fetch; `tests/view_index_http.rs` covers that. This is the document with
    // them in it, which is also what the region is cut from.
    let home = request(&app, Method::GET, "/?summary=inline", None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    let (sidebar, index) = home
        .text()
        .split_once(r#"<section class="cr-view-index mb-5" aria-label="Saved views">"#)
        .unwrap();
    // Saved views first, then every collection, each under its own heading.
    let (saved, collections) = index
        .split_once(r#"<section class="cr-view-index mb-5" aria-label="Collections">"#)
        .unwrap();
    assert!(saved.contains(">Open deals</h2>") && !saved.contains(">Deals</h2>"));
    assert!(collections.contains(">Deals</h2>") && !collections.contains(">Open deals</h2>"));
    assert!(!index.contains(r#"<span class="cr-pill">automatic</span>"#));
    assert!(!index.contains(r#"<span class="cr-pill">saved</span>"#));
    // The index names collections rather than their storage paths.
    assert!(!index.contains("records/deals"));
    assert!(index.contains("<h2 class=\"truncate\">Inbound ratings</h2>"));
    // Every collection count, and a saved view's count is the records it
    // matches rather than the size of its collection.
    let row = |title: &str| {
        let title = index.find(&format!(">{title}</h2>")).unwrap();
        let start = index[..title].rfind("<a ").unwrap();
        let end = index[start..].find("</a>").unwrap();
        &index[start..start + end]
    };
    assert!(row("Deals").contains("cr-view-count\">3<"));
    assert!(row("Open deals").contains("cr-view-count\">2<"));
    assert!(row("Open deals").contains("cr-view-source\">Deals<"));
    assert!(row("Inbound ratings").contains("cr-view-count\">1<"));
    assert!(row("Deals").contains("<time datetime="));
    assert!(home.text().contains(">5 records<"));
    // A saved view shares its collection's icon; the rest use the default.
    assert!(row("Deals").contains(">💼<"));
    assert!(row("Open deals").contains(">💼<"));
    assert!(row("Inbound ratings").contains(">🗃️<"));
    assert!(index.find(">Animals</h2>").unwrap() < index.find(">Deals</h2>").unwrap());
    // The sidebar holds the saved views, with their names and icons, and
    // leaves the collections to the index rather than repeating it.
    assert!(sidebar.contains("aria-hidden=\"true\">💼</span><span class=\"truncate\">Open deals<"));
    for collection in ["Deals", "Inbound ratings", "Animals"] {
        assert!(
            !sidebar.contains(&format!(">{collection}<")),
            "{collection} is in the sidebar"
        );
    }
    assert!(!sidebar.contains("cr-sidebar-label\">Collections<"));
    assert!(sidebar.contains(">🏠</span><span>All views<"));
    assert!(sidebar.contains(">📜</span><span>Audit log<"));

    // A collection's page is reached through the index, so the index's entry
    // is the one lit, without claiming to be the page.
    let collection = request(&app, Method::GET, "/deals", None, &[]).await;
    assert!(
        collection
            .text()
            .contains(r#"<a href="/" class="cr-sidebar-link is-active">"#)
    );
    assert!(
        collection
            .text()
            .contains(r#"<a href="/" class="is-active">"#)
    );
    assert!(!collection.text().contains(r#"aria-current="page""#));
    let record = request(&app, Method::GET, "/deals/records/alpha", None, &[]).await;
    assert!(
        record
            .text()
            .contains(r#"<a href="/" class="cr-sidebar-link is-active">"#)
    );
    // A saved view's own page lights its own entry instead.
    let saved_page = request(&app, Method::GET, "/open-deals", None, &[]).await;
    assert!(
        saved_page
            .text()
            .contains(r#"<a href="/" class="cr-sidebar-link">"#)
    );
    assert!(saved_page.text().contains(
        r#"<a href="/open-deals" class="cr-sidebar-link is-active" aria-current="page""#
    ));

    // A collection that cannot be read leaves a dash rather than an error
    // page: the index is how a reader reaches the view that explains it.
    fs::write(
        database.root().join("records/inbound-ratings/broken.md"),
        "---\n: [\n---\n",
    )
    .unwrap();
    let degraded = request(&app, Method::GET, "/?summary=inline", None, &[]).await;
    assert_eq!(degraded.status, StatusCode::OK);
    let degraded_index = degraded
        .text()
        .split_once(r#"aria-label="Collections""#)
        .unwrap()
        .1;
    let start = degraded_index.find(">Inbound ratings</h2>").unwrap();
    let broken_row = &degraded_index[start..start + degraded_index[start..].find("</a>").unwrap()];
    assert!(broken_row.contains("cr-view-count\"><span class=\"text-gray-400\">—<"));
    assert!(!degraded.text().contains(">5 records<"));

    // Clearing a label returns the sentence-cased directory name.
    assert!(database.set_collection_label("zebras", None).unwrap());
    let cleared = request(&app, Method::GET, "/zebras", None, &[]).await;
    assert!(cleared.text().contains("<span>Zebras</span></h1>"));
}

#[tokio::test]
async fn owners_can_browse_and_preview_the_filesystem_without_mutating_it() {
    let (temporary, database) = test_database("filesystem-browser");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let notes = database.root().join("notes");
    fs::create_dir(&notes).unwrap();
    let text = notes.join("unsafe # name.txt");
    fs::write(&text, "<script>alert('escaped')</script>\nhello").unwrap();
    let binary = notes.join("bytes.bin");
    fs::write(&binary, [0_u8, 1, 2, 255]).unwrap();
    let outside = temporary.path().join("outside.txt");
    fs::write(&outside, "visible above the database root").unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let home = request(&app, Method::GET, "/", None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(home.text().contains("href=\"/browse\""));
    assert!(home.text().contains("Files visible to the server process"));

    let root = request(&app, Method::GET, "/browse", None, &[]).await;
    assert_eq!(root.status, StatusCode::OK, "{}", root.text());
    assert!(root.text().contains("<span>All files</span></h1>"));
    assert!(root.text().contains("owner only"));
    assert!(root.text().contains("notes"));
    assert!(root.text().contains(".."));
    assert!(root.text().contains("hidden files included"));

    let directory = request(&app, Method::GET, &browse_uri(&notes), None, &[]).await;
    assert_eq!(directory.status, StatusCode::OK, "{}", directory.text());
    assert!(directory.text().contains("unsafe # name.txt"));
    assert!(directory.text().contains("bytes.bin"));
    assert!(
        root.text()
            .contains("<span class=\"cr-file-icon\" aria-hidden=\"true\">📁</span>notes<")
    );
    assert!(
        directory
            .text()
            .contains("<span class=\"cr-file-icon\" aria-hidden=\"true\">📄</span>bytes.bin<")
    );

    let file = request(&app, Method::GET, &browse_uri(&text), None, &[]).await;
    assert_eq!(file.status, StatusCode::OK, "{}", file.text());
    assert!(file.text().contains("text preview"));
    assert!(
        file.text()
            .contains("&lt;script&gt;alert('escaped')&lt;/script&gt;")
    );
    assert!(!file.text().contains("<script>alert('escaped')</script>"));

    let binary_file = request(&app, Method::GET, &browse_uri(&binary), None, &[]).await;
    assert_eq!(binary_file.status, StatusCode::OK, "{}", binary_file.text());
    assert!(binary_file.text().contains("binary · hex preview"));
    assert!(binary_file.text().contains("00000000  00 01 02 ff"));

    // The parent entry is intentionally not a database-root sandbox: an owner
    // can inspect the rest of the filesystem visible to the service account.
    let parent = request(&app, Method::GET, &browse_uri(temporary.path()), None, &[]).await;
    assert_eq!(parent.status, StatusCode::OK, "{}", parent.text());
    assert!(parent.text().contains("outside.txt"));

    let relative = request(&app, Method::GET, "/browse?path=notes", None, &[]).await;
    assert_eq!(relative.status, StatusCode::BAD_REQUEST);
    assert!(relative.text().contains("must be absolute"));

    // Looking changes nothing: the page itself answers only `GET`, and editing
    // and deleting are routes of their own.
    let post = request(&app, Method::POST, "/browse", None, &[]).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        fs::read_to_string(&text).unwrap(),
        "<script>alert('escaped')</script>\nhello"
    );
}

/// A directory with a README or a `SKILL.md` shows it beneath the listing, in
/// the same bounded, escaped panel opening the file would give, and text
/// previews wrap while hex dumps keep their columns.
#[tokio::test]
async fn directory_listings_show_file_times_and_sort_by_column_within_kind_groups() {
    use std::time::{Duration, SystemTime};

    let (_temporary, database) = test_database("filesystem-browser-sorting");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let skills = database.root().join("skills");
    fs::create_dir(&skills).unwrap();
    let day = Duration::from_secs(24 * 60 * 60);
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_780_000_000);
    // Name order, update order, and size order all disagree, so each sort is
    // visible in the listing.
    for (name, age_in_days, bytes) in [("alpha.md", 3, 30), ("beta.md", 1, 10), ("gamma.md", 2, 20)]
    {
        let file = fs::File::create(skills.join(name)).unwrap();
        file.set_len(bytes).unwrap();
        file.set_modified(base - day * age_in_days).unwrap();
    }
    for (name, age_in_days) in [("old-dir", 5), ("new-dir", 0)] {
        fs::create_dir(skills.join(name)).unwrap();
        fs::File::open(skills.join(name))
            .unwrap()
            .set_modified(base - day * age_in_days)
            .unwrap();
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let order = |html: &str, names: &[&str]| {
        let positions = names
            .iter()
            .map(|name| html.find(&format!("</span>{name}<")).unwrap())
            .collect::<Vec<_>>();
        positions.windows(2).all(|pair| pair[0] < pair[1])
    };
    let sorted = |field: &str, direction: &str| {
        format!(
            "{}&sort_field={field}&sort_direction={direction}",
            browse_uri(&skills)
        )
    };

    // Newest created first by default, like a view table.
    let listing = request(&app, Method::GET, &browse_uri(&skills), None, &[]).await;
    assert_eq!(listing.status, StatusCode::OK, "{}", listing.text());
    assert!(listing.text().contains(">Created<"));
    assert!(listing.text().contains(">Updated<"));
    assert!(listing.text().contains("aria-sort=\"descending\""));
    assert!(
        listing
            .text()
            .contains("aria-label=\"Sort by created ascending\"")
    );
    assert!(listing.text().contains("<time datetime=\"2026-05-28T"));

    // Updated, newest first: directories still lead, each group in order.
    let updated = request(&app, Method::GET, &sorted("updated", "desc"), None, &[]).await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.text());
    assert!(order(
        updated.text(),
        &["new-dir", "old-dir", "beta.md", "gamma.md", "alpha.md"]
    ));
    // The chosen order follows the reader into a directory, but the default
    // order's links stay canonical so a pin still recognizes them.
    let new_dir = skills.join("new-dir");
    assert!(updated.text().contains(&format!(
        "href=\"{}&amp;sort_field=updated&amp;sort_direction=desc\"",
        browse_uri(&new_dir).replace('&', "&amp;")
    )));
    assert!(
        listing
            .text()
            .contains(&format!("href=\"{}\"", browse_uri(&new_dir)))
    );

    let oldest = request(&app, Method::GET, &sorted("updated", "asc"), None, &[]).await;
    assert!(order(
        oldest.text(),
        &["old-dir", "new-dir", "alpha.md", "gamma.md", "beta.md"]
    ));
    let by_name = request(&app, Method::GET, &sorted("name", "desc"), None, &[]).await;
    assert!(order(
        by_name.text(),
        &["old-dir", "new-dir", "gamma.md", "beta.md", "alpha.md"]
    ));
    // Directories have no size, so the files carry the ordering.
    let by_size = request(&app, Method::GET, &sorted("size", "asc"), None, &[]).await;
    assert!(order(by_size.text(), &["beta.md", "gamma.md", "alpha.md"]));
    assert!(
        by_size
            .text()
            .contains("aria-label=\"Sort by size descending\"")
    );

    let unknown = request(&app, Method::GET, &sorted("type", "asc"), None, &[]).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn directories_preview_their_readme_and_skill_and_text_previews_wrap() {
    let (_temporary, database) = test_database("filesystem-readme");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let docs = database.root().join("docs");
    fs::create_dir(&docs).unwrap();
    // Lower case on disk: a code host matches README names without case.
    fs::write(
        docs.join("readme.md"),
        "# Docs\n<script>alert('readme')</script>\n",
    )
    .unwrap();
    fs::write(
        docs.join("README.txt"),
        "the plain-text README loses to Markdown",
    )
    .unwrap();
    fs::write(docs.join("data.bin"), [0_u8, 1, 2, 255]).unwrap();
    fs::write(
        docs.join("SKILL.md"),
        "---\nname: docs\n---\nskill instructions\n",
    )
    .unwrap();
    let skill_only = database.root().join("skill-only");
    fs::create_dir(&skill_only).unwrap();
    fs::write(skill_only.join("skill.md"), "a skill with no README").unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let listing = request(&app, Method::GET, &browse_uri(&docs), None, &[]).await;
    assert_eq!(listing.status, StatusCode::OK, "{}", listing.text());
    let text = listing.text();
    let table = text.find("data.bin").unwrap();
    let readme = text.find("id=\"readme\"").unwrap();
    assert!(table < readme, "the README renders beneath the listing");
    assert!(text.contains("&lt;script&gt;alert('readme')&lt;/script&gt;"));
    assert!(!text.contains("<script>alert('readme')</script>"));
    assert!(!text.contains("the plain-text README loses to Markdown"));
    // The README header opens the file itself.
    assert!(text[readme..].contains(&browse_uri(&docs.join("readme.md")).replace('&', "&amp;")));
    assert!(text[readme..].contains("cr-file-preview cr-file-preview-wrap"));
    // The skill follows the README rather than replacing it.
    let skill = text.find("id=\"skill\"").unwrap();
    assert!(readme < skill, "the SKILL.md renders after the README");
    assert!(text[skill..].contains("skill instructions"));

    let only = request(&app, Method::GET, &browse_uri(&skill_only), None, &[]).await;
    assert!(only.text().contains("id=\"skill\""));
    assert!(only.text().contains("a skill with no README"));
    assert!(!only.text().contains("id=\"readme\""));

    // Opening a text file wraps; opening a binary file keeps its hex columns.
    let file = request(
        &app,
        Method::GET,
        &browse_uri(&docs.join("README.txt")),
        None,
        &[],
    )
    .await;
    assert!(
        file.text()
            .contains("class=\"cr-file-preview cr-file-preview-wrap\"")
    );
    let binary = request(
        &app,
        Method::GET,
        &browse_uri(&docs.join("data.bin")),
        None,
        &[],
    )
    .await;
    assert!(binary.text().contains("class=\"cr-file-preview\""));
    assert!(
        !binary
            .text()
            .contains("class=\"cr-file-preview cr-file-preview-wrap\"")
    );

    // A directory with no README is just a listing.
    let root = request(&app, Method::GET, &browse_uri(database.root()), None, &[]).await;
    assert!(!root.text().contains("id=\"readme\""));
}

fn file_action_uri(route: &str, path: &Path, from: &Path) -> String {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("path", path.to_str().unwrap());
    serializer.append_pair("from", from.to_str().unwrap());
    format!("{route}?{}", serializer.finish())
}

fn expected_version(html: &str) -> &str {
    let marker = "name=\"_expected_version\" value=\"";
    let rest = html
        .split_once(marker)
        .unwrap_or_else(|| panic!("file version field missing from HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
}

/// The pencil on a file panel opens the file in a textarea — in place for htmx,
/// as a page of its own without it — and Save writes it back, refusing a file
/// that changed underneath the editor without losing what was typed.
#[tokio::test]
async fn owners_edit_a_text_file_and_save_it_back() {
    let (_temporary, database) = test_database("filesystem-edit");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let skills = database.root().join("skills");
    fs::create_dir(&skills).unwrap();
    let skill = skills.join("SKILL.md");
    // A leading blank line, which a textarea drops unless one is added for it.
    fs::write(&skill, "\n---\nname: docs\n---\nold <instructions>\n").unwrap();
    fs::write(skills.join("data.bin"), [0_u8, 1, 2, 255]).unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // The listing's SKILL.md panel offers Edit, in place, and Delete.
    let listing = request(&app, Method::GET, &browse_uri(&skills), None, &[]).await;
    assert_eq!(listing.status, StatusCode::OK, "{}", listing.text());
    let edit_uri = file_action_uri("/browse/edit", &skill, &skills);
    let panel = &listing.text()[listing.text().find("id=\"skill\"").unwrap()..];
    assert!(panel.contains(&format!(
        "href=\"{}\" hx-target=\"#skill\" hx-swap=\"innerHTML show:none\"",
        edit_uri.replace('&', "&amp;")
    )));
    assert!(panel.contains("aria-label=\"Edit SKILL.md\""));
    assert!(panel.contains(&format!(
        "href=\"{}\"",
        file_action_uri("/browse/delete", &skill, &skills).replace('&', "&amp;")
    )));

    // htmx asks for the panel alone and swaps it into the section.
    let fragment = request(
        &app,
        Method::GET,
        &edit_uri,
        None,
        &[("hx-request", "true"), ("hx-target", "skill")],
    )
    .await;
    assert_eq!(fragment.status, StatusCode::OK, "{}", fragment.text());
    // An editor in the middle of a page is not a page of its own.
    assert_eq!(fragment.headers["hx-push-url"], "false");
    assert!(
        fragment
            .text()
            .starts_with("<form method=\"post\" action=\"/browse/edit\"")
    );
    assert!(!fragment.text().contains("<html"));
    assert!(fragment.text().contains("id=\"skill-editor\""));

    // Without JavaScript the same URL is a page, whose textarea holds the file
    // exactly, escaped.
    let page = request(&app, Method::GET, &edit_uri, None, &[]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    assert!(!page.headers.contains_key("hx-push-url"));
    assert!(page.text().contains("<span>Edit</span></h1>"));
    assert!(page.text().contains(
        "name=\"contents\" spellcheck=\"false\" autofocus class=\"cr-file-editor\">\n\n---\nname: docs\n---\nold &lt;instructions&gt;\n</textarea>"
    ));
    assert!(page.text().contains("This file is inside the database"));
    let token = csrf(page.text()).to_owned();
    let version = expected_version(page.text()).to_owned();
    assert!(version.starts_with("sha256:"));

    // A textarea sends CRLF; a file written with line feeds keeps them. Save
    // returns to the directory, at the panel.
    let skill_path = skill.to_str().unwrap();
    let skills_path = skills.to_str().unwrap();
    let save = |contents: &'static str, version: String, token: String| {
        let app = app.clone();
        async move {
            request(
                &app,
                Method::POST,
                "/browse/edit",
                Some(form(&[
                    ("_csrf", &token),
                    ("path", skill_path),
                    ("from", skills_path),
                    ("_expected_version", &version),
                    ("contents", contents),
                ])),
                &[],
            )
            .await
        }
    };
    let saved = save(
        "\r\n---\r\nname: docs\r\n---\r\nnew instructions\r\n",
        version.clone(),
        token.clone(),
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.text());
    assert_eq!(
        saved.headers[header::LOCATION],
        format!("{}#skill", browse_uri(&skills)).as_str()
    );
    assert_eq!(
        fs::read_to_string(&skill).unwrap(),
        "\n---\nname: docs\n---\nnew instructions\n"
    );
    // The native form's second submission finds its text already saved.
    let again = save(
        "\r\n---\r\nname: docs\r\n---\r\nnew instructions\r\n",
        version.clone(),
        token.clone(),
    )
    .await;
    assert_eq!(again.status, StatusCode::SEE_OTHER, "{}", again.text());

    // A file that changed since it was opened is not overwritten, and the
    // editor comes back with what was typed.
    let stale = save("my lost work", version.clone(), token.clone()).await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert!(stale.text().contains("The file was not saved"));
    assert!(stale.text().contains("changed after it was opened"));
    assert!(stale.text().contains(">my lost work</textarea>"));
    assert!(stale.text().contains(&format!("value=\"{version}\"")));
    assert_eq!(
        fs::read_to_string(&skill).unwrap(),
        "\n---\nname: docs\n---\nnew instructions\n"
    );

    // A forged token writes nothing.
    let reopened = request(&app, Method::GET, &edit_uri, None, &[]).await;
    let current = expected_version(reopened.text()).to_owned();
    let forged = save("forged", current.clone(), "forged".to_owned()).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(
        fs::read_to_string(&skill)
            .unwrap()
            .contains("new instructions")
    );

    // A binary file offers no editor, and asking for one is refused.
    let binary = skills.join("data.bin");
    let binary_page = request(&app, Method::GET, &browse_uri(&binary), None, &[]).await;
    assert!(
        binary_page
            .text()
            .contains("title=\"A binary file cannot be edited here\"")
    );
    assert!(
        !binary_page
            .text()
            .contains(&file_action_uri("/browse/edit", &binary, &binary).replace('&', "&amp;"))
    );
    let binary_editor = request(
        &app,
        Method::GET,
        &file_action_uri("/browse/edit", &binary, &binary),
        None,
        &[],
    )
    .await;
    assert_eq!(binary_editor.status, StatusCode::UNPROCESSABLE_ENTITY);

    let relative = request(&app, Method::GET, "/browse/edit?path=skills", None, &[]).await;
    assert_eq!(relative.status, StatusCode::BAD_REQUEST);
}

/// Saving keeps what the file was: CRLF line endings and permission bits.
#[cfg(unix)]
#[tokio::test]
async fn saving_a_file_keeps_its_line_endings_and_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let (temporary, database) = test_database("filesystem-edit-preserve");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    // Outside the database, which the editor does not warn about.
    let notes = temporary.path().join("notes.txt");
    fs::write(&notes, "one\r\ntwo\r\n").unwrap();
    fs::set_permissions(&notes, fs::Permissions::from_mode(0o640)).unwrap();
    let notes = fs::canonicalize(&notes).unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let file = request(&app, Method::GET, &browse_uri(&notes), None, &[]).await;
    assert!(file.text().contains("id=\"file\""));
    assert!(file.text().contains("hx-target=\"#file\""));
    let edit_uri = file_action_uri("/browse/edit", &notes, &notes);
    let page = request(&app, Method::GET, &edit_uri, None, &[]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    assert!(!page.text().contains("This file is inside the database"));
    let notes_path = notes.to_str().unwrap();
    let saved = request(
        &app,
        Method::POST,
        "/browse/edit",
        Some(form(&[
            ("_csrf", csrf(page.text())),
            ("path", notes_path),
            ("from", notes_path),
            ("_expected_version", expected_version(page.text())),
            ("contents", "one\r\ntwo\r\nthree"),
        ])),
        &[],
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.text());
    // An opened file is its own page, so there is no panel to scroll to.
    assert_eq!(saved.headers[header::LOCATION], browse_uri(&notes).as_str());
    assert_eq!(fs::read(&notes).unwrap(), b"one\r\ntwo\r\nthree");
    assert_eq!(
        fs::metadata(&notes).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

/// The trash can asks first, on a page the server renders, then deletes the
/// file and returns to its directory. Only regular files are deleted.
#[tokio::test]
async fn owners_delete_a_file_after_confirming() {
    let (_temporary, database) = test_database("filesystem-delete");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let docs = database.root().join("docs");
    fs::create_dir(&docs).unwrap();
    let readme = docs.join("README.md");
    fs::write(&readme, "# Going away\n").unwrap();
    let nested = docs.join("nested");
    fs::create_dir(&nested).unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let confirm_uri = file_action_uri("/browse/delete", &readme, &docs);
    let confirm = request(&app, Method::GET, &confirm_uri, None, &[]).await;
    assert_eq!(confirm.status, StatusCode::OK, "{}", confirm.text());
    let text = confirm.text();
    assert!(text.contains("Delete this file?"));
    assert!(text.contains("<code class=\"cr-filter-tag\">README.md</code> (13 B)"));
    assert!(text.contains("not moved to a trash"));
    assert!(text.contains("It is inside the database"));
    assert!(text.contains("action=\"/browse/delete\""));
    // Cancel returns to the panel the trash can was on.
    assert!(text.contains(&format!(
        "href=\"{}#readme\" class=\"cr-button\">Cancel<",
        browse_uri(&docs).replace('&', "&amp;")
    )));
    // Asking deleted nothing.
    assert!(readme.exists());

    let token = csrf(text).to_owned();
    let delete = |path: String, token: String| {
        let app = app.clone();
        async move {
            request(
                &app,
                Method::POST,
                "/browse/delete",
                Some(form(&[("_csrf", &token), ("path", &path)])),
                &[],
            )
            .await
        }
    };
    let readme_path = readme.to_str().unwrap().to_owned();
    let forged = delete(readme_path.clone(), "forged".to_owned()).await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert!(readme.exists());

    let deleted = delete(readme_path.clone(), token.clone()).await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER, "{}", deleted.text());
    assert_eq!(
        deleted.headers[header::LOCATION],
        browse_uri(&docs).as_str()
    );
    assert!(!readme.exists());
    // A second submission of the native form has nothing left to do.
    let again = delete(readme_path, token.clone()).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);

    // A directory is not a file: neither asked about nor deleted.
    let directory = request(
        &app,
        Method::GET,
        &file_action_uri("/browse/delete", &nested, &docs),
        None,
        &[],
    )
    .await;
    assert_eq!(directory.status, StatusCode::UNPROCESSABLE_ENTITY);
    let refused = delete(nested.to_str().unwrap().to_owned(), token.clone()).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert!(nested.is_dir());

    #[cfg(unix)]
    {
        // Nor is a link followed to whatever it points at.
        let target = docs.join("target.txt");
        fs::write(&target, "kept").unwrap();
        let link = docs.join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refused = delete(link.to_str().unwrap().to_owned(), token).await;
        assert_eq!(refused.status, StatusCode::CONFLICT);
        assert!(fs::symlink_metadata(&link).unwrap().is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "kept");
    }
}

/// A README the server cannot read is reported in place rather than taking the
/// directory listing down with it.
#[cfg(unix)]
#[tokio::test]
async fn an_unreadable_readme_does_not_hide_the_listing() {
    use std::os::unix::fs::PermissionsExt;

    let (_temporary, database) = test_database("filesystem-readme-unreadable");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let docs = database.root().join("docs");
    fs::create_dir(&docs).unwrap();
    let readme = docs.join("README.md");
    fs::write(&readme, "contents-the-server-cannot-read").unwrap();
    fs::write(docs.join("notes.txt"), "public").unwrap();
    fs::set_permissions(&readme, fs::Permissions::from_mode(0o000)).unwrap();
    // Permission bits do not bind a superuser, and then there is nothing to
    // test: the README is simply readable.
    if fs::read(&readme).is_ok() {
        return;
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    let listing = request(&app, Method::GET, &browse_uri(&docs), None, &[]).await;
    fs::set_permissions(&readme, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(listing.status, StatusCode::OK, "{}", listing.text());
    assert!(listing.text().contains("notes.txt"));
    assert!(listing.text().contains("could not be previewed"));
    // Not the word "private": on macOS temporary directories canonicalize under
    // `/private`, and the page names its own location.
    assert!(!listing.text().contains("contents-the-server-cannot-read"));
}

/// The sidebar's Browse section: "All files", then pinned locations, each an
/// ordinary link an owner can add and remove from the page it points at.
#[tokio::test]
async fn owners_pin_browse_locations_to_their_own_sidebar_section() {
    let (temporary, database) = test_database("filesystem-pins");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let docs = database.root().join("docs");
    fs::create_dir(&docs).unwrap();
    let outside = temporary.path().join("notes.txt");
    fs::write(&outside, "outside the database").unwrap();
    database
        .pin(outside.to_str().unwrap(), Some("Notes"))
        .unwrap();
    database.pin("not-yet-created", None).unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();

    // A section of its own, ahead of Internal, which keeps only Users.
    let home = request(&app, Method::GET, "/", None, &[]).await;
    let text = home.text();
    let browse = text.find("cr-sidebar-label\">Browse<").unwrap();
    let internal = text.find("cr-sidebar-label\">Internal<").unwrap();
    assert!(browse < internal);
    let section = &text[browse..internal];
    assert!(section.contains("All files"));
    assert!(section.contains(">Notes<"));
    // Linked by canonical location, which on macOS differs from the temporary
    // path as spelled (`/var` is a link to `/private/var`).
    let canonical_outside = fs::canonicalize(&outside).unwrap();
    assert!(section.contains(&browse_uri(&canonical_outside).replace('&', "&amp;")));
    assert!(section.contains(">not-yet-created<"));
    assert!(section.contains(">missing<"));
    // Internal ends where the sidebar's primary navigation does; the mobile
    // strip further down lists "All files" too.
    let internal_section = &text[internal..internal + text[internal..].find("</nav>").unwrap()];
    assert!(internal_section.contains(">Users<"));
    assert!(!internal_section.contains("All files"));

    // Browsing somewhere unpinned: "All files" is the active entry, and the page
    // offers to pin itself.
    let page = request(&app, Method::GET, &browse_uri(&docs), None, &[]).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.text());
    assert!(page.text().contains("Pin to sidebar"));
    let token = csrf(page.text()).to_owned();
    let docs_path = docs.to_str().unwrap();
    let pinned = request(
        &app,
        Method::POST,
        "/browse/pin",
        Some(form(&[
            ("_csrf", &token),
            ("path", docs_path),
            ("from", docs_path),
        ])),
        &[],
    )
    .await;
    assert_eq!(pinned.status, StatusCode::SEE_OTHER, "{}", pinned.text());
    assert_eq!(pinned.headers[header::LOCATION], browse_uri(&docs).as_str());
    assert_eq!(database.pins().unwrap()[2].path, "docs");

    // The pinned page is now the active entry, and offers to unpin by the
    // stored spelling.
    let page = request(&app, Method::GET, &browse_uri(&docs), None, &[]).await;
    let text = page.text();
    let href = browse_uri(&docs).replace('&', "&amp;");
    assert!(text.contains(&format!(
        "href=\"{href}\" class=\"cr-sidebar-link is-active\""
    )));
    assert!(
        !text.contains(
            "class=\"cr-sidebar-link is-active\" aria-current=\"page\" title=\"Every file"
        )
    );
    assert!(text.contains("name=\"path\" value=\"docs\""));
    let unpinned = request(
        &app,
        Method::POST,
        "/browse/unpin",
        Some(form(&[
            ("_csrf", &token),
            ("path", "docs"),
            ("from", docs_path),
        ])),
        &[],
    )
    .await;
    assert_eq!(unpinned.status, StatusCode::SEE_OTHER);
    assert_eq!(database.pins().unwrap().len(), 2);
    // A second submission of the same native form has nothing left to do.
    let again = request(
        &app,
        Method::POST,
        "/browse/unpin",
        Some(form(&[
            ("_csrf", &token),
            ("path", "docs"),
            ("from", docs_path),
        ])),
        &[],
    )
    .await;
    assert_eq!(again.status, StatusCode::SEE_OTHER);

    // Refusals: a forged token, and a return address that is not a browse path.
    let forged = request(
        &app,
        Method::POST,
        "/browse/pin",
        Some(form(&[
            ("_csrf", "forged"),
            ("path", docs_path),
            ("from", docs_path),
        ])),
        &[],
    )
    .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    let elsewhere = request(
        &app,
        Method::POST,
        "/browse/pin",
        Some(form(&[
            ("_csrf", &token),
            ("path", docs_path),
            ("from", "https://example.com"),
        ])),
        &[],
    )
    .await;
    assert_eq!(elsewhere.status, StatusCode::BAD_REQUEST);
    assert_eq!(database.pins().unwrap().len(), 2);
}

/// A hand-edited pins file that no longer parses must not take the UI down.
#[tokio::test]
async fn an_invalid_pins_file_is_reported_in_the_sidebar_not_on_every_page() {
    let (_temporary, database) = test_database("filesystem-pins-invalid");
    let database = database.with_actor("Owner <owner@example.com>").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    fs::write(database.root().join(".cr/pins.yaml"), "pins: [unclosed").unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    for path in ["/", "/browse"] {
        let page = request(&app, Method::GET, path, None, &[]).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.text());
        assert!(page.text().contains("All files"));
        assert!(page.text().contains("Pins unavailable"));
    }
}

/// Without RBAC there is nothing in the internal registry to show, so the page
/// stays reachable but unlinked and says how to bootstrap access control. The
/// more sensitive filesystem browser is absent until RBAC can identify an
/// actual database owner.
#[tokio::test]
async fn the_internal_users_page_is_unlinked_until_access_control_exists() {
    let (_temporary, database) = test_database("views-internal-users");
    database.create("deals", "one", &[], "").unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let home = request(&app, Method::GET, "/", None, &[]).await;
    assert_eq!(home.status, StatusCode::OK);
    assert!(!home.text().contains("href=\"/users\""));
    assert!(!home.text().contains("href=\"/browse\""));

    let browse = request(&app, Method::GET, "/browse", None, &[]).await;
    assert_eq!(browse.status, StatusCode::NOT_FOUND);

    let users = request(&app, Method::GET, "/users", None, &[]).await;
    assert_eq!(users.status, StatusCode::OK, "{}", users.text());
    assert!(users.text().contains("no registered principals"));
    assert!(users.text().contains("cr access init"));

    // Pinning belongs to the browser, so it is absent with it.
    let pin = request(
        &app,
        Method::POST,
        "/browse/pin",
        Some(form(&[("_csrf", "x"), ("path", "/tmp"), ("from", "/tmp")])),
        &[],
    )
    .await;
    assert_eq!(pin.status, StatusCode::NOT_FOUND);
    assert!(!home.text().contains("All files"));

    // So are editing and deleting files.
    for (method, uri) in [
        (Method::GET, "/browse/edit?path=%2Ftmp%2Fx"),
        (Method::POST, "/browse/edit"),
        (Method::GET, "/browse/delete?path=%2Ftmp%2Fx"),
        (Method::POST, "/browse/delete"),
    ] {
        let response = request(
            &app,
            method,
            uri,
            Some(form(&[("_csrf", "x"), ("path", "/tmp/x")])),
            &[],
        )
        .await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn view_routes_respect_api_authentication_and_return_html_errors() {
    let (_temporary, database) = test_database("views-auth");
    database.create("deals", "one", &[], "").unwrap();
    let app = router(
        database,
        ServerConfig {
            api_token: Some("secret".into()),
            ..ServerConfig::default()
        },
    )
    .unwrap();

    let health = request(&app, Method::GET, "/health", None, &[]).await;
    assert_eq!(health.status, StatusCode::OK);
    let unauthorized = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    assert!(unauthorized.text().contains("unauthorized"));
    let unauthorized_audit = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(unauthorized_audit.status, StatusCode::UNAUTHORIZED);

    let authorized = request(
        &app,
        Method::GET,
        "/deals",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(authorized.status, StatusCode::OK);
    assert!(authorized.text().starts_with("<!DOCTYPE html>"));

    let missing = request(
        &app,
        Method::GET,
        "/missing-view",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert!(missing.text().contains("Request could not be completed"));

    let invalid_query = request(
        &app,
        Method::GET,
        "/deals?filter_field=status",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(invalid_query.status, StatusCode::BAD_REQUEST);
    assert!(invalid_query.text().contains("one matching filter_value"));

    let invalid_operators = request(
        &app,
        Method::GET,
        "/deals?filter_field=status&filter_operator=eq&filter_operator=ne&filter_value=open",
        None,
        &[("authorization", "Bearer secret")],
    )
    .await;
    assert_eq!(invalid_operators.status, StatusCode::BAD_REQUEST);
    assert!(
        invalid_operators
            .text()
            .contains("one matching filter_operator")
    );
}

/// Server-rendered error pages are redacted exactly like the JSON API, and
/// carry the same request ID so a reader can quote it.
#[tokio::test]
async fn html_error_pages_are_redacted_and_carry_a_request_id() {
    let (_temporary, database) = test_database("views-errors");
    let root = database.root().display().to_string();
    database.create("deals", "alpha", &[], "Alpha\n").unwrap();
    fs::create_dir(database.root().join("records/deals/broken.md")).unwrap();
    #[cfg(unix)]
    {
        let outside = database.root().join("outside.md");
        fs::write(&outside, "---\nstatus: leaked\n---\n").unwrap();
        std::os::unix::fs::symlink(&outside, database.root().join("records/deals/linked.md"))
            .unwrap();
    }
    let app = router(database, ServerConfig::default()).unwrap();

    #[allow(unused_mut)]
    let mut cases = vec![
        (
            "/missing-view",
            StatusCode::NOT_FOUND,
            "view 'missing-view'",
        ),
        (
            "/deals/records/nope",
            StatusCode::NOT_FOUND,
            "record deals/nope does not exist",
        ),
        (
            "/deals/records/broken",
            StatusCode::CONFLICT,
            "record deals/broken is not a regular file",
        ),
    ];
    #[cfg(unix)]
    cases.push((
        "/deals/records/linked",
        StatusCode::CONFLICT,
        "is stored behind a symbolic link",
    ));

    for (uri, status, expected) in cases {
        let response = request(&app, Method::GET, uri, None, &[]).await;
        assert_eq!(response.status, status, "{uri}");
        let text = response.text();
        assert!(text.contains("Request could not be completed"), "{uri}");
        assert!(text.contains(expected), "{uri}: {text}");
        assert!(!text.contains(&root), "{uri} leaked the database root");
        assert!(!text.contains("os error"), "{uri} leaked an OS error");
        assert!(!text.contains(" at /"), "{uri} leaked a filesystem path");

        let request_id = response
            .headers
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            text.contains(&format!("Request ID {request_id}")),
            "{uri} did not show its request ID"
        );
    }
}

/// An HTML failure nobody can act on still says nothing beyond a request ID.
#[tokio::test]
async fn unclassified_html_failures_stay_generic() {
    let (_temporary, database) = test_database("views-internal");
    let root = database.root().display().to_string();
    fs::write(
        database
            .root()
            .join(".cr/audit/segments/00000000000000000001.jsonl"),
        "{\"hash\":\"sha256:none\",\"payload\":{}}",
    )
    .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let response = request(&app, Method::GET, "/audit", None, &[]).await;
    assert_eq!(response.status, StatusCode::INTERNAL_SERVER_ERROR);
    let text = response.text();
    assert!(text.contains("quote the request ID"), "{text}");
    assert!(!text.contains(&root), "leaked the database root");
    assert!(!text.contains("truncated tail"), "leaked internal context");
}
