use std::{fs, str::FromStr};

use axum::{
    body::Body,
    http::{header, HeaderMap, Method, Request, StatusCode},
    Router,
};
use cr::{
    server::{router, ServerConfig},
    Assignment, AuditAction, AuditSource, Database, ViewLayout, ViewPredicateMatch,
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

fn csrf(html: &str) -> &str {
    let marker = "name=\"_csrf\" value=\"";
    let rest = html
        .split_once(marker)
        .unwrap_or_else(|| panic!("CSRF field missing from HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
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
    assert!(home.text().contains("data-design-system=\"cr-clean\""));

    let automatic = request(&app, Method::GET, "/deals", None, &[]).await;
    assert_eq!(automatic.status, StatusCode::OK);
    assert!(automatic
        .text()
        .contains("https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"));
    assert!(automatic.text().contains("alpha"));
    assert!(automatic.text().contains("beta"));
    assert!(automatic.text().contains("href=\"/deals/records/alpha\""));
    assert!(automatic.text().contains("data-filter-builder=\"true\""));
    assert!(automatic.text().contains("data-view-search=\"true\""));
    assert!(automatic.text().contains("aria-label=\"Submit search\""));
    assert!(automatic
        .text()
        .contains("data-filter-disclosure=\"true\" data-active-filters=\"0\""));
    assert!(automatic.text().contains("data-filter-panel=\"true\""));
    let search_position = automatic.text().find("data-view-search=\"true\"").unwrap();
    let filter_position = automatic
        .text()
        .find("data-filter-disclosure=\"true\"")
        .unwrap();
    let new_record_position = automatic.text().find("href=\"/deals/new\"").unwrap();
    assert!(search_position < filter_position && filter_position < new_record_position);
    assert!(automatic.text().contains("+ Add condition"));
    assert!(automatic.text().contains("data-close-filter=\"true\""));
    assert!(automatic.text().contains("All conditions match"));
    assert!(automatic.text().contains("name=\"filter_match\""));
    assert!(automatic.text().contains("Any condition matches"));
    assert!(automatic.text().contains("aria-label=\"Sort by\""));
    assert!(automatic.text().contains("aria-label=\"Sort direction\""));
    assert!(automatic.text().contains("aria-label=\"Visible columns\""));
    assert!(automatic
        .text()
        .contains("name=\"columns\" value=\"custom\""));
    assert!(automatic
        .text()
        .contains("name=\"column\" value=\"name\" checked"));
    assert!(automatic.text().contains("Missing values stay last"));
    assert!(automatic.text().contains("Sort by Value ascending"));
    assert!(automatic.text().contains("md:grid-cols-2 xl:grid-cols-12"));
    assert!(automatic
        .text()
        .contains("md:col-span-2 xl:col-span-1 xl:justify-self-end"));
    assert!(automatic
        .text()
        .contains("&lt;script&gt;alert('x')&lt;/script&gt;"));
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
    assert!(browser_pipeline_page.text().contains("Kanban grouped by"));
    assert!(browser_pipeline_page
        .text()
        .contains("data-kanban-board=\"true\""));

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
    assert!(missing_group
        .text()
        .contains("Kanban layout must provide group_by"));

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
    assert!(sorted.text().contains("value=\"asc\" selected"));
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
    assert!(sorted_page
        .text()
        .contains("sort_field=value&amp;sort_direction=asc&amp;limit=1&amp;offset=1"));

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
    assert!(projected.text().contains("2 shown"));
    assert!(projected.text().contains("Sort by Name ascending"));
    assert!(projected.text().contains("Sort by Value ascending"));
    assert!(!projected.text().contains("Sort by Status ascending"));
    assert!(projected.text().contains(
        "sort_field=name&amp;sort_direction=asc&amp;columns=custom&amp;column=name&amp;column=value"
    ));
    assert!(projected
        .text()
        .contains("columns=custom&amp;column=name&amp;column=value&amp;limit=1&amp;offset=1"));

    let empty_projection = request(&app, Method::GET, "/deals?columns=custom", None, &[]).await;
    assert_eq!(empty_projection.status, StatusCode::BAD_REQUEST);
    assert!(empty_projection
        .text()
        .contains("select at least one visible column"));

    let unknown_projection = request(
        &app,
        Method::GET,
        "/deals?columns=custom&column=unknown",
        None,
        &[],
    )
    .await;
    assert_eq!(unknown_projection.status, StatusCode::BAD_REQUEST);
    assert!(unknown_projection
        .text()
        .contains("column 'unknown' is not available"));

    let duplicate_projection = request(
        &app,
        Method::GET,
        "/deals?columns=custom&column=name&column=name",
        None,
        &[],
    )
    .await;
    assert_eq!(duplicate_projection.status, StatusCode::BAD_REQUEST);
    assert!(duplicate_projection
        .text()
        .contains("cannot be selected more than once"));

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
    assert!(greater_than
        .text()
        .contains("data-filter-disclosure=\"true\" data-active-filters=\"1\""));
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
    assert!(empty.text().contains("No value needed"));
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
    assert!(any.text().contains("value=\"any\" selected"));
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
    assert!(any_first_page
        .text()
        .contains("filter_match=any&amp;filter_field=status"));
    assert!(any_first_page.text().contains("limit=1&amp;offset=1"));

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

    let first_page = request(&app, Method::GET, "/deals?limit=1", None, &[]).await;
    assert!(first_page.text().contains("alpha"));
    assert!(!first_page.text().contains("beta"));
    assert!(first_page.text().contains("limit=1&amp;offset=1"));
    let second_page = request(&app, Method::GET, "/deals?limit=1&offset=1", None, &[]).await;
    assert!(!second_page.text().contains("alpha"));
    assert!(second_page.text().contains("beta"));
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
    assert!(board.text().contains("Kanban grouped by"));
    assert!(board.text().contains("data-kanban-board=\"true\""));
    assert!(board.text().contains("draggable=\"true\""));
    assert!(board.text().contains("form.submit()"));
    assert!(board.text().contains("Move alpha to"));
    assert!(board.text().contains("score&gt;=40"));
    assert!(!board.text().contains("/pipeline/records/excluded"));
    assert!(board.text().contains("value=\"score\" selected"));
    assert!(board.text().contains("value=\"asc\" selected"));
    assert!(board.text().contains("Unassigned"));
    assert!(board
        .text()
        .contains("&lt;script&gt;alert('x')&lt;/script&gt;"));
    assert!(!board.text().contains("<script>alert('x')</script>"));
    let qualification = board.text().find(">qualification<").unwrap();
    let interview = board.text().find(">interview<").unwrap();
    let offer = board.text().find(">offer<").unwrap();
    let won = board.text().find(">won<").unwrap();
    let lost = board.text().find(">lost<").unwrap();
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
    assert!(projected_board.text().contains("1 shown"));
    assert!(projected_board.text().contains(">name</dt>"));
    assert!(!projected_board.text().contains(">owner</dt>"));
    assert!(!projected_board.text().contains(">score</dt>"));

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
    assert!(typed_filter
        .text()
        .contains("name=\"filter_value\" data-filter-value=\"true\""));
    assert!(typed_filter
        .text()
        .contains("value=\"offer\" selected>Offer</option>"));
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
        .audit_recent(1, Some("deals"), Some("alpha"))
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
    assert!(database
        .get("deals", "beta")
        .unwrap()
        .field("stage")
        .unwrap()
        .is_none());
    assert_eq!(
        database
            .audit_recent(1, Some("deals"), Some("beta"))
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
        .audit_recent(1, Some("deals"), Some("acme"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Create);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "sales@example.com");

    let edit_page = request(&app, Method::GET, "/open-deals/records/acme", None, &[]).await;
    assert_eq!(edit_page.status, StatusCode::OK);
    assert!(edit_page.text().contains("Schema-powered"));
    assert!(edit_page.text().contains("name=\"attribute.status\""));
    assert!(edit_page
        .text()
        .contains("value=\"open\" selected>Open</option>"));
    assert!(edit_page.text().contains("name=\"attribute.value\""));
    assert!(edit_page.text().contains("value=\"12500\""));
    assert!(edit_page.text().contains("Audit history"));
    assert!(edit_page.text().contains("sales@example.com"));
    assert!(edit_page.text().contains("create"));
    assert!(edit_page
        .text()
        .contains("/audit?collection=deals&amp;id=acme"));
    let edit_token = csrf(edit_page.text()).to_owned();

    let invalid = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", &edit_token),
            ("front_matter", "status: lost\nvalue: 12500\n"),
            ("markdown", "Invalid attempt"),
        ])),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(invalid.text().contains("does not match schema"));
    assert_eq!(database.get("deals", "acme").unwrap().body, "First contact");
    assert_eq!(database.audit_recent(10, None, None).unwrap().len(), 1);

    let bad_csrf = request(
        &app,
        Method::POST,
        "/open-deals/records/acme",
        Some(form(&[
            ("_csrf", "wrong"),
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
        .audit_recent(1, Some("deals"), Some("acme"))
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
    let delete_token = csrf(delete_page.text()).to_owned();
    let deleted = request(
        &app,
        Method::POST,
        "/open-deals/records/acme/delete",
        Some(form(&[("_csrf", &delete_token)])),
        &[],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::SEE_OTHER);
    assert!(database.get("deals", "acme").is_err());
    let audit = database
        .audit_recent(1, Some("deals"), Some("acme"))
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
    "budget": { "type": "number", "minimum": 0, "maximum": 1000000 },
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
    assert!(new_page.text().contains("Schema-powered"));
    assert!(new_page
        .text()
        .contains("name=\"_form_mode\" value=\"structured\""));
    assert!(new_page.text().contains("Candidate &lt;name&gt;"));
    assert!(new_page
        .text()
        .contains("Displayed &lt;script&gt;alert('schema')&lt;/script&gt; name"));
    assert!(!new_page.text().contains("<script>alert('schema')</script>"));
    assert!(new_page
        .text()
        .contains("type=\"email\" name=\"attribute.email\""));
    assert!(new_page
        .text()
        .contains("type=\"number\" step=\"any\" name=\"attribute.budget\""));
    assert!(new_page
        .text()
        .contains("select id=\"field-stage\" name=\"attribute.stage\""));
    assert!(new_page.text().contains("Single select"));
    assert!(new_page.text().contains("Multi-select"));
    assert!(new_page
        .text()
        .contains("type=\"checkbox\" name=\"attribute.tags\""));
    assert!(new_page.text().contains("Structured YAML"));
    assert!(new_page.text().contains("+ Additional attributes"));
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
        .audit_recent(1, Some("candidates"), Some("jane-doe"))
        .unwrap();
    assert_eq!(audit[0].payload.action, AuditAction::Create);
    assert_eq!(audit[0].payload.source, AuditSource::Api);
    assert_eq!(audit[0].payload.actor, "recruiter@example.com");

    let edit_page = request(&app, Method::GET, "/candidates/records/jane-doe", None, &[]).await;
    assert_eq!(edit_page.status, StatusCode::OK);
    assert!(edit_page.text().contains("value=\"jane@example.com\""));
    assert!(edit_page
        .text()
        .contains("value=\"interview\" selected>Interview</option>"));
    assert!(edit_page
        .text()
        .contains("name=\"attribute.tags\" value=\"rust\" checked"));
    assert!(edit_page.text().contains("source: referral"));

    let invalid = request(
        &app,
        Method::POST,
        "/candidates/records/jane-doe",
        Some(form(&[
            ("_csrf", &token),
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
            .audit_recent(10, Some("candidates"), Some("jane-doe"))
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
    assert!(global.text().contains("Global audit log"));
    assert!(global.text().contains("contacts/beta"));
    assert!(global.text().contains("deals/alpha"));
    assert!(global.text().contains("sales@example.com"));
    assert!(global.text().contains("/attributes/stage"));
    assert!(global.text().contains("proposal"));
    assert!(global.text().contains("won"));
    assert!(global
        .text()
        .contains("&lt;script&gt;alert('historical')&lt;/script&gt;"));
    assert!(!global
        .text()
        .contains("<script>alert('historical')</script>"));
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
    assert!(invalid_operators
        .text()
        .contains("one matching filter_operator"));
}

/// Server-rendered error pages are redacted exactly like the JSON API, and
/// carry the same request ID so a reader can quote it.
#[tokio::test]
async fn html_error_pages_are_redacted_and_carry_a_request_id() {
    let (_temporary, database) = test_database("views-errors");
    let root = database.root().display().to_string();
    database.create("deals", "alpha", &[], "Alpha\n").unwrap();
    fs::create_dir(database.root().join("records/deals/broken.md")).unwrap();
    let app = router(database, ServerConfig::default()).unwrap();

    let cases = [
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
            StatusCode::INTERNAL_SERVER_ERROR,
            "quote the request ID",
        ),
    ];

    for (uri, status, expected) in cases {
        let response = request(&app, Method::GET, uri, None, &[]).await;
        assert_eq!(response.status, status, "{uri}");
        let text = response.text();
        assert!(text.contains("Request could not be completed"), "{uri}");
        assert!(text.contains(expected), "{uri}: {text}");
        assert!(!text.contains(&root), "{uri} leaked the database root");
        assert!(!text.contains("os error"), "{uri} leaked an OS error");
        assert!(
            !text.contains("must be a regular file"),
            "{uri} leaked internal context"
        );

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
