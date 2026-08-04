mod common;

use std::fs;

use common::{run_failure, run_success, TestDatabase};
use serde_json::Value;

#[test]
fn saved_views_are_file_backed_and_override_automatic_collection_pages() {
    let database = TestDatabase::new("views-cli");
    run_success(
        database
            .command()
            .args(["create", "deals", "acme", "--set", "status=open"]),
    );

    let automatic: Value = serde_json::from_str(&run_success(
        database.command().args(["view", "show", "deals", "--json"]),
    ))
    .unwrap();
    assert_eq!(automatic["collection"], "deals");
    assert_eq!(automatic["saved"], false);
    assert_eq!(automatic["layout"], "table");
    assert!(automatic["group_by"].is_null());
    assert_eq!(automatic["page_size"], 50);

    assert_eq!(
        run_success(database.command().args([
            "view",
            "create",
            "open-deals",
            "--collection",
            "deals",
            "--title",
            "Open deals",
            "--where",
            "status=open",
            "--column",
            "name",
            "--column",
            "owner.email",
            "--layout",
            "kanban",
            "--group-by",
            "stage",
            "--page-size",
            "25",
        ])),
        "/open-deals\n"
    );

    let stored = fs::read_to_string(database.root.join(".cr/views/open-deals.yaml")).unwrap();
    assert!(stored.contains("version: 1"));
    assert!(stored.contains("title: Open deals"));
    assert!(stored.contains("collection: deals"));
    assert!(stored.contains("- status=open"));
    assert!(stored.contains("- owner.email"));
    assert!(stored.contains("layout: kanban"));
    assert!(stored.contains("group_by: stage"));

    let shown: Value = serde_json::from_str(&run_success(database.command().args([
        "view",
        "show",
        "open-deals",
        "--json",
    ])))
    .unwrap();
    assert_eq!(shown["name"], "open-deals");
    assert_eq!(shown["title"], "Open deals");
    assert_eq!(shown["filters"], serde_json::json!(["status=open"]));
    assert_eq!(shown["columns"], serde_json::json!(["name", "owner.email"]));
    assert_eq!(shown["layout"], "kanban");
    assert_eq!(shown["group_by"], "stage");
    assert_eq!(shown["page_size"], 25);
    assert_eq!(shown["saved"], true);

    let listed: Value = serde_json::from_str(&run_success(
        database.command().args(["view", "list", "--json"]),
    ))
    .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 2);
    assert!(listed
        .as_array()
        .unwrap()
        .iter()
        .any(|view| view["name"] == "deals" && view["saved"] == false));
    assert!(listed
        .as_array()
        .unwrap()
        .iter()
        .any(|view| view["name"] == "open-deals" && view["saved"] == true));
}

#[test]
fn view_cli_rejects_invalid_duplicate_reserved_and_malformed_definitions() {
    let database = TestDatabase::new("views-cli-errors");

    let invalid_filter = run_failure(database.command().args([
        "view",
        "create",
        "bad-filter",
        "--collection",
        "deals",
        "--where",
        "status",
    ]));
    assert!(invalid_filter.contains("invalid filter"));

    let invalid_column = run_failure(database.command().args([
        "view",
        "create",
        "bad-column",
        "--collection",
        "deals",
        "--column",
        "owner..email",
    ]));
    assert!(invalid_column.contains("invalid column"));

    let invalid_page_size = run_failure(database.command().args([
        "view",
        "create",
        "bad-page",
        "--collection",
        "deals",
        "--page-size",
        "0",
    ]));
    assert!(invalid_page_size.contains("page_size must be between"));

    let missing_group = run_failure(database.command().args([
        "view",
        "create",
        "missing-group",
        "--collection",
        "deals",
        "--layout",
        "kanban",
    ]));
    assert!(missing_group.contains("requires group_by"));

    let table_group = run_failure(database.command().args([
        "view",
        "create",
        "table-group",
        "--collection",
        "deals",
        "--group-by",
        "stage",
    ]));
    assert!(table_group.contains("only valid for the kanban layout"));

    let reserved =
        run_failure(
            database
                .command()
                .args(["view", "create", "api", "--collection", "deals"]),
        );
    assert!(reserved.contains("reserved"));

    run_success(
        database
            .command()
            .args(["view", "create", "open-deals", "--collection", "deals"]),
    );
    let duplicate = run_failure(database.command().args([
        "view",
        "create",
        "open-deals",
        "--collection",
        "deals",
    ]));
    assert!(duplicate.contains("could not create view 'open-deals'"));

    fs::write(
        database.root.join(".cr/views/future.yaml"),
        "version: 2\ntitle: Future\ncollection: deals\n",
    )
    .unwrap();
    let future = run_failure(
        database
            .command()
            .args(["view", "show", "future", "--json"]),
    );
    assert!(future.contains("unsupported format version 2"));

    fs::write(
        database.root.join(".cr/views/unknown.yaml"),
        "version: 1\ntitle: Unknown\ncollection: deals\nsurprise: true\n",
    )
    .unwrap();
    let unknown = run_failure(
        database
            .command()
            .args(["view", "show", "unknown", "--json"]),
    );
    assert!(unknown.contains("unknown field"));
}
