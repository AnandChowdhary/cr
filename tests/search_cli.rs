mod common;

use std::{fs, process::Command};

use common::{TestDatabase, binary, run_failure, run_success};
use serde_json::Value;

#[test]
fn search_spans_collections_combines_filters_and_returns_compact_results() {
    let database = TestDatabase::new("search-query");
    run_success(database.command().args([
        "create",
        "deals",
        "acme-renewal",
        "--set",
        "status=won",
        "--set",
        "active=true",
        "--set",
        "value=25000",
        "--body",
        "Shared account notes.",
    ]));
    run_success(database.command().args([
        "create",
        "deals",
        "old-renewal",
        "--set",
        "status=won",
        "--set",
        "active=false",
        "--body",
        "Archived notes.",
    ]));
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=interview",
        "--body",
        "Shared hiring notes.",
    ]));

    let all = run_success(database.command().args(["search", "Shared"]));
    assert_eq!(
        all.lines().collect::<Vec<_>>(),
        [
            "records/candidates/jane.md",
            "records/deals/acme-renewal.md"
        ]
    );

    run_success(database.command().args([
        "create",
        "deals",
        "new-renewal",
        "--set",
        "status=open",
        "--set",
        "active=true",
        "--set",
        "value=10000",
        "--body",
        "Shared account notes for a smaller deal.",
    ]));
    let sorted = run_success(database.command().args([
        "search",
        "notes",
        "--collection",
        "deals",
        "--sort",
        "value",
        "--desc",
    ]));
    assert_eq!(
        sorted.lines().collect::<Vec<_>>(),
        [
            "records/deals/acme-renewal.md",
            "records/deals/new-renewal.md",
            "records/deals/old-renewal.md",
        ]
    );

    let filtered = run_success(database.command().args([
        "search",
        "won",
        "--collection",
        "deals",
        "--where",
        "active=true",
        "--json",
    ]));
    let filtered: Value = serde_json::from_str(&filtered).unwrap();
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["path"], "records/deals/acme-renewal.md");
    assert_eq!(filtered[0]["front_matter"]["status"], "won");
    assert_eq!(filtered[0]["front_matter"]["active"], true);
    assert_eq!(filtered[0]["front_matter"]["value"], 25000);
    assert_eq!(
        filtered[0].as_object().unwrap().keys().collect::<Vec<_>>(),
        ["front_matter", "path"]
    );

    let compared = run_success(database.command().args([
        "search",
        "notes",
        "--collection",
        "deals",
        "--ignore-case",
        "--where-expr",
        "value>=20000",
        "--json",
    ]));
    let compared: Value = serde_json::from_str(&compared).unwrap();
    assert_eq!(compared.as_array().unwrap().len(), 1);
    assert_eq!(compared[0]["path"], "records/deals/acme-renewal.md");

    assert!(run_success(database.command().args(["search", "missing"])).is_empty());
    let none = run_success(database.command().args(["search", "missing", "--json"]));
    assert_eq!(
        serde_json::from_str::<Value>(&none).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn search_supports_literal_regex_case_and_target_scopes() {
    let database = TestDatabase::new("search-scopes");
    run_success(database.command().args([
        "create",
        "companies",
        "acme-vip",
        "--set",
        "name=Acme Industries",
        "--set",
        "contact.city=Amsterdam",
        "--set",
        "metadata_token=FRONT_ONLY",
        "--body",
        "Priority account [VIP]. BODY_ONLY",
    ]));

    let field = run_success(database.command().args([
        "search",
        "^amster.*$",
        "--regex",
        "--ignore-case",
        "--field",
        "contact.city",
    ]));
    assert_eq!(field.trim(), "records/companies/acme-vip.md");

    let literal = run_success(database.command().args(["search", "[VIP]", "--body"]));
    assert_eq!(literal.trim(), "records/companies/acme-vip.md");

    assert!(
        run_success(
            database
                .command()
                .args(["search", "BODY_ONLY", "--front-matter"])
        )
        .is_empty()
    );
    assert!(run_success(database.command().args(["search", "FRONT_ONLY", "--body"])).is_empty());

    let path = run_success(database.command().args(["search", "acme-vip.md", "--path"]));
    assert_eq!(path.trim(), "records/companies/acme-vip.md");

    let invalid = run_failure(database.command().args(["search", "[", "--regex"]));
    assert!(invalid.contains("invalid search regular expression"));

    let invalid_field =
        run_failure(
            database
                .command()
                .args(["search", "anything", "--field", "contact..city"]),
        );
    assert!(invalid_field.contains("contains an empty segment"));

    let conflict = run_failure(
        database
            .command()
            .args(["search", "acme", "--body", "--path"]),
    );
    assert!(conflict.contains("cannot be used with"));
}

#[test]
fn unsaved_direct_edits_are_immediately_searchable_without_being_accepted() {
    let database = TestDatabase::new("search-direct-edits");
    run_success(database.command().args([
        "create",
        "deals",
        "renewal",
        "--set",
        "status=open",
        "--body",
        "Initial notes.",
    ]));

    fs::write(
        database.root.join("records/deals/renewal.md"),
        "---\nstatus: won\n---\nEdited outside the CLI.\n",
    )
    .unwrap();

    let searched = run_success(database.command().args([
        "search",
        "won",
        "--collection",
        "deals",
        "--field",
        "status",
    ]));
    assert_eq!(searched.trim(), "records/deals/renewal.md");
    assert_eq!(
        run_success(database.command().arg("status")).trim(),
        "M deals/renewal"
    );

    let collection = database.root.join("records/deals");
    fs::create_dir(collection.join("nested")).unwrap();
    fs::write(
        collection.join("nested/hidden.md"),
        "---\nstatus: won\n---\n",
    )
    .unwrap();
    fs::write(collection.join("notes.txt"), "won").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(collection.join("renewal.md"), collection.join("alias.md")).unwrap();

    #[cfg(unix)]
    {
        let external = database.root.join("external");
        fs::create_dir(&external).unwrap();
        fs::write(
            external.join("outside.md"),
            "---\nstatus: won\n---\noutside\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&external, database.root.join("records/external-link")).unwrap();
        // Naming the linked collection is refused rather than silently
        // answered from outside the database.
        assert!(
            run_failure(database.command().args([
                "search",
                "outside",
                "--collection",
                "external-link"
            ]))
            .contains("symbolic link")
        );
        assert!(
            run_failure(database.command().args(["list", "external-link"]))
                .contains("symbolic link")
        );
    }

    let searched = run_success(database.command().args(["search", "won"]));
    assert_eq!(
        searched.lines().collect::<Vec<_>>(),
        ["records/deals/renewal.md"]
    );
}

#[test]
fn search_help_is_available_without_a_database() {
    let output = run_success(Command::new(binary()).args(["search", "--help"]));
    assert!(output.contains("Search record paths, front matter, and Markdown bodies"));
    assert!(output.contains("--front-matter"));
    assert!(output.contains("--field <KEY>"));
    assert!(output.contains("--regex"));
    assert!(output.contains("--sort <FIELD>"));
    assert!(output.contains("--desc"));
}
