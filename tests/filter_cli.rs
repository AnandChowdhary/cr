//! `--filter` — the boolean filter language on `list`, `search`, and
//! `backlinks`. Its grammar and semantics are unit-tested in `src/query.rs`;
//! these tests pin that every command applies the same filter the same way.

mod common;

use std::process::Command;

use common::{TestDatabase, run_failure, run_success};

fn ids(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|line| {
            let path = line.split('\t').next().unwrap();
            path.rsplit('/')
                .next()
                .unwrap()
                .trim_end_matches(".md")
                .to_owned()
        })
        .collect()
}

fn pipeline(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    for (id, fields) in [
        ("alpha", vec!["stage=open", "value=5000", "owner=null"]),
        ("beta", vec!["stage=won", "value=20000", "owner=ada"]),
        ("gamma", vec!["stage=lost", "value=15000"]),
        (
            "delta",
            vec!["stage=open", "value=30000", "tags=[enterprise]"],
        ),
    ] {
        let mut command = database.command();
        command.args(["create", "deals", id]);
        for field in fields {
            command.args(["--set", field]);
        }
        run_success(&mut command);
    }
    run_success(database.command().args(["create", "companies", "acme"]));
    for id in ["alpha", "beta", "delta"] {
        run_success(
            database
                .command()
                .args(["link", "deals", id, "company", "companies", "acme"]),
        );
    }
    database
}

fn list(database: &TestDatabase, filter: &str) -> Vec<String> {
    ids(&run_success(
        database
            .command()
            .args(["list", "deals", "--filter", filter]),
    ))
}

#[test]
fn list_applies_boolean_filters() {
    let database = pipeline("filter-list");
    assert_eq!(
        list(
            &database,
            "stage in [open, won] AND (value >= 20000 OR owner is null)"
        ),
        ["alpha", "beta", "delta"]
    );
    assert_eq!(
        list(&database, "stage = open AND NOT tags exists"),
        ["alpha"]
    );
    assert_eq!(list(&database, "owner not exists"), ["delta", "gamma"]);
    assert_eq!(list(&database, "tags contains enterprise"), ["delta"]);
    assert_eq!(
        list(&database, "$id starts-with g OR $id = alpha"),
        ["alpha", "gamma"]
    );
    assert_eq!(list(&database, "stage not in [open]"), ["beta", "gamma"]);
    assert!(list(&database, "value > 100000").is_empty());
}

#[test]
fn filter_combines_with_where_and_where_expr_by_and() {
    let database = pipeline("filter-combined");
    let output = run_success(database.command().args([
        "list",
        "deals",
        "--where",
        "stage=open",
        "--where-expr",
        "value>=10000",
        "--filter",
        "owner not exists OR owner is null",
    ]));
    assert_eq!(ids(&output), ["delta"]);
}

#[test]
fn search_and_backlinks_apply_the_same_filter() {
    let database = pipeline("filter-search");
    let output = run_success(database.command().args([
        "search",
        "open",
        "--front-matter",
        "--filter",
        "value < 10000",
    ]));
    assert_eq!(ids(&output), ["alpha"]);
    let output = run_success(database.command().args([
        "backlinks",
        "companies",
        "acme",
        "--filter",
        "stage = open AND value > 10000",
    ]));
    assert_eq!(ids(&output), ["delta"]);
}

#[test]
fn a_filter_that_does_not_parse_says_where() {
    let database = pipeline("filter-errors");
    let run = |filter: &str| -> String {
        let mut command: Command = database.command();
        command.args(["list", "deals", "--filter", filter]);
        run_failure(&mut command)
    };
    let error = run("stage = open AND");
    assert!(
        error.contains("expected a field, NOT, or '(' at the end of the filter (column 17)"),
        "{error}"
    );
    let error = run("name = Acme Corp");
    assert!(
        error.contains("quote a value that contains spaces"),
        "{error}"
    );
}
