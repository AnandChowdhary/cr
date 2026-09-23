//! `--select` — returning only chosen fields from `get`, `list`, `search`,
//! `backlinks`, and `traverse`.

mod common;

use std::process::Command;

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

fn json_output(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn crm(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    run_success(
        database
            .command()
            .args(["create", "companies", "acme", "--set", "name=Acme"]),
    );
    for (id, value, owner) in [("alpha", "5000", "Ada"), ("beta", "20000", "Grace")] {
        run_success(database.command().args([
            "create",
            "deals",
            id,
            "--set",
            &format!("value={value}"),
            "--set",
            &format!("owner.name={owner}"),
            "--body",
            "Line one\nLine two",
        ]));
        run_success(
            database
                .command()
                .args(["link", "deals", id, "company", "companies", "acme"]),
        );
    }
    run_success(
        database
            .command()
            .args(["create", "deals", "gamma", "--set", "value=1"]),
    );
    database
}

#[test]
fn list_selects_fields_as_rows_or_flat_objects() {
    let database = crm("select-list");
    assert_eq!(
        run_success(database.command().args([
            "list",
            "deals",
            "--select",
            "$id,value",
            "--select",
            "owner.name",
        ])),
        "alpha\t5000\tAda\nbeta\t20000\tGrace\ngamma\t1\t\n"
    );
    let objects = json_output(database.command().args([
        "list",
        "deals",
        "--select",
        "$id,owner.name,$body",
        "--filter",
        "value > 1",
        "--json",
    ]));
    assert_eq!(
        objects,
        json!([
            { "$id": "alpha", "owner.name": "Ada", "$body": "Line one\nLine two" },
            { "$id": "beta", "owner.name": "Grace", "$body": "Line one\nLine two" }
        ])
    );
    let gamma = json_output(database.command().args([
        "list",
        "deals",
        "--select",
        "$id,owner.name",
        "--where",
        "value=1",
        "--json",
    ]));
    assert_eq!(
        gamma,
        json!([{ "$id": "gamma" }]),
        "missing fields are left out"
    );
}

#[test]
fn get_search_and_backlinks_select_the_same_way() {
    let database = crm("select-others");
    assert_eq!(
        run_success(
            database
                .command()
                .args(["get", "deals", "alpha", "--select", "$id,$body"])
        ),
        "alpha\tLine one\\nLine two\n"
    );
    let version =
        json_output(database.command().args(["get", "deals", "alpha", "--json"]))["version"]
            .clone();
    assert_eq!(
        json_output(database.command().args([
            "get",
            "deals",
            "alpha",
            "--select",
            "$version,value",
            "--json",
        ])),
        json!({ "$version": version, "value": 5000 })
    );
    assert_eq!(
        run_success(database.command().args([
            "search",
            "Grace",
            "--front-matter",
            "--select",
            "$collection,$id",
        ])),
        "deals\tbeta\n"
    );
    assert_eq!(
        run_success(database.command().args([
            "backlinks",
            "companies",
            "acme",
            "--select",
            "$id,value",
            "--sort",
            "value",
            "--desc",
        ])),
        "beta\t20000\nalpha\t5000\n"
    );
}

#[test]
fn traverse_puts_selected_fields_under_fields() {
    let database = crm("select-traverse");
    let graph = json_output(database.command().args([
        "traverse",
        "deals",
        "alpha",
        "--json",
        "--select",
        "name,value",
    ]));
    assert_eq!(graph["nodes"][0]["fields"], json!({ "value": 5000 }));
    assert_eq!(graph["nodes"][1]["fields"], json!({ "name": "Acme" }));
    assert!(graph["nodes"][1].get("front_matter").is_none());
    let tree = json_output(database.command().args([
        "traverse", "deals", "alpha", "--json", "--expand", "--select", "name",
    ]));
    assert_eq!(
        tree["links"]["company"][0]["fields"],
        json!({ "name": "Acme" })
    );
    let error = run_failure(
        database
            .command()
            .args(["traverse", "deals", "alpha", "--select", "name"]),
    );
    assert!(error.contains("--json"), "{error}");
}

#[test]
fn unusable_selections_are_refused() {
    let database = crm("select-refusals");
    let error = run_failure(
        database
            .command()
            .args(["list", "deals", "--select", "$nope"]),
    );
    assert!(
        error.contains("$id, $collection, $path, $version, and $body"),
        "{error}"
    );
    let error = run_failure(
        database
            .command()
            .args(["list", "deals", "--select", "a,,b"]),
    );
    assert!(error.contains("empty selector"), "{error}");
    let error = run_failure(database.command().args([
        "get", "deals", "alpha", "--select", "value", "--field", "value",
    ]));
    assert!(error.contains("cannot be used with"), "{error}");
}
