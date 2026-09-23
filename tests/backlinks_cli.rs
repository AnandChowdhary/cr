//! `cr backlinks` — every record that links to a record.

mod common;

use std::process::Command;

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

const OWNER: &str = "Owner <owner@example.com>";

fn json_output(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn create(database: &TestDatabase, collection: &str, id: &str, fields: &[&str]) {
    let mut command = database.command();
    command.args(["create", collection, id]);
    for field in fields {
        command.args(["--set", field]);
    }
    run_success(&mut command);
}

fn link(database: &TestDatabase, source: (&str, &str), relation: &str, target: (&str, &str)) {
    run_success(
        database
            .command()
            .args(["link", source.0, source.1, relation, target.0, target.1]),
    );
}

/// A company with two deals and a contact pointing at it, one deal pointing
/// at it through two relations, and a record pointing somewhere else.
fn crm(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    create(&database, "companies", "acme", &["name=Acme"]);
    create(&database, "companies", "globex", &["name=Globex"]);
    create(&database, "deals", "renewal", &["value=1000", "stage=open"]);
    create(
        &database,
        "deals",
        "expansion",
        &["value=5000", "stage=won"],
    );
    create(&database, "deals", "other", &["value=10"]);
    create(&database, "contacts", "jane", &["name=Jane"]);
    link(
        &database,
        ("deals", "renewal"),
        "company",
        ("companies", "acme"),
    );
    link(
        &database,
        ("deals", "expansion"),
        "company",
        ("companies", "acme"),
    );
    link(
        &database,
        ("deals", "expansion"),
        "partner",
        ("companies", "acme"),
    );
    link(
        &database,
        ("contacts", "jane"),
        "employer",
        ("companies", "acme"),
    );
    link(
        &database,
        ("deals", "other"),
        "company",
        ("companies", "globex"),
    );
    database
}

fn references(backlinks: &Value) -> Vec<String> {
    backlinks
        .as_array()
        .unwrap()
        .iter()
        .map(|backlink| {
            format!(
                "{}/{} {}",
                backlink["collection"].as_str().unwrap(),
                backlink["id"].as_str().unwrap(),
                backlink["relations"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|relation| relation.as_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .collect()
}

#[test]
fn backlinks_lists_every_source_and_the_relations_that_refer() {
    let database = crm("backlinks");

    let all = json_output(
        database
            .command()
            .args(["backlinks", "companies", "acme", "--json"]),
    );
    assert_eq!(
        references(&all),
        [
            "contacts/jane employer",
            "deals/expansion company,partner",
            "deals/renewal company",
        ]
    );
    assert_eq!(all[0]["path"], "records/contacts/jane.md");
    assert_eq!(all[0]["front_matter"]["name"], "Jane");

    let plain = run_success(database.command().args(["backlinks", "companies", "acme"]));
    assert_eq!(
        plain,
        "records/contacts/jane.md\temployer\nrecords/deals/expansion.md\tcompany,partner\nrecords/deals/renewal.md\tcompany\n"
    );

    // Nothing links to a record nobody references.
    let none = run_success(database.command().args(["backlinks", "deals", "renewal"]));
    assert!(none.is_empty(), "{none}");
}

#[test]
fn backlinks_filter_by_source_collection_relation_fields_and_sort() {
    let database = crm("backlinks-filters");
    let query = |arguments: &[&str]| {
        references(&json_output(
            database
                .command()
                .args(["backlinks", "companies", "acme", "--json"])
                .args(arguments),
        ))
    };

    assert_eq!(
        query(&["--from", "deals"]),
        ["deals/expansion company,partner", "deals/renewal company"]
    );
    // Only the named relation is reported, even on a record with two.
    assert_eq!(
        query(&["--relation", "partner"]),
        ["deals/expansion partner"]
    );
    assert_eq!(query(&["--where", "stage=open"]), ["deals/renewal company"]);
    assert_eq!(
        query(&["--where-expr", "value>=2000"]),
        ["deals/expansion company,partner"]
    );
    assert_eq!(
        query(&["--from", "deals", "--sort", "value", "--desc"]),
        ["deals/expansion company,partner", "deals/renewal company"]
    );
    assert!(query(&["--from", "nothing-here"]).is_empty());
}

#[test]
fn backlinks_find_references_to_a_record_that_no_longer_exists() {
    let database = crm("backlinks-dangling");
    run_success(
        database
            .command()
            .args(["delete", "companies", "globex", "--yes"]),
    );
    let backlinks =
        json_output(
            database
                .command()
                .args(["backlinks", "companies", "globex", "--json"]),
        );
    assert_eq!(references(&backlinks), ["deals/other company"]);
}

#[test]
fn backlinks_match_annotated_references_and_ignore_malformed_relations() {
    let database = crm("backlinks-shapes");
    std::fs::write(
        database.root.join("records/deals/other.md"),
        "---\nvalue: 10\nrelations:\n  company:\n  - collection: companies\n    id: acme\n    role: buyer\n  notes: not-a-list\n---\n",
    )
    .unwrap();
    std::fs::write(
        database.root.join("records/contacts/bob.md"),
        "---\nname: Bob\nrelations: nope\n---\n",
    )
    .unwrap();
    let backlinks = json_output(database.command().args([
        "backlinks",
        "companies",
        "acme",
        "--from",
        "deals",
        "--json",
    ]));
    assert_eq!(
        references(&backlinks),
        [
            "deals/expansion company,partner",
            "deals/other company",
            "deals/renewal company"
        ]
    );
    run_success(database.command().args(["backlinks", "companies", "acme"]));
}

#[test]
fn backlinks_refuse_unusable_names() {
    let database = crm("backlinks-names");
    let error = run_failure(
        database
            .command()
            .args(["backlinks", "companies", "../acme"]),
    );
    assert!(error.contains("id"), "{error}");
    let error = run_failure(database.command().args([
        "backlinks",
        "companies",
        "acme",
        "--relation",
        "a/b",
    ]));
    assert!(error.contains("relation"), "{error}");
}

#[test]
fn backlinks_only_list_sources_the_principal_may_read() {
    let database = TestDatabase::new("backlinks-access");
    let as_principal = |actor: &str| {
        let mut command = database.command();
        command.env("CR_ACTOR", actor);
        command
    };
    run_success(as_principal(OWNER).args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(as_principal(OWNER).args([
        "user",
        "add",
        "bob@example.com",
        "--name",
        "Bob",
        "--email",
        "bob@example.com",
    ]));
    for collection in ["companies", "deals"] {
        run_success(as_principal(OWNER).args([
            "access",
            "grant",
            "bob@example.com",
            "viewer",
            &format!("collection:{collection}"),
        ]));
    }
    run_success(as_principal(OWNER).args(["create", "companies", "acme", "--set", "name=Acme"]));
    for (collection, id) in [("deals", "renewal"), ("secrets", "plan")] {
        run_success(as_principal(OWNER).args(["create", collection, id]));
        run_success(as_principal(OWNER).args([
            "link",
            collection,
            id,
            "company",
            "companies",
            "acme",
        ]));
    }

    let owner = json_output(as_principal(OWNER).args(["backlinks", "companies", "acme", "--json"]));
    assert_eq!(
        references(&owner),
        ["deals/renewal company", "secrets/plan company"]
    );
    let bob = json_output(as_principal("Bob <bob@example.com>").args([
        "backlinks",
        "companies",
        "acme",
        "--json",
    ]));
    assert_eq!(references(&bob), ["deals/renewal company"]);
    assert_eq!(bob, json!([owner[0].clone()]));
}
