//! `cr traverse` — following relations outward from one record.

mod common;

use std::{fs, process::Command};

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

const OWNER: &str = "Owner <owner@example.com>";

fn json_output(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn link(database: &TestDatabase, source: &str, relation: &str, target: &str) {
    let (source_collection, source_id) = source.split_once('/').unwrap();
    let (target_collection, target_id) = target.split_once('/').unwrap();
    run_success(database.command().args([
        "link",
        source_collection,
        source_id,
        relation,
        target_collection,
        target_id,
    ]));
}

/// A deal linked to a company, a contact, and a deleted partner; the contact
/// works for the same company; and the company and its holding refer to each
/// other, which is a cycle.
fn crm(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    for (collection, id) in [
        ("companies", "acme"),
        ("companies", "holding"),
        ("companies", "gone"),
        ("contacts", "jane"),
        ("deals", "renewal"),
    ] {
        run_success(database.command().args([
            "create",
            collection,
            id,
            "--set",
            &format!("name={id}"),
        ]));
    }
    link(&database, "deals/renewal", "company", "companies/acme");
    link(
        &database,
        "deals/renewal",
        "primary_contact",
        "contacts/jane",
    );
    link(&database, "deals/renewal", "partner", "companies/gone");
    run_success(
        database
            .command()
            .args(["delete", "companies", "gone", "--yes"]),
    );
    link(&database, "contacts/jane", "employer", "companies/acme");
    link(&database, "companies/acme", "parent", "companies/holding");
    link(
        &database,
        "companies/holding",
        "subsidiary",
        "companies/acme",
    );
    database
}

fn traverse(database: &TestDatabase, arguments: &[&str]) -> Command {
    let mut command = database.command();
    command
        .args(["traverse", "deals", "renewal"])
        .args(arguments);
    command
}

#[test]
fn plain_output_is_a_tree_that_stops_at_cycles_and_missing_records() {
    let database = crm("traverse-plain");
    assert_eq!(
        run_success(&mut traverse(&database, &["--depth", "3"])),
        "deals/renewal
  company: companies/acme
    parent: companies/holding
      subsidiary: companies/acme (shown above)
  primary_contact: contacts/jane
    employer: companies/acme (shown above)
  partner: companies/gone (missing)
"
    );
    // The default depth follows one step only.
    assert_eq!(
        run_success(&mut traverse(&database, &[])),
        "deals/renewal
  company: companies/acme
  primary_contact: contacts/jane
  partner: companies/gone (missing)
"
    );
}

#[test]
fn json_output_lists_every_record_once_and_every_reference_followed() {
    let database = crm("traverse-graph");
    let graph = json_output(&mut traverse(&database, &["--depth", "3", "--json"]));
    assert_eq!(graph["root"], "deals/renewal");
    assert_eq!(graph["depth"], 3);
    assert_eq!(graph["truncated"], false);
    let nodes: Vec<_> = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            format!(
                "{}/{} {} {}",
                node["collection"].as_str().unwrap(),
                node["id"].as_str().unwrap(),
                node["depth"],
                node["status"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        nodes,
        [
            "deals/renewal 0 found",
            "companies/acme 1 found",
            "contacts/jane 1 found",
            "companies/gone 1 missing",
            "companies/holding 2 found",
        ]
    );
    assert_eq!(graph["nodes"][1]["front_matter"]["name"], "acme");
    assert_eq!(graph["nodes"][1]["path"], "records/companies/acme.md");
    assert!(graph["nodes"][3].get("front_matter").is_none());
    assert_eq!(
        graph["edges"],
        json!([
            { "from": "deals/renewal", "relation": "company", "to": "companies/acme" },
            { "from": "deals/renewal", "relation": "primary_contact", "to": "contacts/jane" },
            { "from": "deals/renewal", "relation": "partner", "to": "companies/gone" },
            { "from": "companies/acme", "relation": "parent", "to": "companies/holding" },
            { "from": "contacts/jane", "relation": "employer", "to": "companies/acme" },
            { "from": "companies/holding", "relation": "subsidiary", "to": "companies/acme" }
        ])
    );
}

#[test]
fn expanded_output_nests_each_record_where_it_was_first_reached() {
    let database = crm("traverse-tree");
    let tree = json_output(&mut traverse(
        &database,
        &["--depth", "3", "--json", "--expand"],
    ));
    assert_eq!(tree["collection"], "deals");
    assert_eq!(tree["truncated"], false);
    let acme = &tree["links"]["company"][0];
    assert_eq!(acme["id"], "acme");
    assert_eq!(acme["front_matter"]["name"], "acme");
    let holding = &acme["links"]["parent"][0];
    assert_eq!(holding["id"], "holding");
    assert_eq!(
        holding["links"]["subsidiary"][0],
        json!({ "collection": "companies", "id": "acme", "status": "found", "seen": true })
    );
    assert_eq!(
        tree["links"]["primary_contact"][0]["links"]["employer"][0]["seen"],
        true
    );
    assert_eq!(
        tree["links"]["partner"][0],
        json!({ "collection": "companies", "id": "gone", "status": "missing" })
    );
}

#[test]
fn relation_filters_apply_at_every_step() {
    let database = crm("traverse-relations");
    assert_eq!(
        run_success(&mut traverse(
            &database,
            &[
                "--depth",
                "3",
                "--relation",
                "company",
                "--relation",
                "parent"
            ],
        )),
        "deals/renewal
  company: companies/acme
    parent: companies/holding
"
    );
}

#[test]
fn unusable_requests_fail_and_only_the_start_must_exist() {
    let database = crm("traverse-refusals");
    for depth in ["0", "11"] {
        let error = run_failure(&mut traverse(&database, &["--depth", depth]));
        assert!(error.contains("between 1 and 10"), "{error}");
    }
    let error = run_failure(database.command().args(["traverse", "deals", "nope"]));
    assert!(
        error.contains("record deals/nope does not exist"),
        "{error}"
    );
    let error = run_failure(&mut traverse(&database, &["--relation", "a/b"]));
    assert!(error.contains("relation"), "{error}");
    let error = run_failure(&mut traverse(&database, &["--expand"]));
    assert!(error.contains("--json"), "{error}");

    // A malformed relation is skipped rather than failing the traversal.
    fs::write(
        database.root.join("records/contacts/jane.md"),
        "---\nname: jane\nrelations:\n  employer: not-a-list\n  manager:\n  - people/bob\n---\n",
    )
    .unwrap();
    assert_eq!(
        run_success(&mut traverse(
            &database,
            &[
                "--depth",
                "2",
                "--relation",
                "primary_contact",
                "--relation",
                "employer"
            ],
        )),
        "deals/renewal\n  primary_contact: contacts/jane\n"
    );
}

#[test]
fn records_the_principal_may_not_read_are_reported_and_not_followed() {
    let database = TestDatabase::new("traverse-access");
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
    run_success(as_principal(OWNER).args([
        "access",
        "grant",
        "bob@example.com",
        "viewer",
        "collection:deals",
    ]));
    run_success(as_principal(OWNER).args(["create", "deals", "renewal"]));
    run_success(as_principal(OWNER).args(["create", "secrets", "plan"]));
    run_success(as_principal(OWNER).args(["create", "secrets", "deeper"]));
    run_success(as_principal(OWNER).args(["link", "deals", "renewal", "plan", "secrets", "plan"]));
    run_success(as_principal(OWNER).args(["link", "secrets", "plan", "next", "secrets", "deeper"]));

    let bob = json_output(
        as_principal("Bob <bob@example.com>")
            .args(["traverse", "deals", "renewal", "--depth", "3", "--json"]),
    );
    assert_eq!(bob["nodes"].as_array().unwrap().len(), 2, "{bob:#}");
    assert_eq!(
        bob["nodes"][1],
        json!({ "collection": "secrets", "id": "plan", "status": "forbidden", "depth": 1 })
    );
    let owner = json_output(
        as_principal(OWNER).args(["traverse", "deals", "renewal", "--depth", "3", "--json"]),
    );
    assert_eq!(owner["nodes"].as_array().unwrap().len(), 3);
}

#[test]
fn a_traversal_stops_at_its_record_budget_and_says_so() {
    let database = TestDatabase::new("traverse-budget");
    let mut front_matter = String::from("---\nrelations:\n  items:\n");
    for index in 0..1005 {
        front_matter.push_str(&format!("  - collection: items\n    id: item-{index}\n"));
    }
    front_matter.push_str("---\n");
    fs::create_dir_all(database.root.join("records/hubs")).unwrap();
    fs::write(database.root.join("records/hubs/big.md"), front_matter).unwrap();
    run_success(
        database
            .command()
            .args(["save", "hubs/big", "--message", "fan out"]),
    );

    let graph = json_output(
        database
            .command()
            .args(["traverse", "hubs", "big", "--json"]),
    );
    assert_eq!(graph["truncated"], true);
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 1000);
    let plain = run_success(database.command().args(["traverse", "hubs", "big"]));
    assert!(plain.ends_with("(stopped after 1000 records)\n"), "{plain}");
}
