//! `cr unlink` and `cr update --unset` — removing what `link` and `--set` add.
//!
//! Each removal is one audited, schema-validated, atomic write through the same
//! path as the addition it undoes, so every test here also asserts what the
//! journal recorded and that it still verifies.

mod common;

use std::{fs, path::PathBuf, process::Command};

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

const OWNER: &str = "Owner <owner@example.com>";

fn record_path(database: &TestDatabase, collection: &str, id: &str) -> PathBuf {
    database
        .root
        .join("records")
        .join(collection)
        .join(format!("{id}.md"))
}

fn json_output(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

/// The newest audit events for one record, newest first.
fn history(database: &TestDatabase, collection: &str, id: &str) -> Vec<Value> {
    json_output(
        database
            .command()
            .args(["audit", "log", collection, id, "--json"]),
    )
    .as_array()
    .unwrap()
    .clone()
}

fn head(database: &TestDatabase) -> u64 {
    json_output(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap()
}

/// Two companies and a deal, with the deal not yet linked to either.
fn seeded(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    for company in ["acme", "globex"] {
        run_success(database.command().args([
            "create",
            "companies",
            company,
            "--set",
            &format!("name={company}"),
        ]));
    }
    run_success(
        database
            .command()
            .args(["create", "deals", "renewal", "--set", "value=1000"]),
    );
    database
}

fn link(database: &TestDatabase, target: &str) {
    run_success(database.command().args([
        "link",
        "deals",
        "renewal",
        "company",
        "companies",
        target,
    ]));
}

fn unlink(database: &TestDatabase, target: &str) -> Command {
    let mut command = database.command();
    command.args(["unlink", "deals", "renewal", "company", "companies", target]);
    command
}

#[test]
fn unlinking_the_only_reference_restores_the_record_byte_for_byte() {
    let database = seeded("unlink-round-trip");
    let path = record_path(&database, "deals", "renewal");
    let before = fs::read(&path).unwrap();
    link(&database, "acme");
    assert_ne!(fs::read(&path).unwrap(), before);

    run_success(unlink(&database, "acme").args(["--message", "wrong company"]));
    assert_eq!(fs::read(&path).unwrap(), before);

    // One event, recorded as a relation change whose diff is the removal.
    let events = history(&database, "deals", "renewal");
    let newest = &events[0];
    assert_eq!(newest["action"], "link");
    assert_eq!(newest["message"], "wrong company");
    assert_eq!(
        newest["changes"],
        json!([{
            "operation": "remove",
            "path": "/attributes/relations",
            "before": { "company": [{ "collection": "companies", "id": "acme" }] }
        }])
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn unlinking_one_of_several_references_keeps_the_others() {
    let database = seeded("unlink-one-of-two");
    link(&database, "acme");
    link(&database, "globex");

    let record = json_output(unlink(&database, "acme").arg("--json"));
    assert_eq!(
        record["attributes"]["relations"],
        json!({ "company": [{ "collection": "companies", "id": "globex" }] })
    );
    let newest = &history(&database, "deals", "renewal")[0];
    assert_eq!(newest["changes"][0]["operation"], "replace");
    assert_eq!(
        newest["changes"][0]["path"],
        "/attributes/relations/company"
    );
}

#[test]
fn unlinking_a_reference_that_is_not_there_changes_nothing() {
    let database = seeded("unlink-idempotent");
    let path = record_path(&database, "deals", "renewal");
    link(&database, "acme");
    run_success(&mut unlink(&database, "acme"));
    let after_first = fs::read(&path).unwrap();

    // A repeat, a relation the record never had, and a record with no
    // relations at all all succeed and leave the file alone, as a repeated
    // link does.
    run_success(&mut unlink(&database, "acme"));
    run_success(
        database
            .command()
            .args(["unlink", "deals", "renewal", "owner", "people", "nobody"]),
    );
    assert_eq!(fs::read(&path).unwrap(), after_first);
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn a_dangling_reference_can_be_unlinked_and_check_comes_back_clean() {
    let database = seeded("unlink-dangling");
    link(&database, "acme");
    run_success(
        database
            .command()
            .args(["delete", "companies", "acme", "--yes"]),
    );
    let report = database
        .command()
        .args(["check", "--json"])
        .output()
        .unwrap();
    assert_eq!(report.status.code(), Some(2));

    run_success(&mut unlink(&database, "acme"));
    let report = json_output(database.command().args(["check", "--json"]));
    assert_eq!(report["findings"], json!([]));
}

#[test]
fn unlink_matches_annotated_and_duplicated_references_by_collection_and_id() {
    let database = seeded("unlink-annotated");
    fs::write(
        record_path(&database, "deals", "renewal"),
        "---\nvalue: 1000\nrelations:\n  company:\n  - collection: companies\n    id: acme\n    role: buyer\n  - collection: companies\n    id: acme\n  - collection: companies\n    id: globex\n---\n",
    )
    .unwrap();
    run_success(
        database
            .command()
            .args(["save", "deals/renewal", "--message", "annotate"]),
    );

    let record = json_output(unlink(&database, "acme").arg("--json"));
    assert_eq!(
        record["attributes"]["relations"]["company"],
        json!([{ "collection": "companies", "id": "globex" }])
    );
}

#[test]
fn unlink_is_schema_validated_and_refusals_write_nothing() {
    let database = seeded("unlink-schema");
    link(&database, "acme");
    fs::write(
        database.root.join(".cr/schemas/deals.json"),
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["relations"]}"#,
    )
    .unwrap();
    let path = record_path(&database, "deals", "renewal");
    let before = fs::read(&path).unwrap();
    let sequence = head(&database);

    let error = run_failure(&mut unlink(&database, "acme"));
    assert!(
        error.contains("\"relations\" is a required property"),
        "{error}"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(head(&database), sequence);
}

#[test]
fn unlink_supports_preview_approval_and_version_preconditions() {
    let database = seeded("unlink-preview");
    link(&database, "acme");
    let path = record_path(&database, "deals", "renewal");
    let before = fs::read(&path).unwrap();
    let sequence = head(&database);

    let preview = json_output(unlink(&database, "acme").args(["--preview", "--json"]));
    assert_eq!(preview["changes"][0]["operation"], "remove");
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(head(&database), sequence);

    let stale = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let error = run_failure(unlink(&database, "acme").args(["--expected-record-hash", stale]));
    assert!(
        error.contains("changed since the expected version"),
        "{error}"
    );

    let digest = preview["digest"].as_str().unwrap();
    run_success(unlink(&database, "acme").args([
        "--authorization",
        "interactive",
        "--approved-changes",
        digest,
    ]));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .find("relations")
            .is_none()
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn unlink_refuses_the_users_collection_and_malformed_relations() {
    let database = seeded("unlink-refusals");
    let error = run_failure(
        database
            .command()
            .args(["unlink", "users", "someone", "manager", "users", "other"]),
    );
    assert!(error.contains("managed through 'cr user'"), "{error}");

    fs::write(
        record_path(&database, "deals", "renewal"),
        "---\nvalue: 1000\nrelations:\n  company: companies/acme\n---\n",
    )
    .unwrap();
    run_success(
        database
            .command()
            .args(["save", "deals/renewal", "--message", "hand edit"]),
    );
    let error = run_failure(&mut unlink(&database, "acme"));
    assert!(
        error.contains("relation 'company' must be a list"),
        "{error}"
    );
}

#[test]
fn update_unset_removes_fields_in_one_audited_event() {
    let database = seeded("unset");
    run_success(database.command().args([
        "update",
        "deals",
        "renewal",
        "--set",
        "owner.name=Ada",
        "--set",
        "owner.team=sales",
        "--set",
        "stage=open",
    ]));

    let record = json_output(database.command().args([
        "update",
        "deals",
        "renewal",
        "--unset",
        "owner.team",
        "--unset",
        "stage",
        "--set",
        "value=2000",
        "--json",
    ]));
    assert_eq!(
        record["attributes"],
        json!({ "value": 2000, "owner": { "name": "Ada" } })
    );
    let newest = &history(&database, "deals", "renewal")[0];
    assert_eq!(newest["action"], "update");
    let operations: Vec<_> = newest["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| {
            format!(
                "{} {}",
                change["operation"].as_str().unwrap(),
                change["path"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        operations,
        [
            "remove /attributes/owner/team",
            "remove /attributes/stage",
            "replace /attributes/value"
        ]
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn update_unset_refuses_missing_and_overlapping_fields_without_writing() {
    let database = seeded("unset-refusals");
    let path = record_path(&database, "deals", "renewal");
    let before = fs::read(&path).unwrap();
    let sequence = head(&database);

    let error = run_failure(
        database
            .command()
            .args(["update", "deals", "renewal", "--unset", "stage"]),
    );
    assert!(error.contains("field 'stage' does not exist"), "{error}");

    let error = run_failure(database.command().args([
        "update",
        "deals",
        "renewal",
        "--set",
        "owner.name=Ada",
        "--unset",
        "owner",
    ]));
    assert!(error.contains("cannot be both set and unset"), "{error}");

    let error = run_failure(database.command().args(["update", "deals", "renewal"]));
    assert!(error.contains("--unset"), "{error}");

    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(head(&database), sequence);
}

#[test]
fn update_unset_respects_reserved_access_and_user_fields() {
    let database = TestDatabase::new("unset-access");
    let owner = || {
        let mut command = database.command();
        command.env("CR_ACTOR", OWNER);
        command
    };
    run_success(owner().args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(owner().args([
        "access",
        "policy",
        "set",
        "collection:things",
        "--mode",
        "record-owned",
        "--default-visibility",
        "private",
    ]));
    run_success(owner().args(["create", "things", "t1", "--set", "name=first"]));
    let error = run_failure(owner().args(["update", "things", "t1", "--unset", "$cr_access"]));
    assert!(error.contains("managed through 'cr access'"), "{error}");

    run_success(owner().args([
        "user",
        "add",
        "bob@example.com",
        "--name",
        "Bob",
        "--set",
        "team=sales",
    ]));
    let error =
        run_failure(owner().args(["update", "users", "bob@example.com", "--unset", "email"]));
    assert!(error.contains("may change only profile.*"), "{error}");
    let record = json_output(owner().args([
        "update",
        "users",
        "bob@example.com",
        "--unset",
        "profile.team",
        "--json",
    ]));
    assert!(record["attributes"].get("profile").is_none(), "{record:#}");
}
