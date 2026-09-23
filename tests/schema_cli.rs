//! `cr collections` and `cr schema show|check|set|remove` — managing collection
//! schemas without editing `.cr/schemas` by hand.

mod common;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

const OWNER: &str = "Owner <owner@example.com>";
const KEYS: &str = r#"{"old":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;

fn json_output(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn write_schema(database: &TestDatabase, name: &str, schema: &Value) -> PathBuf {
    let path = database.root.join(name);
    fs::write(&path, schema.to_string()).unwrap();
    path
}

fn installed(database: &TestDatabase, collection: &str) -> Option<Value> {
    let path = database
        .root
        .join(".cr/schemas")
        .join(format!("{collection}.json"));
    path.exists()
        .then(|| serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap())
}

fn stage_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["stage"],
        "properties": {
            "stage": { "enum": ["open", "won"] },
            "value": { "type": "integer" }
        }
    })
}

/// Two deals, only one of which has a stage.
fn deals(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    run_success(database.command().args([
        "create",
        "deals",
        "open-deal",
        "--set",
        "stage=open",
        "--set",
        "value=10",
    ]));
    run_success(
        database
            .command()
            .args(["create", "deals", "no-stage", "--set", "value=20"]),
    );
    database
}

#[test]
fn collections_lists_names_titles_and_schema_features() {
    let database = deals("collections");
    run_success(database.command().args(["create", "notes", "first"]));
    run_success(
        database
            .command()
            .args(["schema", "label", "notes", "Meeting notes"]),
    );
    assert_eq!(
        run_success(database.command().arg("collections")),
        "deals\tDeals\t-\nnotes\tMeeting notes\tschema\n"
    );
    let models = json_output(database.command().args(["collections", "--json"]));
    assert_eq!(models[0], json!({ "name": "deals" }));
    assert_eq!(models[1]["schema"]["x-cr-ui"]["label"], "Meeting notes");
}

#[test]
fn check_reports_the_records_a_proposed_schema_would_reject_without_writing() {
    let database = deals("schema-check");
    let file = write_schema(&database, "proposed.json", &stage_schema());

    let output = database
        .command()
        .args(["schema", "check", "deals"])
        .arg(&file)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "deals/no-stage: \"stage\" is a required property\nChecked the proposed schema for deals: 1 of 2 records satisfy it.\n"
    );
    assert_eq!(installed(&database, "deals"), None);

    let review = database
        .command()
        .args(["schema", "check", "deals", "--json"])
        .arg(&file)
        .output()
        .unwrap();
    let review: Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(
        review,
        json!({
            "collection": "deals",
            "changed": true,
            "applied": false,
            "records": 2,
            "violations": [{ "id": "no-stage", "message": "\"stage\" is a required property" }]
        })
    );

    // A field-level violation names its field.
    run_success(
        database
            .command()
            .args(["update", "deals", "no-stage", "--set", "stage=lost"]),
    );
    let review = database
        .command()
        .args(["schema", "check", "deals", "--json"])
        .arg(&file)
        .output()
        .unwrap();
    let review: Value = serde_json::from_slice(&review.stdout).unwrap();
    assert_eq!(review["violations"][0]["field"], "stage");
}

#[test]
fn set_installs_only_a_schema_every_record_satisfies_unless_told_otherwise() {
    let database = deals("schema-set");
    let file = write_schema(&database, "proposed.json", &stage_schema());

    let error = run_failure(
        database
            .command()
            .args(["schema", "set", "deals"])
            .arg(&file),
    );
    assert!(
        error.contains("1 of 2 records in collection 'deals' do not satisfy the proposed schema"),
        "{error}"
    );
    assert!(
        error.contains("- deals/no-stage: \"stage\" is a required property"),
        "{error}"
    );
    assert_eq!(installed(&database, "deals"), None);

    let installed_anyway = run_success(
        database
            .command()
            .args(["schema", "set", "deals", "--allow-violations"])
            .arg(&file),
    );
    assert!(
        installed_anyway.contains("Installed the schema for deals: 1 of 2"),
        "{installed_anyway}"
    );
    assert_eq!(installed(&database, "deals"), Some(stage_schema()));
    // `check` now reports the record the schema was installed over.
    let report = database
        .command()
        .args(["check", "--json"])
        .output()
        .unwrap();
    let report: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["findings"][0]["kind"], "schema_violation");

    run_success(
        database
            .command()
            .args(["update", "deals", "no-stage", "--set", "stage=won"]),
    );
    assert_eq!(
        run_success(
            database
                .command()
                .args(["schema", "set", "deals"])
                .arg(&file)
        ),
        "The schema for deals is already installed: 2 of 2 records satisfy it.\n"
    );
}

#[test]
fn set_reads_standard_input_and_show_prints_the_installed_schema() {
    let database = deals("schema-stdin");
    let mut child = database
        .command()
        .args(["schema", "set", "deals", "-", "--allow-violations"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stage_schema().to_string().as_bytes())
        .unwrap();
    assert!(child.wait_with_output().unwrap().status.success());

    let shown: Value = serde_json::from_str(&run_success(
        database.command().args(["schema", "show", "deals"]),
    ))
    .unwrap();
    assert_eq!(shown, stage_schema());

    let error = run_failure(database.command().args(["schema", "show", "notes"]));
    assert!(
        error.contains("collection 'notes' does not exist"),
        "{error}"
    );
    run_success(database.command().args(["create", "notes", "first"]));
    let error = run_failure(database.command().args(["schema", "show", "notes"]));
    assert!(
        error.contains("collection 'notes' has no schema"),
        "{error}"
    );
}

#[test]
fn unusable_proposals_are_refused_before_anything_is_judged() {
    let database = deals("schema-unusable");
    let refusals = [
        (json!({ "type": 12 }), "is not a valid JSON Schema"),
        (
            json!({ "type": "object", "x-cr-ui": { "label": "" } }),
            "collection label cannot be empty",
        ),
        (
            json!({ "type": "object", "properties": { "value": { "type": "integer", "x-cr-encrypted": true } } }),
            "changes which values collection 'deals' encrypts",
        ),
        (
            json!({ "type": "object", "x-cr-access": { "mode": "record_owned", "default_visibility": "private" } }),
            "record access policy",
        ),
    ];
    for (schema, expected) in refusals {
        let file = write_schema(&database, "proposed.json", &schema);
        let error = run_failure(
            database
                .command()
                .args(["schema", "set", "deals"])
                .arg(&file),
        );
        assert!(error.contains(expected), "{schema}: {error}");
    }
    fs::write(database.root.join("broken.json"), "{ not json").unwrap();
    let error = run_failure(
        database
            .command()
            .args(["schema", "check", "deals"])
            .arg(database.root.join("broken.json")),
    );
    assert!(error.contains("is not valid JSON"), "{error}");
    let error = run_failure(
        database
            .command()
            .args(["schema", "set", "users"])
            .arg(database.root.join("proposed.json")),
    );
    assert!(error.contains("built-in schema"), "{error}");
    assert_eq!(installed(&database, "deals"), None);
}

#[test]
fn set_keeps_encryption_markers_and_judges_protected_records_without_quoting_them() {
    let database = TestDatabase::new("schema-encrypted");
    let command = || {
        let mut command = database.command();
        command
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", KEYS);
        command
    };
    run_success(command().args(["schema", "encrypt", "secrets", "token"]));
    run_success(command().args(["create", "secrets", "api", "--set", "token=hunter2"]));
    let mut schema = installed(&database, "secrets").unwrap();
    schema["required"] = json!(["owner"]);
    let file = write_schema(&database, "proposed.json", &schema);

    let review = command()
        .args(["schema", "check", "secrets", "--json"])
        .arg(&file)
        .output()
        .unwrap();
    let text = String::from_utf8(review.stdout).unwrap();
    assert!(!text.contains("hunter2"), "{text}");
    let review: Value = serde_json::from_str(&text).unwrap();
    assert!(
        review["violations"][0]["message"]
            .as_str()
            .unwrap()
            .contains("protected values redacted"),
        "{review:#}"
    );

    // The markers survive a schema that keeps them, and stay required.
    schema["required"] = json!([]);
    let file = write_schema(&database, "proposed.json", &schema);
    run_success(command().args(["schema", "set", "secrets"]).arg(&file));
    let error = run_failure(command().args(["schema", "remove", "secrets"]));
    assert!(error.contains("encrypted values"), "{error}");
}

#[test]
fn remove_returns_a_collection_to_schemaless() {
    let database = deals("schema-remove");
    let file = write_schema(&database, "proposed.json", &json!({ "type": "object" }));
    run_success(
        database
            .command()
            .args(["schema", "set", "deals"])
            .arg(&file),
    );
    assert_eq!(
        run_success(database.command().args(["schema", "remove", "deals"])),
        "Removed the schema for deals\n"
    );
    assert_eq!(installed(&database, "deals"), None);
    assert_eq!(
        run_success(database.command().args(["schema", "remove", "deals"])),
        "deals has no schema\n"
    );
}

#[test]
fn schema_changes_are_owner_only_under_access_control() {
    let database = deals("schema-access");
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
        "editor",
        "collection:deals",
    ]));
    let file = write_schema(&database, "proposed.json", &json!({ "type": "object" }));
    let bob = "Bob <bob@example.com>";
    let error = run_failure(
        as_principal(bob)
            .args(["schema", "set", "deals"])
            .arg(&file),
    );
    assert!(
        error.contains("cannot manage_access collection:deals"),
        "{error}"
    );
    let error = run_failure(
        as_principal(bob)
            .args(["schema", "check", "deals"])
            .arg(&file),
    );
    assert!(
        error.contains("cannot manage_access collection:deals"),
        "{error}"
    );
    run_success(
        as_principal(OWNER)
            .args(["schema", "set", "deals"])
            .arg(&file),
    );
    // Anyone who can discover the collection can read its schema.
    run_success(as_principal(bob).args(["schema", "show", "deals"]));
    assert!(Path::new(&database.root.join(".cr/schemas/deals.json")).exists());
}
