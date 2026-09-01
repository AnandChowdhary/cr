mod common;

use std::{fs, process::Command};

use common::{command_for, run_failure, run_success};
use serde_json::Value;

#[test]
fn create_query_update_and_link_records() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("crm");

    run_success(
        Command::new(env!("CARGO_BIN_EXE_cr"))
            .arg("init")
            .arg(&database),
    );

    run_success(command_for(&database).args([
        "create",
        "companies",
        "acme",
        "--set",
        "name=Acme Corp",
    ]));
    run_success(command_for(&database).args([
        "create",
        "candidates",
        "jane-doe",
        "--set",
        "name=Jane Doe",
        "--set",
        "stage=screening",
        "--set",
        "contact.email=jane@example.com",
        "--body",
        "# Jane Doe\n\nStrong systems candidate.\n",
    ]));

    run_success(command_for(&database).args([
        "update",
        "candidates",
        "jane-doe",
        "--set",
        "stage=interview",
    ]));
    run_success(command_for(&database).args([
        "link",
        "candidates",
        "jane-doe",
        "company",
        "companies",
        "acme",
    ]));

    let fetched =
        run_success(command_for(&database).args(["get", "candidates", "jane-doe", "--json"]));
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    assert_eq!(fetched["id"], "jane-doe");
    assert_eq!(fetched["attributes"]["stage"], "interview");
    assert_eq!(
        fetched["attributes"]["contact"]["email"],
        "jane@example.com"
    );
    assert_eq!(
        fetched["attributes"]["relations"]["company"][0]["collection"],
        "companies"
    );
    assert!(
        fetched["body"]
            .as_str()
            .unwrap()
            .contains("systems candidate")
    );

    let listed = run_success(command_for(&database).args([
        "list",
        "candidates",
        "--where",
        "stage=interview",
        "--json",
    ]));
    let listed: Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["path"], "records/candidates/jane-doe.md");
    assert_eq!(listed[0]["front_matter"]["stage"], "interview");
    assert_eq!(
        listed[0]["front_matter"]["contact"]["email"],
        "jane@example.com"
    );
    assert!(listed[0].get("body").is_none());

    let markdown = fs::read_to_string(database.join("records/candidates/jane-doe.md")).unwrap();
    assert!(markdown.starts_with("---\n"));
    assert!(markdown.contains("stage: interview"));
    assert!(markdown.ends_with("# Jane Doe\n\nStrong systems candidate.\n"));
}

#[test]
fn optional_json_schema_rejects_invalid_updates_without_changing_the_file() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("ats");
    run_success(
        Command::new(env!("CARGO_BIN_EXE_cr"))
            .arg("init")
            .arg(&database),
    );

    let schema = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["stage"],
  "properties": {
    "stage": { "enum": ["screening", "interview", "offer"] }
  }
}"#;
    fs::write(database.join(".cr/schemas/candidates.json"), schema).unwrap();

    run_success(command_for(&database).args([
        "create",
        "candidates",
        "jane-doe",
        "--set",
        "stage=screening",
    ]));
    let record_path = database.join("records/candidates/jane-doe.md");
    let before = fs::read_to_string(&record_path).unwrap();

    let stderr = run_failure(command_for(&database).args([
        "update",
        "candidates",
        "jane-doe",
        "--set",
        "stage=rejected",
    ]));
    assert!(stderr.contains("does not match schema"));
    assert_eq!(fs::read_to_string(record_path).unwrap(), before);
}

/// `jsonschema` 0.52 moved `idn-hostname` and `idn-email` behind an `idna`
/// Cargo feature that `default-features = false` switches off, and an unknown
/// format is *accepted*, not rejected. That failure mode is silent: the schema
/// still compiles and every record still validates, so nothing else in this
/// suite would notice the assertion disappearing. Draft-07 is the interesting
/// dialect because `format` asserts there by default; under 2020-12, which every
/// other schema in this repository declares, `format` is only an annotation.
#[test]
fn draft_07_schemas_still_assert_internationalized_formats() {
    let temporary = tempfile::tempdir().unwrap();
    let database = temporary.path().join("hosts");
    run_success(
        Command::new(env!("CARGO_BIN_EXE_cr"))
            .arg("init")
            .arg(&database),
    );

    let schema = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["host"],
  "properties": {
    "host": { "type": "string", "format": "idn-hostname" }
  }
}"#;
    fs::write(database.join(".cr/schemas/servers.json"), schema).unwrap();

    let stderr = run_failure(command_for(&database).args([
        "create",
        "servers",
        "broken",
        "--set",
        "host=-1bad-.example",
    ]));
    assert!(
        stderr.contains("does not match schema"),
        "an invalid internationalized hostname must be refused, got: {stderr}"
    );
    assert!(!database.join("records/servers/broken.md").exists());

    run_success(command_for(&database).args([
        "create",
        "servers",
        "good",
        "--set",
        "host=münchen.example",
    ]));
}
