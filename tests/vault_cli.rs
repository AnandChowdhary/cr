mod common;

use std::{fs, process::Command};

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OWNER: &str = "Owner <owner@example.com>";
const EDITOR: &str = "Editor <editor@example.com>";

fn encrypted_command(database: &TestDatabase) -> Command {
    let mut command = database.command();
    command
        .env("CR_ENCRYPTION_ACTIVE_KEY", "v1")
        .env("CR_ENCRYPTION_KEYS", format!(r#"{{"v1":"{KEY}"}}"#));
    command
}

fn as_principal(database: &TestDatabase, actor: &str) -> Command {
    let mut command = database.command();
    command.env("CR_ACTOR", actor);
    command
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

#[test]
fn schema_commands_create_preserve_and_idempotently_mark_policy() {
    let database = TestDatabase::new("schema-encryption-cli");
    let schema_path = database.root.join(".cr/schemas/secrets.json");
    fs::write(
        &schema_path,
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["name"],
  "properties": {
    "name": { "type": "string" },
    "credentials": {
      "type": "object",
      "properties": { "token": { "type": "string", "minLength": 8 } }
    }
  }
}"#,
    )
    .unwrap();

    assert!(
        run_success(
            database
                .command()
                .args(["schema", "encrypt", "secrets", "credentials.token",])
        )
        .contains("Enabled encrypted storage")
    );
    assert!(
        run_success(
            database
                .command()
                .args(["schema", "encrypt-body", "secrets"]),
        )
        .contains("Enabled encrypted body storage")
    );

    let schema: Value = serde_json::from_str(&fs::read_to_string(&schema_path).unwrap()).unwrap();
    assert_eq!(schema["required"], serde_json::json!(["name"]));
    assert_eq!(schema["properties"]["name"]["type"], "string");
    assert_eq!(
        schema["properties"]["credentials"]["properties"]["token"]["minLength"],
        8
    );
    assert_eq!(
        schema["properties"]["credentials"]["properties"]["token"]["x-cr-encrypted"],
        true
    );
    assert_eq!(schema["x-cr-encrypted-body"], true);

    assert!(
        run_success(
            database
                .command()
                .args(["schema", "encrypt", "secrets", "credentials.token",])
        )
        .contains("Already enabled")
    );
    assert!(
        run_success(
            database
                .command()
                .args(["schema", "encrypt-body", "secrets"]),
        )
        .contains("Already enabled")
    );
}

#[test]
fn set_env_round_trips_exact_strings_through_encrypted_create_and_update() {
    let database = TestDatabase::new("encrypted-env-vault");
    run_success(
        database
            .command()
            .args(["schema", "encrypt", "secrets", "value"]),
    );
    run_success(
        database
            .command()
            .args(["schema", "encrypt-body", "secrets"]),
    );

    let first = "true: [still one exact string] # first secret";
    run_success(
        encrypted_command(&database)
            .env("OPENAI_API_KEY", first)
            .args([
                "create",
                "secrets",
                "production-openai",
                "--set",
                "name=OPENAI_API_KEY",
                "--set-env",
                "value=OPENAI_API_KEY",
            ]),
    );

    let fetched =
        json(encrypted_command(&database).args(["get", "secrets", "production-openai", "--json"]));
    assert_eq!(fetched["attributes"]["value"], first);
    let stored =
        fs::read_to_string(database.root.join("records/secrets/production-openai.md")).unwrap();
    assert!(stored.contains("$cr_encrypted"));
    assert!(stored.contains("cr-encrypted:v1:"));
    assert!(!stored.contains(first));
    let audit = fs::read_dir(database.root.join(".cr/audit/segments"))
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect::<String>();
    assert!(!audit.contains(first));

    let second = "null # remains a string after update";
    run_success(
        encrypted_command(&database)
            .env("OPENAI_API_KEY", second)
            .args([
                "update",
                "secrets",
                "production-openai",
                "--set-env",
                "value=OPENAI_API_KEY",
            ]),
    );
    let fetched =
        json(encrypted_command(&database).args(["get", "secrets", "production-openai", "--json"]));
    assert_eq!(fetched["attributes"]["value"], second);

    // Verification hashes stored ciphertext and deliberately needs no keys.
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn set_env_reports_only_variable_names_and_rejects_ambiguous_fields() {
    let database = TestDatabase::new("set-env-errors");
    let missing = run_failure(database.command().args([
        "create",
        "secrets",
        "missing",
        "--set-env",
        "value=ABSENT_VAULT_SECRET",
    ]));
    assert!(missing.contains("environment variable 'ABSENT_VAULT_SECRET' is not set"));
    assert!(!database.root.join("records/secrets/missing.md").exists());

    let duplicate = run_failure(
        database
            .command()
            .env("VAULT_SECRET", "must-not-appear")
            .args([
                "create",
                "secrets",
                "duplicate",
                "--set",
                "value=ordinary",
                "--set-env",
                "value=VAULT_SECRET",
            ]),
    );
    assert!(duplicate.contains("field 'value' is assigned more than once"));
    assert!(!duplicate.contains("must-not-appear"));
    assert!(!database.root.join("records/secrets/duplicate.md").exists());
}

#[test]
fn schema_policy_changes_refuse_existing_records_and_history() {
    let database = TestDatabase::new("schema-migration-boundary");
    run_success(database.command().args([
        "create",
        "secrets",
        "legacy",
        "--set",
        "value=plaintext",
    ]));

    let error = run_failure(
        database
            .command()
            .args(["schema", "encrypt", "secrets", "value"]),
    );
    assert!(error.contains("cannot change encryption policy"));
    assert!(error.contains("export the plaintext"));
    assert!(!database.root.join(".cr/schemas/secrets.json").exists());

    run_success(
        database
            .command()
            .args(["delete", "secrets", "legacy", "--yes"]),
    );
    let error = run_failure(
        database
            .command()
            .args(["schema", "encrypt", "secrets", "value"]),
    );
    assert!(error.contains("records or audit history"));
}

#[test]
fn schema_policy_requires_collection_ownership_under_rbac() {
    let database = TestDatabase::new("schema-rbac");
    run_success(as_principal(&database, OWNER).args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "user",
        "add",
        "editor@example.com",
        "--name",
        "Editor",
        "--email",
        "editor@example.com",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "editor@example.com",
        "editor",
        "collection:secrets",
    ]));

    let error = run_failure(
        as_principal(&database, EDITOR).args(["schema", "encrypt", "secrets", "value"]),
    );
    assert!(
        error.contains("cannot manage_access collection:secrets"),
        "{error}"
    );
    assert!(!database.root.join(".cr/schemas/secrets.json").exists());

    run_success(as_principal(&database, OWNER).args(["schema", "encrypt", "secrets", "value"]));
}
