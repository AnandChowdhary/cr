mod common;

use std::fs;

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

const OWNER: &str = "Harness <harness@example.com>";

fn as_owner(database: &TestDatabase) -> std::process::Command {
    let mut command = database.command();
    command.env("CR_ACTOR", OWNER);
    command
}

fn json(command: &mut std::process::Command) -> Value {
    serde_json::from_str(&run_success(command)).expect("command output is JSON")
}

fn initialize_service_owner(database: &TestDatabase) {
    run_success(as_owner(database).args([
        "access",
        "init",
        "--name",
        "Harness",
        "--email",
        "harness@example.com",
        "--service",
    ]));
}

#[test]
fn service_bootstrap_and_profile_updates_are_first_class_cli_operations() {
    let database = TestDatabase::new("user-cli");
    initialize_service_owner(&database);

    let owner = json(as_owner(&database).args(["user", "show", "harness@example.com", "--json"]));
    assert_eq!(owner["user"]["kind"], "service");

    run_success(as_owner(&database).args([
        "user",
        "add",
        "ada@example.com",
        "--name",
        "Ada",
        "--email",
        "ada@example.com",
        "--kind",
        "human",
        "--set",
        "role=CEO",
        "--set",
        "slack.id=U123",
        "--json",
    ]));
    run_success(as_owner(&database).args([
        "access",
        "grant",
        "ada@example.com",
        "viewer",
        "collection:people",
    ]));

    let updated = json(as_owner(&database).args([
        "user",
        "update",
        "ada@example.com",
        "--name",
        "Ada Lovelace",
        "--clear-email",
        "--service",
        "--set",
        "role=CTO",
        "--set",
        "team=leadership",
        "--json",
    ]));
    assert_eq!(updated["attributes"]["name"], "Ada Lovelace");

    let ada = json(as_owner(&database).args(["user", "show", "ada@example.com", "--json"]));
    assert_eq!(ada["user"]["name"], "Ada Lovelace");
    assert!(ada["user"].get("email").is_none());
    assert_eq!(ada["user"]["kind"], "service");
    assert_eq!(ada["user"]["profile"]["role"], "CTO");
    assert_eq!(ada["user"]["profile"]["team"], "leadership");
    assert_eq!(ada["user"]["profile"]["slack"]["id"], "U123");
    assert_eq!(ada["user"]["access"][0]["role"], "viewer");
}

#[test]
fn ensure_is_idempotent_and_definition_drift_is_machine_readable() {
    let database = TestDatabase::new("user-ensure-cli");
    initialize_service_owner(&database);

    let first = json(as_owner(&database).args([
        "user",
        "ensure",
        "worker@example.com",
        "--name",
        "Worker",
        "--service",
        "--set",
        "queue=default",
        "--json",
    ]));
    assert_eq!(first["created"], true);
    let second = json(as_owner(&database).args([
        "user",
        "ensure",
        "worker@example.com",
        "--name",
        "Worker",
        "--service",
        "--set",
        "queue=default",
        "--json",
    ]));
    assert_eq!(second["created"], false);

    let error = run_failure(as_owner(&database).args([
        "--json-errors",
        "user",
        "ensure",
        "worker@example.com",
        "--name",
        "Different worker",
        "--service",
        "--set",
        "queue=default",
    ]));
    let error: Value = serde_json::from_str(&error).expect("failure is JSON");
    assert_eq!(error["error"]["code"], "conflict");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not match")
    );
}

#[test]
fn restore_repairs_a_drifted_managed_user_file() {
    let database = TestDatabase::new("user-restore-cli");
    initialize_service_owner(&database);
    run_success(as_owner(&database).args([
        "user",
        "add",
        "worker@example.com",
        "--name",
        "Worker",
        "--service",
    ]));

    let path = database.root().join("records/users/worker@example.com.md");
    let original = fs::read_to_string(&path).unwrap();
    fs::write(&path, original.replace("name: Worker", "name: Drifted")).unwrap();
    assert!(
        run_failure(as_owner(&database).args(["audit", "verify"])).contains("latest audited state")
    );

    run_success(as_owner(&database).args(["user", "restore", "worker@example.com", "--json"]));
    assert_eq!(fs::read_to_string(&path).unwrap(), original);
    run_success(as_owner(&database).args(["audit", "verify"]));
}
