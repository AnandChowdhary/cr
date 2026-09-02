mod common;

use std::fs;

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

const OWNER: &str = "Harness <harness@example.com>";

fn as_owner(database: &TestDatabase) -> std::process::Command {
    as_principal(database, OWNER)
}

fn as_principal(database: &TestDatabase, actor: &str) -> std::process::Command {
    let mut command = database.command();
    command.env("CR_ACTOR", actor);
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

#[test]
fn profile_editors_and_principals_can_use_the_ordinary_cli_without_reserved_field_access() {
    let database = TestDatabase::new("profile-editor-cli");
    initialize_service_owner(&database);
    for (id, name) in [
        ("agent@example.com", "Agent"),
        ("person@example.com", "Person"),
    ] {
        run_success(as_owner(&database).args(["user", "add", id, "--name", name, "--email", id]));
    }
    run_success(as_owner(&database).args([
        "access",
        "grant",
        "agent@example.com",
        "editor",
        "collection:users",
    ]));

    run_success(as_principal(&database, "Agent <agent@example.com>").args([
        "update",
        "users",
        "person@example.com",
        "--set",
        "profile.source=slack",
    ]));
    run_success(as_principal(&database, "Agent <agent@example.com>").args([
        "user",
        "update",
        "person@example.com",
        "--set",
        "summary=Works on platform",
    ]));
    let denied = run_failure(as_principal(&database, "Agent <agent@example.com>").args([
        "user",
        "update",
        "person@example.com",
        "--name",
        "Agent chose this",
    ]));
    assert!(denied.contains("cannot manage_access database"), "{denied}");
    let denied = run_failure(as_principal(&database, "Agent <agent@example.com>").args([
        "update",
        "users",
        "person@example.com",
        "--set",
        "status=disabled",
    ]));
    assert!(denied.contains("only profile.*"), "{denied}");

    run_success(
        as_principal(&database, "Person <person@example.com>").args([
            "user",
            "update",
            "person@example.com",
            "--name",
            "Preferred Person",
            "--set",
            "timezone=Europe/Amsterdam",
        ]),
    );
    run_success(
        as_principal(&database, "Person <person@example.com>").args([
            "update",
            "users",
            "person@example.com",
            "--set",
            "profile.pronouns=they/them",
        ]),
    );
    let denied = run_failure(
        as_principal(&database, "Person <person@example.com>").args([
            "user",
            "update",
            "person@example.com",
            "--service",
        ]),
    );
    assert!(denied.contains("cannot manage_access database"), "{denied}");

    let person = json(as_owner(&database).args(["user", "show", "person@example.com", "--json"]));
    assert_eq!(person["user"]["name"], "Preferred Person");
    assert_eq!(person["user"]["kind"], "human");
    assert_eq!(person["user"]["status"], "active");
    assert_eq!(person["user"]["email"], "person@example.com");
    assert_eq!(person["user"]["profile"]["source"], "slack");
    assert_eq!(person["user"]["profile"]["summary"], "Works on platform");
    assert_eq!(person["user"]["profile"]["timezone"], "Europe/Amsterdam");
    assert_eq!(person["user"]["profile"]["pronouns"], "they/them");
}
