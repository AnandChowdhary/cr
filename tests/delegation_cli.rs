mod common;

use std::{fs, process::Command};

use common::{TestDatabase, binary, run_failure, run_success};
use serde_json::Value;

const OWNER: &str = "Owner <owner@example.com>";
const BOB: &str = "Bob <bob@example.com>";
const MANAGER: &str = "Manager <manager@example.com>";

fn as_principal(database: &TestDatabase, actor: &str) -> Command {
    let mut command = database.command();
    command.env("CR_ACTOR", actor);
    command
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).expect("command output is JSON")
}

fn initialize(database: &TestDatabase) {
    run_success(as_principal(database, OWNER).args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
}

fn add_bob(database: &TestDatabase) {
    run_success(as_principal(database, OWNER).args([
        "user",
        "add",
        "bob@example.com",
        "--name",
        "Bob",
        "--email",
        "bob@example.com",
    ]));
}

#[test]
fn owner_delegation_uses_the_targets_permissions_and_records_the_operator() {
    let database = TestDatabase::new("cli-delegation");
    initialize(&database);
    for id in ["public", "secret"] {
        run_success(as_principal(&database, OWNER).args([
            "create",
            "deals",
            id,
            "--set",
            "stage=open",
        ]));
    }
    add_bob(&database);
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "bob@example.com",
        "editor",
        "collection:deals",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "bob@example.com",
        "viewer",
        "record:deals/secret",
    ]));

    let identity = json(as_principal(&database, OWNER).args([
        "--as",
        "bob@example.com",
        "identity",
        "--json",
    ]));
    assert_eq!(identity["actor"], BOB);
    assert_eq!(identity["principal"], "bob@example.com");
    assert_eq!(
        identity["impersonated_by"]["principal"],
        "owner@example.com"
    );
    assert_eq!(identity["impersonated_by"]["display"], OWNER);

    let secret = run_success(as_principal(&database, OWNER).args([
        "--as",
        "bob@example.com",
        "get",
        "deals",
        "secret",
    ]));
    assert!(secret.contains("stage: open"));
    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "--as",
            "bob@example.com",
            "update",
            "deals",
            "secret",
            "--set",
            "stage=won",
        ]))
        .contains("principal 'bob@example.com' cannot update record:deals/secret")
    );

    run_success(as_principal(&database, OWNER).args([
        "--as",
        "bob@example.com",
        "update",
        "deals",
        "public",
        "--set",
        "stage=won",
    ]));
    let history =
        json(as_principal(&database, OWNER).args(["audit", "log", "deals", "public", "--json"]));
    assert_eq!(history[0]["actor"], BOB);
    assert_eq!(history[0]["access"]["principal"], "bob@example.com");
    assert_eq!(history[0]["access"]["role"], "editor");
    assert_eq!(
        history[0]["access"]["impersonated_by"]["principal"],
        "owner@example.com"
    );
    assert_eq!(history[0]["access"]["impersonated_by"]["display"], OWNER);

    let bob_path = database.root().join("records/users/bob@example.com.md");
    let policy = fs::read_to_string(&bob_path).unwrap();
    fs::write(&bob_path, policy.replace("role: viewer", "role: editor")).unwrap();
    let drifted_target = run_failure(as_principal(&database, OWNER).args([
        "--as",
        "bob@example.com",
        "update",
        "deals",
        "secret",
        "--set",
        "stage=won",
    ]));
    assert!(
        drifted_target.contains("latest audited state"),
        "{drifted_target}"
    );
}

#[test]
fn delegation_requires_an_initialized_database_owner_and_a_registered_target() {
    let legacy = TestDatabase::new("legacy-delegation");
    assert!(
        run_failure(
            legacy
                .command()
                .args(["--as", "bob@example.com", "identity"])
        )
        .contains("access control is not initialized")
    );

    let database = TestDatabase::new("delegation-boundaries");
    initialize(&database);
    add_bob(&database);

    let non_owner =
        run_failure(as_principal(&database, BOB).args(["--as", "owner@example.com", "identity"]));
    assert!(
        non_owner.contains("must be an owner of database"),
        "{non_owner}"
    );
    let missing_as_non_owner =
        run_failure(as_principal(&database, BOB).args(["--as", "missing@example.com", "identity"]));
    assert_eq!(non_owner, missing_as_non_owner);
    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "--as",
            "missing@example.com",
            "identity",
        ]))
        .contains("users/missing@example.com")
    );

    run_success(as_principal(&database, OWNER).args([
        "user",
        "add",
        "manager@example.com",
        "--name",
        "Manager",
        "--email",
        "manager@example.com",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "manager@example.com",
        "access_manager",
        "database",
    ]));
    let manager_path = database.root().join("records/users/manager@example.com.md");
    let policy = fs::read_to_string(&manager_path).unwrap();
    fs::write(&manager_path, policy.replace("access_manager", "owner")).unwrap();
    let drifted = run_failure(as_principal(&database, MANAGER).args([
        "--as",
        "owner@example.com",
        "identity",
    ]));
    assert!(drifted.contains("latest audited state"), "{drifted}");
}

#[test]
fn top_level_help_documents_delegation() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("failed to run cr --help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help output was not UTF-8");
    assert!(stdout.contains("--as <PRINCIPAL>"));
    assert!(stdout.contains("Requires database ownership"));
}

#[test]
fn delegation_cannot_be_stretched_across_a_long_lived_server() {
    let database = TestDatabase::new("delegated-server");
    initialize(&database);
    add_bob(&database);

    let error =
        run_failure(as_principal(&database, OWNER).args(["--as", "bob@example.com", "serve"]));
    assert!(
        error.contains("--as cannot be used to launch the long-lived server"),
        "{error}"
    );
}
