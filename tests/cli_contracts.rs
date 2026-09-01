mod common;

use std::process::{Command, Output};

use common::{TestDatabase, binary, run_success};
use serde_json::Value;

const OWNER: &str = "Owner <owner@example.com>";

fn failure(command: &mut Command) -> Output {
    let output = command.output().expect("failed to run cr");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn json_error(command: &mut Command) -> Value {
    let output = failure(command);
    assert!(output.stdout.is_empty(), "errors belong on stderr");
    serde_json::from_slice(&output.stderr).unwrap_or_else(|error| {
        panic!(
            "stderr was not a JSON error envelope: {error}\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn as_owner(database: &TestDatabase) -> Command {
    let mut command = database.command();
    command.env("CR_ACTOR", OWNER);
    command
}

#[test]
fn json_errors_classify_duplicate_records_and_users() {
    let database = TestDatabase::new("json-domain-errors");
    run_success(database.command().args(["create", "items", "one"]));

    let duplicate_record =
        json_error(
            database
                .command()
                .args(["create", "items", "one", "--json-errors"]),
        );
    assert_eq!(duplicate_record["error"]["code"], "already_exists");
    assert_eq!(
        duplicate_record["error"]["message"],
        "record items/one already exists"
    );

    run_success(as_owner(&database).args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(as_owner(&database).args([
        "user",
        "add",
        "worker@example.com",
        "--name",
        "Worker",
        "--service",
    ]));
    let duplicate_user = json_error(as_owner(&database).args([
        "user",
        "add",
        "worker@example.com",
        "--name",
        "Worker",
        "--service",
        "--json-errors",
    ]));
    assert_eq!(duplicate_user["error"]["code"], "already_exists");
    assert_eq!(
        duplicate_user["error"]["message"],
        "record users/worker@example.com already exists"
    );
}

#[test]
fn json_errors_give_unclassified_failures_a_stable_fallback() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("existing");
    run_success(Command::new(binary()).arg("init").arg(&root));

    let payload = json_error(
        Command::new(binary())
            .arg("--json-errors")
            .arg("init")
            .arg(&root),
    );
    assert_eq!(payload["error"]["code"], "internal_error");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message is a string")
            .contains("a database already exists")
    );
}

#[test]
fn json_errors_include_command_line_usage_failures() {
    let missing_arguments = json_error(Command::new(binary()).args(["--json-errors", "create"]));
    assert_eq!(missing_arguments["error"]["code"], "usage_error");
    assert!(
        missing_arguments["error"]["message"]
            .as_str()
            .unwrap()
            .contains("required arguments")
    );

    let unknown = json_error(Command::new(binary()).args(["--json-errors", "--not-a-real-option"]));
    assert_eq!(unknown["error"]["code"], "usage_error");
    assert!(
        unknown["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unexpected argument")
    );

    let help = Command::new(binary())
        .args(["--json-errors", "--help"])
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout).unwrap().contains("Usage:"));
}

#[test]
fn audit_filters_have_clear_names_and_compatible_aliases() {
    let database = TestDatabase::new("audit-filter-names");
    run_success(database.command().args([
        "create",
        "items",
        "one",
        "--agent",
        "worker",
        "--agent-session",
        "session-a",
    ]));

    for (primary, alias, value) in [
        ("--by-agent", "--agent", "worker"),
        ("--by-session", "--session", "session-a"),
    ] {
        let primary: Value = serde_json::from_str(&run_success(
            database
                .command()
                .args(["audit", "log", primary, value, "--json"]),
        ))
        .expect("primary audit filter emits JSON");
        let alias: Value = serde_json::from_str(&run_success(
            database
                .command()
                .args(["audit", "log", alias, value, "--json"]),
        ))
        .expect("compatibility audit filter emits JSON");
        assert_eq!(primary, alias);
        assert_eq!(primary.as_array().expect("an array").len(), 1);
    }

    let help = run_success(Command::new(binary()).args(["audit", "log", "--help"]));
    assert!(help.contains("--by-agent <AGENT>"));
    assert!(help.contains("--by-session <SESSION>"));
    assert!(help.contains("--agent"));
    assert!(help.contains("--session"));
}
