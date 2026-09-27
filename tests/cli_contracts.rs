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
fn cli_expected_record_hash_is_obtainable_and_typed_when_stale() {
    let database = TestDatabase::new("cli-record-preconditions");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=open"]),
    );
    let fetched: Value = serde_json::from_str(&run_success(
        database.command().args(["get", "items", "one", "--json"]),
    ))
    .unwrap();
    let version = fetched["version"].as_str().expect("record version");

    run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=won",
        "--expected-record-hash",
        version,
    ]));
    let stale = json_error(database.command().args([
        "--json-errors",
        "update",
        "items",
        "one",
        "--set",
        "stage=lost",
        "--expected-record-hash",
        version,
    ]));
    assert_eq!(stale["error"]["code"], "precondition_failed");
    assert_eq!(
        stale["error"]["message"],
        "record items/one changed since the expected version"
    );

    let malformed = json_error(database.command().args([
        "--json-errors",
        "delete",
        "items",
        "one",
        "--yes",
        "--expected-record-hash",
        "sha256:NOT-A-HASH",
    ]));
    assert_eq!(malformed["error"]["code"], "validation_failed");
}

/// An operating-system failure nobody anticipated keeps the fallback code and,
/// unlike a classified failure, its complete chain.
#[test]
fn json_errors_give_unclassified_failures_a_stable_fallback() {
    let temporary = tempfile::tempdir().unwrap();
    let blocker = temporary.path().join("blocker");
    std::fs::write(&blocker, "not a directory\n").unwrap();

    let payload = json_error(
        Command::new(binary())
            .arg("--json-errors")
            .arg("init")
            .arg(blocker.join("database")),
    );
    assert_eq!(payload["error"]["code"], "internal_error");
    assert!(
        payload["error"]["message"]
            .as_str()
            .expect("error message is a string")
            .contains("could not create database root")
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

/// The argument checks clap cannot express are the same mistake as the ones
/// it can, caught later, so a script sees the same code and exit status for
/// both. Without `--json-errors` the message is unchanged.
#[test]
fn argument_checks_clap_cannot_express_are_usage_errors() {
    let database = TestDatabase::new("json-usage-errors");
    run_success(database.command().args(["create", "items", "one"]));
    let record = database.root().join("records/items/one.md");
    let before = std::fs::read(&record).unwrap();

    let clap_status =
        failure(Command::new(binary()).args(["--json-errors", "--not-a-real-option"]))
            .status
            .code();
    assert_eq!(clap_status, Some(2));

    let secret = "must-not-appear";
    let cases: [(Vec<&str>, &str); 8] = [
        (
            vec!["--as", "bob@example.com", "serve"],
            "--as cannot be used to launch the long-lived server",
        ),
        (
            vec!["--as", "bob@example.com", "init", "elsewhere"],
            "--as cannot be used while initializing a database",
        ),
        (
            vec!["update", "items", "one"],
            "provide at least one --set, --set-env, --unset, or --body value",
        ),
        (
            vec!["delete", "items", "one"],
            "deleting a record requires --yes to confirm the destructive operation",
        ),
        (
            vec!["audit", "log", "--limit", "0"],
            "audit log limit must be greater than zero",
        ),
        (
            vec!["user", "delete", "bob@example.com"],
            "deleting a user requires --yes to confirm the destructive operation",
        ),
        (
            vec![
                "access",
                "policy",
                "set",
                "database",
                "--mode",
                "record-owned",
            ],
            "record-owned access policy requires collection:NAME",
        ),
        (
            vec![
                "create",
                "items",
                "two",
                "--set",
                "token=a",
                "--set-env",
                "token=CR_USAGE_SECRET",
            ],
            "field 'token' is assigned more than once across --set and --set-env",
        ),
    ];
    for (arguments, message) in cases {
        let mut command = database.command();
        command.env("CR_USAGE_SECRET", secret).args(&arguments);
        let json = failure(command.arg("--json-errors"));
        assert_eq!(json.status.code(), clap_status, "{arguments:?}");
        assert!(json.stdout.is_empty(), "{arguments:?}");
        let payload: Value = serde_json::from_slice(&json.stderr).unwrap();
        assert_eq!(payload["error"]["code"], "usage_error", "{arguments:?}");
        assert_eq!(payload["error"]["message"], message, "{arguments:?}");

        let mut command = database.command();
        command.env("CR_USAGE_SECRET", secret).args(&arguments);
        let human = failure(&mut command);
        assert_eq!(human.status.code(), clap_status, "{arguments:?}");
        let stderr = String::from_utf8(human.stderr).unwrap();
        assert_eq!(stderr, format!("error: {message}\n"));
        assert!(!stderr.contains(secret));
    }

    assert_eq!(std::fs::read(&record).unwrap(), before);
    assert!(!database.root().join("records/items/two.md").exists());
    assert!(!database.root().join("records/users").exists());
    run_success(database.command().args(["audit", "verify"]));
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
