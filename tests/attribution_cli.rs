//! Agent, authorization, and intent attribution through the command line.
//!
//! These tests cover the two halves of the claim this feature makes. The
//! functional half is that an agent-run mutation records the human as `actor`,
//! the software beside it, and both parts of the intent. The compatibility half
//! is that none of it can make `audit verify` fail: a journal written before the
//! fields existed still verifies, byte for byte, to the same head hash.

mod common;

use std::{fs, path::Path, process::Command};

use common::{TestDatabase, binary, command_for, run_failure, run_success};
use serde_json::Value;

/// The head hash `cr` at `0ca95fb` wrote for `tests/fixtures/legacy-journal`,
/// recorded here so a change that alters how stored bytes are hashed cannot pass
/// unnoticed.
const LEGACY_HEAD: &str = "sha256:5b872015034716e3845cf69dc5c7ced7d801b05fe21aef406de4f965ff54f3ef";

/// The head hash of `tests/fixtures/future-journal`, whose events name
/// attribution values this build does not know.
const FUTURE_HEAD: &str = "sha256:b63e39719e07ca692675af1a16c98eed9749d5be01b4369a35e0668849733b60";

/// Copy the committed pre-attribution database into a scratch directory.
fn legacy_database(target: &Path) {
    copy_fixture("legacy-journal", target);
}

/// Copy a committed fixture database into a scratch directory.
fn copy_fixture(name: &str, target: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    copy_tree(&source, target);
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("could not create the scratch directory");
    for entry in fs::read_dir(source).expect("could not read the fixture") {
        let entry = entry.expect("could not read a fixture entry");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("could not stat a fixture entry")
            .is_dir()
        {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), &destination).expect("could not copy a fixture file");
        }
    }
}

/// A journal written before this feature existed must verify unchanged, and to
/// exactly the head hash the older `cr` reported. This is the guarantee that
/// made an audit version bump unnecessary: nothing about adding optional
/// metadata may make an existing chain fail.
#[test]
fn a_journal_written_before_attribution_existed_still_verifies() {
    let temporary = tempfile::tempdir().expect("could not create a temporary directory");
    let root = temporary.path().join("legacy");
    legacy_database(&root);

    let verified = run_success(command_for(&root).arg("audit").arg("verify"));
    assert!(verified.contains("Verified 4 audit events and 2 records"));
    assert!(verified.contains(LEGACY_HEAD));

    let head = run_success(command_for(&root).args(["audit", "head"]));
    assert_eq!(head.trim(), format!("4 {LEGACY_HEAD}"));

    run_success(command_for(&root).args(["audit", "verify", "--expected-head", LEGACY_HEAD]));

    let entries: Value = serde_json::from_str(&run_success(
        command_for(&root).args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    for entry in entries.as_array().expect("audit log is an array") {
        assert_eq!(entry["version"], 2);
        assert!(entry.get("agent").is_none());
        assert!(entry.get("authorization").is_none());
        assert!(entry.get("intent").is_none());
    }
}

/// A journal written by a later `cr` that grew an attribution value must still
/// verify here, and the value it named must survive unchanged.
///
/// `tests/fixtures/future-journal` carries an `agent.detected_from` of
/// `attestation`, an `authorization.mode` of `escalated`, and an
/// `intent.request.author` of `operator`. None of them exists in this build.
/// Before the reader was made tolerant, `audit verify` on this fixture failed
/// with `unknown variant \`attestation\`` and refused the *entire* chain,
/// including the two events that carry no attribution at all — the precise
/// hard failure that not bumping the audit version exists to prevent.
///
/// Appending to that journal must leave the earlier bytes alone, so the head
/// still chains from the fixture's own head hash.
#[test]
fn a_journal_naming_unknown_attribution_values_still_verifies() {
    let temporary = tempfile::tempdir().expect("could not create a temporary directory");
    let root = temporary.path().join("future");
    copy_fixture("future-journal", &root);

    let verified = run_success(command_for(&root).args(["audit", "verify"]));
    assert!(verified.contains("Verified 4 audit events and 2 records"));
    assert!(verified.contains(FUTURE_HEAD));
    run_success(command_for(&root).args(["audit", "verify", "--expected-head", FUTURE_HEAD]));

    let entries: Value = serde_json::from_str(&run_success(
        command_for(&root).args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    let entries = entries.as_array().expect("audit log is an array");
    let unknown = entries
        .iter()
        .find(|entry| entry["sequence"] == 3)
        .expect("the unknown-value event is present");
    assert_eq!(unknown["agent"]["detected_from"], "attestation");
    assert_eq!(unknown["authorization"]["mode"], "escalated");
    assert_eq!(unknown["intent"]["request"]["author"], "operator");

    let known = entries
        .iter()
        .find(|entry| entry["sequence"] == 4)
        .expect("the known-value event is present");
    assert_eq!(known["agent"]["detected_from"], "environment");
    assert_eq!(known["authorization"]["mode"], "delegated");

    run_success(
        command_for(&root)
            .args(["update", "deals", "acme-renewal", "--set", "stage=won"])
            .args(["--agent", "claude-code"]),
    );
    run_success(command_for(&root).args(["audit", "verify"]));
    let entries: Value = serde_json::from_str(&run_success(
        command_for(&root).args(["audit", "log", "--json", "-n", "1"]),
    ))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["previous_hash"], FUTURE_HEAD);
}

/// Reading an unknown value is not the same as accepting one. `cr` must never
/// record an approval mode it cannot name: a permanent record of `escalated`
/// would look stronger than `delegated` to a reader and mean nothing.
#[test]
fn an_unknown_attribution_value_cannot_be_declared() {
    let database = TestDatabase::new("unknown-values");
    run_success(database.command().args(["create", "deals", "one"]));

    let error = run_failure(
        database
            .command()
            .args(["update", "deals", "one", "--set", "stage=won"])
            .args(["--authorization", "escalated"]),
    );
    assert!(
        error.contains("must be direct, interactive"),
        "unexpected error: {error}"
    );

    let error = run_failure(
        database
            .command()
            .args(["update", "deals", "one", "--set", "stage=won"])
            .args([
                "--intent",
                r#"{"request":{"author":"operator","text":"go"}}"#,
            ]),
    );
    assert!(
        error.contains("author must be human, agent, or system"),
        "unexpected error: {error}"
    );
}

/// A change written today with attribution must still extend that same chain,
/// leaving every earlier event and its hash untouched.
#[test]
fn attribution_extends_a_pre_attribution_chain_without_disturbing_it() {
    let temporary = tempfile::tempdir().expect("could not create a temporary directory");
    let root = temporary.path().join("legacy");
    legacy_database(&root);

    run_success(
        command_for(&root)
            .args(["update", "deals", "acme-renewal", "--set", "stage=won"])
            .args(["--agent", "claude-code", "--authorization", "delegated"]),
    );
    run_success(command_for(&root).args(["audit", "verify"]));

    let entries: Value = serde_json::from_str(&run_success(
        command_for(&root).args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    let entries = entries.as_array().expect("audit log is an array");
    assert_eq!(entries.len(), 5);
    let previous = entries
        .iter()
        .find(|entry| entry["sequence"] == 5)
        .expect("the new event is present");
    assert_eq!(previous["previous_hash"], LEGACY_HEAD);
    assert_eq!(previous["agent"]["id"], "claude-code");
}

/// The motivating scenario: an agent updates a deal for a human. The human owns
/// `actor`, the agent is named beside it, and the two halves of the intent are
/// attributed separately.
#[test]
fn an_agent_run_update_records_the_human_the_agent_and_both_intents() {
    let database = TestDatabase::new("agent-update");
    run_success(
        database
            .command()
            .args(["--actor", "Ada Lovelace <ada@example.com>"])
            .args(["create", "deals", "acme-renewal"])
            .args(["--set", "status=open", "--set", "stage=negotiation"]),
    );

    run_success(
        database
            .command()
            .args(["--actor", "Ada Lovelace <ada@example.com>"])
            .args(["update", "deals", "acme-renewal"])
            .args(["--set", "status=closed-won", "--set", "stage=closed"])
            .args(["--agent", "claude-code"])
            .args(["--agent-version", "2.1.237"])
            .args(["--agent-model", "claude-opus-4-5"])
            .args(["--agent-session", "6d1baa69-f114-490c-ae19-4be99c2bd744"])
            .args(["--agent-turn", "prompt_01HXZ"])
            .args(["--authorization", "delegated"])
            .args(["--grant", "acceptEdits"])
            .args(["--approved-by", "Ada Lovelace <ada@example.com>"])
            .args(["--approved-at", "2026-09-01T09:17:55Z"])
            .args([
                "--intent-request",
                "someone messaged me that they want to buy — update this deal to closed-won",
            ])
            .args([
                "--intent-rationale",
                "Set status to closed-won and stage to closed. Value left unchanged because no figures were given.",
            ]),
    );

    let entries: Value = serde_json::from_str(&run_success(database.command().args([
        "audit",
        "log",
        "deals",
        "acme-renewal",
        "-n",
        "1",
        "--json",
    ])))
    .expect("audit log is JSON");
    let event = &entries[0];

    assert_eq!(event["actor"], "Ada Lovelace <ada@example.com>");
    assert_eq!(event["version"], 2);
    assert_eq!(event["source"], "cli");
    assert_eq!(event["agent"]["id"], "claude-code");
    assert_eq!(event["agent"]["version"], "2.1.237");
    assert_eq!(event["agent"]["model"], "claude-opus-4-5");
    assert_eq!(
        event["agent"]["session"],
        "6d1baa69-f114-490c-ae19-4be99c2bd744"
    );
    assert_eq!(event["agent"]["turn"], "prompt_01HXZ");
    assert_eq!(event["agent"]["detected_from"], "flag");
    assert_eq!(event["authorization"]["mode"], "delegated");
    assert_eq!(event["authorization"]["grant"], "acceptEdits");
    assert_eq!(
        event["authorization"]["approved_by"],
        "Ada Lovelace <ada@example.com>"
    );
    assert_eq!(event["authorization"]["at"], "2026-09-01T09:17:55Z");
    assert!(event["authorization"].get("approved_changes").is_none());
    assert_eq!(event["intent"]["request"]["author"], "human");
    assert!(
        event["intent"]["request"]["text"]
            .as_str()
            .expect("the request is text")
            .contains("want to buy")
    );
    assert_eq!(event["intent"]["rationale"]["author"], "agent");
    assert!(
        event["intent"]["rationale"]["text"]
            .as_str()
            .expect("the rationale is text")
            .contains("Value left unchanged")
    );

    run_success(database.command().args(["audit", "verify"]));
}

/// Every mutating command has an intent path now, not only `cr save`.
#[test]
fn every_mutating_command_can_record_a_message_and_an_agent() {
    let database = TestDatabase::new("mutation-intent");
    run_success(
        database
            .command()
            .args(["create", "people", "ada", "--set", "name=Ada"])
            .args(["-m", "seed the directory", "--agent", "claude-code"]),
    );
    run_success(
        database
            .command()
            .args(["create", "deals", "acme", "--set", "status=open"])
            .args(["-m", "seed the pipeline", "--agent", "claude-code"]),
    );
    run_success(
        database
            .command()
            .args(["update", "deals", "acme", "--set", "status=won"])
            .args(["-m", "buyer confirmed", "--agent", "claude-code"]),
    );
    run_success(
        database
            .command()
            .args(["link", "deals", "acme", "owner", "people", "ada"])
            .args(["-m", "assign the owner", "--agent", "claude-code"]),
    );
    run_success(
        database
            .command()
            .args(["delete", "people", "ada", "--yes"])
            .args(["-m", "duplicate record", "--agent", "claude-code"]),
    );

    let entries: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    let messages: Vec<&str> = entries
        .as_array()
        .expect("audit log is an array")
        .iter()
        .map(|entry| {
            entry["message"]
                .as_str()
                .expect("every event has a message")
        })
        .collect();
    assert_eq!(
        messages,
        vec![
            "duplicate record",
            "assign the owner",
            "buyer confirmed",
            "seed the pipeline",
            "seed the directory"
        ]
    );
    run_success(database.command().args(["audit", "verify"]));
}

/// Recording the delegate is only useful if it can be queried back out, which
/// is the step the prior art skipped.
#[test]
fn history_can_be_filtered_by_agent_and_by_session() {
    let database = TestDatabase::new("agent-filter");
    run_success(
        database
            .command()
            .args(["create", "deals", "one", "--set", "status=open"]),
    );
    run_success(
        database
            .command()
            .args(["create", "deals", "two", "--set", "status=open"])
            .args(["--agent", "claude-code", "--agent-session", "session-a"]),
    );
    run_success(
        database
            .command()
            .args(["create", "deals", "three", "--set", "status=open"])
            .args([
                "--agent",
                r#"{"id":"claude-code-subagent","session":"session-b","via":[{"id":"claude-code","session":"session-a"}]}"#,
            ]),
    );

    let by_agent: Value = serde_json::from_str(&run_success(database.command().args([
        "audit",
        "log",
        "--agent",
        "claude-code",
        "--json",
    ])))
    .expect("audit log is JSON");
    let matched: Vec<&str> = by_agent
        .as_array()
        .expect("audit log is an array")
        .iter()
        .map(|entry| entry["record"]["id"].as_str().expect("an id"))
        .collect();
    assert_eq!(matched, vec!["three", "two"]);

    let by_session: Value = serde_json::from_str(&run_success(database.command().args([
        "audit",
        "log",
        "--session",
        "session-b",
        "--json",
    ])))
    .expect("audit log is JSON");
    assert_eq!(by_session.as_array().expect("an array").len(), 1);
    assert_eq!(by_session[0]["record"]["id"], "three");

    let missing: Value = serde_json::from_str(&run_success(database.command().args([
        "audit",
        "log",
        "--agent",
        "cursor-agent",
        "--json",
    ])))
    .expect("audit log is JSON");
    assert!(missing.as_array().expect("an array").is_empty());

    let plain = run_success(
        database
            .command()
            .args(["audit", "log", "--agent", "claude-code"]),
    );
    assert_eq!(plain.lines().count(), 2);
    assert!(plain.lines().all(|line| line.contains("agent=")));
}

/// A documented agent variable is enough to make the agent visible without any
/// flag, and the record says the belief came from the environment.
#[test]
fn a_documented_environment_variable_is_detected_and_marked_as_sniffed() {
    let database = TestDatabase::new("agent-environment");
    run_success(
        database
            .command()
            .env("CLAUDECODE", "1")
            .env("CLAUDE_CODE_SESSION_ID", "6d1baa69")
            .args(["create", "deals", "one", "--set", "status=open"]),
    );

    let entries: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["agent"]["id"], "claude-code");
    assert_eq!(entries[0]["agent"]["session"], "6d1baa69");
    assert_eq!(entries[0]["agent"]["detected_from"], "environment");
    assert!(entries[0]["agent"].get("model").is_none());
    assert!(entries[0]["agent"].get("version").is_none());

    let identity = run_success(
        database
            .command()
            .env("CLAUDECODE", "1")
            .env("CLAUDE_CODE_SESSION_ID", "6d1baa69")
            .arg("identity"),
    );
    assert!(identity.contains("agent: claude-code session=6d1baa69"));
    assert!(identity.contains("asserted, detected from environment"));
}

/// Detection is defeatable, deliberately and by design. `cr` runs as the local
/// user, who owns the process, the environment, and the journal file, so this
/// test documents the limit rather than a defence.
#[test]
fn declaring_no_agent_produces_an_event_indistinguishable_from_a_human_one() {
    let database = TestDatabase::new("agent-none");
    for (id, extra) in [("declared", vec!["--agent", "none"]), ("silent", vec![])] {
        let mut command = database.command();
        command
            .env("CLAUDECODE", "1")
            .env("CR_AGENT", "none")
            .args(["create", "deals", id, "--set", "status=open"]);
        command.args(extra);
        run_success(&mut command);
    }

    let entries: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    for entry in entries.as_array().expect("an array") {
        assert!(entry.get("agent").is_none());
    }
    run_success(database.command().args(["audit", "verify"]));
}

/// A flag outranks a sniffed environment, and enriching an observed agent
/// downgrades its evidence to "declared" rather than overstating what was seen.
#[test]
fn an_explicit_declaration_outranks_the_environment() {
    let database = TestDatabase::new("agent-precedence");
    run_success(
        database
            .command()
            .env("CLAUDECODE", "1")
            .env("CR_AGENT", "cursor-agent")
            .args(["create", "deals", "one", "--set", "status=open"]),
    );
    run_success(
        database
            .command()
            .env("CLAUDECODE", "1")
            .env("CR_AGENT", "cursor-agent")
            .args(["create", "deals", "two", "--set", "status=open"])
            .args(["--agent", "claude-code"]),
    );
    run_success(
        database
            .command()
            .env("CLAUDECODE", "1")
            .args(["create", "deals", "three", "--set", "status=open"])
            .args(["--agent-model", "claude-opus-4-5"]),
    );

    let entries: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    let by_id = |id: &str| {
        entries
            .as_array()
            .expect("an array")
            .iter()
            .find(|entry| entry["record"]["id"] == id)
            .expect("the event exists")
            .clone()
    };
    assert_eq!(by_id("one")["agent"]["id"], "cursor-agent");
    assert_eq!(by_id("one")["agent"]["detected_from"], "flag");
    assert_eq!(by_id("two")["agent"]["id"], "claude-code");
    assert_eq!(by_id("three")["agent"]["id"], "claude-code");
    assert_eq!(by_id("three")["agent"]["model"], "claude-opus-4-5");
    assert_eq!(by_id("three")["agent"]["detected_from"], "flag");
}

/// `cr identity` shows what would be recorded, including nothing at all.
#[test]
fn identity_reports_the_complete_attribution_that_would_be_recorded() {
    let database = TestDatabase::new("identity-attribution");
    assert_eq!(
        run_success(database.command().args([
            "--actor",
            "Ada Lovelace <ada@example.com>",
            "identity"
        ])),
        "Ada Lovelace <ada@example.com>\n"
    );

    let json: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args([
                "--actor",
                "Ada Lovelace <ada@example.com>",
                "identity",
                "--json",
            ])
            .args(["--agent", "claude-code", "--agent-session", "6d1baa69"])
            .args(["--authorization", "interactive"])
            .args(["--intent-request", "close the renewal"]),
    ))
    .expect("identity is JSON");
    assert_eq!(json["actor"], "Ada Lovelace <ada@example.com>");
    assert_eq!(json["agent"]["id"], "claude-code");
    assert_eq!(json["agent"]["session"], "6d1baa69");
    assert_eq!(json["authorization"]["mode"], "interactive");
    assert_eq!(json["intent"]["request"]["author"], "human");
    assert_eq!(json["intent"]["request"]["text"], "close the renewal");

    let empty: Value = serde_json::from_str(&run_success(
        database.command().args(["identity", "--json"]),
    ))
    .expect("identity is JSON");
    assert!(empty["agent"].is_null());
    assert!(empty["authorization"].is_null());
    assert!(empty["intent"].is_null());
}

#[test]
fn a_blank_agent_session_is_absent_and_does_not_block_a_write() {
    let database = TestDatabase::new("blank-agent-session");
    run_success(database.command().args([
        "--actor",
        "Harness <harness@example.com>",
        "create",
        "jobs",
        "nightly",
        "--set",
        "status=complete",
        "--agent",
        "host-bookkeeping",
        "--agent-session",
        "",
    ]));

    let entries: Value = serde_json::from_str(&run_success(database.command().args([
        "--actor",
        "Harness <harness@example.com>",
        "audit",
        "log",
        "jobs",
        "nightly",
        "--json",
    ])))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["agent"]["id"], "host-bookkeeping");
    assert!(entries[0]["agent"].get("session").is_none());

    let mut inherited = database.command();
    inherited.env(
        "CR_AGENT",
        r#"{"id":"host-bookkeeping","session":"inherited-session"}"#,
    );
    run_success(inherited.args([
        "--actor",
        "Harness <harness@example.com>",
        "create",
        "jobs",
        "scheduled",
        "--set",
        "status=complete",
        "--agent-session",
        "",
    ]));
    let scheduled: Value = serde_json::from_str(&run_success(database.command().args([
        "--actor",
        "Harness <harness@example.com>",
        "audit",
        "log",
        "jobs",
        "scheduled",
        "--json",
    ])))
    .expect("audit log is JSON");
    assert_eq!(scheduled[0]["agent"]["id"], "host-bookkeeping");
    assert!(scheduled[0]["agent"].get("session").is_none());
}

/// Invalid attribution is refused before anything is written, with wording that
/// names the field and never a path or an operating-system error.
#[test]
fn invalid_attribution_is_refused_without_naming_anything_internal() {
    let database = TestDatabase::new("attribution-errors");
    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["--agent", ""], "agent cannot be empty"),
        (
            vec![
                "--agent",
                r#"{"id":"claude-code","detected_from":"environment"}"#,
            ],
            "detected_from",
        ),
        (
            vec!["--agent-model", "claude-opus-4-5"],
            "without an agent identity",
        ),
        (
            vec!["--authorization", "supervised"],
            "must be direct, interactive",
        ),
        (
            vec![
                "--authorization",
                r#"{"mode":"delegated","approved_changes":"sha256:00"}"#,
            ],
            "64 lowercase hexadecimal",
        ),
        (
            vec!["--approved-changes", "sha256:00"],
            "without an authorization mode",
        ),
        (
            vec![
                "--authorization",
                "interactive",
                "--approved-changes",
                "not-a-digest",
            ],
            "64 lowercase hexadecimal",
        ),
        (
            vec!["--grant", "acceptEdits"],
            "without an authorization mode",
        ),
        (
            vec!["--authorization", "delegated", "--approved-at", "yesterday"],
            "RFC 3339",
        ),
        (vec!["--intent", "not json"], "JSON object"),
    ];
    for (arguments, expected) in cases {
        let error = run_failure(
            database
                .command()
                .args(["create", "deals", "one", "--set", "status=open"])
                .args(&arguments),
        );
        assert!(
            error.contains(expected),
            "expected {expected:?} in {error:?}"
        );
        assert!(!error.contains("os error"), "{error}");
        assert!(
            !error.contains(database.root.to_str().expect("a UTF-8 root")),
            "{error}"
        );
    }
    assert!(
        database
            .command()
            .args(["get", "deals", "one"])
            .output()
            .expect("cr runs")
            .status
            .code()
            .is_some_and(|code| code != 0)
    );

    let long = "x".repeat(5000);
    let error = run_failure(
        database
            .command()
            .args(["create", "deals", "one", "--set", "status=open"])
            .args(["--intent-request", &long]),
    );
    assert!(error.contains("exceeds the"), "{error}");
}

/// A sync definition is the configuration case: a program acting for a person,
/// declared once and recorded on every event the run appends.
#[test]
fn a_sync_definition_records_its_configured_agent() {
    let database = TestDatabase::new("sync-agent");
    let script = database.root.join("adapter.sh");
    fs::write(
        &script,
        "#!/bin/sh\necho '{\"type\":\"upsert\",\"collection\":\"deals\",\"id\":\"imported\",\"front_matter\":{\"status\":\"open\"},\"markdown\":\"\"}'\n",
    )
    .expect("could not write the adapter");
    let mut permissions = fs::metadata(&script)
        .expect("could not stat the adapter")
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
    }
    fs::set_permissions(&script, permissions).expect("could not make the adapter executable");

    run_success(
        database
            .command()
            .args(["sync", "create", "importer"])
            .args(["--actor", "Ada Lovelace <ada@example.com>"])
            .args(["--agent", "notion-importer"])
            .args(["--", script.to_str().expect("a UTF-8 path")]),
    );
    run_success(database.command().args(["sync", "run", "importer"]));

    let entries: Value = serde_json::from_str(&run_success(
        database.command().args(["audit", "log", "--json"]),
    ))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["actor"], "Ada Lovelace <ada@example.com>");
    assert_eq!(entries[0]["source"], "sync");
    assert_eq!(entries[0]["agent"]["id"], "notion-importer");
    assert_eq!(entries[0]["agent"]["detected_from"], "config");
    run_success(database.command().args(["audit", "verify"]));
}

/// The whole feature is inert without a database, so a bad declaration cannot
/// be a way to reach the filesystem.
#[test]
fn attribution_flags_do_not_reach_the_filesystem_before_validation() {
    let temporary = tempfile::tempdir().expect("could not create a temporary directory");
    let mut command = Command::new(binary());
    common::clear_attribution_environment(&mut command);
    let error = run_failure(
        command
            .arg("--database")
            .arg(temporary.path())
            .args(["create", "deals", "one", "--set", "status=open"])
            .args(["--agent", "claude-code"]),
    );
    assert!(error.contains("no database found"), "{error}");
}
