mod common;

use std::{
    fs,
    process::Stdio,
    thread,
    time::{Duration, Instant},
};

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

fn write_script(database: &TestDatabase, name: &str, contents: &str) -> String {
    let directory = database.root.join("scripts");
    fs::create_dir_all(&directory).unwrap();
    let relative = format!("scripts/{name}.sh");
    fs::write(database.root.join(&relative), contents).unwrap();
    relative
}

fn create_sync(database: &TestDatabase, name: &str, script: &str, options: &[&str]) -> String {
    let mut command = database.command();
    command.args(["sync", "create", name]);
    command.args(options);
    command.args(["--", "sh", script]);
    run_success(&mut command)
}

fn json_output(database: &TestDatabase, arguments: &[&str]) -> Value {
    serde_json::from_str(&run_success(database.command().args(arguments))).unwrap()
}

#[test]
fn sync_lifecycle_is_idempotent_checkpointed_and_audited() {
    let database = TestDatabase::new("sync-lifecycle");
    let script = write_script(
        &database,
        "daily",
        r##"#!/bin/sh
set -eu
test "$CR_SYNC_NAME" = "daily"
test "$CR_SYNC_PROTOCOL" = "cr-jsonl-v1"
test "$CR_DATABASE_ROOT" = "$(pwd)"
test -r "$CR_SYNC_STATE_PATH"
test -n "$CR_SYNC_RUN_ID"
printf '%s\n' 'adapter log line' >&2
printf '%s\n' '{"type":"upsert","collection":"meeting_notes","id":"weekly-planning","front_matter":{"notion_id":"page-1","participants":["Ada","Lin"]},"markdown":"# Weekly planning\n\nRoadmap notes.\n"}'
printf '%s\n' '{"type":"upsert","collection":"emails","id":"message-1","front_matter":{"from":"ada@example.com","important":true},"markdown":"Please review the plan.\n"}'
printf '%s\n' '{"type":"delete","collection":"emails","id":"already-missing"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"page-1","history_id":42}}'
"##,
    );

    assert_eq!(
        create_sync(
            &database,
            "daily",
            &script,
            &["--actor", "automation@example.com"]
        ),
        "daily\n"
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "daily"]),
        Value::Null
    );

    let listed = json_output(&database, &["sync", "list", "--json"]);
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["name"], "daily");
    assert_eq!(listed[0]["command"], serde_json::json!(["sh", script]));
    let shown = json_output(&database, &["sync", "show", "daily", "--json"]);
    assert_eq!(shown["version"], 1);
    assert_eq!(shown["timeout_seconds"], 300);
    assert_eq!(shown["actor"], "automation@example.com");

    let first = json_output(&database, &["sync", "run", "daily", "--json"]);
    assert_eq!(first["created"], 2);
    assert_eq!(first["updated"], 0);
    assert_eq!(first["deleted"], 0);
    assert_eq!(first["unchanged"], 1);
    assert_eq!(first["checkpoint_updated"], true);
    assert_eq!(first["run_id"].as_str().unwrap().len(), 24);
    assert_eq!(
        json_output(&database, &["sync", "state", "daily"]),
        serde_json::json!({"cursor": "page-1", "history_id": 42})
    );

    let meeting = run_success(
        database
            .command()
            .args(["get", "meeting_notes", "weekly-planning"]),
    );
    assert!(meeting.contains("notion_id: page-1"));
    assert!(meeting.contains("# Weekly planning"));
    let email = json_output(&database, &["get", "emails", "message-1", "--json"]);
    assert_eq!(email["attributes"]["important"], true);
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");

    let first_audit = json_output(&database, &["audit", "log", "--json"]);
    assert_eq!(first_audit.as_array().unwrap().len(), 2);
    for event in first_audit.as_array().unwrap() {
        assert_eq!(event["actor"], "automation@example.com");
        assert_eq!(event["source"], "sync");
        assert!(
            event["message"]
                .as_str()
                .unwrap()
                .starts_with("sync:daily run:")
        );
    }

    let second = json_output(&database, &["sync", "run", "daily", "--json"]);
    assert_eq!(second["created"], 0);
    assert_eq!(second["updated"], 0);
    assert_eq!(second["deleted"], 0);
    assert_eq!(second["unchanged"], 3);
    assert_eq!(second["checkpoint_updated"], false);
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        2
    );

    fs::write(
        database.root.join(&script),
        r##"#!/bin/sh
set -eu
test "$CR_SYNC_HAS_STATE" = "true"
grep -q '"cursor":"page-1"' "$CR_SYNC_STATE_PATH"
printf '%s\n' '{"type":"upsert","collection":"meeting_notes","id":"weekly-planning","front_matter":{"notion_id":"page-1","participants":["Ada","Lin"]},"markdown":"# Weekly planning\n\nUpdated roadmap notes.\n"}'
printf '%s\n' '{"type":"delete","collection":"emails","id":"message-1"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"page-2","history_id":43}}'
"##,
    )
    .unwrap();
    let third = json_output(&database, &["sync", "run", "daily", "--json"]);
    assert_eq!(third["created"], 0);
    assert_eq!(third["updated"], 1);
    assert_eq!(third["deleted"], 1);
    assert_eq!(third["unchanged"], 0);
    assert_eq!(third["checkpoint_updated"], true);
    assert!(!database.root.join("records/emails/message-1.md").exists());
    assert_eq!(
        json_output(&database, &["sync", "state", "daily"])["cursor"],
        "page-2"
    );
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        4
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn sync_preflights_all_operations_and_discards_failed_process_output() {
    let database = TestDatabase::new("sync-preflight");
    fs::write(
        database.root.join(".cr/schemas/items.json"),
        r#"{
  "type": "object",
  "properties": { "stage": { "enum": ["new", "done"] } },
  "required": ["stage"]
}"#,
    )
    .unwrap();
    let invalid_schema = write_script(
        &database,
        "invalid-schema",
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"items","id":"valid","front_matter":{"stage":"new"}}'
printf '%s\n' '{"type":"upsert","collection":"items","id":"invalid","front_matter":{"stage":"unknown"}}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":1}}'
"#,
    );
    create_sync(&database, "invalid-schema", &invalid_schema, &[]);
    let error = run_failure(database.command().args(["sync", "run", "invalid-schema"]));
    assert!(error.contains("does not match schema"));
    assert!(!database.root.join("records/items/valid.md").exists());
    assert!(!database.root.join("records/items/invalid.md").exists());
    assert_eq!(
        json_output(&database, &["sync", "state", "invalid-schema"]),
        Value::Null
    );

    let failed = write_script(
        &database,
        "failed",
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"items","id":"discarded","front_matter":{"stage":"new"}}'
exit 23
"#,
    );
    create_sync(&database, "failed", &failed, &[]);
    let error = run_failure(database.command().args(["sync", "run", "failed"]));
    assert!(error.contains("exited unsuccessfully"));
    assert!(!database.root.join("records/items/discarded.md").exists());

    let malformed = write_script(
        &database,
        "malformed",
        "#!/bin/sh\nprintf '%s\\n' 'not json'\n",
    );
    create_sync(&database, "malformed", &malformed, &[]);
    let error = run_failure(database.command().args(["sync", "run", "malformed"]));
    assert!(error.contains("output line 1 is invalid"));
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        0
    );
}

#[test]
fn direct_record_writes_are_not_silently_accepted_by_sync() {
    let database = TestDatabase::new("sync-direct-write");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "status=original"]),
    );
    let direct = write_script(
        &database,
        "direct",
        r#"#!/bin/sh
printf '%s\n' '---' 'status: changed' '---' '' 'Changed outside the protocol.' > "$CR_DATABASE_ROOT/records/items/one.md"
"#,
    );
    create_sync(&database, "direct", &direct, &[]);

    let error = run_failure(database.command().args(["sync", "run", "direct"]));
    assert!(error.contains("database changed while the sync command was running"));
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        1
    );
    assert!(run_success(database.command().arg("status")).contains("M items/one"));

    run_success(database.command().args([
        "--actor",
        "editor@example.com",
        "save",
        "items/one",
        "--message",
        "Reviewed adapter direct edit",
    ]));
    let audit = json_output(&database, &["audit", "log", "--limit", "1", "--json"]);
    assert_eq!(audit[0]["source"], "filesystem");
    assert_eq!(audit[0]["actor"], "editor@example.com");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn sync_enforces_timeout_and_output_limits_without_committing_state() {
    let database = TestDatabase::new("sync-limits");
    let slow = write_script(&database, "slow", "#!/bin/sh\nsleep 2\n");
    create_sync(&database, "slow", &slow, &["--timeout-seconds", "1"]);
    let started = Instant::now();
    let error = run_failure(database.command().args(["sync", "run", "slow"]));
    assert!(error.contains("exceeded its 1 second timeout"));
    assert!(started.elapsed() < Duration::from_secs(2));

    let noisy = write_script(
        &database,
        "noisy",
        "#!/bin/sh\nprintf '%s\\n' 'this output is definitely too large'\n",
    );
    create_sync(&database, "noisy", &noisy, &["--max-output-bytes", "8"]);
    let error = run_failure(database.command().args(["sync", "run", "noisy"]));
    assert!(error.contains("output exceeded 8 bytes"));
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        0
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "slow"]),
        Value::Null
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "noisy"]),
        Value::Null
    );
}

#[test]
fn overlapping_runs_of_the_same_sync_are_rejected() {
    let database = TestDatabase::new("sync-overlap");
    let script = write_script(
        &database,
        "overlap",
        r#"#!/bin/sh
set -eu
touch "$CR_DATABASE_ROOT/.cr/sync/adapter-started"
sleep 1
printf '%s\n' '{"type":"checkpoint","state":{"completed":true}}'
"#,
    );
    create_sync(&database, "overlap", &script, &[]);

    let mut command = database.command();
    command
        .args(["sync", "run", "overlap"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    let marker = database.root.join(".cr/sync/adapter-started");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(marker.exists(), "first sync did not start in time");

    let error = run_failure(database.command().args(["sync", "run", "overlap"]));
    assert!(error.contains("already running"));
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "first sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "overlap"]),
        serde_json::json!({"completed": true})
    );
}

#[test]
fn audited_database_changes_during_fetch_reject_stale_sync_output() {
    let database = TestDatabase::new("sync-stale-output");
    let script = write_script(
        &database,
        "stale",
        r#"#!/bin/sh
set -eu
touch "$CR_DATABASE_ROOT/.cr/sync/fetch-started"
sleep 1
printf '%s\n' '{"type":"upsert","collection":"items","id":"from-sync","front_matter":{"status":"fetched"}}'
"#,
    );
    create_sync(&database, "stale", &script, &[]);

    let mut command = database.command();
    command
        .args(["sync", "run", "stale"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().unwrap();
    let marker = database.root.join(".cr/sync/fetch-started");
    let deadline = Instant::now() + Duration::from_secs(2);
    while !marker.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(marker.exists(), "sync did not start in time");
    run_success(database.command().args([
        "create",
        "items",
        "concurrent",
        "--set",
        "status=local",
    ]));

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("database audit head changed while the sync command was running")
    );
    assert!(database.root.join("records/items/concurrent.md").exists());
    assert!(!database.root.join("records/items/from-sync.md").exists());
    assert_eq!(
        json_output(&database, &["audit", "head", "--json"])["sequence"],
        1
    );
}

#[test]
fn sync_definition_validation_rejects_unsafe_names_and_unknown_versions() {
    let database = TestDatabase::new("sync-definition-validation");
    let script = write_script(&database, "empty", "#!/bin/sh\n");
    let error =
        run_failure(
            database
                .command()
                .args(["sync", "create", "../escape", "--", "sh", &script]),
        );
    assert!(error.contains("cannot contain path separators"));

    create_sync(&database, "versioned", &script, &[]);
    let definition = database.root.join(".cr/syncs/versioned.yaml");
    let contents = fs::read_to_string(&definition).unwrap();
    fs::write(&definition, contents.replace("version: 1", "version: 2")).unwrap();
    let error = run_failure(database.command().args(["sync", "show", "versioned"]));
    assert!(error.contains("unsupported format version 2"));
}

/// Force a run to fail durably partway through applying its stream.
///
/// A plain file where a collection directory would go is invisible to the
/// pre-run verification — `records/` listings skip entries that are not
/// directories — and is not something preflight can see either, because
/// preflight only schema-checks front matter. The operation that has to write
/// through it therefore fails after earlier operations are already committed,
/// which is exactly the shape of a disk error or a permission change arriving
/// mid-run.
fn block_collection(database: &TestDatabase, collection: &str) {
    fs::write(database.root.join("records").join(collection), "blocked\n").unwrap();
}

fn unblock_collection(database: &TestDatabase, collection: &str) {
    fs::remove_file(database.root.join("records").join(collection)).unwrap();
}

/// A database whose sync stopped durably after committing two of its four
/// record operations, with its checkpoint still on the previous cursor.
fn interrupted_sync(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    let script = write_script(
        &database,
        "partial",
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"notes","id":"first","front_matter":{"n":1},"markdown":"first\n"}'
printf '%s\n' '{"type":"upsert","collection":"notes","id":"second","front_matter":{"n":2},"markdown":"second\n"}'
printf '%s\n' '{"type":"upsert","collection":"blocked","id":"third","front_matter":{"n":3},"markdown":"third\n"}'
printf '%s\n' '{"type":"upsert","collection":"notes","id":"fourth","front_matter":{"n":4},"markdown":"fourth\n"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"page-2"}}'
"#,
    );
    create_sync(&database, "partial", &script, &[]);
    fs::create_dir_all(database.root.join("records")).unwrap();
    block_collection(&database, "blocked");
    run_failure(database.command().args(["sync", "run", "partial"]));
    assert!(database.root.join("records/notes/first.md").exists());
    assert!(database.root.join("records/notes/second.md").exists());
    assert!(!database.root.join("records/notes/fourth.md").exists());
    assert_eq!(
        json_output(&database, &["sync", "state", "partial"]),
        Value::Null
    );
    database
}

fn interrupted_run_id(database: &TestDatabase) -> String {
    json_output(
        database,
        &["sync", "recover", "partial", "--check", "--json"],
    )["run_id"]
        .as_str()
        .expect("an interrupted run is recorded")
        .to_owned()
}

/// The failure this whole mechanism exists to prevent, stated on its own.
///
/// Before the run ledger, this second run succeeded: it replayed the stale
/// checkpoint's stream from the beginning, committed the operations the first
/// run never reached, and advanced the checkpoint, leaving nothing anywhere to
/// say that a run had been abandoned halfway. Nothing about that outcome is
/// wrong for a deterministic adapter and nothing about it is safe for one whose
/// operations are not.
#[test]
fn a_run_left_partly_applied_cannot_be_silently_restarted() {
    let database = interrupted_sync("sync-silent-restart");
    // Even with the underlying failure gone, the abandoned run has to be
    // acknowledged rather than papered over by a fresh one.
    unblock_collection(&database, "blocked");
    let error = run_failure(database.command().args(["sync", "run", "partial"]));
    assert!(error.contains("has an interrupted run"), "{error}");
    assert_eq!(
        json_output(&database, &["sync", "state", "partial"]),
        Value::Null
    );
    assert!(!database.root.join("records/notes/fourth.md").exists());
}

#[test]
fn a_run_that_fails_partway_through_is_detectable_and_rolls_forward() {
    let database = interrupted_sync("sync-partial-failure");
    let run_id = interrupted_run_id(&database);

    // The disagreement is a durable, inspectable fact rather than something an
    // operator has to infer from the audit log.
    let ledger = json_output(
        &database,
        &["sync", "recover", "partial", "--check", "--json"],
    );
    assert_eq!(ledger["name"], "partial");
    assert_eq!(ledger["operations"], 5);
    assert_eq!(ledger["events_committed"], 2);
    assert_eq!(ledger["checkpoint_pending"], true);
    assert_eq!(ledger["foreign_events"], false);

    // A second run must not silently restart from the stale checkpoint.
    let error = run_failure(database.command().args(["sync", "run", "partial"]));
    assert!(error.contains("has an interrupted run"));
    assert!(error.contains(&run_id));
    assert!(error.contains("cr sync recover partial"));

    // While the underlying failure persists, recovery reports it and changes
    // nothing about the ledger, so the run stays completable.
    run_failure(database.command().args(["sync", "recover", "partial"]));
    assert_eq!(
        json_output(
            &database,
            &["sync", "recover", "partial", "--check", "--json"]
        )["run_id"],
        run_id.as_str()
    );

    unblock_collection(&database, "blocked");
    let recovered = json_output(&database, &["sync", "recover", "partial", "--json"]);
    assert_eq!(recovered["run_id"], run_id.as_str());
    assert_eq!(recovered["resumed"], true);
    assert_eq!(recovered["created"], 2);
    assert_eq!(recovered["unchanged"], 2);
    assert_eq!(recovered["checkpoint_updated"], true);

    // Committed work and the recorded checkpoint now agree.
    assert_eq!(
        json_output(&database, &["sync", "state", "partial"])["cursor"],
        "page-2"
    );
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    run_success(database.command().args(["audit", "verify"]));

    // Roll-forward is forward-only: every event, including the ones the
    // interrupted run committed, stays in the chain under that run's identifier.
    let events = json_output(&database, &["audit", "log", "--json"]);
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 4);
    for event in events {
        assert_eq!(event["message"], format!("sync:partial run:{run_id}"));
    }

    // The ledger is retired, so the next run starts normally and is idempotent.
    assert_eq!(
        json_output(
            &database,
            &["sync", "recover", "partial", "--check", "--json"]
        ),
        Value::Null
    );
    let next = json_output(&database, &["sync", "run", "partial", "--json"]);
    assert_eq!(next["resumed"], false);
    assert_eq!(next["unchanged"], 4);
    assert_eq!(next["checkpoint_updated"], false);
}

#[test]
fn an_interrupted_run_refuses_to_overwrite_a_record_edited_after_it_stopped() {
    let database = interrupted_sync("sync-conflicting-edit");
    let run_id = interrupted_run_id(&database);
    unblock_collection(&database, "blocked");

    // An unrelated record moving on is not a reason to refuse.
    run_success(
        database
            .command()
            .args(["create", "notes", "unrelated", "--set", "n=9"]),
    );
    let ledger = json_output(
        &database,
        &["sync", "recover", "partial", "--check", "--json"],
    );
    assert_eq!(ledger["foreign_events"], true);
    assert_eq!(ledger["events_committed"], 2);

    // A record the run still has to write is.
    run_success(
        database
            .command()
            .args(["update", "notes", "first", "--set", "n=99"]),
    );
    let error = run_failure(database.command().args(["sync", "recover", "partial"]));
    assert!(error.contains("record notes/first changed after it stopped"));
    assert!(error.contains(&run_id));
    assert_eq!(
        json_output(&database, &["sync", "state", "partial"]),
        Value::Null
    );
    assert_eq!(
        json_output(
            &database,
            &["sync", "recover", "partial", "--check", "--json"]
        )["run_id"],
        run_id.as_str()
    );
}

#[test]
fn a_killed_run_leaves_a_ledger_that_completes_the_remaining_records() {
    let database = TestDatabase::new("sync-killed-run");
    let total = 120;
    let mut stream = String::new();
    for index in 0..total {
        stream.push_str(&format!(
            "printf '%s\\n' '{{\"type\":\"upsert\",\"collection\":\"notes\",\"id\":\"r{index:03}\",\"front_matter\":{{\"n\":{index}}},\"markdown\":\"body {index}\"}}'\n"
        ));
    }
    stream.push_str("printf '%s\\n' '{\"type\":\"checkpoint\",\"state\":{\"cursor\":\"done\"}}'\n");
    let script = write_script(&database, "bulk", &format!("#!/bin/sh\n{stream}"));
    create_sync(&database, "bulk", &script, &["--max-operations", "1000"]);

    let mut child = database
        .command()
        .args(["sync", "run", "bulk"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let records = database.root.join("records/notes");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let applied = fs::read_dir(&records).map_or(0, |entries| entries.count());
        if applied >= 10 {
            break;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "the run finished before it could be interrupted"
        );
        assert!(Instant::now() < deadline, "the run never began applying");
        thread::sleep(Duration::from_millis(5));
    }
    child.kill().unwrap();
    child.wait().unwrap();

    let applied = fs::read_dir(&records).unwrap().count();
    assert!(
        applied < total,
        "the run applied every record before the kill"
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "bulk"]),
        Value::Null
    );

    let ledger = json_output(&database, &["sync", "recover", "bulk", "--check", "--json"]);
    assert_eq!(ledger["operations"], total + 1);
    assert!(ledger["events_committed"].as_u64().unwrap() > 0);
    assert_eq!(ledger["checkpoint_pending"], true);
    let run_id = ledger["run_id"].as_str().unwrap().to_owned();

    let error = run_failure(database.command().args(["sync", "run", "bulk"]));
    assert!(error.contains("has an interrupted run"));

    let recovered = json_output(&database, &["sync", "recover", "bulk", "--json"]);
    assert_eq!(recovered["run_id"], run_id.as_str());
    assert_eq!(recovered["resumed"], true);
    assert_eq!(
        recovered["created"].as_u64().unwrap() + recovered["unchanged"].as_u64().unwrap(),
        total as u64
    );
    assert_eq!(
        json_output(&database, &["sync", "state", "bulk"])["cursor"],
        "done"
    );
    // Only records: a process killed between staging a file and linking it
    // into place leaves a `.cr-tmp-*` file behind, which every reader ignores.
    // See `tests/audit_fault_injection.rs`.
    assert_eq!(
        fs::read_dir(&records)
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".md"))
            .count(),
        total
    );
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn a_completed_run_keeps_no_ledger_and_recovery_is_a_no_op() {
    let database = TestDatabase::new("sync-completed-run");
    let script = write_script(
        &database,
        "clean",
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"notes","id":"only","front_matter":{"n":1},"markdown":"only\n"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"one"}}'
"#,
    );
    create_sync(&database, "clean", &script, &[]);
    run_success(database.command().args(["sync", "run", "clean"]));

    assert!(
        fs::read_dir(database.root.join(".cr/sync/runs")).map_or(0, |entries| entries.count()) == 0
    );
    assert_eq!(
        run_success(database.command().args(["sync", "recover", "clean"])),
        "Sync clean has no interrupted run\n"
    );
    assert_eq!(
        json_output(
            &database,
            &["sync", "recover", "clean", "--check", "--json"]
        ),
        Value::Null
    );
}
