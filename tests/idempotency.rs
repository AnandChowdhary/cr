mod common;

use std::{
    fs,
    panic::{AssertUnwindSafe, catch_unwind},
    str::FromStr,
    sync::Arc,
    thread,
};

use common::{
    chain, command_for,
    fault::{FaultDatabase, Point, pending_bytes, pending_json},
    run_failure, run_success,
};
use cr::{
    AccessResource, Assignment, AuditSource, Database, DomainError, Role, SyncAttribution, UserKind,
};
use yaml_serde::{Mapping, Value};

const KEY: &str = "550e8400-e29b-41d4-a716-446655440000";
const OTHER_KEY: &str = "950e8400-e29b-41d4-a716-446655440001";

fn database(name: &str) -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join(name);
    let database = Database::init(&root)
        .unwrap()
        .with_actor("Ada <ada@example.com>")
        .unwrap();
    (temporary, database)
}

fn assignment(value: &str) -> Assignment {
    Assignment::from_str(value).unwrap()
}

#[test]
fn a_committed_create_replays_its_original_result_without_another_event() {
    let (_temporary, database) = database("create-replay");
    let retryable = database.clone().with_idempotency_key(KEY).unwrap();
    let first = retryable
        .create("items", "one", &[assignment("stage=screening")], "hello\n")
        .unwrap();
    let replay = retryable
        .create("items", "one", &[assignment("stage=screening")], "hello\n")
        .unwrap();

    assert_eq!(replay.reference(), first.reference());
    assert_eq!(replay.version, first.version);
    assert_eq!(replay.attributes, first.attributes);
    assert_eq!(replay.body, first.body);
    assert_eq!(database.audit_head().unwrap().sequence, 1);

    let journal = fs::read_to_string(
        database
            .root()
            .join(".cr/audit/segments/00000000000000000001.jsonl"),
    )
    .unwrap();
    assert!(journal.contains("\"idempotency\""));
    assert!(
        !journal.contains(KEY),
        "the raw retry key must never be stored"
    );
}

#[test]
fn yaml_boolean_and_string_keys_have_distinct_request_identities() {
    let (_temporary, database) = database("typed-map-keys");
    let retryable = database.clone().with_idempotency_key(KEY).unwrap();
    let mut boolean_key = Mapping::new();
    boolean_key.insert(Value::Bool(true), Value::String("value".to_owned()));
    let first = retryable
        .create_record("items", "one", boolean_key.clone(), "")
        .unwrap();
    let replay = retryable
        .create_record("items", "one", boolean_key, "")
        .unwrap();
    assert_eq!(replay.attributes, first.attributes);
    assert!(replay.attributes.contains_key(Value::Bool(true)));

    let mut string_key = Mapping::new();
    string_key.insert(
        Value::String("true".to_owned()),
        Value::String("value".to_owned()),
    );
    let error = retryable
        .create_record("items", "one", string_key, "")
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("idempotency_conflict")
    );
}

#[test]
fn composite_yaml_keys_return_typed_errors_without_panicking() {
    let (_temporary, database) = database("composite-map-key");
    let mut attributes = Mapping::new();
    attributes.insert(
        Value::Sequence(vec![Value::String("part".to_owned())]),
        Value::String("value".to_owned()),
    );

    for database in [
        database.clone(),
        database.clone().with_idempotency_key(KEY).unwrap(),
    ] {
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            database.create_record("items", "one", attributes.clone(), "")
        }));
        let error = outcome.expect("composite keys must not panic").unwrap_err();
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("validation_failed")
        );
    }
}

#[test]
fn one_scoped_key_conflicts_on_changed_semantics_but_is_reusable_on_another_target() {
    let (_temporary, database) = database("scope-and-conflict");
    database
        .clone()
        .with_idempotency_key(KEY)
        .unwrap()
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap();

    let error = database
        .clone()
        .with_idempotency_key(KEY)
        .unwrap()
        .create("items", "one", &[assignment("stage=hired")], "")
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("idempotency_conflict")
    );

    database
        .clone()
        .with_idempotency_key(KEY)
        .unwrap()
        .create("items", "two", &[assignment("stage=screening")], "")
        .unwrap();
    assert_eq!(database.audit_head().unwrap().sequence, 2);
}

#[test]
fn update_preconditions_and_audit_context_are_part_of_the_request_digest() {
    let (_temporary, database) = database("request-digest");
    let created = database
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap();
    let precondition = cr::RecordPrecondition::version(created.version).unwrap();
    database
        .clone()
        .with_audit_message("advance")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update_conditionally(
            "items",
            "one",
            &[assignment("stage=interview")],
            None,
            Some(&precondition),
        )
        .unwrap();

    let error = database
        .clone()
        .with_audit_message("different explanation")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update_conditionally(
            "items",
            "one",
            &[assignment("stage=interview")],
            None,
            Some(&precondition),
        )
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("idempotency_conflict")
    );
    assert_eq!(database.audit_head().unwrap().sequence, 2);
}

#[test]
fn delete_replay_returns_the_exact_original_record_after_the_file_is_gone() {
    let (_temporary, database) = database("delete-replay");
    let created = database
        .create("items", "gone", &[assignment("stage=screening")], "notes\n")
        .unwrap();
    let retryable = database.clone().with_idempotency_key(KEY).unwrap();
    let deleted = retryable.delete("items", "gone").unwrap();
    let replay = retryable.delete("items", "gone").unwrap();

    assert_eq!(deleted.version, created.version);
    assert_eq!(replay.version, deleted.version);
    assert_eq!(replay.attributes, deleted.attributes);
    assert_eq!(replay.body, "notes\n");
    assert_eq!(database.audit_head().unwrap().sequence, 2);
}

#[test]
fn cli_delete_replay_returns_the_original_json_result() {
    let database = common::TestDatabase::new("delete-json-replay");
    run_success(database.command().args([
        "create",
        "items",
        "gone",
        "--set",
        "stage=screening",
        "--body",
        "notes",
    ]));
    let delete = [
        "delete",
        "items",
        "gone",
        "--yes",
        "--json",
        "--idempotency-key",
        KEY,
    ];
    let first = run_success(database.command().args(delete));
    let replay = run_success(database.command().args(delete));

    assert_eq!(replay, first);
    let result: serde_json::Value = serde_json::from_str(&replay).unwrap();
    assert_eq!(result["collection"], "items");
    assert_eq!(result["id"], "gone");
    assert_eq!(result["attributes"]["stage"], "screening");
    assert_eq!(result["body"], "notes");
    let head = run_success(database.command().args(["audit", "head", "--json"]));
    let head: serde_json::Value = serde_json::from_str(&head).unwrap();
    assert_eq!(head["sequence"], 2);
}

#[test]
fn replay_keeps_the_original_path_after_data_directory_changes() {
    let database = common::TestDatabase::new("data-dir-replay");
    let create = [
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--json",
        "--idempotency-key",
        KEY,
    ];
    let first = run_success(database.command().args(create));
    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: content/data\n",
    )
    .unwrap();
    fs::create_dir_all(database.root.join("content/data")).unwrap();
    let replay = run_success(database.command().args(create));

    assert_eq!(replay, first);
    let result: serde_json::Value = serde_json::from_str(&replay).unwrap();
    assert_eq!(result["path"], "records/items/one.md");
}

#[test]
fn replay_still_requires_current_authorization() {
    let (_temporary, owner) = database("authorization-recheck");
    owner
        .initialize_access(Some("Ada"), Some("ada@example.com"))
        .unwrap();
    owner
        .add_user(
            "editor@example.com",
            "Editor",
            Some("editor@example.com"),
            UserKind::Human,
        )
        .unwrap();
    owner
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap();
    owner
        .grant_access(
            "editor@example.com",
            AccessResource::collection("items"),
            Role::Editor,
        )
        .unwrap();

    owner
        .impersonate_verified("editor@example.com")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update("items", "one", &[assignment("stage=interview")], None)
        .unwrap();
    owner
        .revoke_access("editor@example.com", &AccessResource::collection("items"))
        .unwrap();

    let error = owner
        .impersonate_verified("editor@example.com")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update("items", "one", &[assignment("stage=interview")], None)
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("forbidden")
    );
}

#[test]
fn the_same_key_is_independent_for_each_effective_principal() {
    let (_temporary, owner) = database("principal-scope");
    owner
        .initialize_access(Some("Ada"), Some("ada@example.com"))
        .unwrap();
    for principal in ["one@example.com", "two@example.com"] {
        owner
            .add_user(principal, principal, Some(principal), UserKind::Human)
            .unwrap();
        owner
            .grant_access(principal, AccessResource::collection("items"), Role::Editor)
            .unwrap();
    }
    owner
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap();
    let before = owner.audit_head().unwrap().sequence;

    let first = owner
        .impersonate_verified("one@example.com")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update("items", "one", &[assignment("stage=interview")], None)
        .unwrap();
    owner
        .impersonate_verified("two@example.com")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update("items", "one", &[assignment("stage=hired")], None)
        .unwrap();
    let replay = owner
        .impersonate_verified("one@example.com")
        .unwrap()
        .with_idempotency_key(KEY)
        .unwrap()
        .update("items", "one", &[assignment("stage=interview")], None)
        .unwrap();

    assert_eq!(replay.version, first.version);
    assert_eq!(replay.attributes, first.attributes);
    assert_eq!(owner.audit_head().unwrap().sequence, before + 2);
    assert_eq!(
        owner.get("items", "one").unwrap().attributes["stage"],
        yaml_serde::Value::String("hired".to_owned())
    );
}

#[test]
fn keys_are_bounded_portable_and_never_echoed() {
    let (_temporary, database) = database("key-validation");
    for key in ["a".repeat(16), "x".repeat(128), "!".repeat(16)] {
        database
            .clone()
            .with_idempotency_key(key)
            .expect("every 16-128 byte visible-ASCII key is valid");
    }
    for key in [
        "x".repeat(15),
        "x".repeat(129),
        "contains whitespace".to_owned(),
        "0123456789abcdeé".to_owned(),
    ] {
        let error = database.clone().with_idempotency_key(&key).unwrap_err();
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("validation_failed")
        );
        assert!(!format!("{error:#}").contains(&key));
    }
}

#[test]
fn concurrent_cli_retries_commit_one_event_and_all_return_success() {
    let database = common::TestDatabase::new("concurrent-idempotency");
    let root = Arc::new(database.root.clone());
    let handles = (0..8)
        .map(|_| {
            let root = Arc::clone(&root);
            thread::spawn(move || {
                run_success(command_for(&root).args([
                    "create",
                    "items",
                    "one",
                    "--set",
                    "stage=screening",
                    "--idempotency-key",
                    KEY,
                ]))
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        assert_eq!(handle.join().unwrap().trim(), "items/one");
    }
    let head = run_success(command_for(&root).args(["audit", "head", "--json"]));
    let head: serde_json::Value = serde_json::from_str(&head).unwrap();
    assert_eq!(head["sequence"], 1);
}

#[test]
fn a_record_written_before_the_event_is_recovered_and_then_replayed() {
    let database = FaultDatabase::new("idempotency-recovery");
    let interruption = database.interrupt(
        "items",
        "one",
        &[
            "create",
            "items",
            "one",
            "--set",
            "stage=screening",
            "--idempotency-key",
            KEY,
        ],
    );
    database.restore(&interruption, "items", "one", Point::RecordReplaced);

    let replay = run_success(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--idempotency-key",
        KEY,
    ]));
    assert_eq!(replay.trim(), "items/one");
    assert_eq!(database.head_sequence(), 1);
    assert!(database.read_pending().is_none());

    // A crash after the append but before pending cleanup leaves the same
    // identity in the journal and pending file. It is one committed event,
    // not a duplicate, and recovery must only finish the cleanup.
    database.put_pending(&interruption.pending);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 1);
    assert!(database.read_pending().is_none());
}

#[test]
fn duplicate_scoped_retry_identity_is_audit_corruption_even_for_another_request() {
    let database = common::TestDatabase::new("duplicate-idempotency-identity");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=interview",
        "--idempotency-key",
        KEY,
    ]));
    run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=hired",
        "--idempotency-key",
        OTHER_KEY,
    ]));

    let segment = chain::segment_paths(&database.root).remove(0);
    let contents = fs::read_to_string(&segment).unwrap();
    let mut events = contents.lines().map(chain::parse_line).collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    let first_key_hash = events[1].parsed["idempotency"]["key_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(
        events[1].parsed["idempotency"]["request_hash"],
        events[2].parsed["idempotency"]["request_hash"],
        "the duplicate identity must be detected independently of request semantics"
    );
    events[2].parsed["idempotency"]["key_hash"] = serde_json::Value::String(first_key_hash);
    events[2].payload = serde_json::to_string(&events[2].parsed).unwrap();
    events[2].hash = chain::event_hash(&events[2].payload);
    let forged = events
        .iter()
        .map(|event| chain::stored_line(&event.hash, &event.payload))
        .collect::<String>();
    fs::write(&segment, forged).unwrap();
    chain::reanchor(&database.root);

    for arguments in [
        vec!["--json-errors", "audit", "verify"],
        vec![
            "--json-errors",
            "update",
            "items",
            "one",
            "--set",
            "stage=interview",
            "--idempotency-key",
            KEY,
        ],
    ] {
        let failure = run_failure(database.command().args(arguments));
        let failure: serde_json::Value = serde_json::from_str(&failure).unwrap();
        assert_eq!(failure["error"]["code"], "audit_integrity_failed");
        assert!(!failure.to_string().contains(KEY));
        assert!(!failure.to_string().contains(OTHER_KEY));
    }
}

#[test]
fn pending_recovery_refuses_a_duplicate_identity_but_accepts_the_honest_event() {
    let database = FaultDatabase::new("duplicate-pending-idempotency");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=interview",
        "--idempotency-key",
        KEY,
    ]));
    let interruption = database.interrupt(
        "items",
        "one",
        &[
            "update",
            "items",
            "one",
            "--set",
            "stage=hired",
            "--idempotency-key",
            OTHER_KEY,
        ],
    );

    let committed = chain::parse_line(&database.journal_lines()[1]);
    let committed_key_hash = committed.parsed["idempotency"]["key_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut pending = pending_json(&interruption.pending);
    let mut payload: serde_json::Value =
        serde_json::from_str(pending["payload"].as_str().unwrap()).unwrap();
    payload["idempotency"]["key_hash"] = serde_json::Value::String(committed_key_hash);
    let payload = serde_json::to_string(&payload).unwrap();
    pending["hash"] = serde_json::Value::String(chain::event_hash(&payload));
    pending["payload"] = serde_json::Value::String(payload);

    database.restore(&interruption, "items", "one", Point::RecordReplaced);
    database.put_pending(&pending_bytes(&pending));
    let failure =
        run_failure(
            database
                .command()
                .args(["--json-errors", "audit", "head", "--json"]),
        );
    let failure: serde_json::Value = serde_json::from_str(&failure).unwrap();
    assert_eq!(failure["error"]["code"], "audit_integrity_failed");
    assert_eq!(database.head_sequence_unrecovered(), 2);
    assert!(database.read_pending().is_some());

    database.put_pending(&interruption.pending);
    let replay = run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=hired",
        "--idempotency-key",
        OTHER_KEY,
    ]));
    assert_eq!(replay.trim(), "items/one");
    assert_eq!(database.head_sequence(), 3);
    assert!(database.read_pending().is_none());
}

#[test]
fn cli_mismatch_has_a_machine_readable_error_code_without_the_key() {
    let database = common::TestDatabase::new("cli-conflict");
    run_success(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--idempotency-key",
        KEY,
    ]));
    let error = run_failure(database.command().args([
        "--json-errors",
        "create",
        "items",
        "one",
        "--set",
        "stage=hired",
        "--idempotency-key",
        KEY,
    ]));
    let error: serde_json::Value = serde_json::from_str(&error).unwrap();
    assert_eq!(error["error"]["code"], "idempotency_conflict");
    assert!(!error.to_string().contains(KEY));
}

#[test]
fn operation_source_is_bound_into_the_request() {
    let (_temporary, database) = database("source-bound");
    database
        .clone()
        .with_idempotency_key(KEY)
        .unwrap()
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap();
    let error = database
        .with_source(AuditSource::Api)
        .with_idempotency_key(KEY)
        .unwrap()
        .create("items", "one", &[assignment("stage=screening")], "")
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("idempotency_conflict")
    );
}

#[test]
fn sync_never_carries_or_consumes_a_caller_idempotency_key() {
    let (_temporary, database) = database("sync-idempotency-boundary");
    fs::create_dir_all(database.root().join("scripts")).unwrap();
    fs::write(
        database.root().join("scripts/import.sh"),
        "#!/bin/sh\nprintf '%s\\n' '{\"type\":\"upsert\",\"collection\":\"items\",\"id\":\"one\",\"front_matter\":{\"stage\":\"synced\"}}'\n",
    )
    .unwrap();
    database
        .create_sync(
            "import",
            vec!["sh".to_owned(), "scripts/import.sh".to_owned()],
            30,
            1024,
            10,
            SyncAttribution::default(),
        )
        .unwrap();

    database
        .clone()
        .with_idempotency_key(KEY)
        .unwrap()
        .run_sync("import")
        .unwrap();
    let journal = fs::read_to_string(
        database
            .root()
            .join(".cr/audit/segments/00000000000000000001.jsonl"),
    )
    .unwrap();
    assert!(journal.contains("\"source\":\"sync\""));
    assert!(!journal.contains("\"idempotency\""));
    assert!(!journal.contains(KEY));
}

#[test]
fn a_rehashed_and_reanchored_forged_result_is_refused_by_verify_and_replay() {
    let database = common::TestDatabase::new("forged-idempotency-result");
    run_success(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--idempotency-key",
        KEY,
    ]));

    let segment = chain::segment_paths(&database.root).remove(0);
    let line = fs::read_to_string(&segment).unwrap();
    let event = chain::parse_line(line.trim_end());
    let mut payload = event.parsed;
    let forged_markdown = "---\nstage: forged\n---\n";
    let forged_version = chain::record_hash(forged_markdown.as_bytes());
    payload["changes"][0]["after"]["attributes"]["stage"] =
        serde_json::Value::String("forged".to_owned());
    payload["after_hash"] = serde_json::Value::String(forged_version.clone());
    payload["idempotency"]["result"]["version"] = serde_json::Value::String(forged_version);
    payload["idempotency"]["result"]["markdown"] =
        serde_json::Value::String(forged_markdown.to_owned());
    let forged = serde_json::to_string(&payload).unwrap();
    fs::write(
        &segment,
        chain::stored_line(&chain::event_hash(&forged), &forged),
    )
    .unwrap();
    chain::reanchor(&database.root);

    let verify = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        verify.contains("audit replay is inconsistent at sequence 1"),
        "unexpected failure: {verify}"
    );
    let replay = run_failure(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--idempotency-key",
        KEY,
    ]));
    assert!(
        replay.contains("audit replay is inconsistent at sequence 1"),
        "unexpected failure: {replay}"
    );
}

#[test]
fn a_forged_retry_result_path_is_rejected_without_disclosure() {
    let database = common::TestDatabase::new("forged-idempotency-path");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--idempotency-key", KEY]),
    );

    let segment = chain::segment_paths(&database.root).remove(0);
    let line = fs::read_to_string(&segment).unwrap();
    let event = chain::parse_line(line.trim_end());
    let mut payload = event.parsed;
    payload["idempotency"]["result"]["path"] =
        serde_json::Value::String("../../private.md".to_owned());
    let forged = serde_json::to_string(&payload).unwrap();
    fs::write(
        &segment,
        chain::stored_line(&chain::event_hash(&forged), &forged),
    )
    .unwrap();
    chain::reanchor(&database.root);

    let verify = run_failure(database.command().args(["audit", "verify"]));
    assert!(verify.contains("audit idempotency result path is invalid at sequence 1"));
    assert!(!verify.contains("private.md"));
}
