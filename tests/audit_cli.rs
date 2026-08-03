mod common;

use std::fs;

use common::{run_failure, run_success, TestDatabase};
use serde_json::Value;

fn audit_json(database: &TestDatabase, arguments: &[&str]) -> Value {
    let output = run_success(database.command().args(arguments));
    serde_json::from_str(&output).unwrap()
}

#[test]
fn create_update_link_and_delete_have_attributed_detailed_events() {
    let database = TestDatabase::new("audit-lifecycle");
    run_success(database.command().args([
        "--actor",
        "alice",
        "create",
        "companies",
        "acme",
        "--set",
        "name=Acme",
    ]));
    run_success(database.command().args([
        "--actor",
        "alice",
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
        "--body",
        "# Jane\n",
    ]));
    run_success(database.command().args([
        "--actor",
        "bob",
        "update",
        "candidates",
        "jane",
        "--set",
        "stage=interview",
    ]));
    run_success(database.command().args([
        "--actor",
        "bob",
        "link",
        "candidates",
        "jane",
        "company",
        "companies",
        "acme",
    ]));
    run_success(database.command().args([
        "--actor",
        "admin",
        "delete",
        "candidates",
        "jane",
        "--yes",
    ]));

    let entries = audit_json(&database, &["audit", "log", "--json"]);
    let entries = entries.as_array().unwrap();
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0]["sequence"], 5);
    assert_eq!(entries[0]["actor"], "admin");
    assert_eq!(entries[0]["action"], "delete");
    assert!(entries[0]["after_hash"].is_null());
    assert_eq!(entries[0]["changes"][0]["before"]["body"], "# Jane\n");

    let update = &entries[2];
    assert_eq!(update["sequence"], 3);
    assert_eq!(update["actor"], "bob");
    assert_eq!(update["changes"][0]["path"], "/attributes/stage");
    assert_eq!(update["changes"][0]["before"], "screening");
    assert_eq!(update["changes"][0]["after"], "interview");

    for pair in entries.windows(2) {
        assert_eq!(pair[0]["previous_hash"], pair[1]["hash"]);
    }
    assert!(entries.last().unwrap()["previous_hash"].is_null());
    assert!(!database.root.join("records/candidates/jane.md").exists());

    let verified = run_success(database.command().args(["audit", "verify"]));
    assert!(verified.contains("Verified 5 audit events"));
}

#[test]
fn failed_mutations_do_not_create_audit_events() {
    let database = TestDatabase::new("audit-failures");
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
    ]));
    let before = audit_json(&database, &["audit", "head", "--json"]);

    run_failure(database.command().args(["create", "candidates", "jane"]));
    fs::write(
        database.root.join(".cr/schemas/candidates.json"),
        r#"{
  "type": "object",
  "properties": { "stage": { "enum": ["screening", "interview"] } }
}"#,
    )
    .unwrap();
    run_failure(
        database
            .command()
            .args(["update", "candidates", "jane", "--set", "stage=offer"]),
    );

    let after = audit_json(&database, &["audit", "head", "--json"]);
    assert_eq!(after, before);
    assert_eq!(after["sequence"], 1);
}

#[test]
fn bounded_segments_rotate_and_recent_log_crosses_boundaries() {
    let database = TestDatabase::new("audit-rotation");
    let config_path = database.root.join(".cr/config.yaml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        config.replace("segment_max_events: 256", "segment_max_events: 2"),
    )
    .unwrap();

    for index in 1..=5 {
        let id = format!("item-{index}");
        run_success(database.command().args(["create", "items", &id]));
    }

    let segments = database.root.join(".cr/audit/segments");
    let mut files: Vec<_> = fs::read_dir(&segments)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "00000000000000000001.jsonl",
            "00000000000000000003.jsonl",
            "00000000000000000005.jsonl"
        ]
    );
    assert_eq!(
        fs::read_to_string(segments.join(&files[0]))
            .unwrap()
            .lines()
            .count(),
        2
    );
    assert_eq!(
        fs::read_to_string(segments.join(&files[1]))
            .unwrap()
            .lines()
            .count(),
        2
    );
    assert_eq!(
        fs::read_to_string(segments.join(&files[2]))
            .unwrap()
            .lines()
            .count(),
        1
    );

    let recent = audit_json(&database, &["audit", "log", "--limit", "3", "--json"]);
    assert_eq!(recent.as_array().unwrap().len(), 3);
    assert_eq!(recent[0]["sequence"], 5);
    assert_eq!(recent[2]["sequence"], 3);

    let filtered = audit_json(&database, &["audit", "log", "items", "item-2", "--json"]);
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["record"]["id"], "item-2");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn segment_byte_limit_bounds_the_active_segment() {
    let database = TestDatabase::new("audit-byte-rotation");
    let config_path = database.root.join(".cr/config.yaml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        config.replace("segment_max_bytes: 8388608", "segment_max_bytes: 1"),
    )
    .unwrap();

    run_success(database.command().args(["create", "items", "one"]));
    run_success(database.command().args(["create", "items", "two"]));

    let mut files: Vec<_> = fs::read_dir(database.root.join(".cr/audit/segments"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    files.sort();
    assert_eq!(
        files,
        ["00000000000000000001.jsonl", "00000000000000000002.jsonl"]
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn verification_detects_record_and_log_tampering_and_checks_external_heads() {
    let database = TestDatabase::new("audit-tampering");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "status=original"]),
    );
    let record_path = database.root.join("records/items/one.md");
    let original_record = fs::read_to_string(&record_path).unwrap();
    let head = audit_json(&database, &["audit", "head", "--json"]);
    let expected_head = head["hash"].as_str().unwrap();

    fs::write(
        &record_path,
        original_record.replace("original", "tampered"),
    )
    .unwrap();
    let stderr = run_failure(database.command().args(["audit", "verify"]));
    assert!(stderr.contains("does not match its latest audited state"));
    let stderr =
        run_failure(
            database
                .command()
                .args(["update", "items", "one", "--set", "status=updated"]),
        );
    assert!(stderr.contains("does not match its latest audited state"));
    fs::write(&record_path, &original_record).unwrap();

    fs::remove_file(&record_path).unwrap();
    let stderr = run_failure(database.command().args(["audit", "verify"]));
    assert!(stderr.contains("does not match its latest audited state"));
    fs::write(&record_path, &original_record).unwrap();

    run_success(
        database
            .command()
            .args(["audit", "verify", "--expected-head", expected_head]),
    );
    let stderr = run_failure(database.command().args([
        "audit",
        "verify",
        "--expected-head",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]));
    assert!(stderr.contains("does not match expected checkpoint"));

    let segment = database
        .root
        .join(".cr/audit/segments/00000000000000000001.jsonl");
    let original_log = fs::read_to_string(&segment).unwrap();
    fs::write(
        &segment,
        original_log.replacen("\"action\":\"create\"", "\"action\":\"update\"", 1),
    )
    .unwrap();
    let stderr = run_failure(database.command().args(["audit", "verify"]));
    assert!(stderr.contains("audit event hash mismatch"));
    fs::write(segment, original_log).unwrap();
}

#[test]
fn untracked_legacy_records_require_an_explicit_baseline() {
    let database = TestDatabase::new("audit-baseline");
    let collection = database.root.join("records/legacy");
    fs::create_dir_all(&collection).unwrap();
    fs::write(
        collection.join("old.md"),
        "---\nstatus: imported\n---\n# Legacy\n",
    )
    .unwrap();

    let stderr = run_failure(database.command().args(["audit", "verify"]));
    assert!(stderr.contains("has no audit history"));
    let stderr =
        run_failure(
            database
                .command()
                .args(["update", "legacy", "old", "--set", "status=active"]),
        );
    assert!(stderr.contains("run 'cr audit baseline'"));

    let output =
        run_success(
            database
                .command()
                .args(["--actor", "migration", "audit", "baseline"]),
        );
    assert!(output.contains("Added 1 baseline audit events"));
    run_success(database.command().args(["audit", "verify"]));

    let entries = audit_json(&database, &["audit", "log", "legacy", "old", "--json"]);
    assert_eq!(entries[0]["action"], "baseline");
    assert_eq!(entries[0]["actor"], "migration");
}

#[test]
fn delete_requires_confirmation_and_retains_an_auditable_tombstone() {
    let database = TestDatabase::new("audit-delete");
    run_success(database.command().args(["create", "items", "one"]));
    let record = database.root.join("records/items/one.md");

    run_failure(database.command().args(["delete", "items", "one"]));
    assert!(record.exists());
    assert_eq!(
        audit_json(&database, &["audit", "head", "--json"])["sequence"],
        1
    );

    run_success(database.command().args(["delete", "items", "one", "--yes"]));
    assert!(!record.exists());
    run_success(database.command().args(["audit", "verify"]));
    let entries = audit_json(&database, &["audit", "log", "items", "one", "--json"]);
    assert_eq!(entries[0]["action"], "delete");
    assert!(entries[0]["after_hash"].is_null());

    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "generation=2"]),
    );
    run_success(database.command().args(["audit", "verify"]));
    let entries = audit_json(&database, &["audit", "log", "items", "one", "--json"]);
    assert_eq!(entries.as_array().unwrap().len(), 3);
    assert_eq!(entries[0]["action"], "create");
    assert_eq!(entries[1]["action"], "delete");
}
