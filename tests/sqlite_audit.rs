//! SQLite is the production default; legacy fixtures exercise the one-time cutover.
mod common;

use common::{TestDatabase, chain, command_for, run_failure, run_success};
use cr::{Assignment, AuditFilter, Database, JournalVerification};
use rusqlite::Connection;
use serde_json::Value;
use std::{fs, path::Path, thread};

const KEY: &str = "550e8400-e29b-41d4-a716-446655440000";

fn sql(root: &Path) -> Connection {
    Connection::open(root.join(".cr/audit.sqlite")).unwrap()
}
fn head(db: &TestDatabase) -> Value {
    serde_json::from_str(&run_success(db.command().args(["audit", "head", "--json"]))).unwrap()
}
fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = target.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
fn pending(db: &TestDatabase) -> String {
    sql(&db.root)
        .query_row("SELECT payload FROM pending", [], |r| r.get(0))
        .unwrap()
}
fn put_pending(db: &TestDatabase, raw: &str) {
    sql(&db.root)
        .execute("INSERT OR REPLACE INTO pending VALUES(1,?1)", [raw])
        .unwrap();
}
fn interrupt(db: &TestDatabase, args: &[&str]) -> String {
    sql(&db.root).execute_batch("CREATE TRIGGER stop_append BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'injected append failure'); END;").unwrap();
    run_failure(db.command().args(args));
    let raw = pending(db);
    sql(&db.root)
        .execute_batch("DROP TRIGGER stop_append")
        .unwrap();
    raw
}

#[test]
fn new_databases_use_sqlite_and_retries_survive_fresh_cli_processes() {
    let db = TestDatabase::new("sqlite-default");
    assert!(
        fs::read_to_string(db.root.join(".cr/config.yaml"))
            .unwrap()
            .contains("version: 2")
    );
    assert!(!db.root.join(".cr/audit/segments").exists());
    let args = [
        "create",
        "items",
        "one",
        "--set",
        "name=original",
        "--idempotency-key",
        KEY,
        "--json",
    ];
    let first = run_success(db.command().args(args));
    run_success(
        db.command()
            .args(["update", "items", "one", "--set", "name=changed"]),
    );
    assert_eq!(run_success(db.command().args(args)), first);
    assert_eq!(head(&db)["sequence"], 2);
    chain::assert_chain_is_well_formed(&db.root);
    run_success(db.command().args(["audit", "verify"]));
}

#[test]
fn migration_preserves_v1_v2_and_unknown_metadata_payload_bytes() {
    for fixture in ["legacy-v1-journal", "legacy-journal", "future-journal"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("database");
        copy_tree(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(fixture),
            &root,
        );
        let original = chain::read_chain(&root);
        let before = run_success(command_for(&root).args(["audit", "head", "--json"]));
        let migrated = run_success(command_for(&root).args(["audit", "migrate", "--json"]));
        assert_eq!(
            serde_json::from_str::<Value>(&migrated).unwrap()["migrated"],
            true
        );
        assert_eq!(
            before,
            run_success(command_for(&root).args(["audit", "head", "--json"]))
        );
        let imported = chain::read_chain(&root);
        for (a, b) in original.iter().zip(&imported) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.payload, b.payload);
        }
        assert_eq!(original.len(), imported.len());
        run_success(command_for(&root).args(["audit", "verify"]));
        assert!(root.join(".cr/audit/segments").is_dir());
        let repeated = run_success(command_for(&root).args(["audit", "migrate", "--json"]));
        assert_eq!(
            serde_json::from_str::<Value>(&repeated).unwrap()["migrated"],
            false
        );
    }
}

#[test]
fn migration_keeps_dirty_files_and_config_and_fences_existing_handles() {
    let db = TestDatabase::new_legacy("migration-dirty");
    let legacy = Database::discover(Some(&db.root)).unwrap();
    run_success(db.command().args(["create", "items", "one"]));
    let original = chain::journal_text(&db.root);
    let dirty = b"---\nname: unsaved\n---\nhand-edited\n";
    fs::write(db.root.join("records/items/one.md"), dirty).unwrap();
    fs::write(db.root.join(".cr/config.yaml"),"version: 1\ndata_dir: records\naudit:\n  full_walk_after_events: 123\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n").unwrap();
    run_success(db.command().args(["audit", "migrate"]));
    assert_eq!(chain::journal_text(&db.root), original);
    assert_eq!(
        fs::read(db.root.join("records/items/one.md")).unwrap(),
        dirty
    );
    let config = fs::read_to_string(db.root.join(".cr/config.yaml")).unwrap();
    assert!(config.contains("123"));
    assert!(config.contains("SKILL.md"));
    assert!(
        format!("{:#}", legacy.create("items", "two", &[], "").unwrap_err())
            .contains("storage changed")
    );
    let status = run_success(db.command().args(["status", "--json"]));
    assert!(status.contains("modified"));
    run_success(db.command().args(["save", "--all"]));
    run_success(db.command().args(["audit", "verify"]));
}

#[test]
fn interrupted_migration_can_resume_a_verified_prefix_after_more_legacy_writes() {
    let db = TestDatabase::new_legacy("migration-resume");
    run_success(db.command().args(["create", "items", "one"]));
    run_success(db.command().args(["audit", "migrate"]));
    // A crash before the final atomic config replacement leaves this state.
    fs::write(
        db.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\n",
    )
    .unwrap();
    run_success(db.command().args(["create", "items", "two"]));
    run_success(db.command().args(["audit", "migrate"]));
    assert_eq!(head(&db)["sequence"], 2);
    run_success(db.command().args(["audit", "verify"]));
}

#[test]
fn corrupt_source_or_conflicting_destination_never_cuts_over() {
    for corrupt_source in [true, false] {
        let db = TestDatabase::new_legacy("migration-conflict");
        run_success(db.command().args(["create", "items", "one"]));
        if corrupt_source {
            let segment = chain::segment_paths(&db.root).remove(0);
            let raw = fs::read_to_string(&segment)
                .unwrap()
                .replace("\"action\":\"create\"", "\"action\":\"update\"");
            fs::write(segment, raw).unwrap();
        } else {
            fs::write(db.root.join(".cr/audit.sqlite"), "unrelated database").unwrap();
        }
        run_failure(db.command().args(["audit", "migrate"]));
        assert!(
            fs::read_to_string(db.root.join(".cr/config.yaml"))
                .unwrap()
                .contains("version: 1")
        );
    }
}

#[test]
fn recovery_handles_unapplied_published_and_already_committed_intents_once() {
    for point in ["before", "after", "committed"] {
        let db = TestDatabase::new("sqlite-recovery");
        run_success(
            db.command()
                .args(["create", "items", "one", "--body", "before"]),
        );
        let before = fs::read(db.root.join("records/items/one.md")).unwrap();
        let raw = interrupt(
            &db,
            &[
                "update",
                "items",
                "one",
                "--body",
                "after",
                "--idempotency-key",
                KEY,
            ],
        );
        if point == "before" {
            fs::write(db.root.join("records/items/one.md"), before).unwrap();
        }
        if point == "committed" {
            run_success(db.command().args(["get", "items", "one"]));
            put_pending(&db, &raw);
            fs::remove_file(db.root.join(".cr-audit-head.json")).unwrap();
        }
        run_success(db.command().args(["get", "items", "one"]));
        assert_eq!(head(&db)["sequence"], if point == "before" { 1 } else { 2 });
        let count: i64 = sql(&db.root)
            .query_row("SELECT count(*) FROM pending", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        run_success(db.command().args(["audit", "verify"]));
        if point != "before" {
            run_success(db.command().args([
                "update",
                "items",
                "one",
                "--body",
                "after",
                "--idempotency-key",
                KEY,
            ]));
            assert_eq!(head(&db)["sequence"], 2);
        }
    }
}

#[test]
fn sqlite_recovery_refuses_conflicting_record_bytes() {
    let db = TestDatabase::new("sqlite-conflicting-pending");
    run_success(
        db.command()
            .args(["create", "items", "one", "--body", "before"]),
    );
    interrupt(&db, &["update", "items", "one", "--body", "after"]);
    fs::write(
        db.root.join("records/items/one.md"),
        "---\nname: unplanned\n---\n",
    )
    .unwrap();
    assert!(run_failure(db.command().args(["get", "items", "one"])).contains("neither state"));
    assert!(!pending(&db).is_empty());
}

#[test]
fn independent_verification_checks_every_operational_projection() {
    for corruption in [
        "UPDATE record_states SET state='{}'",
        "UPDATE record_states SET activity=NULL",
        "DELETE FROM idempotency",
        "UPDATE idempotency SET files='{}' WHERE sequence=1", // no files: changed separately below
        "UPDATE events SET collection='forged'",
        "UPDATE events SET transition='{}'", // equivalent empty transition; replace with invalid object
        "DELETE FROM agent_values",
        "DELETE FROM principals",
        "UPDATE head SET hash='sha256:forged'",
    ] {
        let db = TestDatabase::new("sqlite-index-corruption");
        run_success(db.command().args([
            "--actor",
            "alice",
            "create",
            "items",
            "one",
            "--agent",
            r#"{"id":"test","session":"s-1"}"#,
            "--idempotency-key",
            KEY,
        ]));
        let corruption = match corruption {
            "UPDATE idempotency SET files='{}' WHERE sequence=1" => {
                "UPDATE idempotency SET sequence=99"
            }
            "UPDATE events SET transition='{}'" => "UPDATE events SET transition='{\"before\":{}}'",
            other => other,
        };
        sql(&db.root)
            .execute_batch(&format!("PRAGMA foreign_keys=OFF; {corruption}"))
            .unwrap();
        run_failure(db.command().args(["audit", "verify"]));
    }
}

#[test]
fn missing_or_unknown_sqlite_never_falls_back_to_retired_segments() {
    for missing in [true, false] {
        let db = TestDatabase::new_legacy("sqlite-fail-closed");
        run_success(db.command().args(["create", "items", "one"]));
        run_success(db.command().args(["audit", "migrate"]));
        if missing {
            fs::remove_file(db.root.join(".cr/audit.sqlite")).unwrap();
        } else {
            sql(&db.root)
                .pragma_update(None, "user_version", 99)
                .unwrap();
        }
        run_failure(db.command().args(["get", "items", "one"]));
        assert_eq!(chain::segment_paths(&db.root).len(), 1);
    }
}

#[cfg(unix)]
#[test]
fn main_file_parent_and_all_sidecar_symlinks_are_refused() {
    use std::os::unix::fs::symlink;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let db = TestDatabase::new("sqlite-links");
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        fs::write(&victim, "unchanged").unwrap();
        let path = db.root.join(format!(".cr/audit.sqlite{suffix}"));
        if path.exists() {
            fs::remove_file(&path).unwrap();
        }
        symlink(&victim, path).unwrap();
        run_failure(db.command().args(["audit", "head"]));
        assert_eq!(fs::read_to_string(victim).unwrap(), "unchanged");
    }
    let db = TestDatabase::new("sqlite-parent-link");
    let moved = db.root.join("moved");
    fs::rename(db.root.join(".cr"), &moved).unwrap();
    symlink(moved, db.root.join(".cr")).unwrap();
    run_failure(db.command().args(["audit", "head"]));
}

#[test]
fn concurrent_fresh_handles_serialize_writes_and_share_durable_retry_identity() {
    let db = TestDatabase::new("sqlite-concurrent");
    let mut workers = Vec::new();
    for _ in 0..8 {
        let root = db.root.clone();
        workers.push(thread::spawn(move || {
            let db = Database::discover(Some(&root))
                .unwrap()
                .with_actor("alice")
                .unwrap()
                .with_idempotency_key(KEY)
                .unwrap();
            db.create("items", "one", &[], "same").unwrap()
        }));
    }
    let versions: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().version)
        .collect();
    assert!(versions.iter().all(|value| value == &versions[0]));
    assert_eq!(head(&db)["sequence"], 1);
    run_success(db.command().args(["audit", "verify"]));
}

#[test]
fn history_filters_use_delegation_membership_and_visibility_before_limit() {
    let db = TestDatabase::new("sqlite-filters");
    for (id, agent) in [
        (
            "one",
            r#"{"id":"first","session":"s-1","via":[{"id":"delegate","session":"parent"}]}"#,
        ),
        ("two", r#"{"id":"other","session":"s-2"}"#),
        (
            "three",
            r#"{"id":"first","session":"s-1","via":[{"id":"delegate","session":"parent"}]}"#,
        ),
    ] {
        run_success(db.command().args(["create", "items", id, "--agent", agent]));
    }
    let db = Database::discover(Some(&db.root)).unwrap();
    let entries = db
        .audit_recent(
            1,
            AuditFilter {
                agent: Some("first"),
                session: Some("s-1"),
                ..AuditFilter::all()
            },
        )
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].payload.record.id, "three");
}

#[test]
fn explicitly_requested_full_verification_still_finds_old_damage() {
    let db = TestDatabase::new("sqlite-explicit-verify");
    run_success(db.command().args(["create", "items", "one"]));
    run_success(db.command().args(["create", "items", "two"]));
    sql(&db.root)
        .execute("UPDATE events SET payload='{}' WHERE sequence=1", [])
        .unwrap();
    // A normal scoped mutation trusts committed indexes; the explicit override
    // independently validates all historical bytes before touching files.
    let full = Database::discover(Some(&db.root))
        .unwrap()
        .with_journal_verification(JournalVerification::Full);
    assert!(
        full.update(
            "items",
            "two",
            &["name=changed".parse::<Assignment>().unwrap()],
            None
        )
        .is_err()
    );
    run_failure(db.command().args(["audit", "verify"]));
}

#[test]
fn migration_preserves_bundle_versions_and_the_original_keyed_result() {
    let db = TestDatabase::new_legacy("sqlite-bundle-migration");
    fs::write(
        db.root.join(".cr/config.yaml"),
        "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n",
    )
    .unwrap();
    let source = db.root.join("binary");
    fs::write(&source, [0, 255, 1, 254]).unwrap();
    let file = format!("asset.bin={}", source.display());
    let args = [
        "create",
        "skills",
        "one",
        "--body",
        "instructions",
        "--file",
        &file,
        "--idempotency-key",
        KEY,
        "--json",
    ];
    let original = run_success(db.command().args(args));
    let bytes = chain::journal_text(&db.root);
    run_success(db.command().args(["audit", "migrate"]));
    assert_eq!(chain::journal_text(&db.root), bytes);
    assert_eq!(run_success(db.command().args(args)), original);
    assert_eq!(
        fs::read(db.root.join("records/skills/one/asset.bin")).unwrap(),
        [0, 255, 1, 254]
    );
    fs::write(&source, [8, 7, 6]).unwrap();
    interrupt(&db, &["update", "skills", "one", "--file", &file]);
    run_success(db.command().args(["get", "skills", "one"]));
    assert_eq!(
        fs::read(db.root.join("records/skills/one/asset.bin")).unwrap(),
        [8, 7, 6]
    );
    run_success(db.command().args(["audit", "verify"]));
    assert_eq!(head(&db)["sequence"], 2);
}

#[test]
fn migration_and_sqlite_history_keep_protected_values_encrypted() {
    let db = TestDatabase::new_legacy("sqlite-encryption-migration");
    fs::write(
        db.root.join(".cr/schemas/secrets.json"),
        r#"{"type":"object","properties":{"value":{"type":"string","x-cr-encrypted":true}}}"#,
    )
    .unwrap();
    let keyed = || {
        let mut command = db.command();
        command.env("CR_ENCRYPTION_ACTIVE_KEY", "one").env(
            "CR_ENCRYPTION_KEYS",
            r#"{"one":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        );
        command
    };
    let args = [
        "create",
        "secrets",
        "one",
        "--set",
        "value=private-secret",
        "--idempotency-key",
        KEY,
        "--json",
    ];
    let original = run_success(keyed().args(args));
    let ciphertext = fs::read(db.root.join("records/secrets/one.md")).unwrap();
    let events = chain::journal_text(&db.root);
    run_success(keyed().args(["audit", "migrate"]));
    assert_eq!(
        fs::read(db.root.join("records/secrets/one.md")).unwrap(),
        ciphertext
    );
    assert_eq!(chain::journal_text(&db.root), events);
    assert!(!events.contains("private-secret"));
    assert_eq!(run_success(keyed().args(args)), original);
    assert!(run_success(keyed().args(["audit", "log", "--json"])).contains("private-secret"));
    run_success(keyed().args(["audit", "verify"]));
    let file = fs::read(db.root.join(".cr/audit.sqlite")).unwrap();
    assert!(!String::from_utf8_lossy(&file).contains("private-secret"));
}

#[test]
fn signed_checkpoint_is_identical_after_migration_and_continues_in_sqlite() {
    let db = TestDatabase::new_legacy("sqlite-signed-migration");
    let keys = tempfile::tempdir().unwrap();
    let private = keys.path().join("key");
    run_success(
        db.command()
            .args(["audit", "key", "generate"])
            .arg(&private),
    );
    let key: Value = serde_json::from_str(&run_success(
        db.command()
            .args(["audit", "key", "show", "--json"])
            .arg(&private),
    ))
    .unwrap();
    let public = key["public_key"].as_str().unwrap();
    let signed = || {
        let mut command = db.command();
        command.env("CR_AUDIT_SIGNING_KEY", &private);
        command.env("CR_AUDIT_TRUSTED_KEYS", public);
        command
    };
    run_success(signed().args(["create", "items", "one"]));
    let before = fs::read(db.root.join(".cr-audit-head.sig.json")).unwrap();
    run_success(signed().args(["audit", "migrate"]));
    assert_eq!(
        fs::read(db.root.join(".cr-audit-head.sig.json")).unwrap(),
        before
    );
    run_success(signed().args(["update", "items", "one", "--body", "next"]));
    assert_ne!(
        fs::read(db.root.join(".cr-audit-head.sig.json")).unwrap(),
        before
    );
    run_success(signed().args(["audit", "verify"]));
}

#[test]
fn healthy_sqlite_reads_do_not_wait_for_the_filesystem_writer_lock() {
    use std::{
        fs::OpenOptions,
        time::{Duration, Instant},
    };
    let db = TestDatabase::new("sqlite-reader-lock");
    run_success(db.command().args(["create", "items", "one"]));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(db.root.join(".cr/audit/lock"))
        .unwrap();
    lock.lock().unwrap();
    let mut child = db
        .command()
        .args(["get", "items", "one"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() > deadline {
            drop(lock);
            child.kill().unwrap();
            panic!("a healthy read queued behind the writer lock");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn missing_config_does_not_reactivate_retired_legacy_history() {
    let db = TestDatabase::new_legacy("sqlite-config-fence");
    run_success(db.command().args(["create", "items", "one"]));
    run_success(db.command().args(["audit", "migrate"]));
    fs::remove_file(db.root.join(".cr/config.yaml")).unwrap();
    assert!(
        run_failure(db.command().args(["get", "items", "one"]))
            .contains("configuration is missing")
    );
}

#[test]
fn migration_requires_the_current_database_owner() {
    let db = TestDatabase::new_legacy("sqlite-migration-access");
    run_success(db.command().env("CR_ACTOR", "owner@example.com").args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(db.command().env("CR_ACTOR", "owner@example.com").args([
        "user",
        "add",
        "reader@example.com",
        "--name",
        "Reader",
        "--email",
        "reader@example.com",
    ]));
    run_failure(
        db.command()
            .env("CR_ACTOR", "reader@example.com")
            .args(["audit", "migrate"]),
    );
    assert!(
        fs::read_to_string(db.root.join(".cr/config.yaml"))
            .unwrap()
            .contains("version: 1")
    );
    run_success(
        db.command()
            .env("CR_ACTOR", "owner@example.com")
            .args(["audit", "migrate"]),
    );
    run_success(
        db.command()
            .env("CR_ACTOR", "owner@example.com")
            .args(["audit", "verify"]),
    );
}

#[test]
fn a_failed_import_rolls_back_every_event_and_can_be_retried() {
    let db = TestDatabase::new("sqlite-import-rollback");
    // Preserve a valid empty destination as an interrupted migration artifact.
    fs::write(
        db.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\n",
    )
    .unwrap();
    for id in ["one", "two", "three"] {
        run_success(db.command().args(["create", "items", id]));
    }
    sql(&db.root).execute_batch("CREATE TRIGGER stop_import BEFORE INSERT ON events WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT,'interrupted import'); END;").unwrap();
    run_failure(db.command().args(["audit", "migrate"]));
    let count: i64 = sql(&db.root)
        .query_row("SELECT count(*) FROM events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    assert!(
        fs::read_to_string(db.root.join(".cr/config.yaml"))
            .unwrap()
            .contains("version: 1")
    );
    sql(&db.root)
        .execute_batch("DROP TRIGGER stop_import")
        .unwrap();
    run_success(db.command().args(["audit", "migrate"]));
    run_success(db.command().args(["audit", "verify"]));
    assert_eq!(head(&db)["sequence"], 3);
}
