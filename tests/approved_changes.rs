//! Previewing a change set, approving its digest, and checking it afterwards.
//!
//! This is the one part of the attribution design that is checked rather than
//! believed, so the tests that matter here are the negative ones: a preview
//! that writes something, an apply that diverges from what was approved, or an
//! `audit verify` that stays quiet about a mismatch would each make the feature
//! worse than not having it.

mod common;

use std::{fs, path::Path};

use common::{TestDatabase, command_for, run_failure, run_success};
use serde_json::Value;

/// Everything `cr` may have written for a database, as one comparable value.
fn snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries = Vec::new();
    collect(root, root, &mut entries);
    entries.sort();
    entries
}

fn collect(root: &Path, directory: &Path, entries: &mut Vec<(String, Vec<u8>)>) {
    for entry in fs::read_dir(directory).expect("could not read the database") {
        let entry = entry.expect("could not read a database entry");
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, entries);
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .expect("every entry is under the root")
            .to_string_lossy()
            .into_owned();
        // The lock file is created by taking the lock and is always empty; it
        // says nothing about whether the lock is still held.
        if relative.ends_with("audit/lock") {
            continue;
        }
        entries.push((relative, fs::read(&path).expect("could not read a file")));
    }
}

/// The digest line a preview always ends with.
fn digest_of(preview: &str) -> String {
    preview
        .lines()
        .last()
        .and_then(|line| line.strip_prefix("digest "))
        .unwrap_or_else(|| panic!("a preview ends with a digest line: {preview:?}"))
        .to_owned()
}

fn seeded(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
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
            .args(["create", "people", "ada", "--set", "name=Ada"]),
    );
    database
}

/// A preview must leave the database byte-for-byte as it found it.
///
/// Not "no audit event" — nothing at all. No record written, no event appended,
/// no pending-mutation file left behind, and the audit lock released, which the
/// following command proves by taking it.
#[test]
fn a_preview_writes_nothing_at_all() {
    let database = seeded("preview-writes-nothing");
    let before = snapshot(&database.root);
    let head = run_success(database.command().args(["audit", "head"]));

    for arguments in [
        vec!["create", "deals", "new-deal", "--set", "status=open"],
        vec!["update", "deals", "acme-renewal", "--set", "status=closed"],
        vec!["link", "deals", "acme-renewal", "owner", "people", "ada"],
        vec!["delete", "deals", "acme-renewal"],
    ] {
        let output = run_success(database.command().args(&arguments).arg("--preview"));
        assert!(
            output.contains("digest sha256:"),
            "{arguments:?} produced {output:?}"
        );

        assert_eq!(
            snapshot(&database.root),
            before,
            "{arguments:?} changed the database"
        );
    }

    assert!(!database.root.join(".cr/audit/pending.json").exists());
    assert_eq!(
        run_success(database.command().args(["audit", "head"])),
        head
    );
    run_success(database.command().args(["audit", "verify"]));
    // The lock was released, so an ordinary mutation still succeeds.
    run_success(database.command().args([
        "update",
        "deals",
        "acme-renewal",
        "--set",
        "stage=closed",
    ]));
}

/// `--preview` computes exactly the change set the apply records, and passing
/// its digest back records the digest in the event.
#[test]
fn an_approved_digest_matches_the_applied_change_set_and_is_recorded() {
    let database = seeded("approve-and-apply");
    let preview = run_success(
        database
            .command()
            .args(["update", "deals", "acme-renewal"])
            .args(["--set", "status=closed-won", "--set", "stage=closed"])
            .arg("--preview"),
    );
    let digest = digest_of(&preview);
    assert!(preview.contains(r#"replace /attributes/status "open" -> "closed-won""#));

    run_success(
        database
            .command()
            .args(["update", "deals", "acme-renewal"])
            .args(["--set", "status=closed-won", "--set", "stage=closed"])
            .args(["--authorization", "interactive"])
            .args(["--approved-changes", &digest]),
    );

    let entries: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args(["audit", "log", "--json", "-n", "1"]),
    ))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["authorization"]["approved_changes"], digest);
    assert_eq!(entries[0]["authorization"]["mode"], "interactive");
    run_success(database.command().args(["audit", "verify"]));
}

/// The adversarial case. A digest that was approved for one change set must not
/// be usable to write a different one, and the refusal must say so rather than
/// looking like any other conflict.
#[test]
fn applying_a_change_other_than_the_one_approved_is_refused() {
    let database = seeded("apply-something-else");
    let digest = digest_of(&run_success(
        database
            .command()
            .args([
                "update",
                "deals",
                "acme-renewal",
                "--set",
                "status=closed-won",
            ])
            .arg("--preview"),
    ));
    let before = snapshot(&database.root);

    let error = run_failure(
        database
            .command()
            .args(["update", "deals", "acme-renewal", "--set", "status=lost"])
            .args(["--authorization", "interactive"])
            .args(["--approved-changes", &digest]),
    );
    assert!(
        error.contains("does not match the approved change set"),
        "unexpected error: {error}"
    );
    assert!(error.contains(&digest), "unexpected error: {error}");
    assert!(!error.contains("os error"), "{error}");
    assert!(
        !error.contains(database.root.to_str().expect("a UTF-8 root")),
        "{error}"
    );
    assert_eq!(
        snapshot(&database.root),
        before,
        "the refused mutation still wrote something"
    );
}

/// The gap between preview and apply is real: another write can land in it.
///
/// The digest closes it for the approved change specifically. When the record
/// moves underneath, the change set the apply would record is no longer the one
/// that was previewed — its `before` values differ — so the write is refused
/// instead of silently applying under a stale approval.
#[test]
fn a_change_set_that_went_stale_between_preview_and_apply_is_refused() {
    let database = seeded("stale-approval");
    let digest = digest_of(&run_success(
        database
            .command()
            .args([
                "update",
                "deals",
                "acme-renewal",
                "--set",
                "status=closed-won",
            ])
            .arg("--preview"),
    ));

    run_success(database.command().args([
        "update",
        "deals",
        "acme-renewal",
        "--set",
        "status=stalled",
    ]));

    let error = run_failure(
        database
            .command()
            .args([
                "update",
                "deals",
                "acme-renewal",
                "--set",
                "status=closed-won",
            ])
            .args(["--authorization", "delegated"])
            .args(["--approved-changes", &digest]),
    );
    assert!(
        error.contains("does not match the approved change set"),
        "unexpected error: {error}"
    );
}

/// `audit verify` must recompute the digest from the stored change set and fail
/// with its own named error when they disagree.
///
/// `tests/fixtures/mismatched-approval` is a committed journal whose head event
/// had its `changes` rewritten and its event hash recomputed, leaving
/// `authorization.approved_changes` pointing at the change set that was
/// actually approved. That is deliberately the case a hash chain cannot catch:
/// the chain is intact, the record matches its `after_hash`, and `audit head`
/// answers normally. Only recomputing the approved digest finds it, and the
/// failure has to be distinguishable from "the chain is corrupt" or an auditor
/// cannot tell the two apart.
#[test]
fn audit_verify_names_a_change_set_that_is_not_the_one_approved() {
    let temporary = tempfile::tempdir().expect("could not create a temporary directory");
    let root = temporary.path().join("mismatched");
    copy_fixture("mismatched-approval", &root);

    let error = run_failure(command_for(&root).args(["audit", "verify"]));
    assert!(
        error.contains("records an approved change set that is not the one it applied"),
        "unexpected error: {error}"
    );
    assert!(error.contains("audit event 2"), "unexpected error: {error}");
    assert!(!error.contains("os error"), "{error}");
    assert!(
        !error.contains(root.to_str().expect("a UTF-8 root")),
        "{error}"
    );

    // The chain itself is sound, which is exactly the point: a generic
    // verification failure here would have told the auditor the wrong thing.
    run_success(command_for(&root).args(["audit", "head"]));
    let log = run_success(command_for(&root).args(["audit", "log"]));
    assert!(log.contains("deals/acme-renewal"));
}

/// One digest cannot stand for several independent change sets, so approving a
/// multi-record save is refused rather than checked against one of them.
#[test]
fn a_multi_record_save_cannot_be_approved_by_one_digest() {
    let database = seeded("multi-record-save");
    fs::write(
        database.root.join("records/deals/acme-renewal.md"),
        "---\nstatus: closed-won\nstage: negotiation\n---\n",
    )
    .expect("could not edit a record");
    fs::write(
        database.root.join("records/people/ada.md"),
        "---\nname: Ada Lovelace\n---\n",
    )
    .expect("could not edit a record");

    let preview = run_success(database.command().args(["save", "--all", "--preview"]));
    assert_eq!(
        preview.matches("digest sha256:").count(),
        2,
        "a preview per record: {preview}"
    );

    let digest = digest_of(&run_success(database.command().args([
        "save",
        "deals/acme-renewal",
        "--preview",
    ])));
    let error = run_failure(
        database
            .command()
            .args(["save", "--all"])
            .args(["--authorization", "interactive"])
            .args(["--approved-changes", &digest]),
    );
    assert!(
        error.contains("naming exactly one COLLECTION/ID"),
        "unexpected error: {error}"
    );

    run_success(
        database
            .command()
            .args(["save", "deals/acme-renewal"])
            .args(["--authorization", "interactive"])
            .args(["--approved-changes", &digest]),
    );
    let entries: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args(["audit", "log", "--json", "-n", "1"]),
    ))
    .expect("audit log is JSON");
    assert_eq!(entries[0]["authorization"]["approved_changes"], digest);
    assert_eq!(entries[0]["record"]["id"], "acme-renewal");
}

/// A deletion is the change most worth previewing, and previewing one must not
/// require confirming it.
#[test]
fn a_delete_can_be_previewed_without_confirming_it() {
    let database = seeded("preview-delete");
    let preview =
        run_success(
            database
                .command()
                .args(["delete", "deals", "acme-renewal", "--preview"]),
        );
    assert!(preview.contains("delete deals/acme-renewal"));
    assert!(preview.contains("remove (record)"));
    assert!(database.root.join("records/deals/acme-renewal.md").exists());

    let error = run_failure(database.command().args(["delete", "deals", "acme-renewal"]));
    assert!(error.contains("--yes"), "unexpected error: {error}");

    let digest = digest_of(&preview);
    run_success(
        database
            .command()
            .args(["delete", "deals", "acme-renewal", "--yes"])
            .args(["--authorization", "direct"])
            .args(["--approved-changes", &digest]),
    );
    run_success(database.command().args(["audit", "verify"]));
}

/// `--preview --json` is the shape an agent reads, and it must carry the same
/// digest as the human-readable form plus the state hashes around it.
#[test]
fn a_json_preview_carries_the_digest_and_the_surrounding_state() {
    let database = seeded("preview-json");
    let text = run_success(
        database
            .command()
            .args(["update", "deals", "acme-renewal", "--set", "status=won"])
            .arg("--preview"),
    );
    let json: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args(["update", "deals", "acme-renewal", "--set", "status=won"])
            .args(["--preview", "--json"]),
    ))
    .expect("a JSON preview");

    assert_eq!(json["preview"], true);
    assert_eq!(json["action"], "update");
    assert_eq!(json["record"]["collection"], "deals");
    assert_eq!(json["digest"], digest_of(&text));
    assert!(json["before_hash"].as_str().is_some());
    assert!(json["after_hash"].as_str().is_some());
    assert_eq!(json["changes"][0]["path"], "/attributes/status");
}

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
