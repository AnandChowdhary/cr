//! Adversarial coverage for symbolic links planted inside a database.
//!
//! Each test builds an escape an attacker with write access to the database
//! directory could construct, then asserts that `cr` refuses it and that
//! nothing outside the database root was read or written. Symbolic links only
//! exist on Unix, so the whole file is scoped to it.

#![cfg(unix)]

mod common;

use std::{fs, os::unix::fs::symlink, path::Path, process::Command};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::{command_for, run_failure, run_success, TestDatabase};
use cr::{
    server::{router, ServerConfig},
    Database,
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SECRET: &str = "---\nclassified: true\n---\nDo not read me.\n";

/// A directory outside the database holding one Markdown file `cr` must never
/// reach, plus the collection layout an escape would expose.
fn planted_target(parent: &Path) -> std::path::PathBuf {
    let outside = parent.join("outside");
    fs::create_dir_all(outside.join("people")).unwrap();
    fs::write(outside.join("people/ada.md"), SECRET).unwrap();
    outside
}

fn assert_untouched(outside: &Path) {
    assert_eq!(
        fs::read_to_string(outside.join("people/ada.md")).unwrap(),
        SECRET
    );
    let entries: Vec<_> = fs::read_dir(outside.join("people"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "cr created something outside the database"
    );
}

/// The configured records directory itself is replaced by a link. Every
/// command must refuse rather than treat the linked tree as the database.
#[test]
fn a_symlinked_records_directory_is_refused_for_reads_and_writes() {
    let database = TestDatabase::new("linked-data-dir");
    let parent = database.root.parent().unwrap().to_path_buf();
    let outside = planted_target(&parent);

    fs::remove_dir_all(database.root.join("records")).unwrap();
    symlink(&outside, database.root.join("records")).unwrap();

    for arguments in [
        vec!["list", "people"],
        vec!["get", "people", "ada"],
        vec!["search", "classified"],
        vec!["status"],
        vec!["audit", "verify"],
        vec!["create", "people", "bob", "--set", "name=Bob"],
        vec!["update", "people", "ada", "--set", "name=Ada"],
        vec!["delete", "people", "ada", "--yes"],
        vec!["save", "--all"],
    ] {
        let stderr = run_failure(database.command().args(&arguments));
        assert!(
            stderr.contains("symbolic link"),
            "cr {arguments:?} did not refuse the link: {stderr}"
        );
    }
    assert_untouched(&outside);
}

/// An intermediate directory named by `data_dir` is replaced by a link, so the
/// final component still looks ordinary.
#[test]
fn an_intermediate_configured_directory_cannot_be_a_symlink() {
    let database = TestDatabase::new("linked-intermediate");
    let parent = database.root.parent().unwrap().to_path_buf();
    let outside = parent.join("outside");
    fs::create_dir_all(outside.join("records/people")).unwrap();
    fs::write(outside.join("records/people/ada.md"), SECRET).unwrap();

    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: data/records\n",
    )
    .unwrap();
    symlink(&outside, database.root.join("data")).unwrap();

    let stderr = run_failure(database.command().args(["get", "people", "ada"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");
    let stderr = run_failure(database.command().args(["list", "people"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert_eq!(
        fs::read_to_string(outside.join("records/people/ada.md")).unwrap(),
        SECRET
    );
}

/// `data_dir` may not leave the root through plain path syntax either.
#[test]
fn an_absolute_or_ascending_data_dir_is_rejected() {
    let database = TestDatabase::new("escaping-data-dir");

    for value in ["/etc", "../outside", "records/../../outside"] {
        fs::write(
            database.root.join(".cr/config.yaml"),
            format!("version: 1\ndata_dir: {value}\n"),
        )
        .unwrap();
        let stderr = run_failure(database.command().args(["list", "people"]));
        assert!(
            stderr.contains("data_dir must be a relative path"),
            "{value}: {stderr}"
        );
    }
}

/// One collection directory is replaced by a link. The final record file is a
/// perfectly ordinary regular file, so only checking it would let this through.
#[test]
fn a_symlinked_collection_directory_is_refused_on_both_paths() {
    let database = TestDatabase::new("linked-collection");
    let parent = database.root.parent().unwrap().to_path_buf();
    let outside = planted_target(&parent);
    symlink(outside.join("people"), database.root.join("records/people")).unwrap();

    let stderr = run_failure(database.command().args(["get", "people", "ada"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert!(!stderr.contains("Do not read me"));

    let stderr = run_failure(database.command().args(["list", "people"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");

    let stderr = run_failure(
        database
            .command()
            .args(["create", "people", "bob", "--set", "name=Bob"]),
    );
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert_untouched(&outside);

    // The refusal does not depend on where the link points: a link into the
    // database is refused too, because the rule is that stored paths are real.
    fs::remove_file(database.root.join("records/people")).unwrap();
    fs::create_dir_all(database.root.join("records/staff")).unwrap();
    symlink(
        database.root.join("records/staff"),
        database.root.join("records/people"),
    )
    .unwrap();
    let stderr = run_failure(database.command().args(["list", "people"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");
}

/// A record file is replaced by a link to a file outside the database. Reads
/// must not disclose it and writes must not reach it.
#[test]
fn a_symlinked_record_file_is_never_read_or_written_through() {
    let database = TestDatabase::new("linked-record");
    let parent = database.root.parent().unwrap().to_path_buf();
    let outside = planted_target(&parent);

    fs::create_dir_all(database.root.join("records/people")).unwrap();
    symlink(
        outside.join("people/ada.md"),
        database.root.join("records/people/ada.md"),
    )
    .unwrap();

    for arguments in [
        vec!["get", "people", "ada"],
        vec!["update", "people", "ada", "--set", "name=Ada"],
        vec!["delete", "people", "ada", "--yes"],
    ] {
        let stderr = run_failure(database.command().args(&arguments));
        assert!(
            stderr.contains("symbolic link"),
            "cr {arguments:?}: {stderr}"
        );
        assert!(!stderr.contains("Do not read me"));
    }
    // Creation sees the link as an occupied name and refuses to publish
    // through it, which is the same protection under a different wording.
    let stderr = run_failure(
        database
            .command()
            .args(["create", "people", "ada", "--set", "name=Ada"]),
    );
    assert!(stderr.contains("already exists"), "{stderr}");
    assert_untouched(&outside);
}

/// The `.cr` marker directory is replaced by a link, which would relocate
/// configuration, views, syncs, and the audit journal in one move.
#[test]
fn a_symlinked_database_directory_is_refused() {
    let database = TestDatabase::new("linked-marker");
    let parent = database.root.parent().unwrap().to_path_buf();
    let stolen = parent.join("stolen");
    fs::rename(database.root.join(".cr"), &stolen).unwrap();
    symlink(&stolen, database.root.join(".cr")).unwrap();

    for arguments in [vec!["status"], vec!["view", "list"], vec!["audit", "head"]] {
        let stderr = run_failure(database.command().args(&arguments));
        assert!(
            stderr.contains("symbolic link"),
            "cr {arguments:?}: {stderr}"
        );
    }
}

/// The audit journal is the project's integrity foundation, so neither its
/// directory nor its segment directory may be redirected.
#[test]
fn the_audit_journal_cannot_be_relocated_by_a_link() {
    for target in [".cr/audit", ".cr/audit/segments"] {
        let database = TestDatabase::new("linked-audit");
        let parent = database.root.parent().unwrap().to_path_buf();
        let stolen = parent.join("stolen");
        fs::create_dir_all(&stolen).unwrap();
        let original = database.root.join(target);
        fs::remove_dir_all(&original).unwrap();
        symlink(&stolen, &original).unwrap();

        let stderr = run_failure(
            database
                .command()
                .args(["create", "people", "ada", "--set", "name=Ada"]),
        );
        assert!(stderr.contains("symbolic link"), "{target}: {stderr}");
        assert!(
            fs::read_dir(&stolen).unwrap().next().is_none(),
            "{target}: an audit file was written outside the database"
        );
    }
}

/// View, schema, and sync configuration directories are refused the same way,
/// on the listing path and the creation path.
#[test]
fn configuration_directories_cannot_be_redirected() {
    let database = TestDatabase::new("linked-config");
    let parent = database.root.parent().unwrap().to_path_buf();
    let stolen = parent.join("stolen");
    fs::create_dir_all(&stolen).unwrap();
    fs::write(stolen.join("secret.yaml"), "version: 1\n").unwrap();

    for (directory, arguments) in [
        (
            ".cr/views",
            vec!["view", "create", "board", "--collection", "deals"],
        ),
        (
            ".cr/syncs",
            vec!["sync", "create", "feed", "--", "/bin/true"],
        ),
    ] {
        let original = database.root.join(directory);
        fs::remove_dir_all(&original).unwrap();
        symlink(&stolen, &original).unwrap();

        let stderr = run_failure(database.command().args(&arguments));
        assert!(stderr.contains("symbolic link"), "{directory}: {stderr}");
        fs::remove_file(&original).unwrap();
        fs::create_dir_all(&original).unwrap();
    }

    // Schemas are consulted by every listing and every write.
    let schemas = database.root.join(".cr/schemas");
    fs::remove_dir_all(&schemas).unwrap();
    symlink(&stolen, &schemas).unwrap();
    let stderr = run_failure(database.command().args(["view", "list"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");
    let stderr = run_failure(
        database
            .command()
            .args(["create", "deals", "one", "--set", "name=One"]),
    );
    assert!(stderr.contains("symbolic link"), "{stderr}");
    assert_eq!(fs::read_dir(&stolen).unwrap().count(), 1);
}

/// A single collection's JSON Schema is replaced by a link to a file outside
/// the database, which is read on every create and update.
#[test]
fn a_symlinked_collection_schema_is_refused_before_validation() {
    let database = TestDatabase::new("linked-schema");
    let parent = database.root.parent().unwrap().to_path_buf();
    let outside = parent.join("secret.json");
    fs::write(&outside, "{\"type\":\"object\"}").unwrap();
    symlink(&outside, database.root.join(".cr/schemas/deals.json")).unwrap();

    let stderr = run_failure(
        database
            .command()
            .args(["create", "deals", "one", "--set", "name=One"]),
    );
    assert!(stderr.contains("symbolic link"), "{stderr}");

    // Accepting a direct edit validates against the same schema.
    fs::create_dir_all(database.root.join("records/deals")).unwrap();
    fs::write(
        database.root.join("records/deals/two.md"),
        "---\nname: Two\n---\n",
    )
    .unwrap();
    let stderr = run_failure(database.command().args(["save", "deals/two"]));
    assert!(stderr.contains("symbolic link"), "{stderr}");

    // Listings keep ignoring entries that are not regular files, as they
    // already do for records, so the linked schema is never opened at all.
    run_success(database.command().args(["view", "list"]));
}

/// A discovered database whose root is reached through a link still works:
/// the root is resolved once, and only components beneath it are constrained.
#[test]
fn a_linked_database_root_remains_usable() {
    let temporary = tempfile::tempdir().unwrap();
    let real = temporary.path().join("real");
    run_success(Command::new(common::binary()).arg("init").arg(&real));
    let alias = temporary.path().join("alias");
    symlink(&real, &alias).unwrap();

    run_success(command_for(&alias).args(["create", "deals", "one", "--set", "name=One"]));
    assert!(run_success(command_for(&alias).args(["get", "deals", "one"])).contains("name: One"));
}

/// Over HTTP the same refusals arrive as a classified `409` that names the
/// record, and never a filesystem path or an operating-system error.
#[tokio::test]
async fn http_reports_symlink_refusals_as_conflicts_without_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("http-links")).unwrap();
    let root = database.root().to_path_buf();
    let outside = planted_target(temporary.path());
    fs::remove_dir_all(root.join("records")).unwrap();
    symlink(&outside, root.join("records")).unwrap();

    let app = router(database, ServerConfig::default()).unwrap();
    for uri in [
        "/api/v1/collections/people/records",
        "/api/v1/collections/people/records/ada",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{uri}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        let payload: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(payload["error"]["code"], "conflict", "{uri}");
        let message = payload["error"]["message"].as_str().unwrap();
        assert!(message.contains("symbolic link"), "{uri}: {message}");
        assert!(
            !text.contains(root.to_str().unwrap()),
            "{uri} leaked a path"
        );
        assert!(!text.contains("os error"), "{uri} leaked an OS error");
        assert!(!text.contains("Do not read me"), "{uri} leaked content");
    }
    assert_untouched(&outside);
}
