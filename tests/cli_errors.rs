mod common;

use std::fs;

use common::{TestDatabase, run_failure, run_success};

#[test]
fn duplicate_create_never_overwrites_the_existing_record() {
    let database = TestDatabase::new("duplicate-create");
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
        "--body",
        "Original notes\n",
    ]));
    let path = database.root.join("records/candidates/jane.md");
    let before = fs::read_to_string(&path).unwrap();

    let stderr = run_failure(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=offer",
        "--body",
        "Replacement notes\n",
    ]));

    assert!(stderr.contains("already exists"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[test]
fn repeated_init_does_not_modify_an_existing_configless_database() {
    let database = TestDatabase::new("duplicate-init");
    let config = database.root.join(".cr/config.yaml");
    let marker = database.root.join(".cr/keep");
    fs::write(&marker, "unchanged").unwrap();
    assert!(!config.exists());

    let stderr = run_failure(
        std::process::Command::new(common::binary())
            .arg("init")
            .arg(&database.root),
    );

    assert!(stderr.contains("a database already exists"));
    assert!(!config.exists());
    assert_eq!(fs::read_to_string(marker).unwrap(), "unchanged");
}

#[test]
fn an_explicit_directory_without_a_cr_marker_is_not_a_database() {
    let temporary = tempfile::tempdir().unwrap();
    let stderr = run_failure(
        std::process::Command::new(common::binary())
            .arg("--database")
            .arg(temporary.path())
            .args(["list", "items"]),
    );

    assert!(stderr.contains("no database found at"));
    assert!(!temporary.path().join(".cr").exists());
}

#[test]
fn failed_nested_update_never_changes_the_record() {
    let database = TestDatabase::new("failed-update");
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "contact=unknown",
    ]));
    let path = database.root.join("records/candidates/jane.md");
    let before = fs::read_to_string(&path).unwrap();

    let stderr = run_failure(database.command().args([
        "update",
        "candidates",
        "jane",
        "--set",
        "contact.email=jane@example.com",
    ]));

    assert!(stderr.contains("below non-object"));
    assert_eq!(fs::read_to_string(path).unwrap(), before);
}

#[test]
fn missing_records_and_relation_targets_return_errors() {
    let database = TestDatabase::new("missing-records");

    let stderr = run_failure(database.command().args(["get", "candidates", "missing"]));
    assert!(stderr.contains("could not read record"));

    let stderr = run_failure(database.command().args([
        "update",
        "candidates",
        "missing",
        "--set",
        "stage=offer",
    ]));
    assert!(stderr.contains("could not read record"));

    run_success(database.command().args(["create", "candidates", "jane"]));
    let stderr = run_failure(database.command().args([
        "link",
        "candidates",
        "jane",
        "company",
        "companies",
        "missing",
    ]));
    assert!(stderr.contains("relation target companies/missing does not exist"));
}

#[test]
fn malformed_and_unsupported_configs_are_rejected() {
    let malformed = TestDatabase::new("malformed-config");
    fs::write(malformed.root.join(".cr/config.yaml"), "version: [\n").unwrap();
    let stderr = run_failure(malformed.command().args(["list", "candidates"]));
    assert!(stderr.contains("is not valid YAML"));

    let unsupported = TestDatabase::new("unsupported-config");
    fs::write(
        unsupported.root.join(".cr/config.yaml"),
        "version: 99\ndata_dir: records\n",
    )
    .unwrap();
    let stderr = run_failure(unsupported.command().args(["list", "candidates"]));
    assert!(stderr.contains("format version 99 is unsupported"));

    let escaping = TestDatabase::new("escaping-config");
    fs::write(
        escaping.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: ../outside\n",
    )
    .unwrap();
    let stderr = run_failure(escaping.command().args(["list", "candidates"]));
    assert!(stderr.contains("data_dir must be a relative path"));

    let invalid_audit = TestDatabase::new("invalid-audit-config");
    fs::write(
        invalid_audit.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\naudit:\n  segment_max_events: 0\n",
    )
    .unwrap();
    let stderr = run_failure(invalid_audit.command().args(["list", "candidates"]));
    assert!(stderr.contains("audit.segment_max_events must be greater than zero"));
}

#[test]
fn malformed_json_and_invalid_json_schemas_block_creation() {
    let database = TestDatabase::new("invalid-schema");
    let schema = database.root.join(".cr/schemas/candidates.json");
    let record = database.root.join("records/candidates/jane.md");

    fs::write(&schema, "{").unwrap();
    let stderr = run_failure(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
    ]));
    assert!(stderr.contains("is not valid JSON"));
    assert!(!record.exists());

    fs::write(&schema, r#"{ "type": "not-a-real-type" }"#).unwrap();
    let stderr = run_failure(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
    ]));
    assert!(stderr.contains("invalid JSON Schema"));
    assert!(!record.exists());
}

#[test]
fn malformed_markdown_is_reported_by_get_and_list() {
    let database = TestDatabase::new("malformed-markdown");
    let collection = database.root.join("records/candidates");
    fs::create_dir_all(&collection).unwrap();
    fs::write(collection.join("jane.md"), "# Missing front matter\n").unwrap();

    let stderr = run_failure(database.command().args(["get", "candidates", "jane"]));
    assert!(stderr.contains("must begin with a YAML front matter delimiter"));

    let stderr = run_failure(database.command().args(["list", "candidates"]));
    assert!(stderr.contains("could not parse"));
}

#[test]
fn path_traversal_and_invalid_assignments_are_rejected() {
    let database = TestDatabase::new("invalid-input");

    for arguments in [
        vec!["create", "../outside", "jane"],
        vec!["create", "candidates", "../outside"],
        vec!["create", "candidates", "jane", "--set", "stage"],
        vec!["create", "candidates", "jane", "--set", "=interview"],
        vec!["create", "candidates", "jane", "--set", "contact..email=x"],
        vec!["create", "candidates", "jane", "--set", "tags=["],
    ] {
        run_failure(database.command().args(arguments));
    }

    let expression_error =
        run_failure(
            database
                .command()
                .args(["list", "candidates", "--where-expr", "score"]),
        );
    assert!(expression_error.contains("expected a filter expression"));

    let sort_error = run_failure(database.command().args(["list", "candidates", "--desc"]));
    assert!(sort_error.contains("--sort <FIELD>"));
    assert!(sort_error.contains("required"));

    assert!(!database.root.join("outside.md").exists());
    assert!(!database.root.join("records/candidates/jane.md").exists());
}

#[test]
fn empty_updates_and_missing_fields_return_errors() {
    let database = TestDatabase::new("empty-update");
    run_success(database.command().args(["create", "candidates", "jane"]));

    let stderr = run_failure(database.command().args(["update", "candidates", "jane"]));
    assert!(stderr.contains("provide at least one --set or --body value"));

    let stderr =
        run_failure(
            database
                .command()
                .args(["get", "candidates", "jane", "--field", "missing"]),
        );
    assert!(stderr.contains("field 'missing' does not exist"));
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_record_names_are_reported_instead_of_silently_ignored() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let database = TestDatabase::new("non-utf8-name");
    let collection = database.root.join("records/items");
    fs::create_dir_all(&collection).unwrap();
    let name = OsString::from_vec(b"invalid-\xff.md".to_vec());
    fs::write(collection.join(name), "---\nname: hidden\n---\n").unwrap();

    let stderr = run_failure(database.command().args(["list", "items"]));
    assert!(stderr.contains("not valid UTF-8"));
}

/// The `..md` file from the P1 report, and every command that has to agree
/// about it.
///
/// Three enumeration paths used to disagree three ways on this exact database:
/// `list` never checked the stem and returned the file as a record with exit
/// 0, `record_files` refused the whole database with `id must be a non-empty
/// path component`, and the audit log's own walk invented a record called
/// `deals/.` and reported it as unaudited. None of the refusals said which
/// file or which collection, so nobody could save an edit to the healthy
/// record beside it without first finding the bad file themselves.
#[test]
fn one_unusable_record_filename_is_refused_by_name_by_every_command() {
    let database = TestDatabase::new("unusable-record-name");
    run_success(database.command().args(["create", "deals", "acme"]));
    fs::write(
        database.root.join("records/deals/..md"),
        "---\nvalue: 1\n---\n",
    )
    .unwrap();

    let root = database.root.to_string_lossy().to_string();
    for arguments in [
        vec!["list", "deals"],
        vec!["status"],
        vec!["save", "--all"],
        vec!["search", "acme"],
        vec!["audit", "verify"],
        vec!["audit", "baseline"],
    ] {
        let command = arguments.join(" ");
        let stderr = run_failure(database.command().args(&arguments));
        assert!(
            stderr.contains("collection 'deals'"),
            "cr {command} did not name the collection: {stderr}"
        );
        assert!(
            stderr.contains("'..md'"),
            "cr {command} did not name the file: {stderr}"
        );
        assert!(
            stderr.contains("cannot be a record ID"),
            "cr {command} disagreed about what is wrong: {stderr}"
        );
        // Naming the file is what makes the refusal actionable; naming where
        // it lives would break the invariant that a caller-facing message is
        // safe to return over HTTP.
        assert!(
            !stderr.contains(&root) && !stderr.contains("records/deals"),
            "cr {command} leaked a filesystem path: {stderr}"
        );
    }

    // Naming a record directly never enumerates its collection, so the healthy
    // record beside the bad file stays readable.
    run_success(database.command().args(["get", "deals", "acme"]));

    // And deleting the one file named in the refusal is the whole repair.
    fs::remove_file(database.root.join("records/deals/..md")).unwrap();
    assert_eq!(
        run_success(database.command().args(["list", "deals"])).trim(),
        "records/deals/acme.md"
    );
    run_success(database.command().args(["audit", "verify"]));
    run_success(database.command().args(["status"]));
}

/// The collection half of the same split. A directory cannot be called `.` or
/// `..` — the kernel refuses — but a backslash is an ordinary character in a
/// POSIX filename and a path separator to `validate_component`, so `a\b` is a
/// directory name that exists and cannot be a collection.
#[cfg(unix)]
#[test]
fn an_unusable_collection_directory_name_is_refused_by_name() {
    let database = TestDatabase::new("unusable-collection-name");
    run_success(database.command().args(["create", "deals", "acme"]));
    fs::create_dir(database.root.join("records").join("a\\b")).unwrap();

    let root = database.root.to_string_lossy().to_string();
    for arguments in [
        vec!["status"],
        vec!["search", "acme"],
        vec!["audit", "verify"],
    ] {
        let command = arguments.join(" ");
        let stderr = run_failure(database.command().args(&arguments));
        assert!(
            stderr.contains("named 'a\\b'") && stderr.contains("cannot be a collection"),
            "cr {command} did not name the directory: {stderr}"
        );
        assert!(
            !stderr.contains(&root),
            "cr {command} leaked a filesystem path: {stderr}"
        );
    }
}
