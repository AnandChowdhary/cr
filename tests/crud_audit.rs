mod common;

use std::fs;

use common::{run_failure, run_success, TestDatabase};
use serde_json::Value;

fn json_output(database: &TestDatabase, arguments: &[&str]) -> Value {
    let output = run_success(database.command().args(arguments));
    serde_json::from_str(&output).unwrap()
}

fn audit_head(database: &TestDatabase) -> Value {
    json_output(database, &["audit", "head", "--json"])
}

#[test]
fn cli_crud_reads_are_audit_neutral_and_mutations_form_one_history() {
    let database = TestDatabase::new("cli-crud-audit");
    run_success(database.command().args([
        "--actor",
        "creator@example.com",
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
        "--body",
        "Candidate notes\n",
    ]));
    let after_create = audit_head(&database);
    assert_eq!(after_create["sequence"], 1);

    let fetched = json_output(&database, &["get", "candidates", "jane", "--json"]);
    assert_eq!(fetched["attributes"]["stage"], "screening");
    assert_eq!(fetched["body"], "Candidate notes\n");
    assert_eq!(
        run_success(
            database
                .command()
                .args(["get", "candidates", "jane", "--field", "stage",])
        )
        .trim(),
        "screening"
    );
    assert_eq!(
        json_output(
            &database,
            &["list", "candidates", "--where", "stage=screening", "--json"],
        )
        .as_array()
        .unwrap()
        .len(),
        1
    );
    assert_eq!(audit_head(&database), after_create);

    run_success(database.command().args([
        "--actor",
        "recruiter@example.com",
        "update",
        "candidates",
        "jane",
        "--set",
        "stage=interview",
    ]));
    let after_update = audit_head(&database);
    assert_eq!(after_update["sequence"], 2);
    assert_eq!(
        json_output(&database, &["get", "candidates", "jane", "--json"])["attributes"]["stage"],
        "interview"
    );
    assert_eq!(audit_head(&database), after_update);

    run_success(database.command().args([
        "--actor",
        "admin@example.com",
        "delete",
        "candidates",
        "jane",
        "--yes",
    ]));
    assert!(
        run_failure(database.command().args(["get", "candidates", "jane"]))
            .contains("could not read record")
    );
    assert!(json_output(&database, &["list", "candidates", "--json"])
        .as_array()
        .unwrap()
        .is_empty());
    let after_delete = audit_head(&database);
    assert_eq!(after_delete["sequence"], 3);

    let entries = json_output(&database, &["audit", "log", "candidates", "jane", "--json"]);
    assert_eq!(entries.as_array().unwrap().len(), 3);
    assert_eq!(entries[0]["action"], "delete");
    assert_eq!(entries[0]["actor"], "admin@example.com");
    assert_eq!(entries[1]["action"], "update");
    assert_eq!(entries[1]["actor"], "recruiter@example.com");
    assert_eq!(entries[2]["action"], "create");
    assert_eq!(entries[2]["actor"], "creator@example.com");
    assert!(entries
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["source"] == "cli"));
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn manual_markdown_crud_is_readable_while_dirty_and_fully_auditable_after_save() {
    let database = TestDatabase::new("manual-crud-audit");
    let collection = database.root.join("records/candidates");
    fs::create_dir_all(&collection).unwrap();
    let record = collection.join("jane.md");
    fs::write(
        &record,
        "---\nname: Jane\nstage: screening\n---\nInitial notes\n",
    )
    .unwrap();

    assert_eq!(
        run_success(database.command().arg("status")),
        "A candidates/jane\n"
    );
    assert_eq!(
        json_output(&database, &["get", "candidates", "jane", "--json"])["attributes"]["stage"],
        "screening"
    );
    assert_eq!(
        run_success(database.command().args(["list", "candidates"])),
        "candidates/jane\n"
    );
    assert_eq!(audit_head(&database)["sequence"], 0);
    run_success(database.command().args([
        "--actor",
        "author@example.com",
        "save",
        "candidates/jane",
        "--message",
        "Create in editor",
    ]));

    let contents = fs::read_to_string(&record).unwrap();
    fs::write(&record, contents.replace("screening", "interview")).unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "M candidates/jane\n"
    );
    assert_eq!(
        run_success(
            database
                .command()
                .args(["get", "candidates", "jane", "--field", "stage",])
        )
        .trim(),
        "interview"
    );
    assert_eq!(
        json_output(
            &database,
            &["list", "candidates", "--where", "stage=interview", "--json"],
        )
        .as_array()
        .unwrap()
        .len(),
        1
    );
    assert!(run_failure(database.command().args(["audit", "verify"]))
        .contains("does not match its latest audited state"));
    assert_eq!(audit_head(&database)["sequence"], 1);
    run_success(database.command().args([
        "--actor",
        "editor@example.com",
        "save",
        "candidates/jane",
        "--message",
        "Update in editor",
    ]));

    fs::remove_file(&record).unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "D candidates/jane\n"
    );
    assert!(
        run_failure(database.command().args(["get", "candidates", "jane"]))
            .contains("could not read record")
    );
    assert!(json_output(&database, &["list", "candidates", "--json"])
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(audit_head(&database)["sequence"], 2);
    run_success(database.command().args([
        "--actor",
        "admin@example.com",
        "save",
        "candidates/jane",
        "--message",
        "Delete in editor",
    ]));

    let entries = json_output(&database, &["audit", "log", "candidates", "jane", "--json"]);
    assert_eq!(entries.as_array().unwrap().len(), 3);
    assert_eq!(entries[0]["action"], "delete");
    assert_eq!(entries[0]["message"], "Delete in editor");
    assert_eq!(entries[1]["action"], "update");
    assert_eq!(entries[1]["message"], "Update in editor");
    assert_eq!(entries[2]["action"], "create");
    assert_eq!(entries[2]["message"], "Create in editor");
    assert!(entries
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["source"] == "filesystem"));

    let head = audit_head(&database);
    run_success(database.command().args([
        "audit",
        "verify",
        "--expected-head",
        head["hash"].as_str().unwrap(),
    ]));
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
}

#[test]
fn manual_crud_honors_a_custom_records_directory() {
    let database = TestDatabase::new("manual-custom-directory");
    let config_path = database.root.join(".cr/config.yaml");
    let config = fs::read_to_string(&config_path).unwrap();
    fs::write(
        &config_path,
        config.replace("data_dir: records", "data_dir: content/data"),
    )
    .unwrap();
    let collection = database.root.join("content/data/companies");
    fs::create_dir_all(&collection).unwrap();
    let record = collection.join("acme.md");
    fs::write(&record, "---\nname: Acme\n---\n").unwrap();

    assert_eq!(
        run_success(database.command().arg("status")),
        "A companies/acme\n"
    );
    run_success(database.command().args(["save", "companies/acme"]));
    assert_eq!(
        json_output(&database, &["get", "companies", "acme", "--json"])["path"],
        "content/data/companies/acme.md"
    );

    fs::write(&record, "---\nname: Acme Corp\n---\n").unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "M companies/acme\n"
    );
    run_success(database.command().args(["save", "companies/acme"]));
    fs::remove_file(record).unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "D companies/acme\n"
    );
    run_success(database.command().args(["save", "companies/acme"]));

    let entries = json_output(&database, &["audit", "log", "companies", "acme", "--json"]);
    assert_eq!(entries.as_array().unwrap().len(), 3);
    assert_eq!(entries[0]["action"], "delete");
    assert_eq!(entries[1]["action"], "update");
    assert_eq!(entries[2]["action"], "create");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn failed_and_read_only_crud_commands_never_advance_the_audit_head() {
    let database = TestDatabase::new("crud-failure-audit");
    run_success(database.command().args(["create", "items", "one"]));
    let head = audit_head(&database);

    run_failure(database.command().args(["get", "items", "missing"]));
    run_success(database.command().args(["list", "missing"]));
    run_failure(
        database
            .command()
            .args(["update", "items", "missing", "--set", "stage=active"]),
    );
    run_failure(
        database
            .command()
            .args(["delete", "items", "missing", "--yes"]),
    );
    run_failure(
        database
            .command()
            .args(["link", "items", "one", "owner", "people", "missing"]),
    );

    assert_eq!(audit_head(&database), head);
    run_success(database.command().args(["audit", "verify"]));
}

#[cfg(unix)]
#[test]
fn symlinked_markdown_paths_are_never_treated_as_audited_records() {
    use std::os::unix::fs::symlink;

    let database = TestDatabase::new("symlink-integrity");
    let collection = database.root.join("records/items");
    fs::create_dir_all(&collection).unwrap();
    let outside = database.root.join("outside.md");
    fs::write(&outside, "---\nname: Outside\n---\n").unwrap();
    let untracked_link = collection.join("alias.md");
    symlink(&outside, &untracked_link).unwrap();

    assert!(run_failure(database.command().arg("status")).contains("must be a regular file"));
    assert!(run_failure(database.command().args(["audit", "verify"]))
        .contains("must be a regular file"));
    fs::remove_file(untracked_link).unwrap();

    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "name=One"]),
    );
    let record = collection.join("one.md");
    let original = fs::read_to_string(&record).unwrap();
    fs::write(&outside, original).unwrap();
    fs::remove_file(&record).unwrap();
    symlink(&outside, &record).unwrap();

    for arguments in [
        vec!["status"],
        vec!["audit", "verify"],
        vec!["get", "items", "one"],
        vec!["update", "items", "one", "--set", "name=Changed"],
        vec!["delete", "items", "one", "--yes"],
        vec!["save", "items/one"],
    ] {
        assert!(run_failure(database.command().args(arguments)).contains("must be a regular file"));
    }
    assert_eq!(audit_head(&database)["sequence"], 1);
}
