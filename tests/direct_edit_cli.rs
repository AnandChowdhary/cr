mod common;

use std::{fs, process::Command};

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

fn json_output(database: &TestDatabase, arguments: &[&str]) -> Value {
    let output = run_success(database.command().args(arguments));
    serde_json::from_str(&output).unwrap()
}

#[test]
fn direct_edit_stays_dirty_until_an_explicit_attributed_save() {
    let database = TestDatabase::new("direct-edit");
    run_success(database.command().args([
        "create",
        "candidates",
        "jane",
        "--set",
        "stage=screening",
    ]));
    let record = database.root.join("records/candidates/jane.md");
    let contents = fs::read_to_string(&record).unwrap();
    fs::write(&record, contents.replace("screening", "interview")).unwrap();

    assert_eq!(
        run_success(database.command().arg("status")),
        "M candidates/jane\n"
    );
    assert!(
        run_failure(database.command().args(["audit", "verify"]))
            .contains("does not match its latest audited state")
    );

    let saved = run_success(database.command().args([
        "--actor",
        "Jane Doe <jane@example.com>",
        "save",
        "candidates/jane",
        "--message",
        "Move candidate to interview",
    ]));
    assert!(saved.contains("Saved update candidates/jane as audit event 2"));
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    run_success(database.command().args(["audit", "verify"]));

    let entries = json_output(&database, &["audit", "log", "candidates", "jane", "--json"]);
    assert_eq!(entries[0]["version"], 3);
    assert_eq!(entries[0]["source"], "filesystem");
    assert_eq!(entries[0]["actor"], "Jane Doe <jane@example.com>");
    assert_eq!(entries[0]["message"], "Move candidate to interview");
    assert_eq!(entries[0]["action"], "update");
    assert_eq!(entries[0]["changes"][0]["operation"], "replace");
    assert_eq!(entries[0]["changes"][0]["path"], "/attributes/stage");
    assert_eq!(entries[0]["changes"][0]["before"], "screening");
    assert_eq!(entries[0]["changes"][0]["after"], "interview");
    assert_eq!(entries[1]["source"], "cli");
}

#[test]
fn save_all_records_direct_additions_and_deletions_with_a_replayed_tombstone() {
    let database = TestDatabase::new("direct-add-delete");
    run_success(database.command().args([
        "create",
        "items",
        "old",
        "--set",
        "stage=draft",
        "--body",
        "Original notes\n",
    ]));
    run_success(
        database
            .command()
            .args(["update", "items", "old", "--set", "stage=active"]),
    );
    fs::remove_file(database.root.join("records/items/old.md")).unwrap();
    fs::write(
        database.root.join("records/items/new.md"),
        "---\nstage: imported\n---\nNew notes\n",
    )
    .unwrap();

    let status = json_output(&database, &["status", "--json"]);
    assert_eq!(status.as_array().unwrap().len(), 2);
    assert_eq!(status[0]["status"], "added");
    assert_eq!(status[0]["id"], "new");
    assert!(status[0]["audited_hash"].is_null());
    assert_eq!(status[1]["status"], "deleted");
    assert_eq!(status[1]["id"], "old");
    assert!(status[1]["current_hash"].is_null());

    let entries = json_output(
        &database,
        &[
            "--actor",
            "editor@example.com",
            "save",
            "--all",
            "--message",
            "Import filesystem changes",
            "--json",
        ],
    );
    assert_eq!(entries.as_array().unwrap().len(), 2);
    assert_eq!(entries[0]["action"], "create");
    assert_eq!(entries[0]["record"]["id"], "new");
    assert_eq!(entries[1]["action"], "delete");
    assert_eq!(entries[1]["record"]["id"], "old");
    assert_eq!(
        entries[1]["changes"][0]["before"]["attributes"]["stage"],
        "active"
    );
    assert_eq!(
        entries[1]["changes"][0]["before"]["body"],
        "Original notes\n"
    );
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn save_all_preflights_every_schema_before_recording_any_event() {
    let database = TestDatabase::new("direct-preflight");
    fs::write(
        database.root.join(".cr/schemas/items.json"),
        r#"{
  "type": "object",
  "properties": { "stage": { "enum": ["screening", "interview"] } },
  "required": ["stage"]
}"#,
    )
    .unwrap();
    for id in ["one", "two"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
    }
    let head = json_output(&database, &["audit", "head", "--json"]);
    for (id, stage) in [("one", "interview"), ("two", "offer")] {
        let path = database.root.join(format!("records/items/{id}.md"));
        let contents = fs::read_to_string(&path).unwrap();
        fs::write(path, contents.replace("screening", stage)).unwrap();
    }

    let error = run_failure(database.command().args(["save", "--all"]));
    assert!(error.contains("does not match schema"));
    assert_eq!(json_output(&database, &["audit", "head", "--json"]), head);
    assert_eq!(
        json_output(&database, &["status", "--json"])
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let path = database.root.join("records/items/two.md");
    let contents = fs::read_to_string(&path).unwrap();
    fs::write(path, contents.replace("offer", "interview")).unwrap();
    run_success(database.command().args(["save", "--all"]));
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn replay_and_save_preserve_null_and_format_only_changes() {
    let database = TestDatabase::new("direct-null");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "value=null"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "value=ready"]),
    );
    let path = database.root.join("records/items/one.md");
    fs::write(&path, "---\nvalue: null\n---\n").unwrap();
    run_success(database.command().args(["save", "items/one"]));

    let entries = json_output(&database, &["audit", "log", "items", "one", "--json"]);
    assert_eq!(entries[0]["changes"][0]["operation"], "replace");
    assert_eq!(entries[0]["changes"][0]["before"], "ready");
    assert!(entries[0]["changes"][0]["after"].is_null());
    run_success(database.command().args(["audit", "verify"]));

    fs::write(&path, "---\nvalue: ~\n---\n").unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "M items/one\n"
    );
    let entry = json_output(&database, &["save", "items/one", "--json"]);
    assert!(entry[0]["changes"].as_array().unwrap().is_empty());
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn selective_save_leaves_other_changes_dirty_and_rejects_invalid_selections() {
    let database = TestDatabase::new("direct-selective");
    for id in ["one", "two"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "status=old"]),
        );
        let path = database.root.join(format!("records/items/{id}.md"));
        let contents = fs::read_to_string(&path).unwrap();
        fs::write(path, contents.replace("old", "new")).unwrap();
    }

    run_success(database.command().args(["save", "items/one"]));
    assert_eq!(
        run_success(database.command().arg("status")),
        "M items/two\n"
    );
    assert!(
        run_failure(database.command().args(["save", "items/one"]))
            .contains("has no unsaved changes")
    );
    assert!(run_failure(database.command().arg("save")).contains("provide at least one"));
    assert!(
        run_failure(database.command().args(["save", "invalid"])).contains("must be COLLECTION/ID")
    );
    assert!(
        run_failure(database.command().args(["save", "items/two", "--all"]))
            .contains("cannot be used with")
    );

    run_success(database.command().args(["save", "--all"]));
    assert_eq!(
        run_success(database.command().args(["save", "--all"])),
        "No changes to save\n"
    );
}

#[test]
fn malformed_files_are_visible_but_cannot_be_saved_or_partially_trusted() {
    let database = TestDatabase::new("direct-malformed");
    fs::create_dir_all(database.root.join("records/items")).unwrap();
    fs::write(
        database.root.join("records/items/broken.md"),
        "not front matter\n",
    )
    .unwrap();
    assert_eq!(
        run_success(database.command().arg("status")),
        "A items/broken\n"
    );
    let head = json_output(&database, &["audit", "head", "--json"]);
    assert!(
        run_failure(database.command().args(["save", "items/broken"]))
            .contains("must begin with a YAML front matter delimiter")
    );
    assert_eq!(json_output(&database, &["audit", "head", "--json"]), head);

    fs::write(
        database.root.join("records/items/broken.md"),
        "---\nstatus: repaired\n---\n",
    )
    .unwrap();
    run_success(database.command().args(["save", "items/broken"]));
    run_success(database.command().args(["audit", "verify"]));

    let segment = database
        .root
        .join(".cr/audit/segments/00000000000000000001.jsonl");
    let log = fs::read_to_string(&segment).unwrap();
    fs::write(
        segment,
        log.replace("\"action\":\"create\"", "\"action\":\"update\""),
    )
    .unwrap();
    assert!(run_failure(database.command().arg("status")).contains("audit event hash mismatch"));
    assert!(
        run_failure(database.command().args(["save", "--all"]))
            .contains("audit event hash mismatch")
    );
}

#[test]
fn identity_resolution_prefers_cr_then_git_author_then_repository_config() {
    let database = TestDatabase::new("identity");

    let mut cr_actor = database.command();
    cr_actor
        .env("CR_ACTOR", "cr@example.com")
        .env("CR_EMAIL", "ignored@example.com")
        .arg("identity");
    assert_eq!(run_success(&mut cr_actor), "cr@example.com\n");

    let mut cr_email = database.command();
    cr_email
        .env_remove("CR_ACTOR")
        .env("CR_NAME", "Casey")
        .env("CR_EMAIL", "casey@example.com")
        .arg("identity");
    assert_eq!(run_success(&mut cr_email), "Casey <casey@example.com>\n");

    let mut git_author = database.command();
    git_author
        .env_remove("CR_ACTOR")
        .env_remove("CR_NAME")
        .env_remove("CR_EMAIL")
        .env("GIT_AUTHOR_NAME", "Git Author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .args(["identity", "--json"]);
    assert_eq!(
        serde_json::from_str::<Value>(&run_success(&mut git_author)).unwrap()["actor"],
        "Git Author <author@example.com>"
    );

    run_success(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(&database.root),
    );
    run_success(
        Command::new("git")
            .args(["config", "user.name", "Repository User"])
            .current_dir(&database.root),
    );
    run_success(
        Command::new("git")
            .args(["config", "user.email", "repository@example.com"])
            .current_dir(&database.root),
    );
    let mut git_config = database.command();
    for variable in [
        "CR_ACTOR",
        "CR_NAME",
        "CR_EMAIL",
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "EMAIL",
    ] {
        git_config.env_remove(variable);
    }
    git_config.arg("identity");
    assert_eq!(
        run_success(&mut git_config),
        "Repository User <repository@example.com>\n"
    );

    assert!(
        run_failure(database.command().args(["--actor", "", "identity"]))
            .contains("audit actor cannot be empty")
    );
    assert_eq!(
        run_success(
            database
                .command()
                .args(["--actor", "override@example.com", "identity"])
        ),
        "override@example.com\n"
    );
}
