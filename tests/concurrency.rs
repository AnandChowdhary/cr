mod common;

use std::{fs, process::Stdio};

use common::{run_success, TestDatabase};
use serde_json::Value;

#[test]
fn concurrent_single_record_updates_never_publish_a_torn_file() {
    let database = TestDatabase::new("concurrent-updates");
    run_success(database.command().args([
        "create",
        "items",
        "shared",
        "--set",
        "writer=0",
        "--body",
        "# Shared\n\nBody must remain intact.\n",
    ]));

    let mut children = Vec::new();
    for writer in 1..=12 {
        let assignment = format!("writer={writer}");
        let child = database
            .command()
            .args(["update", "items", "shared", "--set", &assignment])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        children.push(child);
    }

    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "concurrent update failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let fetched = run_success(
        database
            .command()
            .args(["get", "items", "shared", "--json"]),
    );
    let fetched: Value = serde_json::from_str(&fetched).unwrap();
    let writer = fetched["attributes"]["writer"].as_u64().unwrap();
    assert!((1..=12).contains(&writer));
    assert_eq!(fetched["body"], "# Shared\n\nBody must remain intact.\n");

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 13 audit events"));
}

#[test]
fn concurrent_saves_of_distinct_manual_edits_serialize_into_one_valid_chain() {
    let database = TestDatabase::new("concurrent-saves");
    for id in ["one", "two"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
        let path = database.root.join(format!("records/items/{id}.md"));
        let contents = fs::read_to_string(&path).unwrap();
        fs::write(path, contents.replace("screening", "interview")).unwrap();
    }

    let mut children = Vec::new();
    for id in ["one", "two"] {
        let reference = format!("items/{id}");
        children.push(
            database
                .command()
                .args(["--actor", id, "save", &reference])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "concurrent save failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 4 audit events"));
    let log = run_success(database.command().args(["audit", "log", "--json"]));
    let log: Value = serde_json::from_str(&log).unwrap();
    assert_eq!(log[0]["source"], "filesystem");
    assert_eq!(log[1]["source"], "filesystem");
    assert_ne!(log[0]["actor"], log[1]["actor"]);
}
