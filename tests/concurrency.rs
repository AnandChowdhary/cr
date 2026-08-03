mod common;

use std::process::Stdio;

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
