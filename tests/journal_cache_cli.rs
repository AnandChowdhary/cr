//! A CLI command resumes the walk of the journal the last write saved, and
//! still notices when the journal is forged.
//!
//! Every read of a plaintext collection needs audited state, and verifying it
//! from the first event made each `cr get` cost more with every write ever made.
//! A write now saves its verified walk under `.cr/cache/`, and the next command
//! verifies only what was appended since. These tests hold the CLI to what that
//! must not cost: a read still writes nothing, a forged segment is still
//! refused, and `--verify-audit` still walks from the first event.
//!
//! What the saved walk trusts, and what never uses it, is written down beside
//! `JournalCache` in `src/audit.rs`.

mod common;

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use common::{TestDatabase, run_failure, run_success};

const SAVED_WALK: &str = ".cr/cache/verified-journal.json";

/// A database whose journal starts a new segment every two events, with
/// several sealed segments and one still being appended to.
fn seeded(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\naudit:\n  segment_max_events: 2\n",
    )
    .unwrap();
    for index in 0..5 {
        run_success(database.command().args([
            "create",
            "deals",
            &format!("deal-{index}"),
            "--set",
            &format!("value={index}"),
        ]));
    }
    database
}

/// Every file under `.cr/`, as one comparable value.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else if !path.ends_with("audit/lock") {
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                files.insert(relative, fs::read(&path).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, &root.join(".cr"), &mut files);
    files
}

#[test]
fn a_write_saves_its_walk_and_a_read_writes_nothing() {
    let database = seeded("saved-walk");
    assert!(database.root.join(SAVED_WALK).is_file());
    assert_eq!(
        fs::read_to_string(database.root.join(".cr/cache/.gitignore")).unwrap(),
        "*\n"
    );

    let before = snapshot(&database.root);
    let resumed = run_success(
        database
            .command()
            .args(["get", "deals", "deal-3", "--json"]),
    );
    run_success(database.command().args(["list", "deals"]));
    run_success(
        database
            .command()
            .args(["update", "deals", "deal-3", "--set", "value=9"])
            .arg("--preview"),
    );
    assert_eq!(snapshot(&database.root), before, "a read changed .cr/");

    let verified = run_success(database.command().args([
        "--verify-audit",
        "get",
        "deals",
        "deal-3",
        "--json",
    ]));
    assert_eq!(verified, resumed);
    // A global flag, so it also follows the command.
    run_success(database.command().args(["list", "deals", "--verify-audit"]));
    assert_eq!(snapshot(&database.root), before);
}

#[test]
fn a_read_still_refuses_a_forged_segment_and_recovers_when_it_is_restored() {
    let database = seeded("saved-walk-forged");
    let segments = database.root.join(".cr/audit/segments");
    for (segment, which) in [
        ("00000000000000000001.jsonl", "a sealed segment"),
        ("00000000000000000005.jsonl", "the newest segment"),
    ] {
        let path = segments.join(segment);
        let original = fs::read(&path).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();
        let forged =
            String::from_utf8(original.clone())
                .unwrap()
                .replacen("\"value\"", "\"VALUE\"", 1);
        assert_ne!(forged.as_bytes(), original, "{which}: nothing to forge");
        // A coarse filesystem clock must not give the rewrite the change time
        // of the write before it.
        std::thread::sleep(Duration::from_millis(20));
        let rewrite = |contents: &[u8]| {
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            file.write_all(contents).unwrap();
            file.set_modified(modified).unwrap();
        };
        rewrite(forged.as_bytes());

        for flags in [&[][..], &["--verify-audit"][..]] {
            let error = run_failure(
                database
                    .command()
                    .args(flags)
                    .args(["get", "deals", "deal-0"]),
            );
            assert!(
                error.contains("audit event hash mismatch"),
                "{which} {flags:?}: {error}"
            );
        }

        // A write resumes the saved walk too, and is refused the same way,
        // with nothing written.
        let before = fs::read(database.root.join("records/deals/deal-0.md")).unwrap();
        let error = run_failure(
            database
                .command()
                .args(["update", "deals", "deal-0", "--set", "value=9"]),
        );
        assert!(
            error.contains("audit event hash mismatch"),
            "{which} update: {error}"
        );
        assert_eq!(
            fs::read(database.root.join("records/deals/deal-0.md")).unwrap(),
            before
        );

        rewrite(&original);
        run_success(database.command().args(["get", "deals", "deal-0"]));
    }
}

#[test]
fn a_full_walk_interval_of_zero_is_refused() {
    let database = seeded("saved-walk-interval");
    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\naudit:\n  full_walk_after_events: 0\n",
    )
    .unwrap();
    let error = run_failure(database.command().args(["get", "deals", "deal-0"]));
    assert!(
        error.contains("audit.full_walk_after_events must be greater than zero"),
        "{error}"
    );
}

#[test]
fn a_damaged_saved_walk_is_ignored_rather_than_believed() {
    let database = seeded("saved-walk-damaged");
    let expected = run_success(
        database
            .command()
            .args(["get", "deals", "deal-2", "--json"]),
    );
    for damaged in [&b""[..], b"{", b"{\"version\":1}\n", b"not json at all"] {
        fs::write(database.root.join(SAVED_WALK), damaged).unwrap();
        let actual = run_success(
            database
                .command()
                .args(["get", "deals", "deal-2", "--json"]),
        );
        assert_eq!(actual, expected);
    }

    // The next write replaces it with a walk it verified itself.
    run_success(
        database
            .command()
            .args(["update", "deals", "deal-2", "--set", "value=7"]),
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&fs::read(database.root.join(SAVED_WALK)).unwrap()).unwrap();
    assert_eq!(saved["version"], 2);
    assert_eq!(saved["cr"], env!("CARGO_PKG_VERSION"));
}
