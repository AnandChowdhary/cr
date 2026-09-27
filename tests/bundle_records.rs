//! Bundle records: a Markdown entry plus the supporting files in its folder.
//!
//! Every test drives the real `cr` binary against a database whose `skills`
//! collection is declared with `layout: bundle`, and checks what reached disk
//! and the journal independently of `cr`'s own reading of either.

mod common;

use std::{fs, path::PathBuf, process::Command};

use common::{
    TestDatabase,
    chain::{event_hash, parse_line, read_chain, reanchor, record_hash, stored_line},
    run_failure, run_success,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const BUNDLES: &str =
    "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n";

fn bundle_database(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    fs::write(database.root.join(".cr/config.yaml"), BUNDLES).unwrap();
    database
}

/// Write `contents` to a scratch file outside the records tree and return it.
fn source(database: &TestDatabase, name: &str, contents: &[u8]) -> String {
    let directory = database.root.join("sources");
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(name);
    fs::write(&path, contents).unwrap();
    path.display().to_string()
}

fn folder(database: &TestDatabase, id: &str) -> PathBuf {
    database.root.join("records/skills").join(id)
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn sha256(contents: &[u8]) -> String {
    let mut value = String::from("sha256:");
    for byte in Sha256::digest(contents) {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

/// Bytes no UTF-8 decoder accepts, as a font or an image would be.
const BINARY: &[u8] = &[0x00, 0x01, 0xff, 0xfe, 0x80, 0x81, 0x00, 0x7f];

fn create_skill(database: &TestDatabase, id: &str) -> Value {
    let script = source(database, "run.py", b"print('hi')\n");
    let font = source(database, "font.ttf", BINARY);
    json(database.command().args([
        "create",
        "skills",
        id,
        "--set",
        "name=pdf-forms",
        "--set",
        "description=Fill PDF forms",
        "--body",
        "Run scripts/run.py.\n",
        "--file",
        &format!("scripts/run.py={script}"),
        "--file",
        &format!("fonts/body.ttf={font}"),
        "--json",
    ]))
}

/// What `cr check` printed; it exits 2 when it finds a problem.
fn check_output(database: &TestDatabase) -> String {
    let output = database.command().arg("check").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    String::from_utf8(output.stdout).unwrap()
}

fn last_event(database: &TestDatabase) -> Value {
    read_chain(&database.root).pop().unwrap().parsed
}

#[test]
fn a_bundle_is_a_folder_of_exact_files_audited_in_the_record_s_event() {
    let database = bundle_database("bundle-create");
    let record = create_skill(&database, "pdf");

    // The entry is an ordinary record; every other file is stored byte for
    // byte, with no front matter, so a script stays a script.
    let skill = folder(&database, "pdf");
    let entry = fs::read_to_string(skill.join("SKILL.md")).unwrap();
    assert!(entry.starts_with("---\n"), "{entry}");
    assert_eq!(
        fs::read(skill.join("scripts/run.py")).unwrap(),
        b"print('hi')\n"
    );
    assert_eq!(fs::read(skill.join("fonts/body.ttf")).unwrap(), BINARY);

    assert_eq!(record["path"], "records/skills/pdf/SKILL.md");
    assert_eq!(
        record["files"],
        serde_json::json!([
            { "path": "fonts/body.ttf", "hash": sha256(BINARY) },
            { "path": "scripts/run.py", "hash": sha256(b"print('hi')\n") },
        ])
    );
    assert_ne!(record["version"], record_hash(entry.as_bytes()));

    let event = last_event(&database);
    assert_eq!(event["version"], 4);
    assert_eq!(event["action"], "create");
    assert_eq!(event["after_hash"], record["version"]);
    assert_eq!(
        event["files"],
        serde_json::json!([
            { "operation": "add", "path": "fonts/body.ttf", "after": sha256(BINARY) },
            {
                "operation": "add",
                "path": "scripts/run.py",
                "after": sha256(b"print('hi')\n"),
                "diff": "@@ -0,0 +1 @@\n+print('hi')\n"
            },
        ])
    );

    // A supporting file reads back exactly, and the entry is still the record.
    let output = database
        .command()
        .args(["get", "skills", "pdf", "--file", "fonts/body.ttf"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, BINARY);
    assert_eq!(
        run_success(database.command().args(["get", "skills", "pdf"])),
        entry
    );
    let listed = json(database.command().args(["list", "skills", "--json"]));
    assert_eq!(listed[0]["path"], "records/skills/pdf/SKILL.md");

    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
}

#[test]
fn a_bundle_without_supporting_files_keeps_the_audit_format_older_cr_reads() {
    let database = bundle_database("bundle-plain");
    let record = json(database.command().args([
        "create",
        "skills",
        "plain",
        "--set",
        "name=plain",
        "--json",
    ]));
    let entry = fs::read(folder(&database, "plain").join("SKILL.md")).unwrap();
    assert_eq!(record["version"], record_hash(&entry));
    let event = last_event(&database);
    assert_eq!(event["version"], 3);
    assert!(event.get("files").is_none());
}

#[test]
fn updates_add_replace_and_remove_files_in_one_event_with_diffs_for_text() {
    let database = bundle_database("bundle-update");
    let created = create_skill(&database, "pdf");
    let script = source(&database, "run2.py", b"print('hi')\nprint('bye')\n");
    let reference = source(&database, "api.md", b"# API\n");

    let preview = run_success(database.command().args([
        "update",
        "skills",
        "pdf",
        "--set",
        "description=Fill and sign PDF forms",
        "--file",
        &format!("scripts/run.py={script}"),
        "--file",
        &format!("references/api.md={reference}"),
        "--remove-file",
        "fonts/body.ttf",
        "--preview",
    ]));
    assert!(preview.contains("file remove fonts/body.ttf"), "{preview}");
    assert!(
        preview.contains(" print('hi')\n+print('bye')\n"),
        "{preview}"
    );
    let digest = preview
        .lines()
        .last()
        .unwrap()
        .strip_prefix("digest ")
        .unwrap()
        .to_owned();

    let updated = json(database.command().args([
        "update",
        "skills",
        "pdf",
        "--set",
        "description=Fill and sign PDF forms",
        "--file",
        &format!("scripts/run.py={script}"),
        "--file",
        &format!("references/api.md={reference}"),
        "--remove-file",
        "fonts/body.ttf",
        "--expected-record-hash",
        created["version"].as_str().unwrap(),
        "--authorization",
        "interactive",
        "--approved-changes",
        &digest,
        "--json",
    ]));

    let skill = folder(&database, "pdf");
    assert!(
        !skill.join("fonts").exists(),
        "an emptied folder is removed"
    );
    assert_eq!(
        fs::read(skill.join("references/api.md")).unwrap(),
        b"# API\n"
    );
    let event = last_event(&database);
    assert_eq!(event["action"], "update");
    assert_eq!(event["after_hash"], updated["version"]);
    assert_eq!(event["authorization"]["approved_changes"], digest);
    let files = event["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    assert_eq!(files[0]["path"], "fonts/body.ttf");
    assert_eq!(files[0]["operation"], "remove");
    assert_eq!(files[0]["before"], sha256(BINARY));
    assert!(files[0].get("diff").is_none());
    assert_eq!(files[2]["path"], "scripts/run.py");
    assert_eq!(files[2]["operation"], "replace");
    assert_eq!(
        files[2]["diff"],
        "@@ -1 +1,2 @@\n print('hi')\n+print('bye')\n"
    );
    run_success(database.command().args(["audit", "verify"]));

    // An approval covers the files: the same front matter change with other
    // file contents is refused.
    let other = source(&database, "run3.py", b"print('other')\n");
    let second = run_success(database.command().args([
        "update",
        "skills",
        "pdf",
        "--file",
        &format!("scripts/run.py={other}"),
        "--preview",
    ]));
    let approved = second
        .lines()
        .last()
        .unwrap()
        .strip_prefix("digest ")
        .unwrap();
    let refused = run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--file",
        &format!("references/api.md={other}"),
        "--authorization",
        "interactive",
        "--approved-changes",
        approved,
    ]));
    assert!(
        refused.contains("does not match the approved change set"),
        "{refused}"
    );
}

#[test]
fn the_record_version_covers_every_supporting_file() {
    let database = bundle_database("bundle-version");
    let created = create_skill(&database, "pdf");
    let version = created["version"].as_str().unwrap();

    fs::write(
        folder(&database, "pdf").join("scripts/run.py"),
        b"tampered\n",
    )
    .unwrap();
    let current = json(database.command().args(["get", "skills", "pdf", "--json"]));
    assert_ne!(current["version"], version);

    let stale = run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--set",
        "name=x",
        "--expected-record-hash",
        version,
    ]));
    assert!(
        stale.contains("changed since the expected version"),
        "{stale}"
    );
    let unaudited = run_failure(
        database
            .command()
            .args(["update", "skills", "pdf", "--set", "name=x"]),
    );
    assert!(
        unaudited.contains("does not match its latest audited state"),
        "{unaudited}"
    );
    let verify = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        verify.contains("record skills/pdf does not match its latest audited state"),
        "{verify}"
    );
}

#[test]
fn status_and_save_pick_up_direct_edits_to_supporting_files() {
    let database = bundle_database("bundle-direct");
    create_skill(&database, "pdf");
    let skill = folder(&database, "pdf");
    fs::write(skill.join("scripts/run.py"), b"print('edited')\n").unwrap();
    fs::remove_file(skill.join("fonts/body.ttf")).unwrap();
    fs::create_dir_all(skill.join("references")).unwrap();
    fs::write(skill.join("references/api.md"), b"# API\n").unwrap();

    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "M skills/pdf"
    );
    run_success(
        database
            .command()
            .args(["save", "skills/pdf", "-m", "edited by hand"]),
    );
    let event = last_event(&database);
    assert_eq!(event["source"], "filesystem");
    let files: Vec<(&str, &str)> = event["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| {
            (
                file["path"].as_str().unwrap(),
                file["operation"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        files,
        [
            ("fonts/body.ttf", "remove"),
            ("references/api.md", "add"),
            ("scripts/run.py", "replace")
        ]
    );
    assert_eq!(
        event["files"][2]["diff"],
        "@@ -1 +1 @@\n-print('hi')\n+print('edited')\n"
    );
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    run_success(database.command().args(["audit", "verify"]));

    // A whole folder copied in by hand is a new record that save accepts.
    let copied = folder(&database, "copied");
    fs::create_dir_all(copied.join("scripts")).unwrap();
    fs::write(copied.join("SKILL.md"), "---\nname: copied\n---\nBody\n").unwrap();
    fs::write(copied.join("scripts/x.sh"), "echo hi\n").unwrap();
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "A skills/copied"
    );
    run_success(database.command().args(["save", "--all"]));
    let event = last_event(&database);
    assert_eq!(event["action"], "create");
    assert_eq!(event["files"][0]["path"], "scripts/x.sh");
    run_success(database.command().args(["audit", "verify"]));

    // Deleting the folder by hand is a deletion that save records, with every
    // file it removes.
    fs::remove_dir_all(&copied).unwrap();
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "D skills/copied"
    );
    run_success(database.command().args(["save", "skills/copied"]));
    let event = last_event(&database);
    assert_eq!(event["action"], "delete");
    assert_eq!(event["files"][0]["operation"], "remove");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn deleting_a_bundle_removes_its_folder_and_records_every_file() {
    let database = bundle_database("bundle-delete");
    create_skill(&database, "pdf");
    run_success(
        database
            .command()
            .args(["delete", "skills", "pdf", "--yes"]),
    );
    assert!(!folder(&database, "pdf").exists());
    let event = last_event(&database);
    assert_eq!(event["action"], "delete");
    assert_eq!(event["files"].as_array().unwrap().len(), 2);
    run_success(database.command().args(["audit", "verify"]));

    // The ID can be created again, from nothing.
    create_skill(&database, "pdf");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn file_paths_stay_inside_the_record_and_never_follow_links() {
    let database = bundle_database("bundle-paths");
    create_skill(&database, "pdf");
    let contents = source(&database, "x", b"x");
    for (path, reason) in [
        ("../escape", "cannot contain '.' or '..'"),
        ("/etc/passwd", "must be relative"),
        ("a//b", "empty component"),
        ("SKILL.md", "is the record itself"),
        ("skill.md", "is the record itself"),
        (
            "scripts/run.py/inner",
            "would need 'scripts/run.py' to be a folder",
        ),
    ] {
        let refused = run_failure(database.command().args([
            "update",
            "skills",
            "pdf",
            "--file",
            &format!("{path}={contents}"),
        ]));
        assert!(refused.contains(reason), "{path}: {refused}");
    }
    assert!(!database.root.join("records/escape").exists());

    let missing = run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--remove-file",
        "nope.txt",
    ]));
    assert!(missing.contains("does not exist"), "{missing}");

    // A collection that stores Markdown files cannot hold other files.
    let refused = run_failure(database.command().args([
        "create",
        "notes",
        "one",
        "--file",
        &format!("a.txt={contents}"),
    ]));
    assert!(refused.contains("layout: bundle"), "{refused}");

    #[cfg(unix)]
    {
        let outside = database.root.join("sources/secret");
        fs::write(&outside, b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, folder(&database, "pdf").join("leak")).unwrap();
        for arguments in [
            &["get", "skills", "pdf"][..],
            &["status"],
            &["audit", "verify"],
        ] {
            let refused = run_failure(database.command().args(arguments));
            assert!(
                refused.contains("symbolic link, which the database refuses to follow"),
                "{arguments:?}: {refused}"
            );
        }
        let check = check_output(&database);
        assert!(check.contains("unreadable_record"), "{check}");
    }
}

#[test]
fn a_folder_that_lost_its_entry_is_reported_and_refused_rather_than_hidden() {
    let database = bundle_database("bundle-entryless");
    let orphan = folder(&database, "orphan");
    fs::create_dir_all(&orphan).unwrap();
    fs::write(orphan.join("notes.txt"), b"left behind\n").unwrap();

    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "A skills/orphan"
    );
    let refused = run_failure(database.command().args(["save", "skills/orphan"]));
    assert!(
        refused.contains("has supporting files but no 'SKILL.md'"),
        "{refused}"
    );
    let check = check_output(&database);
    assert!(check.contains("unreadable_record"), "{check}");

    // A file named like a staged write, with no interrupted write to have
    // left it, is refused rather than hidden from the audit.
    fs::write(orphan.join(".cr-tmp-000000000000000000000000"), b"?").unwrap();
    let refused = run_failure(database.command().args(["status"]));
    assert!(
        refused.contains("named like a write cr stages"),
        "{refused}"
    );
    fs::remove_file(orphan.join(".cr-tmp-000000000000000000000000")).unwrap();

    // An empty folder is not a record at all.
    fs::remove_file(orphan.join("notes.txt")).unwrap();
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    run_success(database.command().args(["check"]));

    // A Markdown file where a folder belongs is refused, not skipped.
    fs::write(database.root.join("records/skills/stray.md"), "---\n---\n").unwrap();
    let refused = run_failure(database.command().args(["list", "skills"]));
    assert!(
        refused.contains("contains a Markdown file named 'stray.md'"),
        "{refused}"
    );
}

#[test]
fn replay_holds_a_file_diff_to_the_hash_it_claims() {
    let database = bundle_database("bundle-forged-diff");
    create_skill(&database, "pdf");

    // Rewrite the head event's diff, re-hash the event, and re-anchor it: the
    // chain is internally perfect, but the diff no longer produces the file.
    let segment = common::chain::segment_paths(&database.root).pop().unwrap();
    let contents = fs::read_to_string(&segment).unwrap();
    let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
    let head = parse_line(lines.last().unwrap());
    let forged = head.payload.replace("+print('hi')", "+print('pwned')");
    assert_ne!(forged, head.payload);
    *lines.last_mut().unwrap() = stored_line(&event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    fs::write(&segment, lines.join("\n") + "\n").unwrap();
    reanchor(&database.root);

    let refused = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        refused
            .contains("audit replay is inconsistent at sequence 1: file changes cannot be applied"),
        "{refused}"
    );
}

#[test]
fn the_configuration_names_only_usable_bundle_layouts() {
    let database = TestDatabase::new("bundle-config");
    for (config, reason) in [
        (
            "version: 1\ncollections:\n  users:\n    layout: bundle\n",
            "users collection",
        ),
        (
            "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.txt\n",
            "must be a single file name ending in '.md'",
        ),
        (
            "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: a/SKILL.md\n",
            "must be a single file name ending in '.md'",
        ),
        (
            "version: 1\ncollections:\n  skills:\n    entry: SKILL.md\n",
            "applies only to the bundle layout",
        ),
        (
            "version: 1\ncollections:\n  skills:\n    layout: folder\n",
            "not valid YAML",
        ),
    ] {
        fs::write(database.root.join(".cr/config.yaml"), config).unwrap();
        let refused = run_failure(database.command().args(["list", "skills"]));
        assert!(refused.contains(reason), "{config}: {refused}");
    }

    // Without an entry name, a bundle's entry is index.md, as in Hugo.
    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ncollections:\n  pages:\n    layout: bundle\n",
    )
    .unwrap();
    run_success(database.command().args(["create", "pages", "home"]));
    assert!(database.root.join("records/pages/home/index.md").is_file());
    let collections = run_success(database.command().args(["collections"]));
    assert!(collections.starts_with("pages\t"), "{collections}");
    assert!(
        collections.trim_end().ends_with("\tbundle"),
        "{collections}"
    );
}

#[test]
fn a_bundle_collection_refuses_encrypted_storage() {
    let database = bundle_database("bundle-encryption");
    let refused = run_failure(
        database
            .command()
            .args(["schema", "encrypt", "skills", "secret"]),
    );
    assert!(
        refused.contains("cannot use encrypted storage"),
        "{refused}"
    );
}

#[test]
fn supporting_files_take_the_record_s_access_control() {
    let database = bundle_database("bundle-access");
    let as_principal = |actor: &str| {
        let mut command = database.command();
        command.env("CR_ACTOR", actor);
        command
    };
    run_success(as_principal("Owner <owner@example.com>").args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    for id in ["reader@example.com", "stranger@example.com"] {
        run_success(
            as_principal("Owner <owner@example.com>")
                .args(["user", "add", id, "--name", id, "--email", id]),
        );
    }
    let script = source(&database, "run.py", b"print('hi')\n");
    run_success(as_principal("Owner <owner@example.com>").args([
        "create",
        "skills",
        "pdf",
        "--file",
        &format!("scripts/run.py={script}"),
    ]));
    run_success(as_principal("Owner <owner@example.com>").args([
        "access",
        "grant",
        "reader@example.com",
        "viewer",
        "record:skills/pdf",
    ]));

    assert_eq!(
        run_success(as_principal("reader@example.com").args([
            "get",
            "skills",
            "pdf",
            "--file",
            "scripts/run.py",
        ])),
        "print('hi')\n"
    );
    let refused = run_failure(as_principal("reader@example.com").args([
        "update",
        "skills",
        "pdf",
        "--remove-file",
        "scripts/run.py",
    ]));
    assert!(
        refused.contains("cannot update record:skills/pdf"),
        "{refused}"
    );
    let refused = run_failure(as_principal("stranger@example.com").args([
        "get",
        "skills",
        "pdf",
        "--file",
        "scripts/run.py",
    ]));
    assert!(
        refused.contains("cannot read record:skills/pdf"),
        "{refused}"
    );
}

#[test]
fn a_retried_create_returns_the_original_record_and_its_files() {
    let database = bundle_database("bundle-idempotency");
    let script = source(&database, "run.py", b"print('hi')\n");
    let other = source(&database, "other.py", b"print('other')\n");
    let create = |source: &str| {
        let mut command = database.command();
        command.args([
            "create",
            "skills",
            "pdf",
            "--file",
            &format!("scripts/run.py={source}"),
            "--idempotency-key",
            "0123456789abcdef-retry",
            "--json",
        ]);
        command
    };
    let first = json(&mut create(&script));
    let retried = json(&mut create(&script));
    assert_eq!(first, retried);
    assert_eq!(read_chain(&database.root).len(), 1);
    let refused = run_failure(&mut create(&other));
    assert!(
        refused.contains("idempotency key was already used"),
        "{refused}"
    );
}

/// Where the next segment will be written with one event per segment.
fn block_next_segment(database: &TestDatabase) -> PathBuf {
    let next = read_chain(&database.root).len() + 1;
    let path = database
        .root
        .join(format!(".cr/audit/segments/{next:020}.jsonl"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn a_write_interrupted_between_files_is_finished_by_the_next_command() {
    let database = bundle_database("bundle-recovery");
    fs::write(
        database.root.join(".cr/config.yaml"),
        format!("{BUNDLES}audit:\n  segment_max_events: 1\n"),
    )
    .unwrap();
    create_skill(&database, "pdf");
    let skill = folder(&database, "pdf");
    let entry_before = fs::read(skill.join("SKILL.md")).unwrap();
    let script = source(&database, "run2.py", b"print('two')\n");
    let reference = source(&database, "api.md", b"# API\n");
    let update = [
        "update",
        "skills",
        "pdf",
        "--set",
        "name=renamed",
        "--file",
        &format!("scripts/run.py={script}"),
        "--file",
        &format!("references/api.md={reference}"),
        "--remove-file",
        "fonts/body.ttf",
    ];

    // The append fails after every file was written, which leaves the pending
    // write and its staged contents exactly as a crash there would.
    let blocked = block_next_segment(&database);
    run_failure(database.command().args(update));
    fs::remove_dir(&blocked).unwrap();
    assert!(database.root.join(".cr/audit/pending.json").is_file());
    let entry_after = fs::read(skill.join("SKILL.md")).unwrap();

    // Put two files back as they were before the write: the folder now holds
    // a write that stopped partway.
    fs::write(skill.join("SKILL.md"), &entry_before).unwrap();
    fs::create_dir_all(skill.join("fonts")).unwrap();
    fs::write(skill.join("fonts/body.ttf"), BINARY).unwrap();
    // A crash while a file was being staged beside its target leaves this.
    fs::write(
        skill.join("scripts/.cr-tmp-000000000000000000000000"),
        b"half",
    )
    .unwrap();

    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    assert_eq!(fs::read(skill.join("SKILL.md")).unwrap(), entry_after);
    assert!(!skill.join("fonts").exists());
    assert!(
        !skill
            .join("scripts/.cr-tmp-000000000000000000000000")
            .exists()
    );
    assert_eq!(
        fs::read(skill.join("scripts/run.py")).unwrap(),
        b"print('two')\n"
    );
    assert!(!database.root.join(".cr/audit/pending.json").exists());
    let staged = database.root.join(".cr/audit/staged");
    assert_eq!(fs::read_dir(&staged).unwrap().count(), 0);
    assert_eq!(last_event(&database)["action"], "update");
    assert_eq!(read_chain(&database.root).len(), 2);
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn an_interrupted_write_that_never_touched_the_folder_is_discarded() {
    let database = bundle_database("bundle-recovery-before");
    fs::write(
        database.root.join(".cr/config.yaml"),
        format!("{BUNDLES}audit:\n  segment_max_events: 1\n"),
    )
    .unwrap();
    create_skill(&database, "pdf");
    let skill = folder(&database, "pdf");
    let entry_before = fs::read(skill.join("SKILL.md")).unwrap();
    let reference = source(&database, "api.md", b"# API\n");

    let blocked = block_next_segment(&database);
    run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--file",
        &format!("references/api.md={reference}"),
    ]));
    fs::remove_dir(&blocked).unwrap();
    fs::remove_dir_all(skill.join("references")).unwrap();
    assert_eq!(fs::read(skill.join("SKILL.md")).unwrap(), entry_before);

    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    assert!(!database.root.join(".cr/audit/pending.json").exists());
    assert_eq!(read_chain(&database.root).len(), 1);

    // A folder in neither state stops recovery for a human to look at.
    let blocked = block_next_segment(&database);
    run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--file",
        &format!("references/api.md={reference}"),
    ]));
    fs::remove_dir(&blocked).unwrap();
    fs::write(skill.join("references/api.md"), b"something else\n").unwrap();
    let refused = run_failure(database.command().args(["status"]));
    assert!(refused.contains("matches neither state"), "{refused}");
}

#[test]
fn a_sync_upsert_replaces_the_entry_and_keeps_the_supporting_files() {
    let database = bundle_database("bundle-sync");
    create_skill(&database, "pdf");
    let adapter = database.root.join("adapter.sh");
    fs::write(
        &adapter,
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"skills","id":"pdf","front_matter":{"name":"pdf-forms","description":"Synced"},"markdown":"Synced body.\n"}'
printf '%s\n' '{"type":"upsert","collection":"skills","id":"fresh","front_matter":{"name":"fresh"},"markdown":""}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "skills",
        "--",
        "sh",
        adapter.to_str().unwrap(),
    ]));
    let summary = json(database.command().args(["sync", "run", "skills", "--json"]));
    assert_eq!(summary["created"], 1);
    assert_eq!(summary["updated"], 1);

    let skill = folder(&database, "pdf");
    assert_eq!(
        fs::read(skill.join("scripts/run.py")).unwrap(),
        b"print('hi')\n"
    );
    assert!(
        fs::read_to_string(skill.join("SKILL.md"))
            .unwrap()
            .contains("Synced body.")
    );
    assert!(folder(&database, "fresh").join("SKILL.md").is_file());
    run_success(database.command().args(["audit", "verify"]));

    // Unchanged output is recognized as unchanged, files and all.
    let again = json(database.command().args(["sync", "run", "skills", "--json"]));
    assert_eq!(again["unchanged"], 2);
}

#[test]
fn a_file_and_a_folder_can_trade_places_in_one_request() {
    let database = bundle_database("bundle-reshape");
    create_skill(&database, "pdf");
    let contents = source(&database, "x", b"x\n");
    let skill = folder(&database, "pdf");

    // A file becomes a folder: `scripts/run.py` is removed and a file is
    // written beneath its name.
    run_success(database.command().args([
        "update",
        "skills",
        "pdf",
        "--remove-file",
        "scripts/run.py",
        "--file",
        &format!("scripts/run.py/inner.txt={contents}"),
    ]));
    assert!(skill.join("scripts/run.py/inner.txt").is_file());

    // And back: the folder's only file is removed and a file takes its name.
    run_success(database.command().args([
        "update",
        "skills",
        "pdf",
        "--remove-file",
        "scripts/run.py/inner.txt",
        "--file",
        &format!("scripts/run.py={contents}"),
    ]));
    assert!(skill.join("scripts/run.py").is_file());

    // An empty folder is no part of a record, and a file may take its name.
    fs::create_dir_all(skill.join("empty/nested")).unwrap();
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    run_success(database.command().args([
        "update",
        "skills",
        "pdf",
        "--file",
        &format!("empty={contents}"),
    ]));
    assert!(skill.join("empty").is_file());
    run_success(database.command().args(["audit", "verify"]));
    assert!(!database.root.join(".cr/audit/pending.json").exists());
}

#[test]
fn a_write_the_filesystem_cannot_hold_is_refused_before_it_starts() {
    let database = bundle_database("bundle-unwritable");
    create_skill(&database, "pdf");
    let contents = source(&database, "x", b"x\n");
    let long = "n".repeat(300);
    for (path, reason) in [
        (long.as_str(), "longer than 255 bytes"),
        ("Scripts/other.py", "only by letter case"),
        ("skill.md/x", "only by letter case"),
        ("FONTS/body.ttf", "only by letter case"),
    ] {
        let refused = run_failure(database.command().args([
            "update",
            "skills",
            "pdf",
            "--file",
            &format!("a.txt={contents}"),
            "--file",
            &format!("{path}={contents}"),
        ]));
        assert!(refused.contains(reason), "{path}: {refused}");
    }
    assert!(!folder(&database, "pdf").join("a.txt").exists());
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
}

#[cfg(unix)]
#[test]
fn a_write_that_fails_partway_puts_the_folder_back() {
    use std::os::unix::fs::PermissionsExt;

    let database = bundle_database("bundle-rollback");
    create_skill(&database, "pdf");
    let skill = folder(&database, "pdf");
    let entry = fs::read(skill.join("SKILL.md")).unwrap();
    let contents = source(&database, "x", b"x\n");

    // `scripts/` refuses new files, so the write fails after `fonts/` has
    // already gained one.
    let scripts = skill.join("scripts");
    fs::set_permissions(&scripts, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::write(scripts.join("probe"), b"").is_ok() {
        // Permissions do not bind this user; nothing to test here.
        fs::remove_file(scripts.join("probe")).unwrap();
        fs::set_permissions(&scripts, fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    run_failure(database.command().args([
        "update",
        "skills",
        "pdf",
        "--set",
        "name=renamed",
        "--file",
        &format!("fonts/extra.ttf={contents}"),
        "--file",
        &format!("scripts/extra.py={contents}"),
    ]));
    fs::set_permissions(&scripts, fs::Permissions::from_mode(0o755)).unwrap();

    assert!(!skill.join("fonts/extra.ttf").exists());
    assert_eq!(fs::read(skill.join("SKILL.md")).unwrap(), entry);
    assert!(!database.root.join(".cr/audit/pending.json").exists());
    assert_eq!(read_chain(&database.root).len(), 1);
    assert_eq!(
        run_success(database.command().args(["status"])).trim(),
        "Clean"
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn an_interrupted_sync_of_a_bundle_with_files_can_be_recovered() {
    let database = bundle_database("bundle-sync-recover");
    create_skill(&database, "pdf");
    let adapter = database.root.join("adapter.sh");
    fs::write(
        &adapter,
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"skills","id":"pdf","front_matter":{"name":"pdf"},"markdown":"Synced.\n"}'
printf '%s\n' '{"type":"upsert","collection":"blocked","id":"x","front_matter":{},"markdown":""}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":2}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "skills",
        "--",
        "sh",
        adapter.to_str().unwrap(),
    ]));
    // A file where the second collection's folder belongs makes the run fail
    // after the bundle was already updated.
    fs::write(database.root.join("records/blocked"), b"blocked\n").unwrap();
    run_failure(database.command().args(["sync", "run", "skills"]));
    fs::remove_file(database.root.join("records/blocked")).unwrap();

    run_success(database.command().args(["sync", "recover", "skills"]));
    assert_eq!(
        json(database.command().args(["sync", "state", "skills"])),
        serde_json::json!({ "cursor": 2 })
    );
    assert!(folder(&database, "pdf").join("scripts/run.py").is_file());
    run_success(database.command().args(["audit", "verify"]));
}
