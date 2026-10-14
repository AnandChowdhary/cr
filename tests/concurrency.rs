mod common;

use std::{
    fs,
    path::Path,
    process::{Child, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use common::{
    TestDatabase, chain,
    fault::{FaultDatabase, Point},
    run_success,
};
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
fn two_conditional_writers_from_one_version_allow_exactly_one_commit() {
    let database = TestDatabase::new("conditional-update-race");
    run_success(
        database
            .command()
            .args(["create", "items", "shared", "--set", "winner=none"]),
    );
    let fetched: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args(["get", "items", "shared", "--json"]),
    ))
    .unwrap();
    let version = fetched["version"].as_str().unwrap().to_owned();

    let mut children = Vec::new();
    for winner in ["one", "two"] {
        let assignment = format!("winner={winner}");
        children.push(
            database
                .command()
                .args([
                    "--json-errors",
                    "update",
                    "items",
                    "shared",
                    "--set",
                    &assignment,
                    "--expected-record-hash",
                    &version,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }

    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    let stale = outputs
        .iter()
        .find(|output| !output.status.success())
        .expect("one stale writer");
    let stale: Value = serde_json::from_slice(&stale.stderr).unwrap();
    assert_eq!(stale["error"]["code"], "precondition_failed");

    let log: Value = serde_json::from_str(&run_success(
        database
            .command()
            .args(["audit", "log", "items", "shared", "--json"]),
    ))
    .unwrap();
    assert_eq!(log.as_array().unwrap().len(), 2);
    run_success(database.command().args(["audit", "verify"]));
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

/// Concurrent writers racing the recovery of an interrupted mutation.
///
/// Exactly one of them may commit the interrupted event, every one of them must
/// then commit its own, and the chain that results must be dense: recovery
/// holds the same audit lock a mutation does, so there is no window where two
/// processes both believe the pending file is theirs.
#[test]
fn concurrent_writers_racing_recovery_produce_one_dense_chain() {
    let database = FaultDatabase::new("recovery-race");
    run_success(
        database
            .command()
            .args(["create", "items", "shared", "--set", "writer=0"]),
    );
    let interruption = database.interrupt(
        "items",
        "shared",
        &["update", "items", "shared", "--set", "writer=99"],
    );
    database.restore(&interruption, "items", "shared", Point::RecordReplaced);

    let mut children = Vec::new();
    for writer in 1..=8 {
        let assignment = format!("writer={writer}");
        children.push(
            database
                .command()
                .args(["update", "items", "shared", "--set", &assignment])
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
            "a writer racing recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // One create, one recovered update, eight concurrent updates.
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 10 audit events"),
        "unexpected verification: {verification}"
    );
    assert!(database.read_pending().is_none());
    chain::assert_chain_is_well_formed(database.root());
}

/// Writers blocked on the audit lock all commit once it is released.
///
/// The lock is held by this process, not by a sleeping child, so nothing here
/// depends on timing: whether a writer blocks or merely queues, every one of
/// them has to end up in the chain exactly once.
#[test]
fn writers_contending_for_the_audit_lock_all_commit_exactly_once() {
    let database = FaultDatabase::new("lock-contention");
    run_success(
        database
            .command()
            .args(["create", "items", "shared", "--set", "writer=0"]),
    );

    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(database.root().join(".cr/audit/lock"))
        .unwrap();
    lock.lock().expect("the test can hold the audit lock");

    let mut children = Vec::new();
    for writer in 1..=6 {
        let assignment = format!("writer={writer}");
        children.push(
            database
                .command()
                .args(["update", "items", "shared", "--set", &assignment])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    lock.unlock().expect("the audit lock releases");
    drop(lock);

    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "a contending writer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 7 audit events"),
        "unexpected verification: {verification}"
    );
    let head = chain::assert_chain_is_well_formed(database.root());
    assert!(head.is_some());
}

/// A `cr` process killed outright leaves nothing behind that blocks the next
/// one.
///
/// The sync adapter signals its own parent, so the kill happens at a point the
/// test chooses rather than one it guesses at: `cr` is holding the per-sync
/// lock and a staged output file when it dies. Advisory locks are released by
/// the kernel on death, and no audit state was written yet, so the database
/// must be untouched and the next run must succeed.
#[test]
fn a_hard_killed_sync_leaves_no_stale_lock_and_a_verifiable_database() {
    let database = TestDatabase::new("hard-killed-sync");
    run_success(
        database
            .command()
            .args(["create", "items", "kept", "--set", "stage=screening"]),
    );
    let head_before = run_success(database.command().args(["audit", "head", "--json"]));

    let scripts = database.root.join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    fs::write(
        scripts.join("suicidal.sh"),
        "#!/bin/sh\nkill -9 \"$PPID\"\n",
    )
    .unwrap();
    fs::write(
        scripts.join("healthy.sh"),
        concat!(
            "#!/bin/sh\n",
            "printf '%s\\n' '{\"type\":\"upsert\",\"collection\":\"items\",",
            "\"id\":\"added\",\"front_matter\":{\"stage\":\"offer\"},",
            "\"markdown\":\"Added by sync.\\n\"}'\n"
        ),
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "killer",
        "--",
        "sh",
        "scripts/suicidal.sh",
    ]));
    run_success(database.command().args([
        "sync",
        "create",
        "healthy",
        "--",
        "sh",
        "scripts/healthy.sh",
    ]));

    let killed = database
        .command()
        .args(["sync", "run", "killer"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!killed.success(), "the process was supposed to be killed");
    assert_eq!(
        killed.code(),
        None,
        "the process should have died from a signal, not exited"
    );

    // Nothing was committed, nothing is pending, and nothing is locked.
    assert!(!database.root.join(".cr/audit/pending.json").exists());
    assert_eq!(
        run_success(database.command().args(["audit", "head", "--json"])),
        head_before
    );
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");

    // The next run acquires every lock the killed process was holding.
    run_success(database.command().args(["sync", "run", "healthy"]));
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 2 audit events"),
        "unexpected verification: {verification}"
    );
}

/// Hold the audit lock as a `cr` command inside the section it guards does.
fn hold_audit_lock(root: &Path) -> fs::File {
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(".cr/audit/lock"))
        .unwrap();
    lock.lock().expect("the test can hold the audit lock");
    lock
}

/// What `child` printed, once it has exited by itself within `limit`.
fn finished_within(mut child: Child, limit: Duration, what: &str) -> Output {
    let deadline = Instant::now() + limit;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("{what} was still running after {limit:?}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{what} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A read with nothing to recover does not queue behind whoever holds the
/// audit lock, however long they hold it.
///
/// Every command used to take the lock when it opened the database, to
/// recover a mutation a crash might have left, so one slow writer, or one
/// recovery that never finished in the time a caller allowed, stopped every
/// read behind it. Only a pending file makes the lock worth waiting for.
#[test]
fn a_read_with_nothing_to_recover_does_not_wait_for_the_audit_lock() {
    const OWNER: &str = "Owner <owner@example.com>";
    let database = TestDatabase::new("read-without-lock");
    let as_owner = || {
        let mut command = database.command();
        command.env("CR_ACTOR", OWNER);
        command
    };
    run_success(as_owner().args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    run_success(as_owner().args(["create", "deals", "acme", "--set", "stage=open"]));
    run_success(as_owner().args([
        "user",
        "add",
        "bob@example.com",
        "--name",
        "Bob",
        "--email",
        "bob@example.com",
    ]));
    run_success(as_owner().args([
        "access",
        "grant",
        "bob@example.com",
        "viewer",
        "collection:deals",
    ]));

    let lock = hold_audit_lock(database.root());
    for arguments in [
        &["get", "deals", "acme", "--json"][..],
        &["list", "deals"],
        &["--as", "bob@example.com", "get", "deals", "acme", "--json"],
    ] {
        let reader = as_owner()
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let what = format!("'{}' while the audit lock was held", arguments.join(" "));
        let output = finished_within(reader, Duration::from_secs(60), &what);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("acme"),
            "{what}"
        );
    }
    drop(lock);
}

/// A read that finds a pending file still waits for the lock and recovers
/// the interrupted mutation before it reads, so it answers with the state
/// the journal is about to record rather than beside it.
#[cfg(target_os = "linux")]
#[test]
fn a_read_that_finds_an_interrupted_mutation_waits_and_recovers_it_first() {
    use std::os::unix::fs::MetadataExt;

    let database = FaultDatabase::new("read-recovers-first");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    let interruption = database.interrupt(
        "items",
        "one",
        &["update", "items", "one", "--set", "stage=hired"],
    );
    database.restore(&interruption, "items", "one", Point::RecordReplaced);

    let lock = hold_audit_lock(database.root());
    let reader = database
        .command()
        .args(["get", "items", "one", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Linux lists a process blocked in `flock` in `/proc/locks` as
    // `1: -> FLOCK  ADVISORY  WRITE <pid> <major>:<minor>:<inode> 0 EOF`.
    let pid = reader.id().to_string();
    let inode = format!(":{}", lock.metadata().unwrap().ino());
    let waiting = |line: &str| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.get(1) == Some(&"->")
            && fields.get(5) == Some(&pid.as_str())
            && fields.get(6).is_some_and(|file| file.ends_with(&inode))
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    while !fs::read_to_string("/proc/locks")
        .unwrap()
        .lines()
        .any(waiting)
    {
        assert!(
            Instant::now() < deadline,
            "the read did not wait for the audit lock"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert!(database.read_pending().is_some());

    drop(lock);
    let output = finished_within(reader, Duration::from_secs(60), "the read");
    let record: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(record["attributes"]["stage"], "hired");
    assert!(database.read_pending().is_none());
    assert_eq!(database.head_sequence(), 2);
}
