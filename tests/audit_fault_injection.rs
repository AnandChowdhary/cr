//! Crash recovery for the audit write-ahead protocol.
//!
//! `docs/architecture.md` claims that a single-record mutation is recoverable
//! after an interruption at any point, because the record can only be in one of
//! two atomic states and hashing it decides between them. These tests enumerate
//! the interruption points and hold the implementation to that claim, driving a
//! real `cr` process against real files. See `tests/common/fault.rs` for how the
//! interruption is produced.
//!
//! The four points in one mutation are:
//!
//! 1. pending file written, record not yet changed — the mutation must be
//!    discarded;
//! 2. record changed, event not yet appended — the mutation must be committed;
//! 3. event appended, pending file not yet removed — the pending file must be
//!    dropped and nothing appended twice;
//! 4. pending file removed — an ordinary completed mutation.
//!
//! Every state that is none of those four must produce a named refusal rather
//! than a silent repair.

mod common;

use common::{
    fault::{FaultDatabase, Point, pending_bytes, pending_json},
    run_failure, run_success,
};
use serde_json::Value;

/// A create interrupted before the record was written leaves nothing behind.
#[test]
fn a_create_interrupted_before_its_record_landed_is_discarded() {
    let database = FaultDatabase::new("interrupted-create-discard");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    assert!(interruption.before.is_none());
    assert!(interruption.after.is_some());

    database.restore(&interruption, "items", "one", Point::PendingWritten);

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 0 audit events"));
    assert!(database.read_pending().is_none());
    assert!(database.read_record("items", "one").is_none());
    assert_eq!(database.head_sequence(), 0);
}

/// A create interrupted after the record landed is completed on the next run.
#[test]
fn a_create_interrupted_after_its_record_landed_is_committed() {
    let database = FaultDatabase::new("interrupted-create-commit");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    database.restore(&interruption, "items", "one", Point::RecordReplaced);

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 1 audit events and 1 records"));
    assert!(database.read_pending().is_none());
    assert_eq!(database.head_sequence(), 1);

    let log = run_success(database.command().args(["audit", "log", "--json"]));
    let log: Value = serde_json::from_str(&log).unwrap();
    assert_eq!(log[0]["action"], "create");
    assert_eq!(log[0]["sequence"], 1);
}

/// The same two outcomes for an update, which has a real before-state.
#[test]
fn an_update_recovers_to_whichever_atomic_state_the_record_is_in() {
    let database = FaultDatabase::new("interrupted-update");
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

    database.restore(&interruption, "items", "one", Point::PendingWritten);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 1);
    let record = run_success(database.command().args(["get", "items", "one", "--json"]));
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["attributes"]["stage"], "screening");

    database.restore(&interruption, "items", "one", Point::RecordReplaced);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 2);
    let record = run_success(database.command().args(["get", "items", "one", "--json"]));
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["attributes"]["stage"], "hired");
}

/// A deletion's after-state is an absent file, and recovery must read it that
/// way rather than treating a missing record as an unrecoverable third state.
#[test]
fn a_delete_recovers_from_an_absent_record_as_the_committed_state() {
    let database = FaultDatabase::new("interrupted-delete");
    run_success(
        database
            .command()
            .args(["create", "items", "gone", "--set", "stage=screening"]),
    );
    let interruption = database.interrupt("items", "gone", &["delete", "items", "gone", "--yes"]);
    assert!(interruption.after.is_none());

    database.restore(&interruption, "items", "gone", Point::PendingWritten);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 1);
    assert!(database.read_record("items", "gone").is_some());

    database.restore(&interruption, "items", "gone", Point::RecordReplaced);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 2);
    assert!(database.read_record("items", "gone").is_none());
    let log = run_success(database.command().args(["audit", "log", "--json"]));
    let log: Value = serde_json::from_str(&log).unwrap();
    assert_eq!(log[0]["action"], "delete");
}

/// Interruption point three: the event is in the journal and the pending file
/// still names it. Recovery must recognise its own committed work.
#[test]
fn a_pending_file_left_behind_after_a_committed_event_is_dropped_without_a_second_append() {
    let database = FaultDatabase::new("interrupted-clear");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    database.restore(&interruption, "items", "one", Point::RecordReplaced);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 1);

    // The crash happened between the append and the removal.
    database.put_pending(&interruption.pending);
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 1 audit events"));
    assert!(database.read_pending().is_none());
    assert_eq!(database.journal_lines().len(), 1);
}

/// The same state, but with the record rolled back underneath the committed
/// event. Recovery cannot repair that and must say so.
#[test]
fn a_committed_event_whose_record_was_rolled_back_is_refused_not_repaired() {
    let database = FaultDatabase::new("committed-rollback");
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
    run_success(database.command().args(["audit", "verify"]));

    database.put_pending(&interruption.pending);
    database.put_record("items", "one", interruption.before.as_deref());
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure
            .contains("audit event was committed but the record does not match its audited state"),
        "unexpected failure: {failure}"
    );
    assert!(
        database.read_pending().is_some(),
        "an unrecoverable pending file must be kept for investigation"
    );
}

/// A record in neither atomic state is the third state the protocol reserves
/// for manual investigation.
#[test]
fn a_record_matching_neither_atomic_state_stops_recovery() {
    let database = FaultDatabase::new("neither-state");
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
    database.put_record("items", "one", Some(b"---\nstage: tampered\n---\n"));

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("matches neither state"),
        "unexpected failure: {failure}"
    );
    assert!(database.read_pending().is_some());
    // Every command that opens the database refuses, rather than one of them
    // quietly proceeding on a database it could not recover.
    for arguments in [
        vec!["status"],
        vec!["audit", "log"],
        vec!["get", "items", "one"],
        vec!["update", "items", "one", "--set", "stage=other"],
    ] {
        let failure = run_failure(database.command().args(&arguments));
        assert!(
            failure.contains("matches neither state"),
            "'{}' did not refuse: {failure}",
            arguments.join(" ")
        );
    }
}

/// Recovery must not append an event that does not extend the current head.
#[test]
fn a_pending_mutation_that_cannot_extend_the_chain_is_refused() {
    let database = FaultDatabase::new("non-extending-pending");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=interview"]),
    );
    let interruption = database.interrupt(
        "items",
        "one",
        &["update", "items", "one", "--set", "stage=hired"],
    );
    database.restore(&interruption, "items", "one", Point::RecordReplaced);

    // The segment carrying sequence 2 is lost as well, so the pending event at
    // sequence 3 no longer follows the head.
    std::fs::remove_file(&database.segments()[1]).unwrap();
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("does not extend the current chain head"),
        "unexpected failure: {failure}"
    );
}

/// A pending file older than the committed head is stale, not replayable.
#[test]
fn a_pending_mutation_older_than_the_committed_head_is_refused() {
    let database = FaultDatabase::new("stale-pending");
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
    database.restore(&interruption, "items", "one", Point::PendingWritten);
    run_success(database.command().args(["audit", "verify"]));

    // Different work commits at the sequence the stale pending file claims.
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=offer"]),
    );
    database.put_pending(&interruption.pending);
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("conflicts with committed audit history"),
        "unexpected failure: {failure}"
    );
}

/// Recovery of a mutation whose before-state and after-state are identical.
///
/// A no-op update records an event with an empty change set, so hashing the
/// record cannot decide whether the write landed. Committing is the only sound
/// answer — both branches leave identical bytes on disk — and the point of the
/// test is that the decision procedure is total rather than stuck.
#[test]
fn a_mutation_with_identical_before_and_after_states_still_recovers() {
    let database = FaultDatabase::new("identical-states");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    let interruption = database.interrupt(
        "items",
        "one",
        &["update", "items", "one", "--set", "stage=screening"],
    );
    assert_eq!(interruption.before, interruption.after);

    let pending = pending_json(&interruption.pending);
    assert_eq!(pending["before_hash"], pending["after_hash"]);

    database.restore(&interruption, "items", "one", Point::RecordReplaced);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 2);
    let record = run_success(database.command().args(["get", "items", "one", "--json"]));
    let record: Value = serde_json::from_str(&record).unwrap();
    assert_eq!(record["attributes"]["stage"], "screening");
}

/// Recovery appends into an existing partially filled segment, not only into a
/// freshly rotated one. Widening the bound before recovery runs exercises the
/// rewrite-and-rename append path rather than the create-new-segment path.
#[test]
fn recovery_appends_into_an_existing_segment_as_well_as_a_new_one() {
    let database = FaultDatabase::new("recovery-in-segment");
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

    database.set_segment_max_events(256);
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 2);
    assert_eq!(
        database.segments().len(),
        1,
        "the recovered event should have been appended to the existing segment"
    );
    assert_eq!(database.journal_lines().len(), 2);
}

/// An interruption must not leave the mutation half-visible to a reader.
#[test]
fn an_interrupted_mutation_never_exposes_a_torn_record() {
    let database = FaultDatabase::new("no-torn-record");
    run_success(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--body",
        "# One\n\nBody must survive intact.\n",
    ]));
    let interruption = database.interrupt(
        "items",
        "one",
        &["update", "items", "one", "--set", "stage=hired"],
    );

    for bytes in [&interruption.before, &interruption.after] {
        let bytes = bytes.as_deref().expect("an update has both states");
        let text = std::str::from_utf8(bytes).expect("a published record is valid UTF-8");
        assert!(
            text.starts_with("---\n"),
            "front matter is complete: {text}"
        );
        assert!(
            text.contains("# One\n\nBody must survive intact.\n"),
            "body is preserved: {text}"
        );
    }
}

/// The captured pending file describes exactly the mutation that was
/// interrupted, so recovery is deciding on evidence and not on a guess.
#[test]
fn the_pending_file_names_the_record_the_event_mutates() {
    let database = FaultDatabase::new("pending-shape");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    let pending = pending_json(&interruption.pending);
    assert_eq!(pending["target"], "records/items/one.md");
    assert_eq!(pending["before_hash"], Value::Null);
    assert!(
        pending["after_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let payload: Value = serde_json::from_str(pending["payload"].as_str().unwrap()).unwrap();
    assert_eq!(payload["record"]["collection"], "items");
    assert_eq!(payload["record"]["id"], "one");
    assert_eq!(payload["sequence"], 1);
    assert_eq!(payload["after_hash"], pending["after_hash"]);

    // Re-encoding through serde_json changes the formatting but not the
    // meaning, and recovery still accepts it: the file is data, not bytes the
    // hash covers.
    database.restore(&interruption, "items", "one", Point::RecordReplaced);
    database.put_pending(&pending_bytes(&pending));
    run_success(database.command().args(["audit", "verify"]));
    assert_eq!(database.head_sequence(), 1);
}

/// A crash between staging a file and linking it into place leaves the staging
/// file behind, and every reader must ignore it.
///
/// `paths::write_new` and `paths::write_replace` publish atomically by writing
/// `.cr-tmp-<random>` beside the destination and then linking or renaming it.
/// The unlink that tidies up runs in the process, so a process that dies in
/// between orphans the file — observed for real in
/// `tests/sync_cli.rs::a_killed_run_leaves_a_ledger_that_completes_the_remaining_records`,
/// where a `cr sync run` is killed mid-application. The litter is not
/// corruption, because it carries neither a `.md` nor a `.jsonl` extension, but
/// nothing sweeps it either; see the `TODO.md` repair-tooling entry.
#[test]
fn staging_files_orphaned_by_a_crash_are_ignored_by_every_reader() {
    let database = FaultDatabase::new("orphan-staging");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );

    let orphans = [
        database
            .root()
            .join("records/items/.cr-tmp-0123456789abcdef01234567"),
        database
            .root()
            .join(".cr/audit/segments/.cr-tmp-89abcdef0123456789abcdef"),
    ];
    for orphan in &orphans {
        std::fs::write(orphan, "---\nstage: half-written\n---\n").unwrap();
    }

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 1 audit events and 1 records"));
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    let listed = run_success(database.command().args(["list", "items", "--json"]));
    let listed: Value = serde_json::from_str(&listed).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["path"], "records/items/one.md");

    // Mutating still works, and the orphans survive untouched: nothing sweeps
    // them, which is the honest state of affairs rather than an assertion that
    // it is fine.
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );
    run_success(database.command().args(["audit", "verify"]));
    for orphan in &orphans {
        assert!(orphan.exists(), "{} was swept after all", orphan.display());
    }
}
