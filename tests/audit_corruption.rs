//! Torn, truncated, and tampered audit state.
//!
//! The value `cr` claims is that damage to the journal is *detected*, so every
//! case here has to end in one of exactly two ways: clean recovery, or a named
//! refusal. Silent acceptance of a damaged chain is the failure these tests
//! exist to catch, so each one asserts the specific wording rather than merely
//! that something went wrong — an honest but wrong classification is a defect
//! too.
//!
//! The cases are grouped as: a segment's bytes (truncation, tearing, flips),
//! the set of segments (gaps, extras, names), and the write-ahead file.

mod common;

use std::{fs, path::PathBuf};

use common::{TestDatabase, chain, fault::FaultDatabase, run_failure, run_success};
use serde_json::Value;

/// Four events in one segment: three creates and an update.
fn seeded(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    for id in ["one", "two", "three"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
    }
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );
    database
}

fn only_segment(database: &TestDatabase) -> PathBuf {
    let mut segments = chain::segment_paths(&database.root);
    assert_eq!(segments.len(), 1, "the seed fits in one segment");
    segments.remove(0)
}

fn lines(path: &PathBuf) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &PathBuf, lines: &[String]) {
    let mut contents = String::new();
    for line in lines {
        contents.push_str(line);
        contents.push('\n');
    }
    fs::write(path, contents).unwrap();
}

fn verify_fails_with(database: &TestDatabase, expected: &str) {
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains(expected),
        "expected a failure naming '{expected}', got: {failure}"
    );
}

// ---------------------------------------------------------------------------
// A segment's bytes
// ---------------------------------------------------------------------------

/// The last write lost its newline: the final record is not known to be whole.
#[test]
fn a_segment_whose_final_line_lost_its_newline_is_refused() {
    let database = seeded("torn-newline");
    let segment = only_segment(&database);
    let mut bytes = fs::read(&segment).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&segment, &bytes).unwrap();

    verify_fails_with(&database, "has a truncated tail");
}

/// A write torn in the middle of an event, with no terminator to hide behind.
#[test]
fn a_segment_truncated_mid_event_is_refused() {
    let database = seeded("torn-mid-event");
    let segment = only_segment(&database);
    let bytes = fs::read(&segment).unwrap();
    fs::write(&segment, &bytes[..bytes.len() / 2]).unwrap();

    verify_fails_with(&database, "has a truncated tail");
}

/// The same tear, but with a newline appended so the line *looks* complete.
/// The truncated-tail check cannot see it; JSON parsing must.
#[test]
fn a_truncated_event_terminated_by_a_newline_is_refused_as_invalid_json() {
    let database = seeded("torn-plus-newline");
    let segment = only_segment(&database);
    let mut bytes = fs::read(&segment).unwrap();
    bytes.truncate(bytes.len() / 2);
    bytes.push(b'\n');
    fs::write(&segment, &bytes).unwrap();

    verify_fails_with(&database, "audit line is not valid JSON");
}

/// One byte changed inside a payload, which the stored hash covers.
#[test]
fn a_single_flipped_byte_inside_a_payload_is_refused() {
    let database = seeded("flipped-payload");
    let segment = only_segment(&database);
    let mut bytes = fs::read(&segment).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    fs::write(&segment, &bytes).unwrap();

    verify_fails_with(&database, "audit event hash mismatch");
}

/// One byte changed inside the stored hash rather than the payload.
#[test]
fn a_single_flipped_byte_inside_a_stored_hash_is_refused() {
    let database = seeded("flipped-hash");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let mut hash: Vec<char> = event.hash.chars().collect();
    let last = hash.len() - 1;
    hash[last] = if hash[last] == '0' { '1' } else { '0' };
    stored[index] = chain::stored_line(&hash.into_iter().collect::<String>(), &event.payload)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);

    verify_fails_with(&database, "audit event hash mismatch");
}

/// A segment file that exists but holds nothing.
#[test]
fn an_empty_segment_file_is_refused() {
    let database = seeded("empty-segment");
    fs::write(only_segment(&database), b"").unwrap();

    verify_fails_with(&database, "is empty");
}

/// A payload rewritten *and* re-hashed, so the line is internally consistent.
///
/// This is the interesting tamper: hashing the line alone cannot catch it. The
/// replay catches it at the guilty event before the next link is considered.
#[test]
fn a_re_hashed_forged_event_is_caught_by_the_events_that_follow_it() {
    let database = seeded("forged-middle");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[1]);
    let forged = event.payload.replace("\"screening\"", "\"forged\"");
    assert_ne!(forged, event.payload, "the seed must contain the value");
    stored[1] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: record snapshot does not describe the replayed document",
    );
}

/// Forging the *result* of the newest event, where nothing follows to link it.
///
/// Hashing the replayed document closes this part of the head gap. Rewriting
/// the change, event hash, and in-database anchor still fails at the event that
/// made the false claim, and a later mutation is refused for the same reason.
#[test]
fn a_forged_head_result_is_rejected_even_if_rehashed_and_reanchored() {
    let database = TestDatabase::new("forged-head");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(database.command().args([
        "--actor",
        "alice",
        "update",
        "items",
        "one",
        "--set",
        "stage=hired",
        "--message",
        "reviewed and approved",
    ]));
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event
        .payload
        .replacen("\"actor\":\"alice\"", "\"actor\":\"mallory\"", 1)
        .replacen("reviewed and approved", "rubber stamped", 1)
        .replacen("\"after\":\"hired\"", "\"after\":\"never happened\"", 1);
    assert_ne!(forged, event.payload, "the seed must contain those values");
    stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    // The forger's second move, which costs them nothing. `.cr-audit-head.json`
    // is a plain file at the database root, so the same write access that
    // rewrote the journal rewrites the anchor to match in the same pass. This
    // is the whole reason the anchor's protection comes from committing it to
    // Git rather than from its being on disk, and why the assertions below are
    // still true. `tests/audit_anchor.rs` holds the other half: the same
    // forgery, without this line, is caught.
    chain::reanchor(&database.root);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: record snapshot does not describe the replayed document",
    );
    let failure = run_failure(database.command().args([
        "--json-errors",
        "update",
        "items",
        "one",
        "--set",
        "stage=offer",
    ]));
    assert!(
        failure.contains(
            "audit replay is inconsistent at sequence 2: record snapshot does not describe the replayed document"
        ),
        "unexpected mutation refusal: {failure}"
    );
    assert!(failure.contains("\"code\":\"audit_integrity_failed\""));
    assert!(!failure.contains(database.root.to_str().unwrap()));
    assert!(!failure.contains("never happened"));
    assert_eq!(chain::read_chain(&database.root).len(), 2);
}

/// Non-state metadata remains outside what replay can derive.
///
/// An attacker able to rewrite the newest event and its local anchor can still
/// alter actor, timestamp, message, or attribution while leaving the replayed
/// record state intact. An external checkpoint remains the boundary for that
/// forgery.
#[test]
fn a_forged_head_actor_still_needs_an_external_checkpoint() {
    let database = TestDatabase::new("forged-head-actor");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(database.command().args([
        "--actor",
        "alice",
        "update",
        "items",
        "one",
        "--set",
        "stage=hired",
    ]));
    let checkpoint = chain::read_chain(&database.root)
        .last()
        .unwrap()
        .hash
        .clone();

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event
        .payload
        .replacen("\"actor\":\"alice\"", "\"actor\":\"mallory\"", 1);
    assert_ne!(forged, event.payload);
    stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    run_success(database.command().args(["audit", "verify"]));
    let failure =
        run_failure(
            database
                .command()
                .args(["audit", "verify", "--expected-head", &checkpoint]),
        );
    assert!(failure.contains("audit head does not match expected checkpoint"));
}

/// The formerly ignored property: changing the newest event's after-state is
/// detected without relying on an external checkpoint.
#[test]
fn a_forged_head_event_should_be_detected_without_an_external_checkpoint() {
    let database = TestDatabase::new("forged-head-ideal");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event
        .payload
        .replacen("\"after\":\"hired\"", "\"after\":\"never happened\"", 1);
    assert_ne!(forged, event.payload);
    stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: record snapshot does not describe the replayed document",
    );
}

#[test]
fn a_version_three_baseline_cannot_strip_or_downgrade_its_exact_snapshot() {
    for (name, mutate, expected) in [
        (
            "missing",
            "remove",
            "existing state has no exact record snapshot",
        ),
        (
            "future",
            "version",
            "record snapshot uses an unsupported version",
        ),
        (
            "payload-downgrade",
            "payload-version",
            "legacy record witness does not describe the replayed document",
        ),
    ] {
        let database = TestDatabase::new(&format!("baseline-snapshot-{name}"));
        fs::create_dir_all(database.root.join("records/legacy")).unwrap();
        fs::write(
            database.root.join("records/legacy/one.md"),
            "---\r\nstage: screening\r\n---\r\nBody\r\n",
        )
        .unwrap();
        run_success(database.command().args(["audit", "baseline"]));

        let segment = only_segment(&database);
        let mut stored = lines(&segment);
        let event = chain::parse_line(&stored[0]);
        let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
        match mutate {
            "remove" => {
                payload.as_object_mut().unwrap().remove("after_snapshot");
            }
            "version" => payload["after_snapshot"]["version"] = Value::from(99),
            "payload-version" => {
                payload["version"] = Value::from(2);
                payload.as_object_mut().unwrap().remove("after_snapshot");
                payload["changes"][0]["after"]["attributes"]["stage"] = Value::from("forged");
            }
            _ => unreachable!(),
        }
        let forged = serde_json::to_string(&payload).unwrap();
        stored[0] = chain::stored_line(&chain::event_hash(&forged), &forged)
            .trim_end()
            .to_owned();
        write_lines(&segment, &stored);
        chain::reanchor(&database.root);

        verify_fails_with(
            &database,
            &format!("audit replay is inconsistent at sequence 1: {expected}"),
        );
    }
}

#[test]
fn every_version_three_present_state_requires_its_exact_snapshot() {
    let database = TestDatabase::new("update-snapshot-required");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[1]);
    let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
    payload.as_object_mut().unwrap().remove("after_snapshot");
    let forged = serde_json::to_string(&payload).unwrap();
    stored[1] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: existing state has no exact record snapshot",
    );
}

#[test]
fn a_legacy_noncanonical_baseline_accepts_a_v3_successor_and_checks_it() {
    let database = TestDatabase::new("legacy-baseline-successor");
    fs::create_dir_all(database.root.join("records/legacy")).unwrap();
    fs::write(
        database.root.join("records/legacy/one.md"),
        "---\r\nstage: screening\r\n---\r\nBody\r\n",
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));

    // Model an event written by v2: it has the semantic root change and the
    // exact file hash, but predates the exact-representation witness.
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[0]);
    let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
    payload["version"] = Value::from(2);
    payload.as_object_mut().unwrap().remove("after_snapshot");
    let legacy = serde_json::to_string(&payload).unwrap();
    stored[0] = chain::stored_line(&chain::event_hash(&legacy), &legacy)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    run_success(
        database
            .command()
            .args(["update", "legacy", "one", "--set", "stage=hired"]),
    );
    run_success(database.command().args(["audit", "verify"]));

    // The compatibility exception belongs only to the v2 baseline root. A
    // forged v3 successor is still checked against its exact after hash.
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[1]);
    let forged = event
        .payload
        .replacen("\"after\":\"hired\"", "\"after\":\"forged\"", 1);
    assert_ne!(forged, event.payload);
    stored[1] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);
    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: record snapshot does not describe the replayed document",
    );
}

#[test]
fn a_legacy_noncanonical_filesystem_save_uses_the_current_file_as_its_witness() {
    let database = TestDatabase::new("legacy-filesystem-save");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    fs::write(
        database.root.join("records/items/one.md"),
        "---\r\nstage: interview\r\n---\r\nNotes\r\n",
    )
    .unwrap();
    run_success(database.command().args(["save", "items/one"]));

    // Rewrite both entries as an internally valid v2 chain. The filesystem
    // event then has no exact-format witness, exactly like one written by the
    // old `prepare_reconciled` path.
    let segment = only_segment(&database);
    let current = lines(&segment);
    let mut rewritten = Vec::new();
    let mut previous = None;
    for line in current {
        let event = chain::parse_line(&line);
        let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
        payload["version"] = Value::from(2);
        payload.as_object_mut().unwrap().remove("after_snapshot");
        payload["previous_hash"] = previous.clone().map_or(Value::Null, Value::String);
        let payload = serde_json::to_string(&payload).unwrap();
        let hash = chain::event_hash(&payload);
        rewritten.push(chain::stored_line(&hash, &payload).trim_end().to_owned());
        previous = Some(hash);
    }
    write_lines(&segment, &rewritten);
    chain::reanchor(&database.root);

    run_success(database.command().args(["audit", "verify"]));
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn a_baseline_event_is_valid_only_as_the_first_event_for_a_record() {
    let database = TestDatabase::new("late-baseline");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[1]);
    let forged = event
        .payload
        .replacen("\"action\":\"update\"", "\"action\":\"baseline\"", 1);
    assert_ne!(forged, event.payload);
    stored[1] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);
    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: baseline is not the first record event",
    );
}

#[test]
fn an_empty_baseline_cannot_claim_a_present_record_hash() {
    let database = TestDatabase::new("empty-baseline");
    fs::create_dir_all(database.root.join("records/legacy")).unwrap();
    fs::write(
        database.root.join("records/legacy/one.md"),
        "---\nstage: screening\n---\n",
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[0]);
    let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
    payload["changes"] = Value::Array(Vec::new());
    let forged = serde_json::to_string(&payload).unwrap();
    stored[0] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 1: baseline action does not match the absent-to-absent record transition",
    );
}

#[test]
fn event_actions_are_bound_to_their_record_presence_transitions() {
    for (name, setup, replacement, expected) in [
        (
            "create-as-update",
            "create",
            "update",
            "update action does not match the absent-to-present record transition",
        ),
        (
            "update-as-delete",
            "update",
            "delete",
            "delete action does not match the present-to-present record transition",
        ),
        (
            "delete-as-update",
            "delete",
            "update",
            "update action does not match the present-to-absent record transition",
        ),
    ] {
        let database = TestDatabase::new(name);
        run_success(database.command().args([
            "create",
            "items",
            "one",
            "--set",
            "stage=screening",
        ]));
        if setup == "update" {
            run_success(database.command().args([
                "update",
                "items",
                "one",
                "--set",
                "stage=hired",
            ]));
        } else if setup == "delete" {
            run_success(database.command().args(["delete", "items", "one", "--yes"]));
        }

        let segment = only_segment(&database);
        let mut stored = lines(&segment);
        let index = stored.len() - 1;
        let event = chain::parse_line(&stored[index]);
        let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
        payload["action"] = Value::String(replacement.to_owned());
        let forged = serde_json::to_string(&payload).unwrap();
        stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
            .trim_end()
            .to_owned();
        write_lines(&segment, &stored);
        chain::reanchor(&database.root);

        verify_fails_with(
            &database,
            &format!(
                "audit replay is inconsistent at sequence {}: {expected}",
                index + 1
            ),
        );
    }
}

#[test]
fn payload_versions_may_increase_but_never_decrease() {
    let database = TestDatabase::new("payload-version-decrease");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let event = chain::parse_line(&stored[1]);
    let mut payload: Value = serde_json::from_str(&event.payload).unwrap();
    payload["version"] = Value::from(2);
    let forged = serde_json::to_string(&payload).unwrap();
    stored[1] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);
    chain::reanchor(&database.root);

    verify_fails_with(
        &database,
        "audit replay is inconsistent at sequence 2: payload version decreased from 3 to 2",
    );
}

/// A line whose hash is honest but whose format version this build refuses.
#[test]
fn a_correctly_hashed_event_of_an_unsupported_version_is_refused() {
    let database = seeded("future-version");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event.payload.replacen("\"version\":3", "\"version\":99", 1);
    assert_ne!(forged, event.payload);
    stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_lines(&segment, &stored);

    verify_fails_with(&database, "unsupported audit event version 99");
}

// ---------------------------------------------------------------------------
// The set of events and segments
// ---------------------------------------------------------------------------

/// Two adjacent events swapped: the sequence is no longer monotonic.
#[test]
fn events_stored_out_of_order_are_refused() {
    let database = seeded("out-of-order");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    stored.swap(1, 2);
    write_lines(&segment, &stored);

    verify_fails_with(&database, "audit sequence gap at 2");
}

/// A removed middle event leaves a hole the sequence check finds.
#[test]
fn a_removed_middle_event_is_refused() {
    let database = seeded("removed-middle");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    stored.remove(1);
    write_lines(&segment, &stored);

    verify_fails_with(&database, "audit sequence gap at 2");
}

/// A replayed event breaks density at the point it repeats.
#[test]
fn a_duplicated_event_is_refused() {
    let database = seeded("duplicated");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    stored.push(stored.last().unwrap().clone());
    write_lines(&segment, &stored);

    verify_fails_with(&database, "audit sequence gap at 5");
}

/// A missing segment in the middle of the journal.
#[test]
fn a_missing_middle_segment_is_refused() {
    let database = FaultDatabase::new("missing-middle-segment");
    for id in ["one", "two", "three"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
    }
    fs::remove_file(&database.segments()[1]).unwrap();

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("audit segment sequence gap at 2"),
        "unexpected failure: {failure}"
    );
}

/// A segment renamed to a sequence it does not start at.
#[test]
fn a_segment_whose_name_disagrees_with_its_first_event_is_refused() {
    let database = FaultDatabase::new("renamed-segment");
    for id in ["one", "two", "three"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
    }
    let segments = database.segments();
    fs::rename(
        &segments[1],
        segments[1].with_file_name("00000000000000000009.jsonl"),
    )
    .unwrap();

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("audit segment sequence gap at 2"),
        "unexpected failure: {failure}"
    );
}

/// A segment file whose name is not a 20-digit sequence.
#[test]
fn a_segment_with_an_unparsable_name_is_refused() {
    let database = FaultDatabase::new("bad-segment-name");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    let segment = database.segments().remove(0);
    fs::copy(&segment, segment.with_file_name("0002.jsonl")).unwrap();

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("invalid audit segment filename"),
        "unexpected failure: {failure}"
    );
}

/// A file in the segment directory that is not a segment is ignored, so an
/// operator's backup copy or an interrupted staging file cannot break reads.
#[test]
fn a_non_segment_file_beside_the_segments_is_ignored() {
    let database = FaultDatabase::new("segment-litter");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    let segment = database.segments().remove(0);
    fs::copy(&segment, segment.with_extension("jsonl.backup")).unwrap();
    fs::write(
        segment.with_file_name(".cr-tmp-0123456789abcdef01234567"),
        b"staging litter",
    )
    .unwrap();

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 1 audit events"));
}

/// Cutting the head off the journal is the one attack the chain alone cannot
/// see, and the documentation says so. It is still not silent: reconciliation
/// notices the record, and an external checkpoint notices the head.
#[test]
fn a_truncated_chain_is_caught_by_reconciliation_and_by_an_external_checkpoint() {
    let database = seeded("truncated-head");
    let head = run_success(database.command().args(["audit", "head", "--json"]));
    let head: Value = serde_json::from_str(&head).unwrap();
    let head = head["hash"].as_str().unwrap().to_owned();

    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    stored.pop();
    write_lines(&segment, &stored);
    // Rolling the anchor back with the chain, for the same reason as in the
    // forged-head test: an attacker who can delete the newest event can delete
    // the newest anchor. Left in place, the anchor catches this on its own —
    // see `tests/audit_anchor.rs`.
    chain::reanchor(&database.root);

    // The record still holds the state the removed event produced.
    verify_fails_with(&database, "does not match its latest audited state");

    // Rolling the record back too makes the shortened chain self-consistent…
    fs::write(
        database.root.join("records/items/one.md"),
        "---\nstage: screening\n---\n",
    )
    .unwrap();
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 3 audit events"),
        "a rolled-back truncation verifies on its own: {verification}"
    );

    // …and only an externally held head hash catches it.
    let failure =
        run_failure(
            database
                .command()
                .args(["audit", "verify", "--expected-head", &head]),
        );
    assert!(
        failure.contains("audit head does not match expected checkpoint"),
        "unexpected failure: {failure}"
    );
}

// ---------------------------------------------------------------------------
// The write-ahead file
// ---------------------------------------------------------------------------

/// Every malformed shape of `pending.json` must be named, not guessed at.
#[test]
fn a_malformed_pending_file_is_refused_with_a_reason() {
    let database = FaultDatabase::new("malformed-pending");
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
    database.put_record("items", "one", interruption.after.as_deref());
    let good = common::fault::pending_json(&interruption.pending);

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        (
            "truncated",
            interruption.pending[..interruption.pending.len() / 2].to_vec(),
        ),
        ("an empty object", b"{}".to_vec()),
        ("an array", b"[]".to_vec()),
        ("a string", b"\"pending\"".to_vec()),
        ("trailing garbage", {
            let mut bytes = interruption.pending.clone();
            bytes.extend_from_slice(b"trailing");
            bytes
        }),
    ];
    for (field, replacement) in [
        ("target", Value::from(7)),
        ("hash", Value::Null),
        ("payload", Value::from(7)),
    ] {
        let mut broken = good.clone();
        broken[field] = replacement;
        cases.push(("a mistyped field", common::fault::pending_bytes(&broken)));
    }

    for (name, bytes) in cases {
        database.put_pending(&bytes);
        let failure = run_failure(database.command().args(["audit", "verify"]));
        assert!(
            failure.contains("the pending audit mutation is invalid"),
            "{name} was not refused as invalid: {failure}"
        );
    }
}

/// A pending file whose stored hash does not cover its payload.
#[test]
fn a_pending_file_whose_hash_does_not_cover_its_payload_is_refused() {
    let database = FaultDatabase::new("pending-hash-mismatch");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    database.put_record("items", "one", interruption.after.as_deref());

    let mut pending = common::fault::pending_json(&interruption.pending);
    pending["hash"] = Value::from(format!("sha256:{}", "0".repeat(64)));
    database.put_pending(&common::fault::pending_bytes(&pending));
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("pending audit mutation hash does not match its payload"),
        "unexpected failure: {failure}"
    );

    // Rewriting the payload and re-hashing it does not help either: the payload
    // no longer agrees with the state hashes stored beside it.
    let mut pending = common::fault::pending_json(&interruption.pending);
    let payload =
        pending["payload"]
            .as_str()
            .unwrap()
            .replacen("\"sequence\":1", "\"sequence\":9", 1);
    pending["hash"] = Value::from(chain::event_hash(&payload));
    pending["payload"] = Value::from(payload);
    database.put_pending(&common::fault::pending_bytes(&pending));
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("does not extend the current chain head"),
        "unexpected failure: {failure}"
    );
}

/// A pending payload that is not itself valid JSON.
#[test]
fn a_pending_file_carrying_an_unparsable_payload_is_refused() {
    let database = FaultDatabase::new("pending-bad-payload");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    let mut pending = common::fault::pending_json(&interruption.pending);
    pending["payload"] = Value::from("{not json");
    database.put_pending(&common::fault::pending_bytes(&pending));

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("pending audit payload is invalid"),
        "unexpected failure: {failure}"
    );
}

/// A pending file that points anywhere but at its own record.
#[test]
fn a_pending_file_whose_target_is_not_its_record_is_refused() {
    let database = FaultDatabase::new("pending-target");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    database.put_record("items", "one", interruption.after.as_deref());

    for (target, expected) in [
        (
            "../../escape.md",
            "pending audit target must be a safe relative path",
        ),
        (
            "/etc/passwd",
            "pending audit target must be a safe relative path",
        ),
        (
            "records/items/other.md",
            "pending audit mutation target does not match its record identity",
        ),
        (
            "records/other/one.md",
            "pending audit mutation target does not match its record identity",
        ),
    ] {
        let mut pending = common::fault::pending_json(&interruption.pending);
        pending["target"] = Value::from(target);
        database.put_pending(&common::fault::pending_bytes(&pending));
        let failure = run_failure(database.command().args(["audit", "verify"]));
        assert!(
            failure.contains(expected),
            "target '{target}' was not refused with '{expected}': {failure}"
        );
    }
}

/// A pending file whose state hashes disagree with the payload they describe.
#[test]
fn a_pending_file_whose_state_hashes_disagree_with_its_payload_is_refused() {
    let database = FaultDatabase::new("pending-state-hashes");
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
    database.put_record("items", "one", interruption.after.as_deref());

    for field in ["before_hash", "after_hash"] {
        let mut pending = common::fault::pending_json(&interruption.pending);
        pending[field] = Value::from(format!("sha256:{}", "1".repeat(64)));
        database.put_pending(&common::fault::pending_bytes(&pending));
        let failure = run_failure(database.command().args(["audit", "verify"]));
        assert!(
            failure.contains("pending audit mutation state hashes are inconsistent"),
            "'{field}' was not refused: {failure}"
        );
    }
}

/// A pending file naming a record identity that is not a safe path component.
#[test]
fn a_pending_file_naming_an_unsafe_record_identity_is_refused() {
    let database = FaultDatabase::new("pending-identity");
    let interruption = database.interrupt(
        "items",
        "one",
        &["create", "items", "one", "--set", "stage=screening"],
    );
    let mut pending = common::fault::pending_json(&interruption.pending);
    let payload = pending["payload"].as_str().unwrap().replacen(
        "\"collection\":\"items\"",
        "\"collection\":\"..\"",
        1,
    );
    pending["hash"] = Value::from(chain::event_hash(&payload));
    pending["payload"] = Value::from(payload);
    database.put_pending(&common::fault::pending_bytes(&pending));

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("collection"),
        "unexpected failure: {failure}"
    );
}

/// Verification stops at the first record that disagrees with the chain, so
/// which one it names has to be a property of the database and not of a hash
/// map's iteration order. Before the sorted iteration in `verify_records` this
/// reported a different record on most runs.
#[test]
fn verification_names_the_same_divergent_record_on_every_run() {
    let database = TestDatabase::new("divergence-order");
    for id in ["one", "two", "three", "four", "five", "six"] {
        run_success(
            database
                .command()
                .args(["create", "items", id, "--set", "stage=screening"]),
        );
    }
    for id in ["two", "four", "six"] {
        fs::write(
            database.root.join(format!("records/items/{id}.md")),
            "---\nstage: edited\n---\n",
        )
        .unwrap();
    }

    let first = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        first.contains("does not match its latest audited state"),
        "unexpected failure: {first}"
    );
    for _ in 0..24 {
        assert_eq!(
            run_failure(database.command().args(["audit", "verify"])),
            first,
            "verification named a different record on a later run"
        );
    }
}
