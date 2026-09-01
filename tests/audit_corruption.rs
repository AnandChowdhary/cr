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
/// chain has to, through the next event's `previous_hash`.
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

    verify_fails_with(&database, "audit hash chain is broken at sequence 3");
}

/// Forging the *newest* event, where nothing follows to link it.
///
/// This is the weakest point of the chain and the test says so out loud. The
/// linkage that protects every other event does not exist here, and only two
/// things push back: the replay checks each change's `before` value against the
/// state it reconstructed, and `verify_records` pins `after_hash` to the file on
/// disk. Everything else in the head event — actor, timestamp, message,
/// attribution, and the `after` value of every change — can be rewritten and
/// re-hashed, and `cr audit verify` will call the database clean.
///
/// See `docs/architecture.md` (threat boundary) and the `TODO.md` entry it
/// references: the mitigation is an externally held head hash, exactly as it is
/// for the removal of final events.
#[test]
fn a_forged_head_event_is_accepted_by_verification_and_caught_only_by_a_checkpoint() {
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
    let checkpoint = run_success(database.command().args(["audit", "head", "--json"]));
    let checkpoint: Value = serde_json::from_str(&checkpoint).unwrap();
    let checkpoint = checkpoint["hash"].as_str().unwrap().to_owned();

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

    // The bad news, asserted rather than glossed over.
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 2 audit events and 1 records"));
    assert_eq!(run_success(database.command().arg("status")), "Clean\n");
    let log = run_success(database.command().args(["audit", "log", "--json"]));
    let log: Value = serde_json::from_str(&log).unwrap();
    assert_eq!(log[0]["actor"], "mallory");
    assert_eq!(log[0]["changes"][0]["after"], "never happened");

    // The good news: the head hash moved, so a checkpoint held outside the
    // database catches it — the same mitigation as for a truncated chain.
    let failure =
        run_failure(
            database
                .command()
                .args(["audit", "verify", "--expected-head", &checkpoint]),
        );
    assert!(
        failure.contains("audit head does not match expected checkpoint"),
        "unexpected failure: {failure}"
    );

    // A further mutation is accepted too, because a write replays the hash
    // chain but not the per-record change sets. The tamper only surfaces on the
    // next `audit verify`, by which point it is reported against the newer
    // event rather than the forged one.
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=offer"]),
    );
    verify_fails_with(&database, "audit changes are inconsistent at sequence 3");
}

/// The property the previous test shows `cr` does not have.
///
/// Detecting a forged head event without an external checkpoint means checking
/// the replayed document against `after_hash` rather than only its presence.
/// That is not a small change: the replay produces a semantic document, and
/// re-rendering it to Markdown is not byte-identical for records introduced by
/// `audit baseline`, which is why the implementation stops where it does. Left
/// failing on purpose; see the `TODO.md` entry.
#[test]
#[ignore = "known gap: verification cross-checks after_hash against the file, not against the replayed document"]
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

    verify_fails_with(&database, "audit");
}

/// A line whose hash is honest but whose format version this build refuses.
#[test]
fn a_correctly_hashed_event_of_an_unsupported_version_is_refused() {
    let database = seeded("future-version");
    let segment = only_segment(&database);
    let mut stored = lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event.payload.replacen("\"version\":2", "\"version\":99", 1);
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
