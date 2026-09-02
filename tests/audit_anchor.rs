//! The audit anchor: what it catches, what it does not, and how it tells a
//! lagging anchor apart from a rewritten journal.
//!
//! The newest event in the journal is pinned by nothing. Record-state replay
//! now catches a forged result, but
//! `audit_corruption.rs::a_forged_head_actor_still_needs_an_external_checkpoint`
//! specifies the non-state metadata gap this file still closes. It does so
//! *only* to the extent that the anchor itself is held somewhere the forger
//! cannot reach, which in practice means committed and pushed to Git. Every
//! test here is written so that it says which boundary it is proving.
//!
//! The distinction the whole design turns on is stale versus tampered. An
//! anchor may legitimately lag — a crash between appending the event and
//! rewriting the anchor leaves exactly that — and a lag must never be reported
//! as, or confused with, altered history. Both cases are constructed below.

mod common;

use std::{fs, path::Path, process::Command};

use common::{TestDatabase, chain, run_failure, run_success};
use serde_json::Value;

/// One create and one attributed update, the same seed the forged-head
/// specification uses.
fn seeded(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
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
    database
}

fn only_segment(database: &TestDatabase) -> std::path::PathBuf {
    let mut segments = chain::segment_paths(&database.root);
    assert_eq!(segments.len(), 1, "the seed fits in one segment");
    segments.remove(0)
}

fn segment_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_segment_lines(path: &Path, lines: &[String]) {
    let mut contents = String::new();
    for line in lines {
        contents.push_str(line);
        contents.push('\n');
    }
    fs::write(path, contents).unwrap();
}

/// Rewrite the newest event's actor, message, and result, and re-hash it.
///
/// Byte for byte the forgery from the specification test, minus its second
/// move: this one leaves the anchor alone.
fn forge_head_event(database: &TestDatabase) {
    let segment = only_segment(database);
    let mut stored = segment_lines(&segment);
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event
        .payload
        .replacen("\"actor\":\"alice\"", "\"actor\":\"mallory\"", 1)
        .replacen("reviewed and approved", "rubber stamped", 1);
    assert_ne!(forged, event.payload, "the seed must contain those values");
    stored[index] = chain::stored_line(&chain::event_hash(&forged), &forged)
        .trim_end()
        .to_owned();
    write_segment_lines(&segment, &stored);
}

fn check_report(database: &TestDatabase) -> Value {
    let output = database
        .command()
        .args(["check", "--json"])
        .output()
        .expect("failed to run cr");
    serde_json::from_slice(&output.stdout).expect("check emits JSON")
}

fn findings_of(report: &Value, kind: &str) -> Vec<Value> {
    report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .filter(|finding| finding["kind"] == kind)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// The forgery the anchor exists to catch
// ---------------------------------------------------------------------------

/// The head event is forged and re-hashed, and the anchor is left alone.
///
/// This is the adversarial case replay cannot derive from record state: actor
/// and message changed while the result stayed exact. Only a checkpoint can
/// catch it. `verify` does so with no argument and says specifically that the
/// journal disagrees with the anchor rather than that its state replay is
/// corrupt — because replay is internally consistent.
///
/// What this proves is bounded, and the companion assertion at the end says so:
/// the anchor caught this only because the forger did not rewrite it too. See
/// the specification test for the case where they do.
#[test]
fn a_forged_head_event_is_caught_by_the_anchor_without_an_external_checkpoint() {
    let database = seeded("anchor-forged-head");
    let anchored = chain::read_anchor(&database.root).expect("a mutation writes the anchor");
    forge_head_event(&database);

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("does not match the audit anchor"),
        "unexpected failure: {failure}"
    );
    assert!(
        failure.contains(anchored["hash"].as_str().unwrap()),
        "the failure must name the hash that was anchored: {failure}"
    );
    assert!(
        !failure.contains("hash chain is broken"),
        "an anchor mismatch must not be reported as chain damage: {failure}"
    );

    // `check` classifies it as its own finding rather than as chain damage,
    // and at error severity, so `cr check` in CI fails on it by default.
    let report = check_report(&database);
    let findings = findings_of(&report, "audit_anchor_mismatch");
    assert_eq!(findings.len(), 1, "expected one finding: {report}");
    assert_eq!(findings[0]["severity"], "error");
    assert!(
        findings_of(&report, "audit_chain_broken").is_empty(),
        "the chain itself is intact: {report}"
    );

    // And the honest boundary: rewriting the anchor in the same pass, which
    // costs an attacker with write access nothing, restores the old silence.
    chain::reanchor(&database.root);
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 2 audit events"));
}

/// Cutting the newest event off the journal while the anchor still names it.
///
/// The anchor attests to a sequence the journal no longer reaches. That is not
/// a lag — a lagging anchor is always *behind* the journal, never ahead of it —
/// so it is reported as a mismatch.
#[test]
fn an_anchor_that_outlives_the_events_it_names_is_a_mismatch() {
    let database = seeded("anchor-truncated");
    let segment = only_segment(&database);
    let mut stored = segment_lines(&segment);
    stored.pop();
    write_segment_lines(&segment, &stored);
    // Roll the record back too, so the shortened chain is self-consistent and
    // reconciliation has nothing to say. Without the anchor this verifies.
    fs::write(
        database.root.join("records/items/one.md"),
        "---\nstage: screening\n---\n",
    )
    .unwrap();

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("attests to sequence 2 but the journal ends at sequence 1"),
        "unexpected failure: {failure}"
    );
}

// ---------------------------------------------------------------------------
// Stale is not tampered
// ---------------------------------------------------------------------------

/// An anchor left behind by a crash between the append and the anchor write.
///
/// This is the design's main risk and the reason the anchor records a
/// *sequence* as well as a hash. The journal is append-only and hash-linked, so
/// the event at that sequence is fixed forever: an anchor that lags still finds
/// its own hash there, and a journal that was rewritten does not. The two are
/// therefore separable exactly, and this reports as a pass with a notice rather
/// than as a failure.
#[test]
fn a_stale_anchor_reports_that_it_is_behind_rather_than_tampered() {
    let database = seeded("anchor-stale");
    let lagging = fs::read_to_string(database.root.join(chain::ANCHOR_PATH)).unwrap();

    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=offer"]),
    );
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=closed"]),
    );
    // Exactly what a crash after the segment write and before the anchor write
    // leaves behind: the journal moved on, the anchor did not.
    chain::write_anchor(&database.root, &lagging);

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        verification.contains("Verified 4 audit events"),
        "a lagging anchor is not a verification failure: {verification}"
    );
    assert!(
        verification.contains("the audit anchor is behind at sequence 2 of 4"),
        "verify must say how far behind it is: {verification}"
    );
    assert!(
        verification.contains("lagging anchor rather than altered history"),
        "verify must not let a lag read as tampering: {verification}"
    );

    // `check` says the same thing at warning severity, so it does not fail a
    // build the way a mismatch does.
    let report = check_report(&database);
    let findings = findings_of(&report, "audit_anchor_behind");
    assert_eq!(findings.len(), 1, "expected one finding: {report}");
    assert_eq!(findings[0]["severity"], "warning");
    assert_eq!(report["summary"]["errors"], 0);

    // The remaining exposure is stated rather than hidden: only the events up
    // to the anchored sequence are pinned, so the tail is as exposed as it was
    // before the anchor existed. Forging *within* the anchored prefix is still
    // caught.
    let anchor = run_success(database.command().args(["audit", "anchor", "--json"]));
    let anchor: Value = serde_json::from_str(&anchor).unwrap();
    assert_eq!(anchor["status"]["state"], "behind");
    assert_eq!(anchor["status"]["sequence"], 2);
    assert_eq!(anchor["status"]["head"], 4);

    // And it is repairable without a mutation.
    run_success(database.command().args(["audit", "anchor", "--write"]));
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(
        !verification.contains("notice:"),
        "a repaired anchor has nothing to report: {verification}"
    );
}

/// A lagging anchor still pins everything up to its own sequence.
///
/// The point of separating "behind" from "mismatched" is not leniency. The
/// anchored prefix keeps its full guarantee and only the tail past it is
/// unpinned, so an attacker who rewrites history *inside* the prefix is caught
/// even though the anchor is out of date.
#[test]
fn a_lagging_anchor_still_catches_a_forgery_inside_the_prefix_it_covers() {
    let database = seeded("anchor-stale-prefix");
    let lagging = fs::read_to_string(database.root.join(chain::ANCHOR_PATH)).unwrap();
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=offer"]),
    );
    chain::write_anchor(&database.root, &lagging);

    // Rewrite event 2 and relink event 3 onto it, so the chain is internally
    // perfect and the record replay is untouched. Without the anchor this
    // verifies cleanly; the anchor names sequence 2 and does not.
    let segment = only_segment(&database);
    let mut stored = segment_lines(&segment);
    assert_eq!(stored.len(), 3, "the seed is three events");
    let second = chain::parse_line(&stored[1]);
    let forged = second
        .payload
        .replacen("\"actor\":\"alice\"", "\"actor\":\"mallory\"", 1);
    assert_ne!(forged, second.payload, "the seed must contain that actor");
    let forged_hash = chain::event_hash(&forged);
    stored[1] = chain::stored_line(&forged_hash, &forged)
        .trim_end()
        .to_owned();
    let third = chain::parse_line(&stored[2]);
    let relinked = third
        .payload
        .replacen(second.hash.as_str(), forged_hash.as_str(), 1);
    assert_ne!(relinked, third.payload, "event 3 names event 2");
    stored[2] = chain::stored_line(&chain::event_hash(&relinked), &relinked)
        .trim_end()
        .to_owned();
    write_segment_lines(&segment, &stored);

    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("at sequence 2 does not match the audit anchor"),
        "unexpected failure: {failure}"
    );
    assert!(
        !failure.contains("hash chain is broken"),
        "the relinked chain is internally consistent: {failure}"
    );
}

// ---------------------------------------------------------------------------
// Absent, overridden, and unreadable
// ---------------------------------------------------------------------------

/// A database that predates the anchor keeps working, and is told.
///
/// Failing here would break every existing database on upgrade for a property
/// none of them ever had. It passes with a notice instead — and the notice is
/// the point, because an absent anchor is exactly the pre-anchor exposure.
#[test]
fn an_absent_anchor_verifies_with_a_notice_rather_than_failing() {
    let database = seeded("anchor-absent");
    chain::remove_anchor(&database.root);

    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 2 audit events"));
    assert!(
        verification.contains("no audit anchor is recorded"),
        "an unanchored head must be reported: {verification}"
    );

    let report = check_report(&database);
    let findings = findings_of(&report, "audit_anchor_missing");
    assert_eq!(findings.len(), 1, "expected one finding: {report}");
    assert_eq!(findings[0]["severity"], "warning");

    // Adopting it is one command, and the notice goes away.
    run_success(database.command().args(["audit", "anchor", "--write"]));
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(!verification.contains("notice:"), "{verification}");
}

/// An empty journal has nothing to anchor and says nothing about it.
#[test]
fn an_empty_journal_reports_no_anchor_notice() {
    let database = TestDatabase::new("anchor-empty");
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(!verification.contains("notice:"), "{verification}");
    assert_eq!(report_findings_count(&database, "audit_anchor_missing"), 0);

    let failure = run_failure(database.command().args(["audit", "anchor", "--write"]));
    assert!(
        failure.contains("no audit events to anchor"),
        "unexpected failure: {failure}"
    );
}

fn report_findings_count(database: &TestDatabase, kind: &str) -> usize {
    findings_of(&check_report(database), kind).len()
}

/// An explicit checkpoint outranks the recorded anchor.
///
/// The flag arrives from outside the database; the file sits inside the blast
/// radius of anybody who can edit the journal. A caller holding an out-of-band
/// value must not have their answer decided by an in-band file.
#[test]
fn an_explicit_expected_head_wins_over_the_recorded_anchor() {
    let database = seeded("anchor-overridden");
    let head = run_success(database.command().args(["audit", "head", "--json"]));
    let head: Value = serde_json::from_str(&head).unwrap();
    let head = head["hash"].as_str().unwrap().to_owned();

    // A nonsense anchor that would fail the default check.
    chain::write_anchor(
        &database.root,
        "{\n  \"version\": 1,\n  \"sequence\": 1,\n  \"hash\": \"sha256:0\",\n  \"timestamp\": \"2020-01-01T00:00:00Z\"\n}\n",
    );
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(failure.contains("audit anchor"), "{failure}");

    let verification =
        run_success(
            database
                .command()
                .args(["audit", "verify", "--expected-head", &head]),
        );
    assert!(verification.contains("Verified 2 audit events"));
    assert!(
        verification.contains("was not consulted"),
        "the override must be stated, not silent: {verification}"
    );
}

/// Scribbling on the anchor is a refusal, not a downgrade to "absent".
///
/// Treating an unreadable anchor as missing would let one stray byte silently
/// turn the default check off.
#[test]
fn an_unreadable_anchor_is_refused_rather_than_treated_as_absent() {
    let database = seeded("anchor-unreadable");
    chain::write_anchor(&database.root, "not json at all\n");
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("not a readable checkpoint"),
        "unexpected failure: {failure}"
    );

    chain::write_anchor(
        &database.root,
        "{\n  \"version\": 99,\n  \"sequence\": 2,\n  \"hash\": \"sha256:0\",\n  \"timestamp\": \"2020-01-01T00:00:00Z\"\n}\n",
    );
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("checkpoint format version 99"),
        "unexpected failure: {failure}"
    );
}

/// `cr` must not be the tool that launders a forgery into a fresh attestation.
#[test]
fn rewriting_the_anchor_is_refused_while_it_disagrees_with_the_journal() {
    let database = seeded("anchor-no-laundering");
    forge_head_event(&database);

    let failure = run_failure(database.command().args(["audit", "anchor", "--write"]));
    assert!(
        failure.contains("does not match the audit anchor"),
        "unexpected failure: {failure}"
    );
    // And the anchor is unchanged, so the evidence survives the attempt.
    let failure = run_failure(database.command().args(["audit", "verify"]));
    assert!(
        failure.contains("does not match the audit anchor"),
        "{failure}"
    );
}

// ---------------------------------------------------------------------------
// Every path that advances the chain maintains the anchor
// ---------------------------------------------------------------------------

/// `create`, `update`, `save`, and `audit baseline` all move the head, so all
/// of them must move the anchor. They share one append, and this pins that.
#[test]
fn every_command_that_extends_the_chain_advances_the_anchor() {
    let database = TestDatabase::new("anchor-every-path");
    let mut expected = 0;
    let mut assert_anchored = |label: &str| {
        expected += 1;
        let anchor = chain::read_anchor(&database.root).expect("an anchor exists");
        let head = chain::assert_chain_is_well_formed(&database.root).expect("a head exists");
        assert_eq!(anchor["sequence"], expected, "after {label}");
        assert_eq!(anchor["hash"], head, "after {label}");
        assert_eq!(anchor["version"], 1, "after {label}");
    };

    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    assert_anchored("create");

    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=hired"]),
    );
    assert_anchored("update");

    fs::write(
        database.root.join("records/items/one.md"),
        "---\nstage: offer\n---\n",
    )
    .unwrap();
    run_success(database.command().args(["save", "items/one"]));
    assert_anchored("save");

    fs::write(
        database.root.join("records/items/two.md"),
        "---\nstage: screening\n---\n",
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));
    assert_anchored("audit baseline");

    run_success(database.command().args(["delete", "items", "two", "--yes"]));
    assert_anchored("delete");

    // And the whole database still verifies with no notice at all.
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(!verification.contains("notice:"), "{verification}");
}

// ---------------------------------------------------------------------------
// The file itself
// ---------------------------------------------------------------------------

/// One small file, stable field order, newline-terminated, no timestamp of its
/// own — so a commit diff shows the head hash moving and a reviewer can reason
/// about it. Every field is derived from the journal, so two databases holding
/// the same journal hold the same anchor.
#[test]
fn the_anchor_is_a_small_derived_file_with_a_reviewable_shape() {
    let database = seeded("anchor-shape");
    let contents = fs::read_to_string(database.root.join(chain::ANCHOR_PATH)).unwrap();
    assert!(
        contents.ends_with("}\n"),
        "the anchor must be newline-terminated: {contents:?}"
    );
    assert_eq!(
        contents.lines().count(),
        6,
        "one field per line keeps the diff readable: {contents:?}"
    );
    let order: Vec<&str> = contents
        .lines()
        .filter_map(|line| line.split('"').nth(1))
        .collect();
    assert_eq!(
        order,
        ["version", "sequence", "hash", "timestamp"],
        "field order must be stable so a diff shows only what changed"
    );

    // The timestamp is the anchored *event's*, never "now", which is what makes
    // the file a pure function of the journal.
    let anchor = chain::read_anchor(&database.root).unwrap();
    let events = chain::read_chain(&database.root);
    let head = events.last().unwrap();
    assert_eq!(anchor["timestamp"], head.parsed["timestamp"]);
    assert_eq!(anchor["hash"], head.hash);
    assert_eq!(anchor["sequence"], head.sequence());
}

/// The anchor is worthless unless Git actually carries it.
///
/// `cr init` must not write a `.gitignore`, and the repository's own
/// `.gitignore` must not exclude the anchor. Checked against real Git rather
/// than by reading patterns, because the question is what Git does.
#[test]
fn the_anchor_is_tracked_by_git_and_excluded_by_nothing() {
    let database = seeded("anchor-git");
    assert!(
        !database.root.join(".gitignore").exists(),
        "cr init must not write a .gitignore that could exclude the anchor"
    );
    assert!(database.root.join(chain::ANCHOR_PATH).exists());

    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping the Git assertions: git is not on PATH");
        return;
    }

    let repository = env!("CARGO_MANIFEST_DIR");
    let ignore = fs::read_to_string(Path::new(repository).join(".gitignore")).unwrap();
    fs::write(database.root.join(".gitignore"), &ignore).unwrap();

    let git = |arguments: &[&str]| {
        let output = Command::new("git")
            .current_dir(&database.root)
            .args(arguments)
            .output()
            .expect("git runs");
        assert!(
            output.status.success(),
            "git {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("git output is UTF-8")
    };
    git(&["init", "--quiet"]);

    let status = git(&["status", "--porcelain", "--untracked-files=all"]);
    assert!(
        status.contains(chain::ANCHOR_PATH),
        "Git must see the anchor as an ordinary untracked file: {status}"
    );
    let ignored = Command::new("git")
        .current_dir(&database.root)
        .args(["check-ignore", "--quiet", chain::ANCHOR_PATH])
        .status()
        .expect("git runs");
    assert!(
        !ignored.success(),
        "the anchor must not match any ignore rule"
    );
}

/// No anchor message names anything path-shaped.
///
/// `check_cli.rs::no_finding_ever_names_a_filesystem_path` holds this for the
/// findings it constructs; the anchor findings and the `audit verify` and
/// `audit anchor` failures are constructed here. The anchor file's name is
/// documentation, not diagnostics: it belongs in `--help` and the README, and
/// nowhere a remote caller can receive it.
#[test]
fn no_anchor_message_names_a_path_or_a_directory() {
    let assert_clean = |root: &Path, message: &str| {
        let root = root.to_string_lossy().to_string();
        assert!(
            !message.contains(&root),
            "named the database root: {message}"
        );
        assert!(
            !message.contains("records/") && !message.contains(".cr/"),
            "named a directory inside the database: {message}"
        );
        for token in message.split(|character: char| character.is_whitespace() || character == '\'')
        {
            assert!(
                !(token.contains('/') && token.ends_with(".md")),
                "named a filesystem path: {message}"
            );
        }
    };

    // Mismatched.
    let database = seeded("anchor-no-paths-mismatch");
    forge_head_event(&database);
    assert_clean(
        &database.root,
        &run_failure(database.command().args(["audit", "verify"])),
    );
    assert_clean(
        &database.root,
        &run_failure(database.command().args(["audit", "anchor"])),
    );
    for finding in findings_of(&check_report(&database), "audit_anchor_mismatch") {
        assert_clean(&database.root, finding["message"].as_str().unwrap());
    }

    // Unreadable, and a version from the future.
    chain::write_anchor(&database.root, "{\n");
    assert_clean(
        &database.root,
        &run_failure(database.command().args(["audit", "verify"])),
    );

    // Missing and behind, which are notices rather than failures.
    let database = seeded("anchor-no-paths-notice");
    let lagging = fs::read_to_string(database.root.join(chain::ANCHOR_PATH)).unwrap();
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=offer"]),
    );
    chain::write_anchor(&database.root, &lagging);
    assert_clean(
        &database.root,
        &run_success(database.command().args(["audit", "verify"])),
    );
    for kind in ["audit_anchor_behind", "audit_anchor_missing"] {
        for finding in findings_of(&check_report(&database), kind) {
            assert_clean(&database.root, finding["message"].as_str().unwrap());
        }
    }
    chain::remove_anchor(&database.root);
    assert_clean(
        &database.root,
        &run_success(database.command().args(["audit", "verify"])),
    );
    for finding in findings_of(&check_report(&database), "audit_anchor_missing") {
        assert_clean(&database.root, finding["message"].as_str().unwrap());
    }
}
