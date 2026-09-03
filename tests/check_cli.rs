//! `cr check` — whole-database integrity reporting.
//!
//! Every positive test builds a database that genuinely exhibits its finding
//! class rather than asserting on a hand-written report, and
//! [`a_healthy_database_reports_nothing`] is the counterweight that keeps them
//! honest: a check that fires on a working database is worse than no check.

mod common;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use common::{TestDatabase, binary, clear_attribution_environment, run_success};
use serde_json::Value;

/// Exit status for "ran successfully, found problems".
const FOUND_PROBLEMS: i32 = 2;

struct CheckRun {
    status: i32,
    stdout: String,
    stderr: String,
}

impl CheckRun {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|error| panic!("check output was not JSON: {error}\n{}", self.stdout))
    }

    /// Every finding of one kind, in report order.
    fn findings(&self, kind: &str) -> Vec<Value> {
        self.json()["findings"]
            .as_array()
            .expect("findings is an array")
            .iter()
            .filter(|finding| finding["kind"] == kind)
            .cloned()
            .collect()
    }

    fn kinds(&self) -> Vec<String> {
        self.json()["findings"]
            .as_array()
            .expect("findings is an array")
            .iter()
            .map(|finding| finding["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    fn one(&self, kind: &str) -> Value {
        let found = self.findings(kind);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one {kind} finding, got {found:#?}\nreport:\n{}",
            self.stdout
        );
        found.into_iter().next().unwrap()
    }
}

fn check(database: &Path, arguments: &[&str]) -> CheckRun {
    let mut command = Command::new(binary());
    clear_attribution_environment(&mut command);
    command.arg("--database").arg(database).arg("check");
    command.args(arguments);
    let output = command.output().expect("failed to run cr check");
    CheckRun {
        status: output
            .status
            .code()
            .expect("cr check was killed by a signal"),
        stdout: String::from_utf8(output.stdout).expect("stdout was not UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr was not UTF-8"),
    }
}

/// A small database with two collections and one honest relation.
fn seeded() -> TestDatabase {
    let database = TestDatabase::new("check");
    run_success(
        database
            .command()
            .args(["create", "companies", "acme", "--set", "name=Acme"]),
    );
    run_success(database.command().args([
        "create",
        "deals",
        "acme-renewal",
        "--set",
        "value=1000",
    ]));
    run_success(database.command().args([
        "link",
        "deals",
        "acme-renewal",
        "company",
        "companies",
        "acme",
    ]));
    database
}

fn record_path(database: &TestDatabase, collection: &str, id: &str) -> PathBuf {
    database
        .root
        .join("records")
        .join(collection)
        .join(format!("{id}.md"))
}

#[test]
fn a_healthy_database_reports_nothing() {
    let database = seeded();

    let run = check(&database.root, &[]);
    assert_eq!(run.status, 0, "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("No problems found."), "{}", run.stdout);
    assert!(
        run.stdout
            .contains("Checked 2 collections: 2 records on disk, 2 audited records."),
        "{}",
        run.stdout
    );

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.json()["findings"], serde_json::json!([]));
    assert_eq!(run.json()["summary"]["errors"], 0);
    assert_eq!(run.json()["summary"]["warnings"], 0);
    assert_eq!(run.json()["summary"]["records"], 2);
    assert_eq!(run.json()["summary"]["audited_records"], 2);

    // Nothing is reported even when the strictest threshold is asked for.
    assert_eq!(check(&database.root, &["--fail-on", "warning"]).status, 0);
}

#[test]
fn an_empty_database_is_clean_rather_than_suspicious() {
    let database = TestDatabase::new("check-empty");
    let run = check(&database.root, &[]);
    assert_eq!(run.status, 0, "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("No problems found."), "{}", run.stdout);
}

#[test]
fn a_relation_whose_target_was_deleted_is_reported_as_dangling() {
    let database = seeded();
    // Delete through the database so the journal stays consistent: the only
    // problem left is the relation nobody updated.
    run_success(
        database
            .command()
            .args(["delete", "companies", "acme", "--yes"]),
    );

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("dangling_link");
    assert_eq!(finding["severity"], "error");
    assert_eq!(finding["collection"], "deals");
    assert_eq!(finding["id"], "acme-renewal");
    assert_eq!(finding["field"], "relations.company[0]");
    assert_eq!(finding["target"], "companies/acme");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("companies/acme, which does not exist"),
        "{finding:#?}"
    );

    // Deleting through the database leaves nothing else wrong.
    assert_eq!(run.kinds(), vec!["dangling_link"]);
}

#[test]
fn relation_values_that_are_not_references_are_reported_as_malformed() {
    let database = seeded();
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "---\nvalue: 1000\nrelations:\n  company:\n    - collection: companies\n      id: 42\n  owner: not-a-list\n  vendors:\n    - companies/acme\n---\n",
    )
    .unwrap();
    fs::write(
        record_path(&database, "deals", "other"),
        "---\nrelations: nope\n---\n",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let malformed = run.findings("malformed_relation");
    let by_field: BTreeMap<_, _> = malformed
        .iter()
        .map(|finding| {
            (
                finding["field"].as_str().unwrap_or("(none)").to_owned(),
                finding["message"].as_str().unwrap().to_owned(),
            )
        })
        .collect();

    assert!(
        by_field["relations.company[0]"].contains("its 'id' is a number, not a string"),
        "{by_field:#?}"
    );
    assert!(
        by_field["relations.owner"].contains("as a string, but a relation must be a list"),
        "{by_field:#?}"
    );
    assert!(
        by_field["relations.vendors[0]"].contains("it is a string, not an object"),
        "{by_field:#?}"
    );
    assert!(
        by_field["relations"].contains("relations must be an object"),
        "{by_field:#?}"
    );
    assert!(
        malformed
            .iter()
            .all(|finding| finding["severity"] == "error"),
        "{malformed:#?}"
    );
}

#[test]
fn a_relation_annotated_with_extra_keys_is_still_a_reference() {
    let database = seeded();
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "---\nvalue: 1000\nrelations:\n  company:\n    - collection: companies\n      id: acme\n      role: primary\n---\n",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    assert!(
        run.findings("malformed_relation").is_empty(),
        "an annotated reference is not malformed:\n{}",
        run.stdout
    );
    assert!(run.findings("dangling_link").is_empty(), "{}", run.stdout);
}

#[test]
fn records_written_before_a_schema_existed_are_reported_against_it() {
    let database = seeded();
    // The common real case: the model changes after the records were written.
    fs::write(
        database.root.join(".cr/schemas/deals.json"),
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["stage"],"properties":{"stage":{"enum":["open","won"]}}}"#,
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("schema_violation");
    assert_eq!(finding["severity"], "error");
    assert_eq!(finding["collection"], "deals");
    assert_eq!(finding["id"], "acme-renewal");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("does not match the schema for collection 'deals'"),
        "{finding:#?}"
    );
    // The schemaless collection beside it stays clean.
    assert!(
        run.findings("schema_violation")
            .iter()
            .all(|finding| finding["collection"] == "deals")
    );
}

#[test]
fn a_false_boolean_schema_is_a_rejecting_schema_not_an_unusable_one() {
    let database = TestDatabase::new("check-false-boolean-schema");
    run_success(
        database
            .command()
            .args(["create", "closed", "legacy", "--set", "value=1"]),
    );
    fs::write(database.root.join(".cr/schemas/closed.json"), "false\n").unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    assert!(run.findings("unusable_schema").is_empty(), "{}", run.stdout);
    let finding = run.one("schema_violation");
    assert_eq!(finding["collection"], "closed");
    assert_eq!(finding["id"], "legacy");
}

#[test]
fn an_unusable_schema_is_reported_once_rather_than_once_per_record() {
    let database = seeded();
    run_success(database.command().args([
        "create",
        "deals",
        "globex-expansion",
        "--set",
        "value=2",
    ]));
    fs::write(
        database.root.join(".cr/schemas/deals.json"),
        "{ this is not JSON",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("unusable_schema");
    assert_eq!(finding["collection"], "deals");
    assert_eq!(finding["id"], Value::Null);
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("not valid JSON"),
        "{finding:#?}"
    );
    assert!(
        run.findings("schema_violation").is_empty(),
        "{}",
        run.stdout
    );
}

#[test]
fn a_markdown_file_that_cannot_be_a_record_id_is_reported_by_name() {
    let database = seeded();
    fs::write(
        database.root.join("records/deals/..md"),
        "---\nvalue: 1\n---\n",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("invalid_record_name");
    assert_eq!(finding["severity"], "error");
    assert_eq!(finding["collection"], "deals");
    let message = finding["message"].as_str().unwrap();
    assert!(message.contains("cannot be a record ID"), "{finding:#?}");
    // Which file. Every other command refuses this database with this same
    // sentence, so the finding is also the repair instruction.
    assert!(message.contains("'..md'"), "{finding:#?}");
}

/// `check` is the tool that explains a database nothing else will touch, so it
/// has to survive exactly the names that stop everything else.
#[test]
fn check_still_enumerates_a_database_that_every_other_command_refuses() {
    let database = seeded();
    fs::write(
        database.root.join("records/deals/..md"),
        "---\nvalue: 1\n---\n",
    )
    .unwrap();

    // The premise: this database is wedged for every enumerating command.
    for arguments in [
        ["list", "deals"].as_slice(),
        ["status"].as_slice(),
        ["audit", "verify"].as_slice(),
    ] {
        let mut command = database.command();
        let output = command.args(arguments).output().unwrap();
        assert!(
            !output.status.success(),
            "cr {} unexpectedly succeeded",
            arguments.join(" ")
        );
    }

    // `check` reports it and keeps going: both healthy records are still read,
    // parsed, and reconciled against the journal, and the honest relation
    // between them still resolves.
    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    assert_eq!(run.kinds(), ["invalid_record_name"], "{}", run.stdout);
    assert_eq!(run.json()["summary"]["records"], 2, "{}", run.stdout);
    assert_eq!(
        run.json()["summary"]["audited_records"],
        2,
        "{}",
        run.stdout
    );
    assert_eq!(run.json()["summary"]["collections"], 2, "{}", run.stdout);
    assert_eq!(run.json()["summary"]["errors"], 1, "{}", run.stdout);
    assert_eq!(run.json()["summary"]["warnings"], 0, "{}", run.stdout);
}

#[test]
fn a_record_that_cannot_be_parsed_is_reported_without_stopping_the_scan() {
    let database = seeded();
    fs::write(
        record_path(&database, "deals", "notes"),
        "no front matter at all\n",
    )
    .unwrap();
    run_success(
        database
            .command()
            .args(["delete", "companies", "acme", "--yes"]),
    );

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("unreadable_record");
    assert_eq!(finding["collection"], "deals");
    assert_eq!(finding["id"], "notes");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("could not be parsed"),
        "{finding:#?}"
    );
    // The unrelated dangling link is still found, which is the whole point of
    // collecting rather than bailing.
    assert_eq!(run.findings("dangling_link").len(), 1);
}

#[test]
fn unsaved_direct_edits_are_reported_as_warnings_that_defer_to_status() {
    let database = seeded();
    // Modified.
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "---\nvalue: 2000\nrelations:\n  company:\n    - collection: companies\n      id: acme\n---\n",
    )
    .unwrap();
    // Added.
    fs::write(
        record_path(&database, "deals", "globex-expansion"),
        "---\nvalue: 3000\n---\n",
    )
    .unwrap();
    // Deleted.
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();

    let run = check(&database.root, &["--json"]);
    let mismatch = run.one("record_content_mismatch");
    assert_eq!(mismatch["severity"], "warning");
    assert_eq!(mismatch["id"], "acme-renewal");
    let unaudited = run.one("unaudited_record");
    assert_eq!(unaudited["severity"], "warning");
    assert_eq!(unaudited["id"], "globex-expansion");
    let missing = run.one("missing_record");
    assert_eq!(missing["severity"], "warning");
    assert_eq!(missing["id"], "acme");
    for finding in [&mismatch, &unaudited, &missing] {
        assert!(
            finding["message"].as_str().unwrap().contains("'cr status'"),
            "a reconcilable divergence points at status: {finding:#?}"
        );
    }

    // A deleted target still makes the surviving relation dangle, and that one
    // is a genuine error rather than a pending edit.
    assert_eq!(run.findings("dangling_link").len(), 1);

    // Default threshold: the dangling link fails, the three warnings alone
    // would not have.
    assert_eq!(run.status, FOUND_PROBLEMS);
    assert_eq!(run.json()["summary"]["warnings"], 3);
    assert_eq!(run.json()["summary"]["errors"], 1);
}

#[test]
fn unsaved_edits_alone_do_not_fail_the_default_threshold() {
    let database = seeded();
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "---\nvalue: 2000\nrelations:\n  company:\n    - collection: companies\n      id: acme\n---\n",
    )
    .unwrap();

    let run = check(&database.root, &[]);
    assert_eq!(run.status, 0, "stdout:\n{}", run.stdout);
    assert!(
        run.stdout.contains("0 errors, 1 warning."),
        "{}",
        run.stdout
    );

    // A stricter deployment can still make them fail.
    assert_eq!(
        check(&database.root, &["--fail-on", "warning"]).status,
        FOUND_PROBLEMS
    );
    assert_eq!(check(&database.root, &["--fail-on", "never"]).status, 0);
}

#[test]
fn a_divergence_that_save_cannot_reconcile_is_an_error_rather_than_a_warning() {
    let database = seeded();
    // Both records diverge from the journal. Only one of them can be saved.
    fs::write(
        record_path(&database, "companies", "acme"),
        "---\nname: Acme Corporation\n---\n",
    )
    .unwrap();
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "not a record at all\n",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    let findings: BTreeMap<_, _> = run
        .findings("record_content_mismatch")
        .into_iter()
        .map(|finding| {
            (
                finding["id"].as_str().unwrap().to_owned(),
                finding["severity"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        findings["acme"], "warning",
        "an ordinary direct edit stays status's business"
    );
    assert_eq!(
        findings["acme-renewal"], "error",
        "a divergence save will refuse is check's business"
    );

    // `cr save --all` really does refuse the whole set, which is what the
    // escalation exists to explain.
    let output = database
        .command()
        .args(["save", "--all", "--message", "attempt"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn a_schema_violation_escalates_the_unsaved_edit_beside_it() {
    let database = seeded();
    fs::write(
        database.root.join(".cr/schemas/deals.json"),
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["stage"]}"#,
    )
    .unwrap();
    fs::write(
        record_path(&database, "deals", "acme-renewal"),
        "---\nvalue: 2000\n---\n",
    )
    .unwrap();

    let run = check(&database.root, &["--json"]);
    let mismatch = run.one("record_content_mismatch");
    assert_eq!(mismatch["severity"], "error");
    assert!(
        mismatch["message"]
            .as_str()
            .unwrap()
            .contains("cannot be saved until the problems reported above it are fixed"),
        "{mismatch:#?}"
    );
}

#[test]
fn a_damaged_journal_is_reported_without_hiding_the_rest_of_the_database() {
    let database = seeded();
    // Delete the target so a dangling link exists, then corrupt the chain.
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();
    let segment = database
        .root
        .join(".cr/audit/segments/00000000000000000001.jsonl");
    let damaged = fs::read_to_string(&segment)
        .unwrap()
        .replace("\"actor\":", "\"actor\":\"tampered\",\"ignored\":");
    fs::write(&segment, damaged).unwrap();

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("audit_chain_broken");
    assert_eq!(finding["severity"], "error");
    assert_eq!(finding["collection"], Value::Null);
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("could not be replayed"),
        "{finding:#?}"
    );
    // Nothing could be reconciled, so no reconciliation findings are invented.
    assert!(run.findings("record_content_mismatch").is_empty());
    assert!(run.findings("missing_record").is_empty());
    // With no trustworthy replay state, an empty-policy record cannot be
    // projected safely: its mutable syntax cannot prove it was never
    // protected. The record is still enumerated, but relation checks wait
    // until ownership can be verified instead of inspecting its values.
    assert!(run.findings("dangling_link").is_empty());
    assert_eq!(run.findings("unreadable_record").len(), 1);
}

#[test]
fn a_change_set_that_does_not_match_its_approval_is_reported() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("mismatched");
    copy_fixture("mismatched-approval", &root);

    let run = check(&root, &["--json"]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let finding = run.one("approval_mismatch");
    assert_eq!(finding["severity"], "error");
    assert!(
        finding["message"]
            .as_str()
            .unwrap()
            .contains("records an approved change set that is not the one it applied"),
        "{finding:#?}"
    );
    // The chain itself is intact, so records were still reconciled.
    assert!(
        run.findings("audit_chain_broken").is_empty(),
        "{}",
        run.stdout
    );
}

#[test]
fn checking_is_read_only_byte_for_byte() {
    let database = seeded();
    // Give it real problems first: a read-only command has to stay read-only
    // precisely when it has something to report.
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();
    fs::write(
        record_path(&database, "deals", "globex-expansion"),
        "---\nvalue: 3000\n---\n",
    )
    .unwrap();
    fs::write(
        database.root.join(".cr/schemas/deals.json"),
        r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","required":["stage"]}"#,
    )
    .unwrap();

    let before = snapshot(&database.root);
    let run = check(&database.root, &[]);
    assert_eq!(run.status, FOUND_PROBLEMS);
    let json = check(&database.root, &["--json"]);
    assert_eq!(json.status, FOUND_PROBLEMS);
    let scoped = check(&database.root, &["--collection", "deals"]);
    assert_eq!(scoped.status, FOUND_PROBLEMS);
    let after = snapshot(&database.root);

    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>(),
        "check created or removed a file"
    );
    for (path, contents) in &before {
        assert_eq!(
            after.get(path),
            Some(contents),
            "check changed the bytes of {}",
            path.display()
        );
    }
}

#[test]
fn scope_limits_the_expensive_phase_without_losing_link_targets() {
    let database = seeded();
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();
    fs::write(
        record_path(&database, "companies", "broken"),
        "not a record\n",
    )
    .unwrap();

    // Scoped to `deals`, the dangling link is still resolved against the
    // `companies` directory even though nothing in it was read.
    let run = check(&database.root, &["--collection", "deals", "--json"]);
    assert_eq!(run.json()["collection"], "deals");
    assert_eq!(run.json()["summary"]["records"], 1);
    assert_eq!(run.findings("dangling_link").len(), 1);
    assert!(
        run.findings("unreadable_record").is_empty(),
        "an out-of-scope record is not read:\n{}",
        run.stdout
    );

    // Scoped to `companies`, only its own problems appear.
    let run = check(&database.root, &["--collection", "companies", "--json"]);
    assert_eq!(run.findings("unreadable_record").len(), 1);
    assert!(run.findings("dangling_link").is_empty());
}

#[test]
fn a_collection_that_does_not_exist_is_a_failure_to_run_not_a_clean_report() {
    let database = seeded();
    let run = check(&database.root, &["--collection", "typo"]);
    assert_eq!(run.status, 1);
    assert!(
        run.stderr.contains("collection 'typo' does not exist"),
        "{}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "{}", run.stdout);
}

#[test]
fn a_missing_database_fails_to_run_rather_than_reporting_problems() {
    let temporary = tempfile::tempdir().unwrap();
    let run = check(temporary.path(), &[]);
    assert_eq!(run.status, 1);
    assert!(run.stderr.contains("no database found"), "{}", run.stderr);
}

#[test]
fn an_unusable_failure_threshold_is_rejected() {
    let database = seeded();
    let run = check(&database.root, &["--fail-on", "fatal"]);
    assert_eq!(run.status, 1);
    assert!(
        run.stderr.contains("use error, warning, or never"),
        "{}",
        run.stderr
    );
}

#[test]
fn no_finding_ever_names_a_filesystem_path() {
    let database = seeded();
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();
    fs::write(record_path(&database, "deals", "junk"), "not a record\n").unwrap();
    fs::write(database.root.join("records/deals/..md"), "---\n---\n").unwrap();
    fs::write(database.root.join(".cr/schemas/deals.json"), "{ not json").unwrap();

    let run = check(&database.root, &["--json"]);
    let root = database.root.to_string_lossy().to_string();
    for finding in run.json()["findings"].as_array().unwrap() {
        let message = finding["message"].as_str().unwrap();
        assert!(
            !message.contains(&root),
            "a finding named the database root: {message}"
        );
        assert!(
            !message.contains("records/") && !message.contains(".cr/"),
            "a finding named a directory inside the database: {message}"
        );
        // Naming the offending file is the whole value of an invalid-name
        // finding — `'..md'` is how somebody knows what to delete — but naming
        // where it sits is the leak. A bare filename carries no separator; a
        // filename with one in front of it is a path.
        for token in message.split(|character: char| character.is_whitespace() || character == '\'')
        {
            assert!(
                !(token.contains('/') && token.ends_with(".md")),
                "a finding named a filesystem path: {message}"
            );
        }
    }
    assert!(!run.stdout.contains(&root), "{}", run.stdout);
}

#[test]
fn a_symlinked_record_is_refused_rather_than_followed() {
    #[cfg(unix)]
    {
        let database = seeded();
        let outside = database.root.parent().unwrap().join("outside.md");
        fs::write(&outside, "---\nvalue: 9\n---\n").unwrap();
        std::os::unix::fs::symlink(&outside, record_path(&database, "deals", "planted")).unwrap();

        let run = check(&database.root, &["--json"]);
        let finding = run.one("unreadable_record");
        assert_eq!(finding["id"], "planted");
        assert!(
            finding["message"]
                .as_str()
                .unwrap()
                .contains("not a regular file"),
            "{finding:#?}"
        );
        assert_eq!(
            fs::read_to_string(&outside).unwrap(),
            "---\nvalue: 9\n---\n"
        );
    }
}

/// The report is ordered so two runs over the same database are comparable.
#[test]
fn findings_are_ordered_deterministically_with_errors_first() {
    let database = seeded();
    fs::remove_file(record_path(&database, "companies", "acme")).unwrap();
    fs::write(
        record_path(&database, "deals", "globex-expansion"),
        "---\nvalue: 3000\n---\n",
    )
    .unwrap();

    let first = check(&database.root, &["--json"]).kinds();
    let second = check(&database.root, &["--json"]).kinds();
    assert_eq!(first, second);
    let severities: Vec<_> = check(&database.root, &["--json"]).json()["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["severity"].as_str().unwrap().to_owned())
        .collect();
    let mut sorted = severities.clone();
    sorted.sort_by_key(|severity| if severity == "error" { 0 } else { 1 });
    assert_eq!(severities, sorted, "errors come first");
}

/// Every regular file beneath `root`, by database-relative path.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("could not read a database directory") {
        let entry = entry.expect("could not read a directory entry");
        let path = entry.path();
        let kind = entry.file_type().expect("could not stat an entry");
        if kind.is_dir() {
            collect(root, &path, files);
        } else if kind.is_file() {
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            files.insert(relative, fs::read(&path).expect("could not read a file"));
        }
    }
}

fn copy_fixture(name: &str, target: &Path) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    copy_tree(&source, target);
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("could not create the scratch directory");
    for entry in fs::read_dir(source).expect("could not read the fixture") {
        let entry = entry.expect("could not read a fixture entry");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("could not stat a fixture entry")
            .is_dir()
        {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), &destination).expect("could not copy a fixture file");
        }
    }
}

/// A sync that stopped partway leaves a run ledger behind. Nothing else
/// surfaces it: the records it did commit agree with the journal, so `cr
/// status` reports clean and `cr audit verify` passes. `check` is the command
/// that notices without being asked about a particular sync.
#[test]
fn an_interrupted_sync_run_is_reported_where_nothing_else_surfaces_it() {
    let database = TestDatabase::new("check-interrupted-sync");
    let scripts = database.root.join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    fs::write(
        scripts.join("partial.sh"),
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"notes","id":"first","front_matter":{"n":1},"markdown":"first\n"}'
printf '%s\n' '{"type":"upsert","collection":"blocked","id":"second","front_matter":{"n":2},"markdown":"second\n"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"page-2"}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "partial",
        "--",
        "sh",
        "scripts/partial.sh",
    ]));
    // A regular file where the `blocked` collection directory has to go makes
    // the second operation fail durably, after the first has been committed.
    fs::create_dir_all(database.root.join("records")).unwrap();
    fs::write(database.root.join("records/blocked"), "").unwrap();
    assert!(
        !database
            .command()
            .args(["sync", "run", "partial"])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::remove_file(database.root.join("records/blocked")).unwrap();

    // Nothing else says a run was abandoned.
    assert_eq!(
        run_success(database.command().arg("status")).trim(),
        "Clean"
    );
    run_success(database.command().args(["audit", "verify"]));

    let run = check(&database.root, &["--json"]);
    let finding = run.one("interrupted_sync_run");
    assert_eq!(finding["severity"], "warning");
    assert_eq!(finding["collection"], Value::Null);
    assert_eq!(finding["id"], Value::Null);
    let message = finding["message"].as_str().unwrap();
    assert!(message.contains("sync 'partial'"), "{message}");
    assert!(message.contains("never finished"), "{message}");
    assert!(
        message.contains("cr sync recover partial --check"),
        "{message}"
    );
    assert!(
        !message.contains(".json") && !message.contains(".cr/"),
        "an interrupted run is named, never located: {message}"
    );

    // A durability problem, not an integrity one: the default threshold does
    // not fail on it, and the committed prefix reconciles cleanly.
    assert_eq!(run.status, 0, "stdout:\n{}", run.stdout);
    assert_eq!(run.json()["summary"]["errors"], 0);
    assert_eq!(
        check(&database.root, &["--fail-on", "warning"]).status,
        FOUND_PROBLEMS
    );

    // Reported under a collection scope too, because it is not a property of
    // any one collection.
    let before = snapshot(&database.root);
    let scoped = check(&database.root, &["--collection", "notes", "--json"]);
    assert_eq!(scoped.findings("interrupted_sync_run").len(), 1);
    // Reading the ledger is reading: `check` must not complete, truncate, or
    // tidy away the run it just reported.
    assert_eq!(
        snapshot(&database.root),
        before,
        "check changed the database while reporting an interrupted run"
    );

    // Completing the run clears the finding, and `check` did not do it.
    run_success(database.command().args(["sync", "recover", "partial"]));
    let run = check(&database.root, &["--json"]);
    assert!(
        run.findings("interrupted_sync_run").is_empty(),
        "{}",
        run.stdout
    );
    assert_eq!(run.status, 0);
}

/// A sync that has never been interrupted contributes nothing.
#[test]
fn a_completed_sync_run_leaves_no_finding() {
    let database = TestDatabase::new("check-completed-sync");
    let scripts = database.root.join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    fs::write(
        scripts.join("clean.sh"),
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"notes","id":"only","front_matter":{"n":1},"markdown":"only\n"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"done"}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "clean",
        "--",
        "sh",
        "scripts/clean.sh",
    ]));
    run_success(database.command().args(["sync", "run", "clean"]));

    let run = check(&database.root, &["--json"]);
    assert_eq!(run.status, 0, "stdout:\n{}", run.stdout);
    assert!(run.stdout.contains("\"findings\": []"), "{}", run.stdout);
}
