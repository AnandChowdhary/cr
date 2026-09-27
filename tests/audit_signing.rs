//! Ed25519-signed audit checkpoints: what a signature catches that the anchor
//! cannot, and how it keeps a lag apart from a forgery.
//!
//! The anchor at the database root is as writable as the journal, so
//! `audit_corruption.rs::a_forged_head_actor_still_needs_an_external_checkpoint`
//! forges the newest event, re-derives the anchor, and passes local
//! verification. A signed checkpoint is the same position statement under a
//! key held outside the database, checked against a public key that also
//! comes from outside it, and the headline test below is that forgery failing.
//!
//! Every command here clears `CR_AUDIT_SIGNING_KEY` and
//! `CR_AUDIT_TRUSTED_KEYS` first and sets them back explicitly, so what is
//! signed and what is trusted never depends on the shell running the suite.

mod common;

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use common::{
    TestDatabase, binary, chain, clear_attribution_environment, run_failure, run_success,
};
use cr::{
    Database,
    server::{ServerConfig, router},
};
use ed25519_dalek::{Signature, VerifyingKey};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

const SIGNATURE_PATH: &str = ".cr-audit-head.sig.json";
const SIGNING_KEY_ENV: &str = "CR_AUDIT_SIGNING_KEY";
const TRUSTED_KEYS_ENV: &str = "CR_AUDIT_TRUSTED_KEYS";

/// A private signing key in a directory of its own, outside every database.
struct Key {
    path: PathBuf,
    public: String,
    id: String,
    _directory: tempfile::TempDir,
}

fn keyless(mut command: Command) -> Command {
    command
        .env_remove(SIGNING_KEY_ENV)
        .env_remove(TRUSTED_KEYS_ENV);
    command
}

fn generate_key() -> Key {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit-signing.key");
    let mut command = keyless(Command::new(binary()));
    clear_attribution_environment(&mut command);
    let output = run_success(
        command
            .args(["audit", "key", "generate", "--json"])
            .arg(&path),
    );
    let summary: Value = serde_json::from_str(&output).unwrap();
    Key {
        path,
        public: summary["public_key"].as_str().unwrap().to_owned(),
        id: summary["key_id"].as_str().unwrap().to_owned(),
        _directory: directory,
    }
}

/// A command against `database` that neither signs nor trusts anything.
fn unkeyed(database: &TestDatabase) -> Command {
    keyless(database.command())
}

/// A command against `database` that signs every event it appends.
fn signing(database: &TestDatabase, key: &Key) -> Command {
    let mut command = unkeyed(database);
    command.env(SIGNING_KEY_ENV, &key.path);
    command
}

/// One create and one attributed update, both signed: the seed the
/// forged-head specification uses.
fn seeded(name: &str, key: &Key) -> TestDatabase {
    let database = TestDatabase::new(name);
    run_success(signing(&database, key).args([
        "create",
        "items",
        "one",
        "--set",
        "stage=screening",
    ]));
    run_success(signing(&database, key).args([
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

fn read_checkpoint(root: &Path) -> Value {
    let contents = fs::read_to_string(root.join(SIGNATURE_PATH)).expect("a signed checkpoint");
    assert!(
        contents.ends_with('\n'),
        "the checkpoint must be newline-terminated so a Git diff is clean"
    );
    serde_json::from_str(&contents).unwrap()
}

/// The documented signed message, derived here rather than by asking `cr`.
fn checkpoint_message(database: &str, sequence: u64, hash: &str, timestamp: &str) -> Vec<u8> {
    let mut message = b"cr:audit:checkpoint:v1\0".to_vec();
    for part in [database, &sequence.to_string(), hash, timestamp] {
        message.extend_from_slice(&(part.len() as u64).to_be_bytes());
        message.extend_from_slice(part.as_bytes());
    }
    message
}

/// Check the stored checkpoint against the format, independently of `cr`: it
/// names this journal's first event and head, and `key` signed exactly the
/// documented preimage of that position.
fn assert_head_signed_by(root: &Path, key: &Key) {
    let checkpoint = read_checkpoint(root);
    let events = chain::read_chain(root);
    let head = events.last().unwrap();
    assert_eq!(checkpoint["version"], 1);
    assert_eq!(checkpoint["database"], events[0].hash.as_str());
    assert_eq!(checkpoint["sequence"], head.sequence());
    assert_eq!(checkpoint["hash"], head.hash.as_str());
    assert_eq!(checkpoint["timestamp"], head.parsed["timestamp"]);
    assert_eq!(checkpoint["key_id"], key.id.as_str());

    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(key.public.strip_prefix("ed25519:").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        key.id,
        chain::digest(b"cr:audit:signing-key:v1\0", &public),
        "the key ID is the documented fingerprint"
    );
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(
            checkpoint["signature"]
                .as_str()
                .unwrap()
                .strip_prefix("ed25519:")
                .unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
    let message = checkpoint_message(
        checkpoint["database"].as_str().unwrap(),
        checkpoint["sequence"].as_u64().unwrap(),
        checkpoint["hash"].as_str().unwrap(),
        checkpoint["timestamp"].as_str().unwrap(),
    );
    VerifyingKey::from_bytes(&public)
        .unwrap()
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .expect("the checkpoint is signed over the documented message");
}

fn only_segment(database: &TestDatabase) -> PathBuf {
    let mut segments = chain::segment_paths(&database.root);
    assert_eq!(segments.len(), 1, "the seed fits in one segment");
    segments.remove(0)
}

/// Rewrite the newest event's actor and message and re-hash it, leaving the
/// record state exact, so replay has nothing to say.
fn forge_head_event(database: &TestDatabase) -> String {
    let segment = only_segment(database);
    let contents = fs::read_to_string(&segment).unwrap();
    let mut stored: Vec<String> = contents.lines().map(str::to_owned).collect();
    let index = stored.len() - 1;
    let event = chain::parse_line(&stored[index]);
    let forged = event
        .payload
        .replacen("\"actor\":\"alice\"", "\"actor\":\"mallory\"", 1)
        .replacen("reviewed and approved", "rubber stamped", 1);
    assert_ne!(forged, event.payload, "the seed must contain those values");
    let forged_hash = chain::event_hash(&forged);
    stored[index] = chain::stored_line(&forged_hash, &forged)
        .trim_end()
        .to_owned();
    let mut rewritten = stored.join("\n");
    rewritten.push('\n');
    fs::write(&segment, rewritten).unwrap();
    forged_hash
}

fn output_of(command: &mut Command) -> Output {
    command.output().expect("failed to run cr")
}

/// The `--json-errors` envelope a failed command wrote to stderr.
fn error_envelope(command: &mut Command) -> Value {
    let output = output_of(command.arg("--json-errors"));
    assert!(
        !output.status.success(),
        "the command unexpectedly succeeded"
    );
    serde_json::from_slice::<Value>(&output.stderr).expect("stderr is one JSON envelope")["error"]
        .clone()
}

fn check_report(mut command: Command, trusted_key: Option<&str>) -> (Option<i32>, Value) {
    command.args(["check", "--json"]);
    if let Some(key) = trusted_key {
        command.args(["--trusted-key", key]);
    }
    let output = output_of(&mut command);
    let report = serde_json::from_slice(&output.stdout).expect("check emits JSON");
    (output.status.code(), report)
}

fn findings_of(report: &Value, kind: &str) -> Vec<Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["kind"] == kind)
        .cloned()
        .collect()
}

fn signature_findings(report: &Value) -> Vec<Value> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| {
            finding["kind"]
                .as_str()
                .is_some_and(|kind| kind.starts_with("audit_signature"))
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Signing and verifying
// ---------------------------------------------------------------------------

/// Every write signs the new head, and a verifier holding only the public key
/// accepts it, whichever way the key reaches it.
#[test]
fn every_signed_write_verifies_under_the_public_key() {
    let key = generate_key();
    let database = seeded("signed-round-trip", &key);
    assert_head_signed_by(&database.root, &key);

    let verified =
        run_success(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert!(verified.contains("Verified 2 audit events"), "{verified}");
    assert!(
        verified.contains(&format!(
            "Verified the signed checkpoint at sequence 2 under trusted key {}",
            key.id
        )),
        "a verification that checked a signature must say so: {verified}"
    );

    // A file of keys, with a comment and a label, outside the database.
    let keys = key._directory.path().join("trusted-keys");
    fs::write(
        &keys,
        format!(
            "# who may sign this database\n\n{} release signer\n",
            key.public
        ),
    )
    .unwrap();
    let verified = run_success(
        unkeyed(&database)
            .args(["audit", "verify", "--trusted-key"])
            .arg(&keys),
    );
    assert!(verified.contains("Verified the signed checkpoint at sequence 2"));

    // And the environment, which is what CI would set.
    let verified = run_success(
        unkeyed(&database)
            .env(TRUSTED_KEYS_ENV, format!(" {} ", key.public))
            .args(["audit", "verify"]),
    );
    assert!(verified.contains("Verified the signed checkpoint at sequence 2"));

    // Without a trusted key, nothing about the signature is judged, and the
    // output says the checkpoint exists rather than that it was checked.
    let unverified = run_success(unkeyed(&database).args(["audit", "verify"]));
    assert!(
        unverified.contains("a signed audit checkpoint is recorded but was not verified"),
        "{unverified}"
    );
    assert!(!unverified.contains("Verified the signed checkpoint"));

    // `check` agrees and reports nothing.
    let (status, report) = check_report(unkeyed(&database), Some(&key.public));
    assert_eq!(status, Some(0), "{report}");
    assert!(signature_findings(&report).is_empty(), "{report}");

    // Signatures are deterministic, so re-signing the same head reproduces
    // the file byte for byte, as the anchor does.
    let before = fs::read(database.root.join(SIGNATURE_PATH)).unwrap();
    let written = run_success(signing(&database, &key).args(["audit", "anchor", "--write"]));
    assert!(
        written.contains("Anchored and signed sequence 2"),
        "{written}"
    );
    assert_eq!(
        fs::read(database.root.join(SIGNATURE_PATH)).unwrap(),
        before
    );
}

/// A signature by a key the verifier did not name proves nothing to it.
#[test]
fn a_signature_by_an_untrusted_key_is_refused() {
    let signer = generate_key();
    let stranger = generate_key();
    let database = seeded("signed-untrusted", &signer);

    let error = error_envelope(unkeyed(&database).args([
        "audit",
        "verify",
        "--trusted-key",
        &stranger.public,
    ]));
    assert_eq!(error["code"], "signature_mismatch");
    assert_eq!(
        error["message"],
        format!(
            "the signed audit checkpoint was made with key {}, which is not a trusted key",
            signer.id
        )
    );

    let (status, report) = check_report(unkeyed(&database), Some(&stranger.public));
    assert_eq!(status, Some(2), "an error-severity finding fails check");
    let findings = findings_of(&report, "audit_signature_mismatch");
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["severity"], "error");

    // Trusting both keys is fine: any one trusted key suffices.
    run_success(unkeyed(&database).args([
        "audit",
        "verify",
        "--trusted-key",
        &stranger.public,
        "--trusted-key",
        &signer.public,
    ]));
}

// ---------------------------------------------------------------------------
// The forgery the anchor could not catch
// ---------------------------------------------------------------------------

/// The newest event is forged, re-hashed, and the anchor re-derived to match.
///
/// This is the forged-head-actor specification: record replay cannot see it
/// and the anchor was rewritten in the same pass, so local verification is
/// quiet. The signed checkpoint still names the hash the key holder signed,
/// and nobody without the key can sign the forged one.
#[test]
fn a_forged_head_with_its_anchor_rederived_fails_against_the_signed_checkpoint() {
    let key = generate_key();
    let database = seeded("signed-forged-head", &key);
    let signed_hash = chain::read_chain(&database.root)
        .last()
        .unwrap()
        .hash
        .clone();
    let forged_hash = forge_head_event(&database);
    chain::reanchor(&database.root);

    // The boundary the anchor alone leaves open, still open without a key.
    run_success(unkeyed(&database).args(["audit", "verify"]));

    let error =
        error_envelope(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(error["code"], "signature_mismatch");
    assert_eq!(
        error["message"],
        format!(
            "the audit event at sequence 2 does not match the signed audit checkpoint (signed {signed_hash}, actual {forged_hash})"
        )
    );
    assert!(
        !error["message"]
            .as_str()
            .unwrap()
            .contains(database.root.to_str().unwrap()),
        "the classified message never names a path"
    );

    // `check` reports it as its own kind, at error severity, while the
    // re-derived anchor has nothing to say.
    let (status, report) = check_report(unkeyed(&database), Some(&key.public));
    assert_eq!(status, Some(2));
    assert_eq!(
        findings_of(&report, "audit_signature_mismatch").len(),
        1,
        "{report}"
    );
    assert!(
        findings_of(&report, "audit_anchor_mismatch").is_empty(),
        "{report}"
    );

    // The key holder's next write refuses rather than extending, and signing,
    // the forged history. Nothing is written: no event, no pending mutation,
    // no record change.
    let record = fs::read(database.root.join("records/items/one.md")).unwrap();
    let refused = error_envelope(signing(&database, &key).args([
        "update",
        "items",
        "one",
        "--set",
        "stage=offer",
    ]));
    assert_eq!(refused["code"], "signature_mismatch");
    assert_eq!(chain::read_chain(&database.root).len(), 2);
    assert_eq!(
        fs::read(database.root.join("records/items/one.md")).unwrap(),
        record
    );
    assert!(!database.root.join(".cr/audit/pending.json").exists());

    // Nor will `cr` re-sign it on request.
    let refused = error_envelope(signing(&database, &key).args(["audit", "anchor", "--write"]));
    assert_eq!(refused["code"], "signature_mismatch");
    assert_eq!(
        read_checkpoint(&database.root)["hash"],
        signed_hash.as_str()
    );

    // Deleting the checkpoint does not launder the forgery either. A verifier
    // with the key is told nothing is signed, and the key holder's writes go
    // on without signing a history they cannot vouch for.
    fs::remove_file(database.root.join(SIGNATURE_PATH)).unwrap();
    let missing =
        error_envelope(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(missing["code"], "signature_mismatch");
    assert!(
        missing["message"]
            .as_str()
            .unwrap()
            .starts_with("no signed audit checkpoint is recorded"),
        "{missing}"
    );
    run_success(signing(&database, &key).args(["update", "items", "one", "--set", "stage=offer"]));
    assert!(
        !database.root.join(SIGNATURE_PATH).exists(),
        "a write must not start a signed history over one it cannot vouch for"
    );
    run_failure(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
}

/// A checkpoint whose own fields were edited no longer verifies, and says so
/// rather than blaming the journal.
#[test]
fn an_edited_checkpoint_does_not_verify() {
    let key = generate_key();
    let database = seeded("signed-edited", &key);
    let forged_hash = forge_head_event(&database);
    chain::reanchor(&database.root);

    // The forger's best move: point the checkpoint at the forged hash.
    let mut checkpoint = read_checkpoint(&database.root);
    checkpoint["hash"] = Value::from(forged_hash);
    fs::write(
        database.root.join(SIGNATURE_PATH),
        format!("{}\n", serde_json::to_string_pretty(&checkpoint).unwrap()),
    )
    .unwrap();

    let error =
        error_envelope(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(error["code"], "signature_mismatch");
    assert!(
        error["message"].as_str().unwrap().starts_with(&format!(
            "the signed audit checkpoint does not verify under key {}",
            key.id
        )),
        "{error}"
    );

    // A scribble is a refusal, not an absence.
    fs::write(database.root.join(SIGNATURE_PATH), "not json\n").unwrap();
    let error =
        error_envelope(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(error["code"], "signature_mismatch");
    assert_eq!(
        error["message"],
        "the signed audit checkpoint is not readable"
    );
}

// ---------------------------------------------------------------------------
// Stale is not tampered
// ---------------------------------------------------------------------------

/// A signature left behind by a crash, or by writers who do not hold the key,
/// still finds its own event at its own sequence, so it passes with a notice.
#[test]
fn a_lagging_signature_is_a_notice_rather_than_a_failure() {
    let key = generate_key();
    let database = seeded("signed-lagging", &key);
    let lagging = fs::read(database.root.join(SIGNATURE_PATH)).unwrap();

    // Exactly what a crash after the anchor write and before the signature
    // write leaves behind.
    run_success(signing(&database, &key).args(["update", "items", "one", "--set", "stage=offer"]));
    fs::write(database.root.join(SIGNATURE_PATH), &lagging).unwrap();
    // And a writer without the key leaves it where it is.
    run_success(unkeyed(&database).args(["update", "items", "one", "--set", "stage=closed"]));
    assert_eq!(
        fs::read(database.root.join(SIGNATURE_PATH)).unwrap(),
        lagging
    );

    let verified =
        run_success(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert!(verified.contains("Verified 4 audit events"), "{verified}");
    assert!(
        verified.contains("the signed audit checkpoint is behind at sequence 2 of 4"),
        "{verified}"
    );
    assert!(
        verified.contains("lagging signature rather than altered history"),
        "a lag must not read as tampering: {verified}"
    );

    let (status, report) = check_report(unkeyed(&database), Some(&key.public));
    assert_eq!(
        status,
        Some(0),
        "a lag does not fail check by default: {report}"
    );
    let findings = findings_of(&report, "audit_signature_behind");
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["severity"], "warning");

    // The key holder's next write extends a checkpoint it can still vouch
    // for, and so does an explicit re-sign.
    run_success(signing(&database, &key).args(["update", "items", "one", "--set", "stage=won"]));
    assert_head_signed_by(&database.root, &key);
    let verified =
        run_success(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert!(!verified.contains("notice:"), "{verified}");
}

// ---------------------------------------------------------------------------
// Identity and adoption
// ---------------------------------------------------------------------------

/// A checkpoint names its database by the journal's first event, so one
/// copied from a database signed with the same key is refused by name.
#[test]
fn a_signature_copied_from_another_database_is_refused() {
    let key = generate_key();
    let first = seeded("signed-first", &key);
    let second = seeded("signed-second", &key);
    let first_database = read_checkpoint(&first.root)["database"].clone();
    let second_database = read_checkpoint(&second.root)["database"].clone();
    assert_ne!(first_database, second_database);

    fs::copy(
        first.root.join(SIGNATURE_PATH),
        second.root.join(SIGNATURE_PATH),
    )
    .unwrap();
    let error =
        error_envelope(unkeyed(&second).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(error["code"], "signature_mismatch");
    assert_eq!(
        error["message"],
        format!(
            "the signed audit checkpoint was made for a different database (its first event is {}, this journal's is {})",
            first_database.as_str().unwrap(),
            second_database.as_str().unwrap()
        )
    );
}

/// Without a signing key nothing changes: no file, no new output, and the
/// anchor's JSON is exactly what it was.
#[test]
fn unsigned_databases_are_unchanged() {
    let key = generate_key();
    let database = TestDatabase::new("unsigned");
    run_success(unkeyed(&database).args(["create", "items", "one", "--set", "stage=screening"]));
    run_success(unkeyed(&database).args(["update", "items", "one", "--set", "stage=hired"]));
    assert!(!database.root.join(SIGNATURE_PATH).exists());

    let verified = run_success(unkeyed(&database).args(["audit", "verify"]));
    assert_eq!(verified.lines().count(), 1, "{verified}");
    let written = run_success(unkeyed(&database).args(["audit", "anchor", "--write", "--json"]));
    let written: Value = serde_json::from_str(&written).unwrap();
    let mut fields: Vec<_> = written.as_object().unwrap().keys().cloned().collect();
    fields.sort();
    assert_eq!(fields, ["hash", "sequence", "timestamp", "version"]);
    let (status, report) = check_report(unkeyed(&database), None);
    assert_eq!(status, Some(0));
    assert!(signature_findings(&report).is_empty(), "{report}");

    // Asking for a signature on a database that has none is a failure, not a
    // silent pass, and `check` names it.
    let error =
        error_envelope(unkeyed(&database).args(["audit", "verify", "--trusted-key", &key.public]));
    assert_eq!(error["code"], "signature_mismatch");
    let (status, report) = check_report(unkeyed(&database), Some(&key.public));
    assert_eq!(status, Some(2));
    let findings = findings_of(&report, "audit_signature_missing");
    assert_eq!(findings.len(), 1, "{report}");
    assert_eq!(findings[0]["severity"], "error");

    // Configuring a key does not quietly start signing a history that
    // already exists; adopting it is the explicit re-sign.
    run_success(signing(&database, &key).args(["update", "items", "one", "--set", "stage=offer"]));
    assert!(!database.root.join(SIGNATURE_PATH).exists());
    let adopted = run_success(signing(&database, &key).args(["audit", "anchor", "--write"]));
    assert!(
        adopted.contains("Anchored and signed sequence 3"),
        "{adopted}"
    );
    assert!(adopted.contains(".cr-audit-head.sig.json"), "{adopted}");
    run_success(signing(&database, &key).args(["update", "items", "one", "--set", "stage=won"]));
    assert_head_signed_by(&database.root, &key);

    // A new database has no history to vouch for, so its first event signs.
    let fresh = TestDatabase::new("signed-from-the-start");
    run_success(signing(&fresh, &key).args(["create", "items", "one"]));
    assert_head_signed_by(&fresh.root, &key);
}

/// Signers extend checkpoints they trust, which is their own key's and
/// whatever `CR_AUDIT_TRUSTED_KEYS` names, and leave any other alone.
#[test]
fn a_signer_extends_only_checkpoints_it_trusts() {
    let alice = generate_key();
    let bob = generate_key();
    let database = seeded("signed-by-two", &alice);

    // Bob does not trust Alice's key, so he cannot vouch for what she signed
    // and signs nothing; her checkpoint lags.
    run_success(signing(&database, &bob).args(["update", "items", "one", "--set", "stage=offer"]));
    assert_eq!(read_checkpoint(&database.root)["key_id"], alice.id.as_str());
    assert_eq!(read_checkpoint(&database.root)["sequence"], 2);

    // Once he does, his write verifies her checkpoint and signs past it.
    run_success(
        signing(&database, &bob)
            .env(TRUSTED_KEYS_ENV, &alice.public)
            .args(["update", "items", "one", "--set", "stage=won"]),
    );
    assert_head_signed_by(&database.root, &bob);
    run_success(unkeyed(&database).args([
        "audit",
        "verify",
        "--trusted-key",
        &alice.public,
        "--trusted-key",
        &bob.public,
    ]));
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[test]
fn key_generation_writes_a_private_file_once_and_prints_the_public_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit-signing.key");
    let mut command = keyless(Command::new(binary()));
    let printed = run_success(command.args(["audit", "key", "generate"]).arg(&path));
    let public = printed.lines().last().unwrap().to_owned();
    assert!(public.starts_with("ed25519:"), "{printed}");
    assert_eq!(public.len(), "ed25519:".len() + 43);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the private key is its owner's alone");
    }

    // Never overwritten: that would orphan every checkpoint the key signed.
    let before = fs::read(&path).unwrap();
    let mut command = keyless(Command::new(binary()));
    let error = error_envelope(command.args(["audit", "key", "generate"]).arg(&path));
    assert_eq!(error["code"], "already_exists");
    assert_eq!(fs::read(&path).unwrap(), before);

    // `show` recovers the public key later, from a path or the environment,
    // and never prints the secret.
    let mut command = keyless(Command::new(binary()));
    let shown = run_success(command.args(["audit", "key", "show"]).arg(&path));
    assert_eq!(shown.lines().last(), Some(public.as_str()));
    let secret: Value = serde_json::from_slice(&before).unwrap();
    assert!(!shown.contains(secret["secret_key"].as_str().unwrap()));
    let mut command = keyless(Command::new(binary()));
    let shown = run_success(
        command
            .env(SIGNING_KEY_ENV, &path)
            .args(["audit", "key", "show"]),
    );
    assert_eq!(shown.lines().last(), Some(public.as_str()));
    let mut command = keyless(Command::new(binary()));
    let output = output_of(command.args(["audit", "key", "show"]));
    assert_eq!(
        output.status.code(),
        Some(2),
        "no key to show is a usage error"
    );
}

#[test]
fn keys_inside_the_database_are_warned_about() {
    let key = generate_key();
    let database = seeded("signed-keys-inside", &key);

    let inside = database.root.join("audit-signing.key");
    let output = output_of(
        keyless(Command::new(binary()))
            .args(["audit", "key", "generate"])
            .arg(&inside),
    );
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("is inside the database"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let keys = database.root.join("trusted-keys");
    fs::write(&keys, format!("{}\n", key.public)).unwrap();
    let output = output_of(
        unkeyed(&database)
            .args(["audit", "verify", "--trusted-key"])
            .arg(&keys),
    );
    assert!(output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("anyone who can rewrite the journal can rewrite it too"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_unusable_signing_key_refuses_the_write_before_anything_is_written() {
    let database = TestDatabase::new("signed-broken-key");
    run_success(unkeyed(&database).args(["create", "items", "one"]));
    let missing = database.root.with_file_name("no-such.key");
    let error = error_envelope(unkeyed(&database).env(SIGNING_KEY_ENV, &missing).args([
        "update",
        "items",
        "one",
        "--set",
        "stage=offer",
    ]));
    assert_eq!(error["code"], "validation_failed");
    assert_eq!(
        error["message"],
        "the audit signing key file cannot be read"
    );
    assert_eq!(chain::read_chain(&database.root).len(), 1);
    assert!(!database.root.join(".cr/audit/pending.json").exists());

    // A server finds out at launch, before it binds, rather than on the
    // first write a caller makes.
    let error = error_envelope(unkeyed(&database).env(SIGNING_KEY_ENV, &missing).args([
        "serve",
        "--bind",
        "127.0.0.1:0",
    ]));
    assert_eq!(
        error["message"],
        "the audit signing key file cannot be read"
    );
    let error = error_envelope(
        unkeyed(&database)
            .env(TRUSTED_KEYS_ENV, "ed25519:not-a-key")
            .args(["serve", "--bind", "127.0.0.1:0"]),
    );
    assert_eq!(error["code"], "validation_failed");
}

// ---------------------------------------------------------------------------
// The REST route
// ---------------------------------------------------------------------------

async fn get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap())
}

fn served(database: &TestDatabase) -> Router {
    router(
        Database::discover(Some(&database.root)).unwrap(),
        ServerConfig::default(),
    )
    .unwrap()
}

#[tokio::test]
async fn the_rest_routes_verify_signatures_with_inline_keys_only() {
    let key = generate_key();
    let database = seeded("signed-http", &key);
    let app = served(&database);
    let trusting = format!(
        "/api/v1/audit/verify?trusted_key={}",
        percent_encode(&key.public)
    );

    let (status, body) = get(&app, &trusting).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["signature"]["state"], "matched");
    assert_eq!(body["signature"]["sequence"], 2);
    assert_eq!(body["signature"]["key_id"], key.id.as_str());

    let (status, body) = get(&app, "/api/v1/audit/verify").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["signature"]["state"], "unverified");

    // A request cannot make the server read a file.
    let (status, body) = get(&app, "/api/v1/audit/verify?trusted_key=%2Fetc%2Fpasswd").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "validation_failed");
    assert!(
        !body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("passwd")
    );

    forge_head_event(&database);
    chain::reanchor(&database.root);
    let app = served(&database);
    let (status, body) = get(&app, &trusting).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "signature_mismatch");
    assert!(
        !body["error"]["message"]
            .as_str()
            .unwrap()
            .contains(database.root.to_str().unwrap())
    );

    let (status, body) = get(
        &app,
        &format!("/api/v1/check?trusted_key={}", percent_encode(&key.public)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["data"][0]["kind"], "audit_signature_mismatch",
        "{body}"
    );

    // An unsigned database verifies to exactly the response it always did.
    let unsigned = TestDatabase::new("unsigned-http");
    run_success(unkeyed(&unsigned).args(["create", "items", "one"]));
    let (status, body) = get(&served(&unsigned), "/api/v1/audit/verify").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("signature").is_none(), "{body}");
}

fn percent_encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}
