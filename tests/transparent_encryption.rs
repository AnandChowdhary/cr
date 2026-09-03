mod common;

use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use common::{
    TestDatabase,
    fault::{FaultDatabase, Point},
    run_failure, run_success,
};
use cr::{Database, DomainError, SearchQuery, SearchTarget};
use serde_json::Value;

const OLD_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const NEW_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const WRONG_KEY: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";
const RETRY_KEY: &str = "550e8400-e29b-41d4-a716-446655440000";
const UPDATE_KEY: &str = "550e8400-e29b-41d4-a716-446655440010";
const LINK_KEY: &str = "550e8400-e29b-41d4-a716-446655440011";
const DELETE_KEY: &str = "550e8400-e29b-41d4-a716-446655440012";

fn schema() -> &'static str {
    r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "x-cr-encrypted-body": true,
  "required": ["stage", "contact"],
  "properties": {
    "stage": { "enum": ["lead", "customer"] },
    "contact": {
      "type": "object",
      "required": ["token"],
      "properties": {
        "token": { "type": "string", "minLength": 8, "x-cr-encrypted": true }
      }
    }
  }
}"#
}

fn command(database: &TestDatabase) -> Command {
    let mut command = database.command();
    command
        .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
        .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#));
    command
}

fn fault_command(database: &FaultDatabase) -> Command {
    let mut command = database.command();
    command
        .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
        .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#));
    command
}

fn write_schema(database: &TestDatabase) {
    fs::write(database.root.join(".cr/schemas/accounts.json"), schema()).unwrap();
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn stored_document(database: &TestDatabase, id: &str) -> String {
    fs::read_to_string(database.root.join(format!("records/accounts/{id}.md"))).unwrap()
}

fn split_document(raw: &str) -> (yaml_serde::Value, &str) {
    let raw = raw.strip_prefix("---\n").unwrap();
    let (yaml, body) = raw.split_once("---\n").unwrap();
    (yaml_serde::from_str(yaml).unwrap(), body)
}

fn envelope_lines(raw: &str) -> Vec<&str> {
    raw.lines()
        .filter(|line| {
            line.contains("key_id:")
                || line.contains("nonce:")
                || line.contains("ciphertext:")
                || line.contains("cr-encrypted:v1:")
        })
        .collect()
}

fn audit_bytes(database: &TestDatabase) -> String {
    let directory = database.root.join(".cr/audit/segments");
    let mut paths = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .iter()
        .map(|path| fs::read_to_string(path).unwrap())
        .collect()
}

fn encryption_context(database: &TestDatabase) -> String {
    fs::read_to_string(database.root.join(".cr/encryption.json")).unwrap()
}

fn assert_tree_omits(path: &Path, needles: &[&str]) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_tree_omits(&path, needles);
        } else {
            let bytes = fs::read(&path).unwrap();
            let contents = String::from_utf8_lossy(&bytes);
            for needle in needles {
                assert!(
                    !contents.contains(needle),
                    "{} persisted protected plaintext {needle:?}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn encrypted_fields_and_body_are_plaintext_at_every_cr_read_boundary() {
    let database = TestDatabase::new("encrypted-roundtrip");
    write_schema(&database);

    run_success(command(&database).args([
        "create",
        "accounts",
        "acme",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=secret-token-acme",
        "--body",
        "Private account notes\n",
    ]));

    let reserved = run_failure(command(&database).args([
        "update",
        "accounts",
        "acme",
        "--set",
        "$cr_encryption=application-value",
    ]));
    assert!(reserved.contains("front matter field '$cr_encryption' is reserved"));

    let stored = stored_document(&database, "acme");
    assert!(stored.contains("$cr_encrypted"));
    assert!(stored.contains("cr-encrypted:v1:old:"));
    assert!(!stored.contains("secret-token-acme"));
    assert!(!stored.contains("Private account notes"));
    let audit = audit_bytes(&database);
    assert!(!audit.contains("secret-token-acme"));
    assert!(!audit.contains("Private account notes"));

    let fetched = json(command(&database).args(["get", "accounts", "acme", "--json"]));
    assert_eq!(
        fetched["attributes"]["contact"]["token"],
        "secret-token-acme"
    );
    assert_eq!(fetched["body"], "Private account notes\n");
    let markdown = run_success(command(&database).args(["get", "accounts", "acme"]));
    assert!(markdown.contains("token: secret-token-acme"));
    assert!(markdown.contains("Private account notes"));

    let listed = json(command(&database).args([
        "list",
        "accounts",
        "--where",
        "contact.token=secret-token-acme",
        "--json",
    ]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let searched = json(command(&database).args([
        "search",
        "Private account",
        "--collection",
        "accounts",
        "--json",
    ]));
    assert_eq!(searched.as_array().unwrap().len(), 1);

    let entries = json(command(&database).args(["audit", "log", "accounts", "acme", "--json"]));
    let serialized = serde_json::to_string(&entries).unwrap();
    assert!(serialized.contains("secret-token-acme"));
    assert!(serialized.contains("Private account notes"));
    let stored_entry: Value = serde_json::from_str(audit.lines().next().unwrap()).unwrap();
    assert_eq!(entries[0]["hash"], stored_entry["hash"]);
    assert_ne!(entries[0]["changes"], stored_entry["changes"]);

    // Chain and stored-record verification operates over ciphertext hashes and
    // therefore does not require a decryption key.
    run_success(database.command().args(["audit", "verify"]));
    let report = json(command(&database).args(["check", "--json"]));
    assert_eq!(report["summary"]["errors"], 0);
}

#[test]
fn protected_idempotency_keeps_ciphertext_durable_and_replays_logical_plaintext() {
    let database = TestDatabase::new("encrypted-idempotency");
    write_schema(&database);
    let arguments = [
        "create",
        "accounts",
        "acme",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=retry-secret-token",
        "--body",
        "retry private notes\n",
        "--idempotency-key",
        RETRY_KEY,
        "--json",
    ];

    let first = json(command(&database).args(arguments));
    let stored_first = stored_document(&database, "acme");
    let audit_first = audit_bytes(&database);
    assert!(!stored_first.contains("retry-secret-token"));
    assert!(!stored_first.contains("retry private notes"));
    assert!(!audit_first.contains("retry-secret-token"));
    assert!(!audit_first.contains("retry private notes"));
    assert!(!audit_first.contains(RETRY_KEY));

    let stored_event: Value = serde_json::from_str(audit_first.lines().next().unwrap()).unwrap();
    assert!(
        stored_event["payload"]["idempotency"]["request_hash"]
            .as_str()
            .unwrap()
            .starts_with("hmac-sha256:")
    );
    let stored_result = stored_event["payload"]["idempotency"]["result"]["markdown"]
        .as_str()
        .unwrap();
    assert!(stored_result.contains("$cr_encrypted"));
    assert!(!stored_result.contains("retry-secret-token"));
    assert_eq!(
        stored_event["payload"]["idempotency"]["result"]["version"],
        first["version"]
    );

    let replay = json(command(&database).args(arguments));
    assert_eq!(replay, first);
    assert_eq!(stored_document(&database, "acme"), stored_first);
    assert_eq!(audit_bytes(&database), audit_first);

    let history = json(command(&database).args(["audit", "log", "accounts", "acme", "--json"]));
    for projected in [
        history[0]["after_snapshot"]["markdown"].as_str().unwrap(),
        history[0]["idempotency"]["result"]["markdown"]
            .as_str()
            .unwrap(),
    ] {
        assert!(projected.contains("retry-secret-token"));
        assert!(projected.contains("retry private notes"));
        assert!(!projected.contains("$cr_encrypted"));
    }
    assert_eq!(history[0]["hash"], stored_event["hash"]);
    assert_eq!(history[0]["after_hash"], first["version"]);

    let missing = run_failure(database.command().args(arguments));
    assert!(missing.contains("CR_ENCRYPTION_KEYS is required"));
    assert!(!missing.contains("retry-secret-token"));
    assert_eq!(audit_bytes(&database), audit_first);

    let rotated = json(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "new")
            .env(
                "CR_ENCRYPTION_KEYS",
                format!(r#"{{"old":"{OLD_KEY}","new":"{NEW_KEY}"}}"#),
            )
            .args(arguments),
    );
    assert_eq!(rotated, first);
    assert_eq!(stored_document(&database, "acme"), stored_first);
    assert_eq!(audit_bytes(&database), audit_first);

    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: content/data\n",
    )
    .unwrap();
    fs::create_dir_all(database.root.join("content/data")).unwrap();
    let moved_replay = json(command(&database).args(arguments));
    assert_eq!(moved_replay, first);
    assert_eq!(moved_replay["path"], "records/accounts/acme.md");
    assert_eq!(audit_bytes(&database), audit_first);
}

#[test]
fn protected_update_link_and_delete_retries_return_the_exact_logical_result() {
    let database = TestDatabase::new("encrypted-idempotency-operations");
    write_schema(&database);
    for (id, token) in [("one", "initial-secret-one"), ("two", "target-secret-two")] {
        run_success(command(&database).args([
            "create",
            "accounts",
            id,
            "--set",
            "stage=lead",
            "--set",
            &format!("contact.token={token}"),
            "--body",
            "private notes",
        ]));
    }

    let update = [
        "update",
        "accounts",
        "one",
        "--set",
        "contact.token=updated-secret-one",
        "--idempotency-key",
        UPDATE_KEY,
        "--json",
    ];
    let updated = json(command(&database).args(update));
    let updated_storage = stored_document(&database, "one");
    let updated_head = json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap();
    assert_eq!(json(command(&database).args(update)), updated);
    assert_eq!(stored_document(&database, "one"), updated_storage);
    assert_eq!(
        json(database.command().args(["audit", "head", "--json"]))["sequence"],
        updated_head
    );

    let wrong = run_failure(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{WRONG_KEY}"}}"#))
            .args(update),
    );
    assert!(wrong.contains("protected data could not be decrypted"));
    assert!(!wrong.contains("updated-secret-one"));
    assert!(!wrong.contains("contact.token"));

    let link = [
        "link",
        "accounts",
        "one",
        "peer",
        "accounts",
        "two",
        "--idempotency-key",
        LINK_KEY,
        "--json",
    ];
    let linked = json(command(&database).args(link));
    let linked_storage = stored_document(&database, "one");
    let linked_head = json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap();
    assert_eq!(json(command(&database).args(link)), linked);
    assert_eq!(stored_document(&database, "one"), linked_storage);
    assert_eq!(
        json(database.command().args(["audit", "head", "--json"]))["sequence"],
        linked_head
    );

    let delete = [
        "delete",
        "accounts",
        "one",
        "--yes",
        "--idempotency-key",
        DELETE_KEY,
        "--json",
    ];
    let deleted = json(command(&database).args(delete));
    let audit_after_delete = audit_bytes(&database);
    let delete_head = json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap();
    assert_eq!(
        deleted["attributes"]["contact"]["token"],
        "updated-secret-one"
    );
    assert_eq!(json(command(&database).args(delete)), deleted);
    assert_eq!(audit_bytes(&database), audit_after_delete);
    assert_eq!(
        json(database.command().args(["audit", "head", "--json"]))["sequence"],
        delete_head
    );
    assert!(!database.root.join("records/accounts/one.md").exists());
    assert!(!audit_after_delete.contains("initial-secret-one"));
    assert!(!audit_after_delete.contains("updated-secret-one"));
    assert!(!audit_after_delete.contains("private notes"));
}

#[test]
fn unchanged_ciphertext_is_stable_but_equal_plaintexts_use_distinct_nonces() {
    let database = TestDatabase::new("encrypted-nonces");
    write_schema(&database);
    for id in ["one", "two"] {
        run_success(command(&database).args([
            "create",
            "accounts",
            id,
            "--set",
            "stage=lead",
            "--set",
            "contact.token=same-secret",
            "--body",
            "same body",
        ]));
    }
    let one_before = stored_document(&database, "one");
    let two = stored_document(&database, "two");
    assert_ne!(envelope_lines(&one_before), envelope_lines(&two));

    run_success(command(&database).args(["update", "accounts", "one", "--set", "stage=customer"]));
    let one_after = stored_document(&database, "one");
    // The document changed, but its protected envelopes did not get a new
    // nonce merely because an ordinary field changed.
    assert_eq!(envelope_lines(&one_before), envelope_lines(&one_after));
}

#[test]
fn tampering_missing_keys_and_wrong_keys_fail_closed_without_plaintext() {
    let database = TestDatabase::new("encrypted-failures");
    write_schema(&database);
    for (id, secret) in [("one", "first-secret"), ("two", "second-secret")] {
        run_success(command(&database).args([
            "create",
            "accounts",
            id,
            "--set",
            "stage=lead",
            "--set",
            &format!("contact.token={secret}"),
            "--body",
            "private",
        ]));
    }

    let missing = run_failure(
        database
            .command()
            .args(["get", "accounts", "one", "--json"]),
    );
    assert!(missing.contains("CR_ENCRYPTION_KEYS is required"));
    assert!(!missing.contains("first-secret"));

    let wrong = run_failure(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{WRONG_KEY}"}}"#))
            .args(["get", "accounts", "one", "--json"]),
    );
    assert!(wrong.contains("protected data could not be decrypted"));
    assert!(!wrong.contains("first-secret"));

    let one_path = database.root.join("records/accounts/one.md");
    let two_path = database.root.join("records/accounts/two.md");
    let one_raw = fs::read_to_string(&one_path).unwrap();
    fs::write(
        &one_path,
        one_raw.replacen("key_id: old", "key_id: alias", 1),
    )
    .unwrap();
    let alias = run_failure(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env(
                "CR_ENCRYPTION_KEYS",
                format!(r#"{{"old":"{OLD_KEY}","alias":"{OLD_KEY}"}}"#),
            )
            .args(["get", "accounts", "one", "--json"]),
    );
    assert!(alias.contains("protected data could not be decrypted"));
    fs::write(&one_path, &one_raw).unwrap();

    let two_raw = fs::read_to_string(&two_path).unwrap();
    let (mut one, one_body) = split_document(&one_raw);
    let (two, _) = split_document(&two_raw);
    one["contact"]["token"] = two["contact"]["token"].clone();
    let one_yaml = yaml_serde::to_string(&one).unwrap();
    let one_yaml = one_yaml.strip_prefix("---\n").unwrap_or(&one_yaml);
    fs::write(&one_path, format!("---\n{one_yaml}---\n{one_body}")).unwrap();
    let swapped = run_failure(command(&database).args(["get", "accounts", "one", "--json"]));
    assert!(swapped.contains("protected data could not be decrypted"));
    assert!(!swapped.contains("second-secret"));
}

#[test]
fn independent_database_contexts_reject_cross_database_ciphertext_swaps() {
    let first = TestDatabase::new("encrypted-context-first");
    let second = TestDatabase::new("encrypted-context-second");
    write_schema(&first);
    write_schema(&second);
    assert_ne!(encryption_context(&first), encryption_context(&second));

    for (database, secret) in [
        (&first, "first-database-secret"),
        (&second, "second-database-secret"),
    ] {
        run_success(command(database).args([
            "create",
            "accounts",
            "same-id",
            "--set",
            "stage=lead",
            "--set",
            &format!("contact.token={secret}"),
            "--body",
            "private",
        ]));
    }

    let first_raw = stored_document(&first, "same-id");
    let second_path = second.root.join("records/accounts/same-id.md");
    let second_raw = fs::read_to_string(&second_path).unwrap();
    let (first_attributes, _) = split_document(&first_raw);
    let (mut second_attributes, second_body) = split_document(&second_raw);
    second_attributes["contact"]["token"] = first_attributes["contact"]["token"].clone();
    let yaml = yaml_serde::to_string(&second_attributes).unwrap();
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    fs::write(&second_path, format!("---\n{yaml}---\n{second_body}")).unwrap();

    let error = run_failure(command(&second).args(["get", "accounts", "same-id", "--json"]));
    assert!(error.contains("protected data could not be decrypted"));
    assert!(!error.contains("first-database-secret"));
}

#[test]
fn database_context_is_lazy_for_legacy_plaintext_but_never_regenerated_over_ciphertext() {
    let legacy = TestDatabase::new("encrypted-context-legacy");
    fs::remove_file(legacy.root.join(".cr/encryption.json")).unwrap();
    write_schema(&legacy);
    run_success(command(&legacy).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=legacy-first-secret",
    ]));
    assert!(legacy.root.join(".cr/encryption.json").exists());
    assert_eq!(
        json(command(&legacy).args(["get", "accounts", "one", "--json"]))["attributes"]["contact"]
            ["token"],
        "legacy-first-secret"
    );

    let damaged = TestDatabase::new("encrypted-context-damaged");
    write_schema(&damaged);
    run_success(command(&damaged).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=must-remain-bound",
    ]));
    fs::remove_file(damaged.root.join(".cr/encryption.json")).unwrap();
    let read = run_failure(command(&damaged).args(["get", "accounts", "one", "--json"]));
    assert!(read.contains("database encryption context is missing"));
    let write = run_failure(command(&damaged).args([
        "create",
        "accounts",
        "two",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=another-secret",
    ]));
    assert!(write.contains("missing for existing protected data"));
    assert!(!damaged.root.join(".cr/encryption.json").exists());
}

#[test]
fn rotation_reads_history_and_new_values_use_the_active_key() {
    let database = TestDatabase::new("encrypted-rotation");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=old-secret",
        "--body",
        "old body",
    ]));

    let keys = format!(r#"{{"old":"{OLD_KEY}","new":"{NEW_KEY}"}}"#);
    run_success(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "new")
            .env("CR_ENCRYPTION_KEYS", &keys)
            .args([
                "update",
                "accounts",
                "one",
                "--set",
                "contact.token=new-secret",
                "--body",
                "new body",
            ]),
    );
    let stored = stored_document(&database, "one");
    assert!(stored.contains("key_id: new"));
    assert!(stored.contains("cr-encrypted:v1:new:"));
    let entries = json(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "new")
            .env("CR_ENCRYPTION_KEYS", keys)
            .args(["audit", "log", "accounts", "one", "--json"]),
    );
    let history = serde_json::to_string(&entries).unwrap();
    assert!(history.contains("old-secret"));
    assert!(history.contains("new-secret"));
}

#[test]
fn plaintext_migration_and_preview_approval_are_refused_explicitly() {
    let database = TestDatabase::new("encrypted-boundaries");
    write_schema(&database);
    fs::create_dir_all(database.root.join("records/accounts")).unwrap();
    fs::write(
        database.root.join("records/accounts/legacy.md"),
        "---\nstage: lead\ncontact:\n  token: plaintext-secret\n---\nplaintext body\n",
    )
    .unwrap();
    let legacy = run_failure(command(&database).args(["get", "accounts", "legacy"]));
    assert!(legacy.contains("protected data is still plaintext"));
    assert!(!legacy.contains("plaintext-secret"));
    let baseline = run_failure(command(&database).args(["audit", "baseline"]));
    assert!(baseline.contains("protected data is still plaintext"));
    assert!(!audit_bytes(&database).contains("plaintext-secret"));

    let preview = run_failure(command(&database).args([
        "create",
        "accounts",
        "previewed",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=preview-secret",
        "--body",
        "preview body",
        "--preview",
    ]));
    assert!(preview.contains("preview approval is unavailable"));
    assert!(!preview.contains("preview-secret"));

    let invalid_value = run_failure(command(&database).args([
        "create",
        "accounts",
        "invalid",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=short",
    ]));
    assert!(invalid_value.contains("does not match schema"));
    assert!(invalid_value.contains("protected values redacted"));
    assert!(!invalid_value.contains("short"));
    assert!(!database.root.join("records/accounts/invalid.md").exists());
}

#[test]
fn audit_reveals_nested_values_when_the_changed_path_is_their_parent() {
    let database = TestDatabase::new("encrypted-parent-audit");
    let schema = schema().replace(r#", "required": ["contact"]"#, "");
    // The exact schema above puts `required` on separate lines, so make contact
    // optional with a targeted replacement.
    let schema = schema.replace("  \"required\": [\"stage\", \"contact\"],\n", "");
    fs::write(database.root.join(".cr/schemas/accounts.json"), schema).unwrap();
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--body",
        "private",
    ]));
    run_success(command(&database).args([
        "update",
        "accounts",
        "one",
        "--set",
        "contact.token=nested-secret",
    ]));
    let entries = json(command(&database).args(["audit", "log", "accounts", "one", "--json"]));
    assert_eq!(entries[0]["changes"][0]["path"], "/attributes/contact");
    assert_eq!(entries[0]["changes"][0]["after"]["token"], "nested-secret");

    // A direct edit can remove the parent while leaving the encryption
    // manifest and body envelope intact; `save` must also render that parent
    // removal as logical plaintext in history.
    let path = database.root.join("records/accounts/one.md");
    let raw = fs::read_to_string(&path).unwrap();
    let (mut attributes, body) = split_document(&raw);
    attributes
        .as_mapping_mut()
        .unwrap()
        .remove(yaml_serde::Value::String("contact".into()));
    let yaml = yaml_serde::to_string(&attributes).unwrap();
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    fs::write(&path, format!("---\n{yaml}---\n{body}")).unwrap();
    run_success(command(&database).args(["save", "accounts/one"]));
    let entries = json(command(&database).args(["audit", "log", "accounts", "one", "--json"]));
    assert_eq!(entries[0]["changes"][0]["path"], "/attributes/contact");
    assert_eq!(entries[0]["changes"][0]["before"]["token"], "nested-secret");
}

#[test]
fn audit_parent_projection_skips_absent_optional_protected_descendants() {
    let database = TestDatabase::new("encrypted-optional-audit");
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{
  "type": "object",
  "properties": {
    "contact": {
      "type": "object",
      "properties": {
        "label": { "type": "string" },
        "token": { "type": "string", "x-cr-encrypted": true }
      }
    }
  }
}"#,
    )
    .unwrap();
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "contact.label=ordinary",
    ]));
    let entries = json(command(&database).args(["audit", "log", "accounts", "one", "--json"]));
    assert_eq!(entries[0]["changes"][0]["path"], "");
    assert_eq!(
        entries[0]["changes"][0]["after"]["attributes"]["contact"]["label"],
        "ordinary"
    );
}

#[test]
fn encryption_manifest_name_is_reserved_for_writes_but_legacy_data_remains_readable() {
    let database = TestDatabase::new("encrypted-manifest-collision");
    let error = run_failure(database.command().args([
        "create",
        "notes",
        "rejected",
        "--set",
        "$cr_encryption=ordinary",
    ]));
    assert!(error.contains("front matter field '$cr_encryption' is reserved"));
    assert!(!database.root.join("records/notes/rejected.md").exists());

    fs::create_dir_all(database.root.join("records/notes")).unwrap();
    fs::write(
        database.root.join("records/notes/legacy.md"),
        "---\n$cr_encryption: legacy-application-value\ntitle: Legacy\n---\nbody\n",
    )
    .unwrap();
    let legacy = json(
        database
            .command()
            .args(["get", "notes", "legacy", "--json"]),
    );
    assert_eq!(
        legacy["attributes"]["$cr_encryption"],
        "legacy-application-value"
    );
    let exact = fs::read_to_string(database.root.join("records/notes/legacy.md")).unwrap();
    assert_eq!(
        Database::discover(Some(&database.root))
            .unwrap()
            .read_raw("notes", "legacy")
            .unwrap(),
        exact
    );
    assert_eq!(
        run_success(database.command().args(["get", "notes", "legacy"])),
        exact
    );

    // An exact-looking manifest with only absent optional locations does not
    // prove that ciphertext exists and must not make a legacy record unreadable.
    fs::write(
        database.root.join("records/notes/empty-manifest.md"),
        "---\n$cr_encryption:\n  version: 1\n  fields:\n    - [optional, token]\n  body: false\ntitle: Legacy\n---\nbody\n",
    )
    .unwrap();
    let empty = json(
        database
            .command()
            .args(["get", "notes", "empty-manifest", "--json"]),
    );
    assert_eq!(empty["attributes"]["title"], "Legacy");
    let empty_exact =
        fs::read_to_string(database.root.join("records/notes/empty-manifest.md")).unwrap();
    assert_eq!(
        Database::discover(Some(&database.root))
            .unwrap()
            .read_raw("notes", "empty-manifest")
            .unwrap(),
        empty_exact
    );
    assert_eq!(
        run_success(database.command().args(["get", "notes", "empty-manifest"])),
        empty_exact
    );
}

#[test]
fn unchanged_legacy_manifest_collision_survives_updates_and_save_until_removed() {
    let database = TestDatabase::new("encrypted-manifest-collision-updates");
    fs::create_dir_all(database.root.join("records/notes")).unwrap();
    let path = database.root.join("records/notes/legacy.md");
    fs::write(
        &path,
        "---\n$cr_encryption: legacy-application-value\ntitle: Before\n---\noriginal body\n",
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));

    // An unrelated managed update carries the exact grandfathered value.
    run_success(
        database
            .command()
            .args(["update", "notes", "legacy", "--set", "title=After"]),
    );
    let updated = json(
        database
            .command()
            .args(["get", "notes", "legacy", "--json"]),
    );
    assert_eq!(updated["attributes"]["title"], "After");
    assert_eq!(
        updated["attributes"]["$cr_encryption"],
        "legacy-application-value"
    );

    // Adding or changing the reserved value is not grandfathered.
    let changed = run_failure(database.command().args([
        "update",
        "notes",
        "legacy",
        "--set",
        "$cr_encryption=changed",
    ]));
    assert!(changed.contains("front matter field '$cr_encryption' is reserved"));
    run_success(database.command().args(["create", "notes", "plain"]));
    let added = run_failure(database.command().args([
        "update",
        "notes",
        "plain",
        "--set",
        "$cr_encryption=added",
    ]));
    assert!(added.contains("front matter field '$cr_encryption' is reserved"));

    // Direct-save reconciliation has the same compatibility boundary.
    let unrelated_edit = fs::read_to_string(&path)
        .unwrap()
        .replace("original body", "edited body");
    fs::write(&path, unrelated_edit).unwrap();
    run_success(database.command().args(["save", "notes/legacy"]));

    let changed_collision = fs::read_to_string(&path)
        .unwrap()
        .replace("legacy-application-value", "directly-changed");
    fs::write(&path, changed_collision).unwrap();
    let rejected = run_failure(database.command().args(["save", "notes/legacy"]));
    assert!(rejected.contains("front matter field '$cr_encryption' is reserved"));

    // Removing the legacy field is an allowed one-way migration.
    let removed = fs::read_to_string(&path)
        .unwrap()
        .replace("$cr_encryption: directly-changed\n", "");
    fs::write(&path, removed).unwrap();
    run_success(database.command().args(["save", "notes/legacy"]));
    let migrated = json(
        database
            .command()
            .args(["get", "notes", "legacy", "--json"]),
    );
    assert!(migrated["attributes"].get("$cr_encryption").is_none());
}

#[test]
fn standalone_envelope_shaped_application_data_stays_ordinary_in_history_and_migration() {
    let database = TestDatabase::new("encrypted-envelope-shaped-legacy-data");
    fs::remove_file(database.root.join(".cr/encryption.json")).unwrap();
    fs::create_dir_all(database.root.join("records/notes")).unwrap();
    fs::write(
        database.root.join("records/notes/legacy.md"),
        r#"---
payload:
  $cr_encrypted:
    version: 1
    key_id: ordinary
    nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ciphertext: AA
---
ordinary body
"#,
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));

    let history = json(
        database
            .command()
            .args(["audit", "log", "notes", "legacy", "--json"]),
    );
    assert_eq!(
        history[0]["changes"][0]["after"]["attributes"]["payload"]["$cr_encrypted"]["key_id"],
        "ordinary"
    );
    let path = database.root.join("records/notes/legacy.md");
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("key_id: ordinary", "key_id: ordinary-updated");
    fs::write(&path, edited).unwrap();
    run_success(database.command().args(["save", "notes/legacy"]));
    let history = json(
        database
            .command()
            .args(["audit", "log", "notes", "legacy", "--json"]),
    );
    assert_eq!(
        history[0]["changes"][0]["path"],
        "/attributes/payload/$cr_encrypted/key_id"
    );
    assert_eq!(history[0]["changes"][0]["after"], "ordinary-updated");

    // A first encrypted write in this pre-context database must classify the
    // verified legacy history from its complete manifest-free document, not
    // mistake the application's object syntax for CR-owned ciphertext.
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=first-real-secret",
    ]));
    assert!(database.root.join(".cr/encryption.json").exists());
    assert_eq!(
        json(command(&database).args(["get", "accounts", "one", "--json"]))["attributes"]["contact"]
            ["token"],
        "first-real-secret"
    );
    run_success(
        database
            .command()
            .args(["audit", "log", "notes", "legacy", "--json"]),
    );
}

#[test]
fn current_schema_markers_do_not_reinterpret_deleted_ordinary_history() {
    let database = TestDatabase::new("encrypted-envelope-shaped-deleted-history");
    fs::remove_file(database.root.join(".cr/encryption.json")).unwrap();
    fs::create_dir_all(database.root.join("records/accounts")).unwrap();
    fs::write(
        database.root.join("records/accounts/legacy.md"),
        r#"---
stage: lead
contact:
  token:
    $cr_encrypted:
      version: 1
      key_id: ordinary
      nonce: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      ciphertext: AA
---
ordinary body
"#,
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));
    run_success(
        database
            .command()
            .args(["delete", "accounts", "legacy", "--yes"]),
    );

    // An ordinary tombstone carries no protected-storage ownership. A dirty
    // materialization at the same ID therefore remains ordinary while the
    // collection still has no encryption policy.
    let path = database.root.join("records/accounts/legacy.md");
    fs::write(
        &path,
        "---\nstage: resurrected-ordinary\n---\nordinary resurrection\n",
    )
    .unwrap();
    let resurrected = json(
        database
            .command()
            .args(["get", "accounts", "legacy", "--json"]),
    );
    assert_eq!(resurrected["attributes"]["stage"], "resurrected-ordinary");
    fs::remove_file(path).unwrap();

    write_schema(&database);

    // The collection now marks this logical path, but both historical states
    // predate the marker and carry no storage manifest. History remains the
    // exact ordinary object and needs neither a context nor a keyring.
    let history = json(
        database
            .command()
            .args(["audit", "log", "accounts", "legacy", "--json"]),
    );
    assert_eq!(
        history[0]["changes"][0]["before"]["attributes"]["contact"]["token"]["$cr_encrypted"]["key_id"],
        "ordinary"
    );
    assert_eq!(
        history[1]["changes"][0]["after"]["attributes"]["contact"]["token"]["$cr_encrypted"]["key_id"],
        "ordinary"
    );
    assert!(!database.root.join(".cr/encryption.json").exists());
}

#[test]
fn a_manifest_without_owned_envelopes_does_not_claim_its_lifecycle() {
    let database = TestDatabase::new("encrypted-empty-manifest-lifecycle");
    fs::remove_file(database.root.join(".cr/encryption.json")).unwrap();
    fs::create_dir_all(database.root.join("records/notes")).unwrap();
    let path = database.root.join("records/notes/legacy.md");
    fs::write(
        &path,
        r#"---
$cr_encryption:
  version: 1
  fields:
    - [optional, token]
  body: false
title: Legacy
---
ordinary body
"#,
    )
    .unwrap();
    run_success(database.command().args(["audit", "baseline"]));
    run_success(
        database
            .command()
            .args(["delete", "notes", "legacy", "--yes"]),
    );

    fs::write(
        &path,
        "---\ntitle: Dirty resurrection\n---\nordinary body\n",
    )
    .unwrap();
    let resurrected = json(
        database
            .command()
            .args(["get", "notes", "legacy", "--json"]),
    );
    assert_eq!(resurrected["attributes"]["title"], "Dirty resurrection");
    assert_eq!(resurrected["body"], "ordinary body\n");
}

#[test]
fn removing_schema_markers_does_not_expose_envelopes_as_ordinary_data() {
    let database = TestDatabase::new("encrypted-marker-removal");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=still-secret",
        "--body",
        "private",
    ]));
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{"type":"object"}"#,
    )
    .unwrap();
    let error = run_failure(command(&database).args(["get", "accounts", "one", "--json"]));
    assert!(error.contains("stored protected data is no longer declared"));
    assert!(!error.contains("still-secret"));
    let raw_cli = run_failure(command(&database).args(["get", "accounts", "one"]));
    assert!(raw_cli.contains("stored protected data is no longer declared"));
    assert!(!raw_cli.contains("still-secret"));
    assert!(!raw_cli.contains("$cr_encrypted"));
    assert!(!raw_cli.contains("ciphertext"));
    let raw_library = Database::discover(Some(&database.root))
        .unwrap()
        .read_raw("accounts", "one")
        .unwrap_err();
    assert_eq!(
        DomainError::of(&raw_library).map(DomainError::code),
        Some("conflict")
    );
    let raw_library = format!("{raw_library:#}");
    assert!(raw_library.contains("stored protected data is no longer declared"));
    assert!(!raw_library.contains("still-secret"));
    assert!(!raw_library.contains("$cr_encrypted"));
    assert!(!raw_library.contains("ciphertext"));
    let update = run_failure(command(&database).args([
        "update",
        "accounts",
        "one",
        "--set",
        "stage=customer",
    ]));
    assert!(update.contains("stored protected data is no longer declared"));
    assert!(!update.contains("still-secret"));
    let path = database.root.join("records/accounts/one.md");
    let direct_edit = fs::read_to_string(&path)
        .unwrap()
        .replace("stage: lead", "stage: customer");
    fs::write(&path, direct_edit).unwrap();
    let save = run_failure(command(&database).args(["save", "accounts/one"]));
    assert!(save.contains("stored protected data is no longer declared"));
    assert!(!save.contains("still-secret"));
    let raw = fs::read_to_string(&path).unwrap();
    let (mut attributes, body) = split_document(&raw);
    attributes
        .as_mapping_mut()
        .unwrap()
        .remove(yaml_serde::Value::String("$cr_encryption".into()));
    let yaml = yaml_serde::to_string(&attributes).unwrap();
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    fs::write(&path, format!("---\n{yaml}---\n{body}")).unwrap();
    let removed_manifest = run_failure(command(&database).args(["save", "accounts/one"]));
    assert!(removed_manifest.contains("stored protected data is no longer declared"));
    assert!(!removed_manifest.contains("still-secret"));
    let history =
        run_failure(command(&database).args(["audit", "log", "accounts", "one", "--json"]));
    assert!(history.contains("stored protected history is no longer declared"));
    assert!(!history.contains("still-secret"));
}

#[test]
fn audited_ownership_survives_manual_schema_and_manifest_removal_on_every_read() {
    let database = TestDatabase::new("encrypted-audited-ownership");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=history-owned-secret",
        "--body",
        "history-owned body",
    ]));
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{
  "type": "object",
  "properties": {
    "stage": { "type": "string" },
    "contact": {
      "type": "object",
      "properties": { "token": { "type": "string" } }
    }
  }
}"#,
    )
    .unwrap();
    let path = database.root.join("records/accounts/one.md");
    let raw = fs::read_to_string(&path).unwrap();
    let (mut attributes, _) = split_document(&raw);
    let attributes = attributes.as_mapping_mut().unwrap();
    attributes.remove(yaml_serde::Value::String("$cr_encryption".into()));
    let contact = attributes
        .get_mut(yaml_serde::Value::String("contact".into()))
        .unwrap()
        .as_mapping_mut()
        .unwrap();
    let token = contact
        .get_mut(yaml_serde::Value::String("token".into()))
        .unwrap();
    let envelope_fields = token
        .as_mapping_mut()
        .unwrap()
        .remove(yaml_serde::Value::String("$cr_encrypted".into()))
        .unwrap();
    *token = envelope_fields;
    let yaml = yaml_serde::to_string(&attributes).unwrap();
    let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
    fs::write(&path, format!("---\n{yaml}---\nstripped body wrapper\n")).unwrap();

    for arguments in [
        vec!["get", "accounts", "one", "--json"],
        vec!["get", "accounts", "one"],
        vec!["get", "accounts", "one", "--field", "contact.token"],
        vec!["list", "accounts", "--json"],
        vec![
            "search",
            "history-owned",
            "--collection",
            "accounts",
            "--json",
        ],
    ] {
        let error = run_failure(database.command().args(arguments));
        assert!(error.contains("stored protected data is no longer declared"));
        for private in [
            "history-owned-secret",
            "$cr_encrypted",
            "ciphertext",
            "nonce",
        ] {
            assert!(
                !error.contains(private),
                "read error exposed {private}: {error}"
            );
        }
    }

    let library = Database::discover(Some(&database.root)).unwrap();
    let query = SearchQuery::new("history-owned", SearchTarget::Document, false, false).unwrap();
    for error in [
        library.get("accounts", "one").unwrap_err(),
        library.read_raw("accounts", "one").unwrap_err(),
        library.list("accounts", &[]).unwrap_err(),
        library.search(Some("accounts"), &[], &query).unwrap_err(),
    ] {
        assert_eq!(
            DomainError::of(&error).map(DomainError::code),
            Some("conflict")
        );
        let error = format!("{error:#}");
        assert!(error.contains("stored protected data is no longer declared"));
        for private in [
            "history-owned-secret",
            "$cr_encrypted",
            "ciphertext",
            "nonce",
        ] {
            assert!(!error.contains(private));
        }
    }

    let check = database
        .command()
        .args(["check", "--collection", "accounts", "--json"])
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let check = String::from_utf8(check.stdout).unwrap();
    let report: Value = serde_json::from_str(&check).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| {
                finding["kind"] == "unreadable_record"
                    && finding["message"]
                        .as_str()
                        .unwrap()
                        .contains("stored protected data is no longer declared")
            })
    );
    for private in [
        "history-owned-secret",
        "$cr_encrypted",
        "ciphertext",
        "nonce",
    ] {
        assert!(!check.contains(private), "check exposed {private}: {check}");
    }
}

#[test]
fn protected_tombstone_blocks_dirty_resurrection_but_an_audited_create_resets_ownership() {
    let database = TestDatabase::new("encrypted-protected-tombstone-ownership");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=deleted-private-token",
        "--body",
        "deleted private body",
    ]));
    run_success(command(&database).args(["delete", "accounts", "one", "--yes"]));
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{
  "type": "object",
  "properties": {
    "stage": { "type": "string" },
    "contact": {
      "type": "object",
      "properties": { "token": { "type": "string" } }
    }
  }
}"#,
    )
    .unwrap();

    let path = database.root.join("records/accounts/one.md");
    fs::write(
        &path,
        "---\nstage: manual-resurrection\ncontact:\n  token: ordinary-looking\n---\nmanual body\n",
    )
    .unwrap();
    for arguments in [
        vec!["get", "accounts", "one", "--json"],
        vec!["get", "accounts", "one"],
        vec!["get", "accounts", "one", "--field", "contact.token"],
        vec!["list", "accounts", "--json"],
        vec![
            "search",
            "manual-resurrection",
            "--collection",
            "accounts",
            "--json",
        ],
    ] {
        let error = run_failure(database.command().args(arguments));
        assert!(error.contains("stored protected data is no longer declared"));
        assert!(!error.contains("manual-resurrection"));
        assert!(!error.contains("ordinary-looking"));
    }
    let check = database
        .command()
        .args(["check", "--collection", "accounts", "--json"])
        .output()
        .unwrap();
    assert_eq!(check.status.code(), Some(2));
    let check = String::from_utf8(check.stdout).unwrap();
    assert!(check.contains("stored protected data is no longer declared"));
    assert!(!check.contains("manual-resurrection"));
    assert!(!check.contains("ordinary-looking"));

    // Removing the unaudited file and creating a new ordinary lifecycle
    // through cr is an authenticated reset, not a permanent ID quarantine.
    fs::remove_file(&path).unwrap();
    run_success(database.command().args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=fresh",
        "--set",
        "contact.token=ordinary-lifecycle",
        "--body",
        "ordinary body",
    ]));
    let fresh = json(
        database
            .command()
            .args(["get", "accounts", "one", "--json"]),
    );
    assert_eq!(fresh["attributes"]["stage"], "fresh");
    assert_eq!(
        fresh["attributes"]["contact"]["token"],
        "ordinary-lifecycle"
    );
    assert_eq!(fresh["body"], "ordinary body");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn moving_a_schema_marker_never_projects_an_old_envelope_at_the_new_path() {
    let database = TestDatabase::new("encrypted-marker-move");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=marker-move-secret",
    ]));
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{
  "type": "object",
  "properties": {
    "stage": { "type": "string" },
    "contact": {
      "type": "object",
      "properties": {
        "token": { "type": "string" },
        "other": { "type": "string", "x-cr-encrypted": true }
      }
    }
  }
}"#,
    )
    .unwrap();

    let history = run_failure(
        command(&database).args(["audit", "log", "accounts", "one", "--limit", "1", "--json"]),
    );
    assert!(history.contains("stored protected history is no longer declared"));
    assert!(!history.contains("marker-move-secret"));
    assert!(!history.contains("$cr_encrypted"));
    assert!(!history.contains("ciphertext"));
}

#[test]
fn unencrypted_raw_reads_preserve_exact_formatting() {
    let database = TestDatabase::new("unencrypted-raw-format");
    fs::create_dir_all(database.root.join("records/notes")).unwrap();
    let raw = "---\r\nname: Exact\r\n---\r\nBody without final newline";
    fs::write(database.root.join("records/notes/one.md"), raw).unwrap();
    assert_eq!(
        run_success(database.command().args(["get", "notes", "one"])),
        raw
    );
}

#[test]
fn encrypted_pending_mutations_recover_over_ciphertext_without_keys() {
    let database = FaultDatabase::new("encrypted-pending-recovery");
    fs::write(database.root().join(".cr/schemas/accounts.json"), schema()).unwrap();
    let interruption = database.interrupt_with(
        "accounts",
        "one",
        |command| {
            command
                .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
                .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#));
        },
        &[
            "create",
            "accounts",
            "one",
            "--set",
            "stage=lead",
            "--set",
            "contact.token=recovery-secret",
            "--body",
            "recovery notes",
            "--idempotency-key",
            RETRY_KEY,
        ],
    );
    assert!(!String::from_utf8_lossy(&interruption.pending).contains("recovery-secret"));
    assert!(!String::from_utf8_lossy(&interruption.pending).contains("recovery notes"));
    assert!(
        !String::from_utf8_lossy(interruption.after.as_ref().unwrap()).contains("recovery-secret")
    );

    database.restore(&interruption, "accounts", "one", Point::RecordReplaced);
    // Recovery and verification compare the exact stored ciphertext hashes;
    // neither operation needs to decrypt the logical document.
    let verification = run_success(database.command().args(["audit", "verify"]));
    assert!(verification.contains("Verified 1 audit events and 1 records"));
    assert!(database.read_pending().is_none());

    let mut replay_command = database.command();
    replay_command
        .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
        .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#))
        .args([
            "create",
            "accounts",
            "one",
            "--set",
            "stage=lead",
            "--set",
            "contact.token=recovery-secret",
            "--body",
            "recovery notes",
            "--idempotency-key",
            RETRY_KEY,
            "--json",
        ]);
    let replay = json(&mut replay_command);
    assert_eq!(replay["attributes"]["contact"]["token"], "recovery-secret");
    assert_eq!(database.head_sequence(), 1);

    let record = json(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#))
            .args(["get", "accounts", "one", "--json"]),
    );
    assert_eq!(record["attributes"]["contact"]["token"], "recovery-secret");
    assert_eq!(record["body"], "recovery notes");
}

#[test]
fn save_preflights_every_decrypted_projection_before_committing_any_event() {
    let database = TestDatabase::new("encrypted-save-projection");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "encrypted",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=projection-secret",
    ]));
    run_success(database.command().args([
        "create",
        "aardvark",
        "ordinary",
        "--set",
        "status=before",
    ]));
    let head_before = json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap();

    fs::remove_file(database.root.join("records/accounts/encrypted.md")).unwrap();
    fs::write(
        database.root.join("records/aardvark/ordinary.md"),
        "---\nstatus: after\n---\n",
    )
    .unwrap();
    let error = run_failure(database.command().args(["save", "--all"]));
    assert!(error.contains("CR_ENCRYPTION_KEYS is required"));
    let head_after = json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap();
    assert_eq!(head_after, head_before, "save must not accept a prefix");

    run_success(command(&database).args(["save", "--all"]));
    assert_eq!(
        json(database.command().args(["audit", "head", "--json"]))["sequence"],
        head_before + 2
    );
}

fn interrupt_legacy_plaintext_sync(database: &TestDatabase, name: &str, final_collection: &str) {
    fs::create_dir_all(database.root.join("scripts")).unwrap();
    fs::create_dir_all(database.root.join("records")).unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' '{{"type":"upsert","collection":"notes","id":"first","front_matter":{{"n":1}},"markdown":"first"}}'
printf '%s\n' '{{"type":"upsert","collection":"blocked","id":"second","front_matter":{{"n":2}},"markdown":"second"}}'
printf '%s\n' '{{"type":"upsert","collection":"{final_collection}","id":"one","front_matter":{{"stage":"lead","contact":{{"token":"legacy-stream-secret"}}}},"markdown":"legacy stream body"}}'
printf '%s\n' '{{"type":"checkpoint","state":{{"cursor":"legacy-checkpoint-secret"}}}}'
"#
    );
    let script_path = format!("scripts/{name}.sh");
    fs::write(database.root.join(&script_path), script).unwrap();
    fs::write(database.root.join("records/blocked"), "blocked\n").unwrap();
    run_success(
        database
            .command()
            .args(["sync", "create", name, "--", "sh", &script_path]),
    );
    run_failure(database.command().args(["sync", "run", name]));
    assert!(database.root.join("records/notes/first.md").exists());
    assert!(
        fs::read_to_string(database.root.join(format!(".cr/sync/runs/{name}.jsonl")))
            .unwrap()
            .contains("legacy-stream-secret")
    );
}

#[test]
fn legacy_plaintext_sync_recovery_refuses_values_now_governed_by_encryption() {
    for version in [1, 2] {
        let database = TestDatabase::new(&format!("encrypted-legacy-sync-v{version}"));
        let name = format!("legacy-v{version}");
        interrupt_legacy_plaintext_sync(&database, &name, "accounts");
        let ledger_path = database.root.join(format!(".cr/sync/runs/{name}.json"));
        if version == 1 {
            let mut ledger: Value =
                serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
            ledger["version"] = Value::from(1);
            ledger.as_object_mut().unwrap().remove("target_versions");
            fs::write(&ledger_path, serde_json::to_vec_pretty(&ledger).unwrap()).unwrap();
        }
        write_schema(&database);
        fs::remove_file(database.root.join("records/blocked")).unwrap();
        let stream_path = database.root.join(format!(".cr/sync/runs/{name}.jsonl"));
        let stream_before = fs::read(&stream_path).unwrap();
        let ledger_before = fs::read(&ledger_path).unwrap();
        let head_before = json(database.command().args(["audit", "head", "--json"]));

        let error = run_failure(database.command().args(["sync", "recover", &name]));
        assert!(
            error.contains("plaintext operation stream is incompatible with the current protected storage policy"),
            "{error}"
        );
        for secret in [
            "legacy-stream-secret",
            "legacy stream body",
            "legacy-checkpoint-secret",
        ] {
            assert!(!error.contains(secret), "error exposed {secret}: {error}");
        }
        assert_eq!(fs::read(&stream_path).unwrap(), stream_before);
        assert_eq!(fs::read(&ledger_path).unwrap(), ledger_before);
        assert!(!database.root.join("records/accounts/one.md").exists());
        assert_eq!(
            json(database.command().args(["audit", "head", "--json"])),
            head_before
        );
        run_success(database.command().args(["audit", "verify"]));
    }
}

#[test]
fn legacy_plaintext_sync_recovery_remains_compatible_when_its_targets_are_unprotected() {
    let database = TestDatabase::new("encrypted-unrelated-legacy-sync");
    interrupt_legacy_plaintext_sync(&database, "legacy", "notes");
    write_schema(&database);
    fs::remove_file(database.root.join("records/blocked")).unwrap();

    let recovered = json(
        database
            .command()
            .args(["sync", "recover", "legacy", "--json"]),
    );
    assert_eq!(recovered["resumed"], true);
    assert_eq!(recovered["created"], 2);
    assert_eq!(recovered["unchanged"], 1);
    assert_eq!(
        json(database.command().args(["sync", "state", "legacy"]))["cursor"],
        "legacy-checkpoint-secret"
    );
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn marker_removal_refuses_sync_upsert_before_staging_its_plaintext_stream() {
    let database = TestDatabase::new("encrypted-sync-marker-removal-staging");
    write_schema(&database);
    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=original-protected-secret",
        "--body",
        "original protected body",
    ]));
    let stored_before = stored_document(&database, "one");
    let head_before = json(database.command().args(["audit", "head", "--json"]));
    fs::write(
        database.root.join(".cr/schemas/accounts.json"),
        r#"{"type":"object"}"#,
    )
    .unwrap();
    fs::create_dir_all(database.root.join("scripts")).unwrap();
    fs::write(
        database.root.join("scripts/stale.sh"),
        r#"#!/bin/sh
set -eu
printf '%s\n' '{"type":"upsert","collection":"accounts","id":"one","front_matter":{"stage":"lead","contact":{"token":"adapter-plaintext-secret"}},"markdown":"adapter plaintext body"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"adapter-checkpoint-secret"}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "stale",
        "--",
        "sh",
        "scripts/stale.sh",
    ]));

    let error = run_failure(database.command().args(["sync", "run", "stale"]));
    assert!(
        error.contains("stored protected data is no longer declared by the collection schema"),
        "{error}"
    );
    for secret in [
        "adapter-plaintext-secret",
        "adapter plaintext body",
        "adapter-checkpoint-secret",
    ] {
        assert!(!error.contains(secret), "error exposed {secret}: {error}");
    }
    assert_eq!(stored_document(&database, "one"), stored_before);
    assert_eq!(
        json(database.command().args(["audit", "head", "--json"])),
        head_before
    );
    assert!(!database.root.join(".cr/sync/runs/stale.json").exists());
    assert!(!database.root.join(".cr/sync/runs/stale.jsonl").exists());
    assert_tree_omits(
        &database.root.join(".cr"),
        &[
            "adapter-plaintext-secret",
            "adapter plaintext body",
            "adapter-checkpoint-secret",
        ],
    );
}

#[test]
fn interrupted_protected_sync_persists_only_authenticated_ciphertext_and_recovers() {
    let database = FaultDatabase::new("encrypted-sync-ledger");
    fs::write(database.root().join(".cr/schemas/accounts.json"), schema()).unwrap();
    fs::create_dir_all(database.root().join("scripts")).unwrap();
    fs::write(
        database.root().join("scripts/protected.sh"),
        r#"#!/bin/sh
set -eu
test -z "${CR_ENCRYPTION_ACTIVE_KEY+x}"
test -z "${CR_ENCRYPTION_KEYS+x}"
printf '%s\n' '{"type":"upsert","collection":"accounts","id":"one","front_matter":{"stage":"lead","contact":{"token":"sync-ledger-secret"}},"markdown":"sync ledger body"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"secret-checkpoint-value"}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "protected",
        "--",
        "sh",
        "scripts/protected.sh",
    ]));

    let interruption = database.interrupt_with(
        "accounts",
        "one",
        |command| {
            command
                .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
                .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#));
        },
        &["sync", "run", "protected"],
    );
    database.restore(&interruption, "accounts", "one", Point::RecordReplaced);
    let stream = fs::read_to_string(database.root().join(".cr/sync/runs/protected.jsonl")).unwrap();
    assert!(stream.contains("\"ciphertext\""));
    let ledger_path = database.root().join(".cr/sync/runs/protected.json");
    let original_ledger = fs::read(&ledger_path).unwrap();
    let ledger: Value = serde_json::from_slice(&original_ledger).unwrap();
    assert_eq!(ledger["version"], 3);
    assert_eq!(ledger["checkpoint_after"]["recorded"], true);
    assert!(
        ledger["checkpoint_after"]["digest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(ledger["checkpoint_after"].get("state").is_none());
    assert_tree_omits(
        &database.root().join(".cr/sync"),
        &[
            "sync-ledger-secret",
            "sync ledger body",
            "secret-checkpoint-value",
        ],
    );

    // The authenticated stream is the source of the actual checkpoint value;
    // its public ledger commitment must agree before recovery applies work.
    let mut forged_ledger: Value = serde_json::from_slice(&original_ledger).unwrap();
    forged_ledger["checkpoint_after"]["digest"] =
        Value::String(format!("sha256:{}", "0".repeat(64)));
    fs::write(
        &ledger_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&forged_ledger).unwrap()
        ),
    )
    .unwrap();
    let mismatch =
        run_failure(fault_command(&database).args(["sync", "recover", "protected", "--json"]));
    assert!(mismatch.contains("checkpoint metadata does not match its operation stream"));
    assert!(!mismatch.contains("secret-checkpoint-value"));
    fs::write(&ledger_path, &original_ledger).unwrap();

    run_success(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#))
            .args(["sync", "recover", "protected", "--json"]),
    );
    assert!(
        !database
            .root()
            .join(".cr/sync/runs/protected.json")
            .exists()
    );
    assert!(
        !database
            .root()
            .join(".cr/sync/runs/protected.jsonl")
            .exists()
    );
    let recovered = json(
        database
            .command()
            .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
            .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#))
            .args(["get", "accounts", "one", "--json"]),
    );
    assert_eq!(
        recovered["attributes"]["contact"]["token"],
        "sync-ledger-secret"
    );
    assert_eq!(
        json(database.command().args(["sync", "state", "protected"]))["cursor"],
        "secret-checkpoint-value"
    );
}

#[test]
fn a_pre_mutation_protected_sync_run_prevents_context_regeneration() {
    let database = FaultDatabase::new("encrypted-sync-context-guard");
    fs::write(database.root().join(".cr/schemas/accounts.json"), schema()).unwrap();
    fs::create_dir_all(database.root().join("scripts")).unwrap();
    fs::write(
        database.root().join("scripts/protected.sh"),
        r#"#!/bin/sh
set -eu
printf '%s\n' '{"type":"upsert","collection":"accounts","id":"one","front_matter":{"stage":"lead","contact":{"token":"context-bound-secret"}}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "protected",
        "--",
        "sh",
        "scripts/protected.sh",
    ]));

    let original_context = fs::read(database.root().join(".cr/encryption.json")).unwrap();
    let interruption = database.interrupt_with(
        "accounts",
        "one",
        |command| {
            command
                .env("CR_ENCRYPTION_ACTIVE_KEY", "old")
                .env("CR_ENCRYPTION_KEYS", format!(r#"{{"old":"{OLD_KEY}"}}"#));
        },
        &["sync", "run", "protected"],
    );
    // This is the reachable crash window after the stream and ledger became
    // durable but before the first mutation wrote its pending event.
    database.restore(&interruption, "accounts", "one", Point::PendingWritten);
    database.clear_pending();
    assert!(!database.root().join("records/accounts/one.md").exists());
    assert_eq!(database.head_sequence(), 0);

    fs::remove_file(database.root().join(".cr/encryption.json")).unwrap();
    let refused = run_failure(fault_command(&database).args([
        "create",
        "accounts",
        "two",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=another-secret",
    ]));
    assert!(refused.contains("missing for an interrupted protected sync run"));
    assert!(!database.root().join(".cr/encryption.json").exists());
    assert!(!refused.contains("context-bound-secret"));

    fs::write(
        database.root().join(".cr/encryption.json"),
        original_context,
    )
    .unwrap();
    run_success(fault_command(&database).args(["sync", "recover", "protected"]));
    assert_eq!(
        json(fault_command(&database).args(["get", "accounts", "one", "--json"]))["attributes"]["contact"]
            ["token"],
        "context-bound-secret"
    );
}

#[test]
fn orphaned_or_malformed_sync_markers_do_not_claim_an_encryption_context() {
    let database = TestDatabase::new("encrypted-sync-context-marker-validation");
    write_schema(&database);
    fs::remove_file(database.root.join(".cr/encryption.json")).unwrap();
    fs::create_dir_all(database.root.join(".cr/sync/runs")).unwrap();
    fs::write(
        database.root.join(".cr/sync/runs/orphan.jsonl"),
        br#"{"version":1,"key_id":"old","nonce":"bad","ciphertext":"bad"}"#,
    )
    .unwrap();
    fs::write(
        database.root.join(".cr/sync/runs/malformed.json"),
        b"not a run ledger\n",
    )
    .unwrap();

    run_success(command(&database).args([
        "create",
        "accounts",
        "one",
        "--set",
        "stage=lead",
        "--set",
        "contact.token=first-real-secret",
    ]));
    assert!(database.root.join(".cr/encryption.json").exists());
}

#[test]
#[cfg(unix)]
fn killing_a_sync_during_fetch_cannot_orphan_plaintext_output_under_dot_cr() {
    let database = TestDatabase::new("encrypted-sync-crash-output");
    write_schema(&database);
    fs::create_dir_all(database.root.join("scripts")).unwrap();
    fs::write(
        database.root.join("scripts/crash.sh"),
        r#"#!/bin/sh
set -eu
echo $$ > "$CR_DATABASE_ROOT/adapter.pid"
printf '%s\n' '{"type":"upsert","collection":"accounts","id":"one","front_matter":{"stage":"lead","contact":{"token":"crash-output-secret"}},"markdown":"crash output body"}'
sleep 30
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "crash",
        "--",
        "sh",
        "scripts/crash.sh",
    ]));

    let mut child = command(&database)
        .args(["sync", "run", "crash"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid_path = database.root.join("adapter.pid");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !pid_path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_path.exists(), "adapter did not start in time");
    thread::sleep(Duration::from_millis(50));
    child.kill().unwrap();
    child.wait().unwrap();
    let adapter_pid: libc::pid_t = fs::read_to_string(pid_path)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: the PID came from the test adapter and is killed only to avoid
    // leaving its deliberate sleep behind after the parent process is gone.
    unsafe {
        libc::kill(adapter_pid, libc::SIGKILL);
    }
    assert_tree_omits(
        &database.root.join(".cr"),
        &["crash-output-secret", "crash output body"],
    );
}
