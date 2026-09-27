mod common;

use std::process::Command;

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

const OWNER: &str = "Owner <owner@example.com>";
const BOB: &str = "Bob <bob@example.com>";
const MANAGER: &str = "Manager <manager@example.com>";

fn as_principal(database: &TestDatabase, actor: &str) -> Command {
    let mut command = database.command();
    command.env("CR_ACTOR", actor);
    command
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn error_code(command: &mut Command) -> String {
    let stderr = run_failure(command.arg("--json-errors"));
    let envelope: Value = serde_json::from_str(stderr.trim()).unwrap();
    envelope["error"]["code"].as_str().unwrap().to_owned()
}

fn initialize(database: &TestDatabase) {
    run_success(as_principal(database, OWNER).args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    for (id, name) in [
        ("bob@example.com", "Bob"),
        ("manager@example.com", "Manager"),
    ] {
        run_success(
            as_principal(database, OWNER).args(["user", "add", id, "--name", name, "--email", id]),
        );
    }
    run_success(as_principal(database, OWNER).args([
        "access",
        "grant",
        "manager@example.com",
        "access_manager",
        "database",
    ]));
}

#[test]
fn issuing_a_token_is_an_audited_owner_only_policy_change_that_shows_the_secret_once() {
    let database = TestDatabase::new("token-issue");
    initialize(&database);

    let issued = json(as_principal(&database, OWNER).args([
        "access",
        "token",
        "issue",
        "bob@example.com",
        "--label",
        "nightly harness",
        "--expires-in",
        "90d",
        "--json",
    ]));
    let token = issued["token"].as_str().unwrap();
    let id = issued["id"].as_str().unwrap();
    assert!(token.starts_with(&format!("crt_{id}_")));
    assert_eq!(issued["principal"], "bob@example.com");
    assert_eq!(issued["label"], "nightly harness");
    assert!(issued["expires"].as_str().unwrap() > issued["created"].as_str().unwrap());

    // The user record keeps a verifier, never the secret, and the change is an
    // ordinary audited update of the policy record.
    let stored =
        std::fs::read_to_string(database.root().join("records/users/bob@example.com.md")).unwrap();
    assert!(stored.contains(&format!("id: {id}")));
    assert!(stored.contains("hash: sha256:"));
    assert!(!stored.contains(token));
    let history = json(as_principal(&database, OWNER).args([
        "audit",
        "log",
        "users",
        "bob@example.com",
        "--json",
    ]));
    let latest = &history.as_array().unwrap()[0];
    assert_eq!(latest["action"], "update");
    assert_eq!(latest["access"]["principal"], "owner@example.com");
    assert_eq!(latest["access"]["role"], "owner");
    run_success(as_principal(&database, OWNER).args(["audit", "verify"]));

    // Listing never shows a secret or a verifier.
    let listed = json(as_principal(&database, OWNER).args(["access", "token", "list", "--json"]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], id);
    assert_eq!(listed[0]["principal"], "bob@example.com");
    assert_eq!(listed[0]["expired"], false);
    assert!(listed[0].get("hash").is_none());
    assert!(!listed.to_string().contains(token));
    let plain = run_success(as_principal(&database, OWNER).args(["access", "token", "list"]));
    assert!(plain.contains(id) && plain.contains("nightly harness"));
    assert!(!plain.contains(token));

    // Plain issue prints only the secret on stdout, so it can be captured.
    let secret = run_success(as_principal(&database, OWNER).args([
        "access",
        "token",
        "issue",
        "bob@example.com",
    ]));
    assert!(secret.trim().starts_with("crt_"));
    assert_eq!(secret.lines().count(), 1);

    run_success(as_principal(&database, OWNER).args([
        "access",
        "token",
        "revoke",
        "bob@example.com",
        id,
    ]));
    let listed = json(as_principal(&database, OWNER).args([
        "access",
        "token",
        "list",
        "bob@example.com",
        "--json",
    ]));
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_ne!(listed[0]["id"], id);
    run_success(as_principal(&database, OWNER).args(["audit", "verify"]));
}

#[test]
fn only_an_owner_may_issue_list_or_revoke_tokens() {
    let database = TestDatabase::new("token-owner-only");
    initialize(&database);
    let issued = json(as_principal(&database, OWNER).args([
        "access",
        "token",
        "issue",
        "bob@example.com",
        "--json",
    ]));
    let id = issued["id"].as_str().unwrap();

    // Not the principal itself, and not an access manager: a token is the
    // ability to act as its principal, so minting one is minting identity.
    for actor in [BOB, MANAGER] {
        assert_eq!(
            error_code(as_principal(&database, actor).args([
                "access",
                "token",
                "issue",
                "bob@example.com",
            ])),
            "forbidden"
        );
        assert_eq!(
            error_code(as_principal(&database, actor).args(["access", "token", "list"])),
            "forbidden"
        );
        assert_eq!(
            error_code(as_principal(&database, actor).args([
                "access",
                "token",
                "revoke",
                "bob@example.com",
                id,
            ])),
            "forbidden"
        );
    }
}

#[test]
fn tokens_are_refused_for_missing_or_disabled_principals_and_unknown_ids() {
    let database = TestDatabase::new("token-refusals");
    assert_eq!(
        error_code(as_principal(&database, OWNER).args([
            "access",
            "token",
            "issue",
            "bob@example.com",
        ])),
        "conflict"
    );
    initialize(&database);

    assert_eq!(
        error_code(as_principal(&database, OWNER).args([
            "access",
            "token",
            "issue",
            "nobody@example.com",
        ])),
        "not_found"
    );
    assert_eq!(
        error_code(as_principal(&database, OWNER).args([
            "access",
            "token",
            "revoke",
            "bob@example.com",
            "0123456789abcdef",
        ])),
        "not_found"
    );
    run_success(as_principal(&database, OWNER).args([
        "user",
        "update",
        "bob@example.com",
        "--status",
        "disabled",
    ]));
    assert_eq!(
        error_code(as_principal(&database, OWNER).args([
            "access",
            "token",
            "issue",
            "bob@example.com",
        ])),
        "conflict"
    );
    for lifetime in ["0d", "-1d", "90", "90m", "d"] {
        run_failure(as_principal(&database, OWNER).args([
            "access",
            "token",
            "issue",
            "manager@example.com",
            "--expires-in",
            lifetime,
        ]));
    }
}

#[test]
fn ordinary_updates_cannot_write_token_verifiers() {
    let database = TestDatabase::new("token-generic-update");
    initialize(&database);
    assert_eq!(
        error_code(as_principal(&database, OWNER).args([
            "update",
            "users",
            "bob@example.com",
            "--set",
            "tokens=[]",
        ])),
        "validation_failed"
    );
    assert_eq!(
        error_code(as_principal(&database, BOB).args([
            "update",
            "users",
            "bob@example.com",
            "--set",
            "tokens=[]",
        ])),
        "validation_failed"
    );
}
