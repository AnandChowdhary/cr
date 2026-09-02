mod common;

use std::process::Command;

use common::{TestDatabase, run_failure, run_success};
use serde_json::Value;

const OWNER: &str = "Owner <owner@example.com>";
const BOB: &str = "Bob <bob@example.com>";
const READER: &str = "Reader <reader@example.com>";
const MANAGER: &str = "Manager <manager@example.com>";

fn as_principal(database: &TestDatabase, actor: &str) -> Command {
    let mut command = database.command();
    command.env("CR_ACTOR", actor);
    command
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
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
}

fn add_user(database: &TestDatabase, id: &str, name: &str) {
    run_success(
        as_principal(database, OWNER).args(["user", "add", id, "--name", name, "--email", id]),
    );
}

#[test]
fn access_init_creates_a_fixed_schema_audited_owner_record() {
    let database = TestDatabase::new("access-init");
    initialize(&database);

    let shown =
        json(as_principal(&database, OWNER).args(["user", "show", "owner@example.com", "--json"]));
    assert_eq!(shown["id"], "owner@example.com");
    assert_eq!(shown["user"]["name"], "Owner");
    assert_eq!(shown["user"]["status"], "active");
    assert_eq!(shown["user"]["access"][0]["resource"], "database");
    assert_eq!(shown["user"]["access"][0]["role"], "owner");

    let identity = json(as_principal(&database, OWNER).args(["identity", "--json"]));
    assert_eq!(identity["principal"], "owner@example.com");
    assert_eq!(identity["actor"], OWNER);
    assert_eq!(identity["access_control"], true);

    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "update",
            "users",
            "owner@example.com",
            "--set",
            "status=disabled",
        ]))
        .contains("may change only profile.*")
    );
    run_success(as_principal(&database, OWNER).args(["audit", "verify"]));
}

#[test]
fn record_roles_gate_reads_writes_deletes_and_discovery() {
    let database = TestDatabase::new("record-rbac");
    initialize(&database);
    run_success(as_principal(&database, OWNER).args([
        "create",
        "deals",
        "public",
        "--set",
        "stage=open",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "create",
        "deals",
        "secret",
        "--set",
        "stage=open",
    ]));
    add_user(&database, "bob@example.com", "Bob");
    add_user(&database, "reader@example.com", "Reader");
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "bob@example.com",
        "editor",
        "collection:deals",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "bob@example.com",
        "viewer",
        "record:deals/secret",
    ]));
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "reader@example.com",
        "viewer",
        "record:deals/public",
    ]));

    run_success(as_principal(&database, BOB).args([
        "update",
        "deals",
        "public",
        "--set",
        "stage=won",
    ]));
    assert!(
        run_failure(as_principal(&database, BOB).args([
            "update",
            "deals",
            "secret",
            "--set",
            "stage=won",
        ]))
        .contains("cannot update record:deals/secret")
    );
    assert!(
        run_failure(as_principal(&database, BOB).args(["delete", "deals", "public", "--yes",]))
            .contains("cannot delete record:deals/public")
    );

    let reader_list = json(as_principal(&database, READER).args(["list", "deals", "--json"]));
    assert_eq!(reader_list.as_array().unwrap().len(), 1);
    assert_eq!(reader_list[0]["path"], "records/deals/public.md");
    assert!(
        run_failure(as_principal(&database, READER).args(["get", "deals", "secret",]))
            .contains("cannot read record:deals/secret")
    );

    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "--actor",
            "bob@example.com",
            "identity",
        ]))
        .contains("cannot impersonate principal 'bob@example.com'")
    );

    let log =
        json(as_principal(&database, OWNER).args(["audit", "log", "deals", "public", "--json"]));
    assert_eq!(log[0]["access"]["principal"], "bob@example.com");
    assert_eq!(log[0]["access"]["role"], "editor");
    assert_eq!(log[0]["access"]["resource"], "record:deals/public");
    assert!(
        log[0]["access"]["policy_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    run_success(as_principal(&database, OWNER).args(["audit", "verify"]));
}

#[test]
fn access_managers_can_administer_ordinary_roles_but_not_ownership() {
    let database = TestDatabase::new("access-manager");
    initialize(&database);
    run_success(as_principal(&database, OWNER).args([
        "create",
        "deals",
        "one",
        "--set",
        "stage=open",
    ]));
    add_user(&database, "manager@example.com", "Manager");
    run_success(as_principal(&database, OWNER).args([
        "access",
        "grant",
        "manager@example.com",
        "access_manager",
        "database",
    ]));

    run_success(as_principal(&database, MANAGER).args([
        "user",
        "add",
        "new@example.com",
        "--name",
        "New User",
        "--email",
        "new@example.com",
    ]));
    run_success(as_principal(&database, MANAGER).args([
        "access",
        "grant",
        "new@example.com",
        "viewer",
        "collection:deals",
    ]));
    assert_eq!(
        json(as_principal(&database, MANAGER).args(["user", "list", "--json"]))
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let policy_history = json(as_principal(&database, MANAGER).args([
        "audit",
        "log",
        "users",
        "new@example.com",
        "--json",
    ]));
    assert_eq!(policy_history[0]["record"]["collection"], "users");
    assert_eq!(policy_history[0]["record"]["id"], "new@example.com");
    assert!(
        run_failure(as_principal(&database, MANAGER).args(["get", "deals", "one",]))
            .contains("cannot read record:deals/one")
    );
    assert!(
        run_failure(as_principal(&database, MANAGER).args([
            "access",
            "grant",
            "new@example.com",
            "access_manager",
            "database",
        ]))
        .contains("must be an owner of database")
    );
    assert!(
        run_failure(as_principal(&database, MANAGER).args([
            "access",
            "revoke",
            "owner@example.com",
            "database",
        ]))
        .contains("must be an owner of database")
    );
    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "access",
            "revoke",
            "owner@example.com",
            "database",
        ]))
        .contains("cannot remove the final database owner")
    );
    assert!(
        run_failure(as_principal(&database, OWNER).args([
            "user",
            "add",
            "Upper@Example.com",
            "--name",
            "Upper",
            "--email",
            "Upper@Example.com",
        ]))
        .contains("not canonical; use 'upper@example.com'")
    );
}
