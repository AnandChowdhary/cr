use std::fs;

use cr::{
    AccessResource, AuditFilter, Database, Role, UserEnsureOutcome, UserKind, UserStatus,
    UserUpdate,
};
use yaml_serde::{Mapping, Value};

const OWNER: &str = "Owner <owner@example.com>";

fn database(name: &str) -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name))
        .unwrap()
        .with_actor(OWNER)
        .unwrap();
    (temporary, database)
}

fn profile(role: &str) -> Mapping {
    let mut profile = Mapping::new();
    profile.insert(Value::String("role".into()), Value::String(role.into()));
    profile
}

#[test]
fn service_bootstrap_and_namespaced_profile_keep_the_user_schema_closed() {
    let (_temporary, database) = database("service-profile");
    database
        .initialize_access_with_kind(
            Some("Harness"),
            Some("owner@example.com"),
            UserKind::Service,
        )
        .unwrap();
    let owner = database.user("owner@example.com").unwrap();
    assert_eq!(owner.kind, UserKind::Service);

    database
        .add_user_with_profile(
            "ada@example.com",
            "Ada",
            Some("ada@example.com"),
            UserKind::Human,
            profile("CEO"),
        )
        .unwrap();
    let ada = database.user("ada@example.com").unwrap();
    assert_eq!(ada.profile["role"], Value::String("CEO".into()));

    let mut invalid = ada.attributes().unwrap();
    invalid.insert(
        Value::String("slack_id".into()),
        Value::String("U123".into()),
    );
    let error = database
        .validate_record_attributes("users", &invalid)
        .unwrap_err();
    assert!(error.to_string().contains("slack_id"));
}

#[test]
fn ensure_is_atomic_in_shape_idempotent_and_conflicts_on_definition_drift() {
    let (_temporary, database) = database("ensure-user");
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();

    let mut first_profile = Mapping::new();
    first_profile.insert(Value::String("zeta".into()), Value::String("last".into()));
    first_profile.insert(Value::String("alpha".into()), Value::String("first".into()));

    assert_eq!(
        database
            .ensure_user(
                "daemon@example.com",
                "Daemon",
                Some("daemon@example.com"),
                UserKind::Service,
                first_profile,
            )
            .unwrap(),
        UserEnsureOutcome::Created
    );
    let events_after_create = database
        .audit_recent(100, AuditFilter::all())
        .unwrap()
        .len();
    let mut reordered_profile = Mapping::new();
    reordered_profile.insert(Value::String("alpha".into()), Value::String("first".into()));
    reordered_profile.insert(Value::String("zeta".into()), Value::String("last".into()));
    assert_eq!(
        database
            .ensure_user(
                "daemon@example.com",
                "Daemon",
                Some("daemon@example.com"),
                UserKind::Service,
                reordered_profile,
            )
            .unwrap(),
        UserEnsureOutcome::Unchanged
    );
    assert_eq!(
        database
            .audit_recent(100, AuditFilter::all())
            .unwrap()
            .len(),
        events_after_create
    );

    let error = database
        .ensure_user(
            "daemon@example.com",
            "Different daemon",
            Some("daemon@example.com"),
            UserKind::Service,
            {
                let mut changed = Mapping::new();
                changed.insert(
                    Value::String("alpha".into()),
                    Value::String("changed".into()),
                );
                changed.insert(Value::String("zeta".into()), Value::String("last".into()));
                changed
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("does not match"));

    let first = database.clone();
    let second = database.clone();
    let first = std::thread::spawn(move || {
        first.ensure_user(
            "concurrent@example.com",
            "Concurrent daemon",
            Some("concurrent@example.com"),
            UserKind::Service,
            profile("worker"),
        )
    });
    let second = std::thread::spawn(move || {
        second.ensure_user(
            "concurrent@example.com",
            "Concurrent daemon",
            Some("concurrent@example.com"),
            UserKind::Service,
            profile("worker"),
        )
    });
    let outcomes = [
        first.join().unwrap().unwrap(),
        second.join().unwrap().unwrap(),
    ];
    assert!(outcomes.contains(&UserEnsureOutcome::Created));
    assert!(outcomes.contains(&UserEnsureOutcome::Unchanged));
}

#[test]
fn user_updates_preserve_access_and_protect_privileged_and_final_owner_state() {
    let (_temporary, database) = database("update-user");
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user(
            "editor@example.com",
            "Editor",
            Some("editor@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .grant_access(
            "editor@example.com",
            AccessResource::collection("deals"),
            Role::Editor,
        )
        .unwrap();
    database
        .update_user(
            "editor@example.com",
            UserUpdate {
                name: Some("Editing service".into()),
                kind: Some(UserKind::Service),
                profile: Some(profile("automation")),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let editor = database.user("editor@example.com").unwrap();
    assert_eq!(editor.name, "Editing service");
    assert_eq!(editor.kind, UserKind::Service);
    assert_eq!(editor.profile["role"], Value::String("automation".into()));
    assert_eq!(editor.access.len(), 1);
    assert_eq!(editor.access[0].role, Role::Editor);

    let error = database
        .update_user(
            "owner@example.com",
            UserUpdate {
                status: Some(UserStatus::Disabled),
                ..UserUpdate::default()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("final database owner"));

    let editor_path = database.root().join("records/users/editor@example.com.md");
    let edited = fs::read_to_string(&editor_path).unwrap().replace(
        "resource: collection:deals\n  role: editor",
        "resource: database\n  role: owner",
    );
    fs::write(&editor_path, edited).unwrap();
    let error = database
        .update_user(
            "owner@example.com",
            UserUpdate {
                status: Some(UserStatus::Disabled),
                ..UserUpdate::default()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("final database owner"));

    database
        .add_user(
            "manager@example.com",
            "Manager",
            Some("manager@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .grant_access(
            "manager@example.com",
            AccessResource::Database,
            Role::AccessManager,
        )
        .unwrap();
    let mut manager_profile = Mapping::new();
    manager_profile.insert(Value::String("zeta".into()), Value::String("last".into()));
    manager_profile.insert(Value::String("alpha".into()), Value::String("first".into()));
    database
        .update_user(
            "manager@example.com",
            UserUpdate {
                profile: Some(manager_profile),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let manager = database.impersonate("manager@example.com").unwrap();
    let error = manager
        .update_user(
            "owner@example.com",
            UserUpdate {
                name: Some("Not the owner".into()),
                ..UserUpdate::default()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("must be an owner"));
}

#[test]
fn restore_uses_audited_authority_and_reproduces_the_exact_policy_file() {
    let (_temporary, database) = database("restore-user");
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user(
            "manager@example.com",
            "Manager",
            Some("manager@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .grant_access(
            "manager@example.com",
            AccessResource::Database,
            Role::AccessManager,
        )
        .unwrap();
    let mut manager_profile = Mapping::new();
    manager_profile.insert(Value::String("zeta".into()), Value::String("last".into()));
    manager_profile.insert(Value::String("alpha".into()), Value::String("first".into()));
    database
        .update_user(
            "manager@example.com",
            UserUpdate {
                profile: Some(manager_profile),
                ..UserUpdate::default()
            },
        )
        .unwrap();

    let owner_path = database.root().join("records/users/owner@example.com.md");
    let original_owner = fs::read_to_string(&owner_path).unwrap();
    fs::write(
        &owner_path,
        original_owner.replace("name: Owner", "name: Intruder"),
    )
    .unwrap();

    database.restore_user("owner@example.com").unwrap();
    assert_eq!(fs::read_to_string(&owner_path).unwrap(), original_owner);
    database.audit_verify(None).unwrap();

    let manager_path = database.root().join("records/users/manager@example.com.md");
    let original_manager = fs::read_to_string(&manager_path).unwrap();
    fs::write(
        &manager_path,
        original_manager.replace("access_manager", "owner"),
    )
    .unwrap();
    let manager = database.impersonate("manager@example.com").unwrap();
    let error = manager
        .ensure_user(
            "escalated@example.com",
            "Escalated",
            Some("escalated@example.com"),
            UserKind::Service,
            Mapping::new(),
        )
        .unwrap_err();
    assert!(error.to_string().contains("latest audited state"));
    let error = manager.restore_user("manager@example.com").unwrap_err();
    assert!(error.to_string().contains("must be an owner"));

    database.restore_user("manager@example.com").unwrap();
    assert_eq!(fs::read_to_string(&manager_path).unwrap(), original_manager);
    database.audit_verify(None).unwrap();
}
