use std::{fs, str::FromStr};

use cr::{
    AccessDecisionBasis, AccessResource, Assignment, AuditFilter, Database, Role,
    UserEnsureOutcome, UserKind, UserStatus, UserUpdate,
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

#[test]
fn profile_updates_use_ordinary_editor_grants_and_self_service_stays_narrow() {
    let (_temporary, database) = database("profile-access");
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    for (id, name) in [
        ("agent@example.com", "Agent"),
        ("person@example.com", "Person"),
    ] {
        database
            .add_user(id, name, Some(id), UserKind::Human)
            .unwrap();
    }
    database
        .grant_access(
            "agent@example.com",
            AccessResource::collection("users"),
            Role::Editor,
        )
        .unwrap();

    let agent = database.impersonate("agent@example.com").unwrap();
    agent
        .update_user(
            "person@example.com",
            UserUpdate {
                profile_assignments: vec![Assignment::from_str("remembered_by=agent").unwrap()],
                ..UserUpdate::default()
            },
        )
        .unwrap();
    agent
        .update(
            "users",
            "person@example.com",
            &[Assignment::from_str("profile.context.team=platform").unwrap()],
            None,
        )
        .unwrap();
    let mut nested_profile = Mapping::new();
    nested_profile.insert(
        Value::String("temporary".into()),
        Value::Mapping(profile("temporary")),
    );
    let mut patch = Mapping::new();
    patch.insert(
        Value::String("profile".into()),
        Value::Mapping(nested_profile),
    );
    agent
        .patch("users", "person@example.com", &patch, &[], None)
        .unwrap();
    agent
        .patch(
            "users",
            "person@example.com",
            &Mapping::new(),
            &["profile.temporary".into()],
            None,
        )
        .unwrap();

    let person = database.user("person@example.com").unwrap();
    assert_eq!(person.name, "Person");
    assert_eq!(
        person.profile["remembered_by"],
        Value::String("agent".into())
    );
    assert_eq!(
        person.profile["context"]["team"],
        Value::String("platform".into())
    );
    assert!(person.profile.get("temporary").is_none());
    let history = database
        .audit_recent(10, AuditFilter::record("users", "person@example.com"))
        .unwrap();
    let access = history[0].payload.access.as_ref().unwrap();
    assert_eq!(access.principal, "agent@example.com");
    assert_eq!(access.action, cr::AccessAction::Update);
    assert_eq!(access.role, Role::Editor);
    assert_eq!(access.granted_at, AccessResource::collection("users"));
    assert_eq!(access.basis, AccessDecisionBasis::Grant);
    assert!(serde_json::to_value(access).unwrap().get("basis").is_none());

    let before = database.user("person@example.com").unwrap();
    for update in [
        UserUpdate {
            name: Some("Owned by agent".into()),
            profile_assignments: vec![Assignment::from_str("should_not_land=true").unwrap()],
            ..UserUpdate::default()
        },
        UserUpdate {
            kind: Some(UserKind::Service),
            ..UserUpdate::default()
        },
        UserUpdate {
            status: Some(UserStatus::Disabled),
            ..UserUpdate::default()
        },
    ] {
        let error = agent.update_user("person@example.com", update).unwrap_err();
        assert!(
            error.to_string().contains("cannot manage_access database"),
            "{error:#}"
        );
    }
    assert!(
        agent
            .update(
                "users",
                "person@example.com",
                &[Assignment::from_str("name=Owned by agent").unwrap()],
                None,
            )
            .unwrap_err()
            .to_string()
            .contains("cannot manage_access database")
    );
    let mut forbidden_patch = Mapping::new();
    forbidden_patch.insert(
        Value::String("status".into()),
        Value::String("disabled".into()),
    );
    assert!(
        agent
            .patch("users", "person@example.com", &forbidden_patch, &[], None,)
            .unwrap_err()
            .to_string()
            .contains("only profile.*")
    );
    assert_eq!(database.user("person@example.com").unwrap(), before);

    let person = database.impersonate("person@example.com").unwrap();
    person
        .update_user(
            "person@example.com",
            UserUpdate {
                name: Some("Preferred name".into()),
                profile_assignments: vec![Assignment::from_str("timezone=Europe/Paris").unwrap()],
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let current = database.user("person@example.com").unwrap();
    assert_eq!(current.name, "Preferred name");
    assert_eq!(
        current.profile["timezone"],
        Value::String("Europe/Paris".into())
    );
    let history = database
        .audit_recent(1, AuditFilter::record("users", "person@example.com"))
        .unwrap();
    let access = history[0].payload.access.as_ref().unwrap();
    assert_eq!(access.basis, AccessDecisionBasis::SelfService);
    assert_eq!(
        serde_json::to_value(access).unwrap()["basis"],
        "self_service"
    );
    assert_eq!(access.role, Role::Editor);
    assert_eq!(
        access.granted_at,
        AccessResource::record("users", "person@example.com")
    );
    assert_eq!(
        access.impersonated_by.as_ref().unwrap().principal,
        "owner@example.com"
    );

    let error = person
        .update_user(
            "person@example.com",
            UserUpdate {
                email: Some(Some("new@example.com".into())),
                ..UserUpdate::default()
            },
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("cannot manage_access database"),
        "{error:#}"
    );

    database
        .update_user(
            "person@example.com",
            UserUpdate {
                status: Some(UserStatus::Disabled),
                ..UserUpdate::default()
            },
        )
        .unwrap();
    let error = person
        .update_user(
            "person@example.com",
            UserUpdate {
                profile_assignments: vec![Assignment::from_str("after_disable=true").unwrap()],
                ..UserUpdate::default()
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("is not active"), "{error:#}");
}
