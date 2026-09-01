use std::str::FromStr;

use cr::{AccessResource, Assignment, AuditFilter, Database, Role, UserKind};

const OWNER: &str = "Owner <owner@example.com>";

fn seeded_database() -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("audit-access"))
        .unwrap()
        .with_actor(OWNER)
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    for (id, name) in [
        ("reader@example.com", "Reader"),
        ("editor@example.com", "Editor"),
    ] {
        database
            .add_user(id, name, Some(id), UserKind::Human)
            .unwrap();
    }
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "public"),
            Role::Viewer,
        )
        .unwrap();
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "deleted"),
            Role::Viewer,
        )
        .unwrap();
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "revoked"),
            Role::Viewer,
        )
        .unwrap();
    database
        .grant_access(
            "editor@example.com",
            AccessResource::collection("deals"),
            Role::Editor,
        )
        .unwrap();

    let open = [Assignment::from_str("stage=open").unwrap()];
    database.create("deals", "revoked", &open, "").unwrap();
    database
        .revoke_access(
            "reader@example.com",
            &AccessResource::record("deals", "revoked"),
        )
        .unwrap();
    for id in ["public", "deleted", "secret"] {
        database.create("deals", id, &open, "").unwrap();
    }
    database.delete("deals", "deleted").unwrap();
    database.delete("deals", "secret").unwrap();
    (temporary, database)
}

fn references(database: &Database, limit: usize) -> Vec<String> {
    database
        .audit_recent(limit, AuditFilter::all())
        .unwrap()
        .into_iter()
        .map(|entry| entry.payload.record.reference())
        .collect()
}

#[test]
fn global_audit_filters_by_current_record_policy_before_the_limit() {
    let (_temporary, database) = seeded_database();
    let reader = database.impersonate("reader@example.com").unwrap();
    let editor = database.impersonate("editor@example.com").unwrap();

    // The newest journal event deletes an inaccessible record. It must not
    // consume the requested limit; the next visible event is the delete of a
    // record the reader can still audit under current policy.
    assert_eq!(references(&reader, 1), ["deals/deleted"]);

    let reader_history = references(&reader, 100);
    assert!(reader_history.contains(&"deals/public".to_owned()));
    assert!(reader_history.contains(&"deals/deleted".to_owned()));
    assert!(
        reader_history
            .iter()
            .all(|reference| reference != "deals/secret" && reference != "deals/revoked")
    );
    assert!(
        reader_history
            .iter()
            .filter(|reference| reference.as_str() == "users/reader@example.com")
            .count()
            >= 1
    );
    assert!(reader_history.iter().all(|reference| {
        reference == "deals/public"
            || reference == "deals/deleted"
            || reference == "users/reader@example.com"
    }));

    let editor_history = references(&editor, 100);
    assert!(editor_history.contains(&"deals/public".to_owned()));
    assert!(editor_history.contains(&"deals/deleted".to_owned()));
    assert!(editor_history.contains(&"deals/secret".to_owned()));
    assert!(editor_history.contains(&"deals/revoked".to_owned()));
    assert!(editor_history.contains(&"users/editor@example.com".to_owned()));

    let owner_history = references(&database, 100);
    assert!(owner_history.contains(&"users/owner@example.com".to_owned()));
    assert!(owner_history.contains(&"users/reader@example.com".to_owned()));
    assert!(owner_history.contains(&"users/editor@example.com".to_owned()));
    assert!(owner_history.contains(&"deals/secret".to_owned()));
}

#[test]
fn principals_may_read_only_their_own_user_policy_history() {
    let (_temporary, database) = seeded_database();
    let reader = database.impersonate("reader@example.com").unwrap();

    let own_history = reader
        .audit_recent(100, AuditFilter::record("users", "reader@example.com"))
        .unwrap();
    assert!(!own_history.is_empty());
    assert!(own_history.iter().all(|entry| {
        entry.payload.record.collection == "users"
            && entry.payload.record.id == "reader@example.com"
    }));

    let error = reader
        .audit_recent(100, AuditFilter::record("users", "editor@example.com"))
        .unwrap_err();
    assert!(error.to_string().contains("cannot read_access database"));
}
