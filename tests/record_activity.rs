//! Record creation and update times are derived from the audit journal.
//!
//! Nothing on disk records a record's age. Front matter that claimed to would
//! be a second copy a direct edit could contradict, so the journal stays the
//! only source and these tests pin what it reports: which event starts a
//! lifecycle, which events advance it, what a deletion does to it, and who is
//! allowed to see any of it.

use std::str::FromStr;

use cr::{
    AccessResource, Assignment, Database, Role, SortDirection, UserKind, sort_records_by_field,
};

const OWNER: &str = "Owner <owner@example.com>";

fn database(name: &str) -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name))
        .unwrap()
        .with_actor(OWNER)
        .unwrap();
    (temporary, database)
}

fn assignment(value: &str) -> Vec<Assignment> {
    vec![Assignment::from_str(value).unwrap()]
}

#[test]
fn creation_and_update_times_come_from_the_journal_and_a_deletion_ends_the_lifecycle() {
    let (_temporary, database) = database("activity-lifecycle");
    database
        .create("deals", "alpha", &assignment("status=open"), "")
        .unwrap();
    database
        .create("deals", "beta", &assignment("status=open"), "")
        .unwrap();

    let activity = database.record_activity("deals").unwrap();
    let alpha = activity["alpha"].clone();
    assert_eq!(alpha.created_sequence, 1);
    assert_eq!(alpha.created_at, alpha.updated_at);
    assert_eq!(alpha.created_sequence, alpha.updated_sequence);
    assert_eq!(activity["beta"].created_sequence, 2);

    // An update moves `updated_at` and leaves `created_at` where it was.
    database
        .update("deals", "alpha", &assignment("status=won"), None)
        .unwrap();
    let activity = database.record_activity("deals").unwrap();
    assert_eq!(activity["alpha"].created_sequence, 1);
    assert_eq!(activity["alpha"].updated_sequence, 3);
    assert_eq!(activity["beta"].updated_sequence, 2);

    // A link is a record change like any other.
    database
        .link("deals", "alpha", "peer", "deals", "beta")
        .unwrap();
    let activity = database.record_activity("deals").unwrap();
    assert_eq!(activity["alpha"].created_sequence, 1);
    assert_eq!(activity["alpha"].updated_sequence, 4);

    // Deleting ends the lifecycle, so re-creating the same ID starts a new one
    // rather than inheriting the tombstoned record's age.
    database.delete("deals", "alpha").unwrap();
    let activity = database.record_activity("deals").unwrap();
    assert!(!activity.contains_key("alpha"));
    assert!(activity.contains_key("beta"));

    database
        .create("deals", "alpha", &assignment("status=open"), "")
        .unwrap();
    let activity = database.record_activity("deals").unwrap();
    assert_eq!(activity["alpha"].created_sequence, 6);
    assert_eq!(activity["alpha"].updated_sequence, 6);

    // A collection with no history at all reports nothing rather than failing.
    assert!(database.record_activity("contacts").unwrap().is_empty());
}

/// A file written directly and never saved has no audited age, and must not be
/// given a borrowed one.
#[test]
fn records_with_no_audit_history_are_absent_from_the_activity_map() {
    let (temporary, database) = database("activity-unaudited");
    database
        .create("deals", "alpha", &assignment("status=open"), "")
        .unwrap();
    std::fs::write(
        temporary
            .path()
            .join("activity-unaudited/records/deals/manual.md"),
        "---\nstatus: open\n---\n",
    )
    .unwrap();

    let records = database.list("deals", &[]).unwrap();
    assert_eq!(records.len(), 2);
    let activity = database.record_activity("deals").unwrap();
    assert!(activity.contains_key("alpha"));
    assert!(!activity.contains_key("manual"));
}

/// The activity fields are a history read, so they follow audit-read
/// permission rather than being visible to anyone who can name a collection.
#[test]
fn activity_is_limited_to_the_history_a_principal_may_read() {
    let (_temporary, database) = database("activity-access");
    database.create("deals", "public", &[], "").unwrap();
    database.create("deals", "private", &[], "").unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database
        .add_user(
            "reader@example.com",
            "Reader",
            Some("reader@example.com"),
            UserKind::Human,
        )
        .unwrap();
    database
        .grant_access(
            "reader@example.com",
            AccessResource::record("deals", "public"),
            Role::Viewer,
        )
        .unwrap();

    let owner = database.record_activity("deals").unwrap();
    assert_eq!(owner.len(), 2);

    let reader = database
        .impersonate_verified("reader@example.com")
        .unwrap()
        .record_activity("deals")
        .unwrap();
    assert_eq!(reader.keys().collect::<Vec<_>>(), vec!["public"]);
}

/// Sorting a plain record scan by an audit-derived field would quietly replay
/// the whole journal, so the shared comparator refuses it by name.
#[test]
fn record_scans_refuse_to_sort_by_an_audit_derived_field() {
    let (_temporary, database) = database("activity-sort");
    database.create("deals", "alpha", &[], "").unwrap();
    let mut records = database.list("deals", &[]).unwrap();

    for field in ["$created_at", "$updated_at"] {
        let error = sort_records_by_field(&mut records, field, SortDirection::Desc).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(field), "{message}");
        assert!(message.contains("server-rendered views"), "{message}");
    }
}
