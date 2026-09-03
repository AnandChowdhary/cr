use std::str::FromStr;

use cr::{Assignment, AuditFilter, Database, DomainError, RecordPrecondition};

#[test]
fn record_versions_are_exact_and_stale_conditions_do_not_mutate_or_audit() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("record-versions")).unwrap();
    let created = database
        .create(
            "items",
            "one",
            &[Assignment::from_str("stage=open").unwrap()],
            "Original notes",
        )
        .unwrap();
    assert!(created.version.starts_with("sha256:"));
    assert_eq!(created.version.len(), 71);
    assert_eq!(
        database.get("items", "one").unwrap().version,
        created.version
    );

    let expected = RecordPrecondition::version(created.version.clone()).unwrap();
    let updated = database
        .update_conditionally(
            "items",
            "one",
            &[Assignment::from_str("stage=won").unwrap()],
            None,
            Some(&expected),
        )
        .unwrap();
    assert_ne!(updated.version, created.version);

    let error = database
        .update_conditionally(
            "items",
            "one",
            &[Assignment::from_str("stage=lost").unwrap()],
            None,
            Some(&expected),
        )
        .unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("precondition_failed")
    );
    assert_eq!(
        error.to_string(),
        "record items/one changed since the expected version"
    );
    assert!(
        !error
            .to_string()
            .contains(database.root().to_string_lossy().as_ref())
    );
    assert_eq!(
        database.get("items", "one").unwrap().attributes["stage"],
        "won"
    );
    assert_eq!(
        database
            .audit_recent(10, AuditFilter::record("items", "one"))
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn malformed_expected_versions_are_validation_errors() {
    let error = RecordPrecondition::version("not-a-record-hash").unwrap_err();
    assert_eq!(
        DomainError::of(&error).map(DomainError::code),
        Some("validation_failed")
    );
}
