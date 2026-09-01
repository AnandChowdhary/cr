use std::str::FromStr;

use cr::{Assignment, CheckScope, Database, FindingKind};

#[test]
fn scans_a_moderately_sized_collection_deterministically() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path()).unwrap();

    for index in (0..128).rev() {
        let id = format!("item-{index:03}");
        let assignment = Assignment::from_str(&format!("index={index}")).unwrap();
        database.create("items", &id, &[assignment], "").unwrap();
    }

    let records = database.list("items", &[]).unwrap();
    assert_eq!(records.len(), 128);
    assert_eq!(records.first().unwrap().id, "item-000");
    assert_eq!(records.last().unwrap().id, "item-127");

    let filter = Assignment::from_str("index=64").unwrap();
    let records = database.list("items", &[filter]).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, "item-064");
}

/// `check` is O(records) with no index behind it, so the scan has to stay
/// usable on a database large enough to notice. This also proves the
/// whole-database relation index resolves a link at that size rather than
/// degrading into a per-link directory walk.
#[test]
fn checks_a_moderately_sized_collection_with_relations() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path()).unwrap();

    for index in 0..128 {
        let id = format!("item-{index:03}");
        let peer = format!("item-{:03}", (index + 1) % 128);
        let assignment = Assignment::from_str(&format!(
            "relations.peer=[{{collection: items, id: {peer}}}]"
        ))
        .unwrap();
        database.create("items", &id, &[assignment], "").unwrap();
    }

    // Every relation resolves and every record reconciles, so a database this
    // size must still report nothing at all.
    let report = database.check(&CheckScope::default()).unwrap();
    assert_eq!(report.findings, Vec::new());
    assert_eq!(report.summary.records, 128);
    assert_eq!(report.summary.audited_records, 128);

    // One removed record dangles exactly one relation, not 128.
    std::fs::remove_file(temporary.path().join("records/items/item-064.md")).unwrap();
    let report = database.check(&CheckScope::default()).unwrap();
    let dangling: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::DanglingLink)
        .collect();
    assert_eq!(dangling.len(), 1);
    assert_eq!(dangling[0].id.as_deref(), Some("item-063"));
    assert_eq!(dangling[0].target.as_deref(), Some("items/item-064"));
    assert_eq!(report.summary.records, 127);
}
