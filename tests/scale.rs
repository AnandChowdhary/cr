use std::str::FromStr;

use cr::{Assignment, Database};

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
