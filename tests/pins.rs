//! Pinned filesystem locations: how a path is stored, what counts as the same
//! pin, and who may read or change the list.

mod common;

use std::fs;

use common::{TestDatabase, run_failure, run_success};
use cr::{Database, DomainError, Pin, UserKind};

const OWNER: &str = "Owner <owner@example.com>";

fn database(name: &str) -> (tempfile::TempDir, Database) {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join(name))
        .unwrap()
        .with_actor(OWNER)
        .unwrap();
    (temporary, database)
}

fn stored(database: &Database) -> Vec<String> {
    database
        .pins()
        .unwrap()
        .into_iter()
        .map(|pin| pin.path)
        .collect()
}

/// A location inside the database is stored relative to it, because `.cr/`
/// travels in Git and an absolute path would point nowhere in another clone.
#[test]
fn locations_inside_the_database_are_stored_relative_to_it() {
    let (temporary, database) = database("pins-relative");
    let root = database.root().to_path_buf();

    database.pin("docs", None).unwrap();
    database
        .pin(root.join("logs").to_str().unwrap(), None)
        .unwrap();
    database.pin(root.to_str().unwrap(), None).unwrap();
    let outside = temporary.path().join("elsewhere");
    database.pin(outside.to_str().unwrap(), None).unwrap();

    assert_eq!(
        stored(&database),
        vec![
            "docs".to_owned(),
            "logs".to_owned(),
            ".".to_owned(),
            outside.to_str().unwrap().to_owned(),
        ]
    );
    let pins = database.pins().unwrap();
    assert_eq!(pins[0].location(&root), root.join("docs"));
    assert_eq!(pins[2].location(&root), root);
    assert_eq!(pins[3].location(&root), outside);
}

/// One location is one pin however it is spelled, and it need not exist yet.
#[test]
fn spellings_of_one_location_are_one_pin() {
    let (_temporary, database) = database("pins-normalized");

    database.pin("docs/../logs", None).unwrap();
    database.pin("./logs/", None).unwrap();
    database.pin("  logs  ", None).unwrap();
    assert_eq!(stored(&database), vec!["logs".to_owned()]);
    assert!(!database.root().join("logs").exists());

    assert!(database.unpin("docs/../logs").unwrap());
    assert!(stored(&database).is_empty());
    assert!(!database.unpin("logs").unwrap());
}

/// Pinning again relabels; pinning again without a label keeps the one it has.
#[test]
fn pinning_again_relabels_without_losing_a_label() {
    let (_temporary, database) = database("pins-labels");

    database.pin("docs", Some("Team docs")).unwrap();
    database.pin("docs", None).unwrap();
    assert_eq!(
        database.pins().unwrap()[0].label.as_deref(),
        Some("Team docs")
    );
    database.pin("docs", Some("  Handbook ")).unwrap();
    assert_eq!(
        database.pins().unwrap(),
        vec![Pin {
            path: "docs".to_owned(),
            label: Some("Handbook".to_owned()),
        }]
    );

    let serialized = fs::read_to_string(database.root().join(".cr/pins.yaml")).unwrap();
    assert!(serialized.contains("version: 1"), "{serialized}");
    assert!(serialized.contains("label: Handbook"), "{serialized}");

    for label in ["x".repeat(81), "line\nbreak".to_owned()] {
        let error = database.pin("docs", Some(&label)).unwrap_err();
        assert!(matches!(
            DomainError::of(&error),
            Some(DomainError::Invalid(_))
        ));
    }
    for path in ["", "   ", "bad\0path"] {
        assert!(database.pin(path, None).is_err());
    }
}

/// The sidebar is navigation, so the list has a ceiling.
#[test]
fn the_pin_list_is_bounded() {
    let (_temporary, database) = database("pins-bounded");
    for index in 0..50 {
        database.pin(&format!("dir-{index}"), None).unwrap();
    }
    let error = database.pin("one-too-many", None).unwrap_err();
    assert!(format!("{error:#}").contains("at most 50"));
    // Relabelling an existing pin is not a new one.
    database.pin("dir-0", Some("First")).unwrap();
}

/// A hand-edited file that no longer parses is reported, not silently emptied.
#[test]
fn an_unreadable_pins_file_is_refused_rather_than_overwritten() {
    let (_temporary, database) = database("pins-invalid");
    let path = database.root().join(".cr/pins.yaml");

    fs::write(&path, "pins: [unclosed").unwrap();
    assert!(database.pins().is_err());
    assert!(database.pin("docs", None).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "pins: [unclosed");

    fs::write(&path, "version: 2\npins: []\n").unwrap();
    let error = database.pins().unwrap_err();
    assert!(format!("{error:#}").contains("unsupported format version 2"));
}

/// Pins map where an administrator looks on this host, so they are an owner's.
#[test]
fn only_an_owner_may_read_or_change_pins() {
    let (_temporary, database) = database("pins-owner");
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    database.pin("docs", None).unwrap();
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
            cr::AccessResource::Database,
            cr::Role::AccessManager,
        )
        .unwrap();

    let manager = database
        .impersonate_verified("manager@example.com")
        .unwrap();
    for error in [
        manager.pins().unwrap_err(),
        manager.pin("logs", None).unwrap_err(),
        manager.unpin("docs").unwrap_err(),
    ] {
        assert!(matches!(
            DomainError::of(&error),
            Some(DomainError::Forbidden(_))
        ));
    }
    assert_eq!(stored(&database), vec!["docs".to_owned()]);
}

#[test]
fn the_cli_adds_lists_and_removes_pins() {
    let database = TestDatabase::new("pins-cli");

    assert_eq!(
        run_success(
            database
                .command()
                .args(["pin", "add", "docs", "--label", "Docs"])
        ),
        "docs\n"
    );
    let absolute = database.root().join("logs");
    run_success(
        database
            .command()
            .args(["pin", "add", absolute.to_str().unwrap()]),
    );
    assert_eq!(
        run_success(database.command().args(["pin", "list"])),
        "docs\tDocs\nlogs\n"
    );
    let json: serde_json::Value = serde_json::from_str(&run_success(
        database.command().args(["pin", "list", "--json"]),
    ))
    .unwrap();
    assert_eq!(json[0]["path"], "docs");
    assert_eq!(json[0]["label"], "Docs");
    assert!(json[1].get("label").is_none());

    assert_eq!(
        run_success(database.command().args(["pin", "remove", "./logs"])),
        "Unpinned ./logs\n"
    );
    // A typo should not look like success.
    let stderr = run_failure(database.command().args(["pin", "remove", "logs"]));
    assert!(stderr.contains("'logs' is not pinned"), "{stderr}");
}
