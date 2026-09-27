//! Front matter through the database: what a record file on disk makes of the
//! readers, and what a write stores.
//!
//! `src/frontmatter/properties.rs` checks the parser and renderer on their
//! own. These check the same boundary where people meet it: a Markdown file
//! somebody edited by hand, and a write through `Database`, whose audit event
//! is a second copy of the front matter that every later command reads back.
//! The seed convention is `tests/common/rng.rs`'s.

mod common;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use common::{
    generate,
    rng::{Rng, cases},
};
use cr::{Attribution, CheckScope, Database, DomainError};
use yaml_serde::{Mapping, Value};

/// A database whose attribution does not depend on the environment, for the
/// reason `tests/audit_properties.rs` gives.
fn open(root: &Path) -> Database {
    Database::discover(Some(root))
        .expect("the database opens")
        .with_attribution(Attribution::default())
}

fn init(root: &Path) -> Database {
    Database::init(root).expect("the database initializes");
    open(root)
}

/// Every file under `root`, with its bytes.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), files);
            } else {
                files.insert(entry.path(), fs::read(entry.path()).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, &mut files);
    files
}

/// `result` succeeded, or failed with a classification whose caller-facing
/// message names no filesystem path.
fn classified<T>(root: &Path, operation: &str, result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            let domain = DomainError::of(&error)
                .unwrap_or_else(|| panic!("{operation} failed unclassified: {error:#}"));
            assert!(
                !domain.message().contains(&*root.to_string_lossy()),
                "{operation} disclosed the database path: {}",
                domain.message()
            );
            None
        }
    }
}

/// Text that is a record file, nearly one, or not one at all.
fn stored_text(rng: &mut Rng) -> Vec<u8> {
    let front_matter = yaml_serde::to_string(&generate::mapping(rng, 3)).unwrap();
    let mut text = match rng.below(4) {
        0 => format!("---\n{front_matter}---\n{}", generate::body(rng)),
        1 => format!(
            "---\n{}\n---\n{}",
            generate::noise(rng, 40),
            generate::body(rng)
        ),
        2 => format!("---\n{front_matter}{}", generate::body(rng)),
        _ => generate::noise(rng, 60),
    }
    .into_bytes();
    // Edit a few bytes anywhere, which can leave the file invalid UTF-8.
    for _ in 0..rng.below(3) {
        if !text.is_empty() {
            let index = rng.below(text.len());
            text[index] = rng.next() as u8;
        }
    }
    text
}

/// Hand-edited record files, valid or not, are read or refused with a
/// classification by every reader, and reading one writes nothing. Accepting
/// them with `save` either records them or leaves the database as it was.
#[test]
fn stored_garbage_is_read_or_refused_with_a_classification() {
    for mut case in cases(
        "stored_garbage_is_read_or_refused_with_a_classification",
        60,
    ) {
        let rng = &mut case.rng;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("db");
        let database = init(&root);
        fs::create_dir_all(root.join("records/items")).unwrap();
        let ids: Vec<String> = (0..rng.between(1, 4))
            .map(|index| format!("r{index}"))
            .collect();
        for id in &ids {
            fs::write(
                root.join(format!("records/items/{id}.md")),
                stored_text(rng),
            )
            .unwrap();
        }

        let before = snapshot(&root);
        for id in &ids {
            classified(&root, "get", database.get("items", id));
            classified(&root, "read_raw", database.read_raw("items", id));
        }
        classified(&root, "list", database.list("items", &[]));
        classified(&root, "status", database.status());
        classified(
            &root,
            "check",
            database.check(&CheckScope {
                collection: Some("items".to_owned()),
            }),
        );
        classified(&root, "audit verify", database.audit_verify(None));
        assert!(
            snapshot(&root) == before,
            "seed {}: a read changed the database",
            case.seed
        );

        let references: Vec<String> = ids.iter().map(|id| format!("items/{id}")).collect();
        match classified(&root, "save", database.save(&references, false, None)) {
            Some(entries) => {
                assert_eq!(entries.len(), ids.len());
                let verification = open(&root)
                    .audit_verify(None)
                    .expect("a saved journal verifies");
                assert_eq!(verification.entries, ids.len() as u64);
            }
            None => assert!(
                snapshot(&root) == before,
                "seed {}: a refused save changed the database",
                case.seed
            ),
        }
    }
}

/// Whether a key anywhere in `mapping` is a mapping or a tagged value, which
/// the YAML emitter cannot write; see
/// `src/frontmatter/properties.rs::non_string_keys_are_pinned_at_the_json_boundary`.
fn has_unrenderable_key(mapping: &Mapping) -> bool {
    fn unrenderable(value: &Value, as_key: bool) -> bool {
        match value {
            Value::Mapping(mapping) => {
                as_key
                    || mapping
                        .iter()
                        .any(|(key, value)| unrenderable(key, true) || unrenderable(value, false))
            }
            Value::Tagged(tagged) => as_key || unrenderable(&tagged.value, false),
            Value::Sequence(items) => items.iter().any(|item| unrenderable(item, as_key)),
            _ => false,
        }
    }
    unrenderable(&Value::Mapping(mapping.clone()), false)
}

/// Front matter a write might be handed through the library: generated values
/// of every type, plus now and then a key JSON cannot represent, or nesting
/// near and past the bound the journal needs.
fn front_matter(rng: &mut Rng) -> Mapping {
    let mut attributes = generate::mapping(rng, 3);
    if rng.chance(1, 5) {
        let key = match rng.below(5) {
            0 => Value::Number(generate::number(rng)),
            1 => Value::Bool(rng.chance(1, 2)),
            2 => Value::Null,
            3 => Value::Sequence(vec![generate::scalar(rng)]),
            _ => Value::Mapping(generate::mapping(rng, 0)),
        };
        attributes.insert(key, generate::scalar(rng));
    }
    if rng.chance(1, 6) {
        let depth = *rng.pick(&[63, 64, 65, 100, 121, 127]);
        attributes.insert("deep".into(), nested(depth));
    }
    attributes
}

/// A mapping `depth` levels deep once it sits in front matter, whose own
/// mapping is the first level.
fn nested(depth: usize) -> Value {
    let mut value = Value::String("leaf".into());
    for _ in 1..depth {
        value = Value::Mapping([("k".into(), value)].into_iter().collect());
    }
    value
}

/// Every write either stores exactly the front matter and body it was given,
/// readable by a fresh handle and verified by the journal, or is refused with
/// a classification and leaves nothing behind.
#[test]
fn generated_front_matter_is_stored_exactly_or_refused_whole() {
    for mut case in cases(
        "generated_front_matter_is_stored_exactly_or_refused_whole",
        40,
    ) {
        let rng = &mut case.rng;
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("db");
        let database = init(&root);
        let mut stored = Vec::new();
        for index in 0..rng.between(1, 5) {
            let id = format!("r{index}");
            let attributes = front_matter(rng);
            let body = generate::body(rng);
            let before = snapshot(&root);
            match database.create_record("items", &id, attributes.clone(), &body) {
                Ok(record) => {
                    assert_eq!(record.attributes, attributes);
                    assert_eq!(record.body, body);
                    stored.push((id, attributes, body));
                }
                Err(error) => {
                    // Pinned: a key the emitter cannot write fails in the
                    // renderer, before any classification is attached.
                    let pinned = has_unrenderable_key(&attributes)
                        && error.to_string() == "could not serialize record front matter";
                    if !pinned {
                        classified(&root, "create", Err::<(), _>(error));
                    }
                    assert!(
                        snapshot(&root) == before,
                        "seed {}: a refused create changed the database",
                        case.seed
                    );
                }
            }
        }

        // A fresh handle, so nothing is answered from a cache the writes left.
        let fresh = open(&root);
        let verification = fresh
            .audit_verify(None)
            .unwrap_or_else(|error| panic!("seed {}: {error:#}", case.seed));
        assert_eq!(verification.entries, stored.len() as u64);
        for (id, attributes, body) in stored {
            let record = fresh.get("items", &id).unwrap();
            assert_eq!(record.attributes, attributes, "seed {}", case.seed);
            assert_eq!(record.body, body, "seed {}", case.seed);
        }
    }
}

/// Front matter nested 121 levels deep used to be accepted, and its event was
/// JSON too deep for the journal reader, so every later read, write, and
/// verification of the database failed. It is refused before anything is
/// written, and the bound is exact.
#[test]
fn front_matter_nested_121_levels_deep_is_refused_before_it_reaches_the_journal() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("db");
    let database = init(&root);
    for (id, depth) in [("deepest", 121), ("over", 65)] {
        let attributes: Mapping = [("deep".into(), nested(depth))].into_iter().collect();
        let error = database
            .create_record("items", id, attributes, "")
            .unwrap_err();
        assert_eq!(
            DomainError::of(&error),
            Some(&DomainError::Invalid(
                "front matter nests more than 64 levels deep".to_owned()
            ))
        );
    }
    let attributes: Mapping = [("deep".into(), nested(64))].into_iter().collect();
    database
        .create_record("items", "limit", attributes.clone(), "")
        .unwrap();

    // A direct edit is held to the same bound when it is saved.
    let edited = format!(
        "---\n{}---\n",
        yaml_serde::to_string(
            &[("deep".into(), nested(100))]
                .into_iter()
                .collect::<Mapping>()
        )
        .unwrap()
    );
    fs::write(root.join("records/items/edited.md"), edited).unwrap();
    let error = database
        .save(&["items/edited".to_owned()], false, None)
        .unwrap_err();
    assert!(matches!(
        DomainError::of(&error),
        Some(DomainError::Invalid(_))
    ));
    fs::remove_file(root.join("records/items/edited.md")).unwrap();

    let fresh = open(&root);
    assert_eq!(fresh.audit_verify(None).unwrap().entries, 1);
    assert_eq!(fresh.get("items", "limit").unwrap().attributes, attributes);
    fresh.create("items", "after", &[], "").unwrap();
}

/// Found by `src/frontmatter/properties.rs`: this value was refused with an
/// unclassified error, a `500` over HTTP, because the rendered record could
/// not be parsed back. It is now stored exactly.
#[test]
fn a_value_ending_in_a_line_separator_after_a_line_break_is_stored_exactly() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("db");
    let database = init(&root);
    let value = Value::String("first\nsecond\u{2028}".into());
    let attributes: Mapping = [("notes".into(), value)].into_iter().collect();
    database
        .create_record("items", "separated", attributes.clone(), "Body\n")
        .unwrap();
    let fresh = open(&root);
    fresh.audit_verify(None).unwrap();
    assert_eq!(
        fresh.get("items", "separated").unwrap().attributes,
        attributes
    );

    let unwritable: Mapping = [("notes".into(), Value::String("first\n\n\u{2028}".into()))]
        .into_iter()
        .collect();
    let error = database
        .create_record("items", "unwritable", unwritable, "")
        .unwrap_err();
    assert!(matches!(
        DomainError::of(&error),
        Some(DomainError::Invalid(_))
    ));
    assert_eq!(open(&root).audit_verify(None).unwrap().entries, 1);
}
