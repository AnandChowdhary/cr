//! Properties the audit chain must hold over arbitrary mutation sequences.
//!
//! ## Why there is no property-testing dependency here
//!
//! A generator crate would buy shrinking and a nicer failure report. It would
//! also change `Cargo.lock`, which needs an MSRV check and is contended with
//! other work in flight, and the generation this suite needs is a weighted
//! choice among five operations over a five-record namespace — not something a
//! combinator library makes materially better. The generator below is
//! SplitMix64 seeded from a constant, so every run explores exactly the same
//! sequences: a failure here is reproducible from the seed printed in the
//! assertion, and a green run in CI means the same thing as a green run on a
//! laptop. That is worth more in a crash-recovery suite than shrinking is.
//!
//! ## What these tests check
//!
//! The chain always verifies after every step; sequence numbers are dense and
//! monotonic across segment rotation; every stored hash covers exactly the
//! documented preimage; a replayed chain reproduces the same head; and every
//! single-byte change anywhere in a segment is detected. The hash re-derivation
//! is written out in `tests/common/chain.rs` from the format documentation
//! rather than borrowed from `src/audit.rs`, so agreement means the stored
//! bytes match the specification and not merely that `cr` agrees with itself.

mod common;

use std::{fs, path::Path, str::FromStr};

use common::chain;
use cr::{Assignment, Attribution, Database};

/// SplitMix64. Deterministic, tiny, and identical on every platform.
#[derive(Debug)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.0;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Deterministic self-check: the generator must not drift between platforms or
/// releases, or "the same seed" would stop meaning anything.
#[test]
fn the_generator_is_reproducible() {
    let mut rng = Rng::new(0);
    let drawn: Vec<u64> = (0..4).map(|_| rng.next()).collect();
    assert_eq!(
        drawn,
        vec![
            16294208416658607535,
            7960286522194355700,
            487617019471545679,
            17909611376780542444,
        ]
    );
}

/// A database whose attribution does not depend on the environment.
///
/// `Attribution::from_environment` reads `CLAUDECODE` and friends, which would
/// otherwise make the recorded payloads differ between CI and a coding agent —
/// the same reason `tests/common/mod.rs` strips those variables for CLI tests.
fn open(root: &Path) -> Database {
    Database::discover(Some(root))
        .expect("the database opens")
        .with_attribution(Attribution::default())
}

fn init(root: &Path, segment_max_events: usize) -> Database {
    Database::init(root).expect("the database initializes");
    fs::write(
        root.join(".cr/config.yaml"),
        format!(
            "version: 1\ndata_dir: records\naudit:\n  segment_max_events: {segment_max_events}\n  segment_max_bytes: 8388608\n"
        ),
    )
    .unwrap();
    open(root)
}

fn assignment(text: &str) -> Assignment {
    Assignment::from_str(text).expect("the assignment parses")
}

const IDS: [&str; 5] = ["alpha", "beta", "gamma", "delta", "epsilon"];
const STAGES: [&str; 4] = ["screening", "interview", "offer", "hired"];

/// Apply one pseudo-random but always-valid mutation, and report how many
/// events it appended — zero when the drawn operation had no legal target, so
/// the generator never has to produce a call it expects to fail.
fn step(database: &Database, rng: &mut Rng, present: &mut Vec<String>) -> u64 {
    let operation = rng.below(10);
    match operation {
        // Create a record that does not exist yet.
        0..=2 => {
            let absent: Vec<&str> = IDS
                .iter()
                .copied()
                .filter(|id| !present.iter().any(|held| held == id))
                .collect();
            if absent.is_empty() {
                return 0;
            }
            let id = absent[rng.below(absent.len())];
            let stage = STAGES[rng.below(STAGES.len())];
            let body = format!("# {id}\n\nRound {}.\n", rng.below(1000));
            database
                .create("items", id, &[assignment(&format!("stage={stage}"))], &body)
                .expect("creating an absent record succeeds");
            present.push(id.to_owned());
            1
        }
        // Update a record that exists.
        3..=5 => {
            if present.is_empty() {
                return 0;
            }
            let id = present[rng.below(present.len())].clone();
            let stage = STAGES[rng.below(STAGES.len())];
            let score = rng.below(100);
            database
                .update(
                    "items",
                    &id,
                    &[
                        assignment(&format!("stage={stage}")),
                        assignment(&format!("score={score}")),
                    ],
                    None,
                )
                .expect("updating a present record succeeds");
            1
        }
        // Link two records that both exist.
        6..=7 => {
            if present.len() < 2 {
                return 0;
            }
            let source = present[rng.below(present.len())].clone();
            let target = present[rng.below(present.len())].clone();
            if source == target {
                return 0;
            }
            database
                .link("items", &source, "related", "items", &target)
                .expect("linking two present records succeeds");
            1
        }
        // Accept a direct edit, which appends without a pending file.
        8 => {
            if present.is_empty() {
                return 0;
            }
            let id = present[rng.below(present.len())].clone();
            let path = database.root().join(format!("records/items/{id}.md"));
            let contents = fs::read_to_string(&path).unwrap();
            let edited = format!("{contents}\nEdited {}.\n", rng.below(1000));
            fs::write(&path, edited).unwrap();
            database
                .save(&[format!("items/{id}")], false, None)
                .expect("saving a direct edit succeeds");
            1
        }
        // Delete a record that exists.
        _ => {
            if present.is_empty() {
                return 0;
            }
            let index = rng.below(present.len());
            let id = present.remove(index);
            database.delete("items", &id).expect("deleting succeeds");
            1
        }
    }
}

/// Over arbitrary valid mutation sequences the chain always verifies, its
/// sequence numbers stay dense, and every stored hash covers its payload.
#[test]
fn arbitrary_mutation_sequences_leave_a_chain_that_always_verifies() {
    for seed in 0..8u64 {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        // Three events per segment, so rotation happens constantly.
        let database = init(root, 3);
        let mut rng = Rng::new(seed);
        let mut present: Vec<String> = Vec::new();
        let mut expected = 0u64;

        for step_index in 0..40 {
            expected += step(&database, &mut rng, &mut present);
            let verification = database
                .audit_verify(None)
                .unwrap_or_else(|error| panic!("seed {seed} step {step_index}: {error:#}"));
            assert_eq!(
                verification.entries, expected,
                "seed {seed} step {step_index}: unexpected event count"
            );
            assert_eq!(
                verification.head.sequence, expected,
                "seed {seed} step {step_index}: head sequence must equal the event count"
            );
        }

        let head = chain::assert_chain_is_well_formed(root);
        assert_eq!(
            head,
            database.audit_head().unwrap().hash,
            "seed {seed}: the independently folded head must match the reported one"
        );
        assert!(expected > 20, "seed {seed}: the sequence must do real work");
    }
}

/// Segment rotation must not perturb the global sequence: the concatenation of
/// the segments is one dense chain, and each segment starts where its name says.
#[test]
fn segment_rotation_preserves_one_dense_globally_ordered_chain() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let database = init(root, 3);
    let mut rng = Rng::new(1234);
    let mut present: Vec<String> = Vec::new();
    let mut expected = 0u64;
    for _ in 0..40 {
        expected += step(&database, &mut rng, &mut present);
    }

    let segments = chain::segment_paths(root);
    assert!(
        segments.len() > 5,
        "the bound should have rotated many times, got {}",
        segments.len()
    );
    let mut seen = 0u64;
    for segment in &segments {
        let contents = fs::read_to_string(segment).unwrap();
        let events: Vec<_> = contents.lines().map(chain::parse_line).collect();
        assert!(!events.is_empty(), "no segment may be empty");
        assert!(events.len() <= 3, "the event bound must hold per segment");
        let stem = segment.file_stem().unwrap().to_str().unwrap();
        assert_eq!(stem.len(), 20, "segment names are fixed width");
        assert_eq!(
            stem.parse::<u64>().unwrap(),
            events[0].sequence(),
            "a segment's name must be its first sequence"
        );
        seen += events.len() as u64;
    }
    assert_eq!(seen, expected);
    chain::assert_chain_is_well_formed(root);
}

/// Copying the journal and the records elsewhere reproduces the same head.
///
/// The head is a function of the stored bytes and of nothing else — not of the
/// path, not of the order segments happen to be listed in, not of anything the
/// process carries.
#[test]
fn a_replayed_chain_reproduces_the_same_head() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("origin");
    fs::create_dir_all(&root).unwrap();
    let database = init(&root, 3);
    let mut rng = Rng::new(99);
    let mut present: Vec<String> = Vec::new();
    for _ in 0..30 {
        step(&database, &mut rng, &mut present);
    }
    let original = database.audit_verify(None).unwrap();

    let replica = temporary.path().join("replica");
    copy_tree(&root, &replica);
    let replayed = open(&replica).audit_verify(None).unwrap();

    assert_eq!(original.head.hash, replayed.head.hash);
    assert_eq!(original.head.sequence, replayed.head.sequence);
    assert_eq!(original.entries, replayed.entries);
    assert_eq!(original.records_checked, replayed.records_checked);
    assert_eq!(
        chain::assert_chain_is_well_formed(&replica),
        original.head.hash
    );

    // Reading the same database again is stable too.
    assert_eq!(
        open(&root).audit_verify(None).unwrap().head.hash,
        original.head.hash
    );
}

/// Every single-byte change anywhere in a segment is detected.
///
/// Exhaustive rather than sampled: the segment is small on purpose, and the
/// claim is about *every* byte. Verification runs in-process, so the whole
/// sweep costs a fraction of a second.
#[test]
fn every_single_byte_change_in_a_segment_is_detected() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let database = init(root, 256);
    database
        .create(
            "items",
            "alpha",
            &[assignment("stage=screening")],
            "Body.\n",
        )
        .unwrap();
    database
        .update("items", "alpha", &[assignment("stage=hired")], None)
        .unwrap();
    drop(database);

    let segment = chain::segment_paths(root).remove(0);
    let original = fs::read(&segment).unwrap();
    assert!(
        original.len() > 400,
        "the segment should be substantial: {} bytes",
        original.len()
    );

    // One handle for the whole sweep: nothing is cached across calls, and
    // reopening the database for every byte would dominate the suite's runtime.
    let database = open(root);
    for index in 0..original.len() {
        for delta in [0x01u8, 0x80] {
            let mut damaged = original.clone();
            damaged[index] ^= delta;
            fs::write(&segment, &damaged).unwrap();
            assert!(
                database.audit_verify(None).is_err(),
                "byte {index} changed by {delta:#04x} was accepted"
            );
        }
    }

    fs::write(&segment, &original).unwrap();
    open(root)
        .audit_verify(None)
        .expect("restoring the bytes restores the chain");
}

/// Every single-byte change anywhere in a *record* is detected too.
#[test]
fn every_single_byte_change_in_a_record_is_detected() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let database = init(root, 256);
    database
        .create(
            "items",
            "alpha",
            &[assignment("stage=screening")],
            "Body.\n",
        )
        .unwrap();
    drop(database);

    let record = root.join("records/items/alpha.md");
    let original = fs::read(&record).unwrap();
    let database = open(root);
    for index in 0..original.len() {
        let mut damaged = original.clone();
        damaged[index] ^= 0x01;
        fs::write(&record, &damaged).unwrap();
        assert!(
            database.audit_verify(None).is_err(),
            "record byte {index} was accepted"
        );
    }
    fs::write(&record, &original).unwrap();
    open(root)
        .audit_verify(None)
        .expect("the record is restored");
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
