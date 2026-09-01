//! An independent reader for the stored audit journal.
//!
//! The tests that use this deliberately do not go through `cr`'s own parser.
//! They re-derive the event hash from the documented preimage — the domain
//! separator `cr:audit:event:v1\0` followed by the exact stored payload bytes —
//! so a claim like "the chain links" is checked against the format rather than
//! against the implementation agreeing with itself.

#![allow(dead_code)]

use std::{fs, path::Path};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The domain separator the audit event hash commits to.
pub const EVENT_HASH_DOMAIN: &[u8] = b"cr:audit:event:v1\0";
/// The domain separator a record content hash commits to.
pub const RECORD_HASH_DOMAIN: &[u8] = b"cr:record:v1\0";

/// One stored journal line, split into the parts the format defines.
#[derive(Clone, Debug)]
pub struct StoredEvent {
    /// The `hash` field exactly as stored.
    pub hash: String,
    /// The `payload` object's exact bytes, never a reserialization.
    pub payload: String,
    /// The payload parsed for field access.
    pub parsed: Value,
}

impl StoredEvent {
    pub fn sequence(&self) -> u64 {
        self.parsed["sequence"]
            .as_u64()
            .expect("sequence is a number")
    }

    pub fn previous_hash(&self) -> Option<&str> {
        self.parsed["previous_hash"].as_str()
    }
}

/// `sha256:` over `domain || contents`, formatted the way `cr` stores it.
pub fn digest(domain: &[u8], contents: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(contents);
    let mut value = String::from("sha256:");
    for byte in digest.finalize() {
        value.push_str(&format!("{byte:02x}"));
    }
    value
}

pub fn event_hash(payload: &str) -> String {
    digest(EVENT_HASH_DOMAIN, payload.as_bytes())
}

pub fn record_hash(contents: &[u8]) -> String {
    digest(RECORD_HASH_DOMAIN, contents)
}

/// Re-encode one journal line exactly as `cr` writes it.
pub fn stored_line(hash: &str, payload: &str) -> String {
    let hash = serde_json::to_string(hash).unwrap();
    format!("{{\"hash\":{hash},\"payload\":{payload}}}\n")
}

/// Split a stored line into its hash and its exact payload bytes.
pub fn parse_line(line: &str) -> StoredEvent {
    // `RawValue` is how `cr` keeps the payload bytes intact; do the same here
    // rather than reserializing, or the recomputed hash would be meaningless.
    #[derive(serde::Deserialize)]
    struct Line {
        hash: String,
        payload: Box<serde_json::value::RawValue>,
    }
    let line: Line = serde_json::from_str(line).expect("stored line is valid JSON");
    let payload = line.payload.get().to_owned();
    let parsed = serde_json::from_str(&payload).expect("payload is valid JSON");
    StoredEvent {
        hash: line.hash,
        payload,
        parsed,
    }
}

/// Every audit segment beneath `root`, ordered by sequence.
pub fn segment_paths(root: &Path) -> Vec<std::path::PathBuf> {
    let mut segments: Vec<_> = fs::read_dir(root.join(".cr/audit/segments"))
        .expect("the segment directory exists")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("jsonl"))
        .collect();
    segments.sort();
    segments
}

/// Read the whole journal as stored events, in chain order.
pub fn read_chain(root: &Path) -> Vec<StoredEvent> {
    segment_paths(root)
        .into_iter()
        .flat_map(|path| {
            let contents = fs::read_to_string(&path).expect("a segment is readable UTF-8");
            assert!(
                contents.is_empty() || contents.ends_with('\n'),
                "segment {} has a truncated tail",
                path.display()
            );
            contents.lines().map(parse_line).collect::<Vec<_>>()
        })
        .collect()
}

/// Check the properties the format promises, independently of `cr`.
///
/// Sequence numbers are dense and start at one, every event names its
/// predecessor's hash, and every stored hash is the SHA-256 of the documented
/// preimage over the exact stored payload bytes. Returns the head hash.
pub fn assert_chain_is_well_formed(root: &Path) -> Option<String> {
    let events = read_chain(root);
    let mut previous: Option<String> = None;
    for (index, event) in events.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        assert_eq!(
            event.sequence(),
            expected_sequence,
            "sequence numbers must be dense and monotonic"
        );
        assert_eq!(
            event.previous_hash(),
            previous.as_deref(),
            "event {expected_sequence} must name its predecessor"
        );
        assert_eq!(
            event_hash(&event.payload),
            event.hash,
            "event {expected_sequence} hash must cover its stored payload bytes"
        );
        previous = Some(event.hash.clone());
    }
    previous
}

/// The anchor `cr` maintains at the database root.
pub const ANCHOR_PATH: &str = ".cr-audit-head.json";

/// Read the stored anchor, or `None` when the database has none.
pub fn read_anchor(root: &Path) -> Option<Value> {
    let contents = fs::read_to_string(root.join(ANCHOR_PATH)).ok()?;
    assert!(
        contents.ends_with('\n'),
        "the anchor must be newline-terminated so a Git diff is clean"
    );
    Some(serde_json::from_str(&contents).expect("the anchor is valid JSON"))
}

/// Overwrite the anchor with `contents` exactly.
pub fn write_anchor(root: &Path, contents: &str) {
    fs::write(root.join(ANCHOR_PATH), contents).expect("the anchor is writable");
}

/// Delete the anchor.
pub fn remove_anchor(root: &Path) {
    fs::remove_file(root.join(ANCHOR_PATH)).expect("the anchor exists");
}

/// Rewrite the anchor so that it agrees with whatever the journal now says.
///
/// This is the forger's second move, and it costs them nothing: the anchor is a
/// plain file at the database root, so anybody who can rewrite `.cr/audit/` can
/// rewrite this in the same pass. Tests that document what the anchor does
/// *not* buy call this; tests that document what it does catch do not.
///
/// Derived from the stored journal here rather than by asking `cr`, so a test
/// that says "the anchor was rewritten to match" is checked against the format
/// rather than against the implementation agreeing with itself.
pub fn reanchor(root: &Path) {
    let events = read_chain(root);
    let head = events.last().expect("the journal has at least one event");
    let anchor = serde_json::json!({
        "version": 1,
        "sequence": head.sequence(),
        "hash": head.hash,
        "timestamp": head.parsed["timestamp"],
    });
    write_anchor(
        root,
        &format!("{}\n", serde_json::to_string_pretty(&anchor).unwrap()),
    );
}
