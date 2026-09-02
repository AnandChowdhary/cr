//! Fault injection for the audit write-ahead protocol.
//!
//! A mutation writes `.cr/audit/pending.json`, atomically changes the record,
//! appends the event to a segment, and removes the pending file. Recovery has
//! to be decidable after an interruption at any of those points, so the tests
//! need a way to stop a *real* `cr` process in the middle of one and inspect
//! what it left behind.
//!
//! The lever is segment rotation. With `audit.segment_max_events: 1` every
//! event lands in a new segment whose name is derived from its sequence number,
//! and segments are published with `linkat`, which refuses to clobber. Creating
//! a *directory* at the name the next segment will take therefore makes the
//! append — and only the append — fail: `segment_paths` skips non-file entries,
//! so nothing before the append notices the obstruction. The process exits
//! non-zero having written its pending file and its record, which is exactly
//! the on-disk state a crash between those two steps leaves.
//!
//! That is preferable to sending a signal at a guessed moment: it is
//! deterministic, needs no timing, needs no hook in production code, and the
//! `pending.json` it captures is written by `cr` itself rather than
//! reconstructed by a test. The other interruption points are then materialised
//! by replaying those captured bytes against the record's before-state or
//! after-state, which differs from a real crash only in how the process
//! stopped.

#![allow(dead_code)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use super::{TestDatabase, run_failure, run_success};

/// Where the write-ahead file lives, relative to the database root.
pub const PENDING_PATH: &str = ".cr/audit/pending.json";
/// Where audit segments live, relative to the database root.
pub const SEGMENTS_PATH: &str = ".cr/audit/segments";

/// A database whose audit journal writes one event per segment.
#[derive(Debug)]
pub struct FaultDatabase {
    database: TestDatabase,
}

/// Everything a mutation left on disk when its append was blocked.
#[derive(Clone, Debug)]
pub struct Interruption {
    /// The exact bytes `cr` wrote to `.cr/audit/pending.json`.
    pub pending: Vec<u8>,
    /// The record's bytes before the mutation, absent when it did not exist.
    pub before: Option<Vec<u8>>,
    /// The record's bytes after the mutation, absent for a deletion.
    pub after: Option<Vec<u8>>,
    /// The chain head sequence the mutation was appending on top of.
    pub previous_sequence: u64,
    /// What the interrupted process printed on the way out.
    pub stderr: String,
}

impl FaultDatabase {
    /// Create a database that rotates its audit segment on every event.
    pub fn new(name: &str) -> Self {
        let database = TestDatabase::new(name);
        let fault = Self { database };
        fault.set_segment_max_events(1);
        fault
    }

    pub fn root(&self) -> &Path {
        &self.database.root
    }

    pub fn command(&self) -> Command {
        self.database.command()
    }

    /// Rewrite `.cr/config.yaml` with an explicit segment event bound.
    pub fn set_segment_max_events(&self, events: usize) {
        let config = format!(
            "version: 1\ndata_dir: records\naudit:\n  segment_max_events: {events}\n  segment_max_bytes: 8388608\n"
        );
        fs::create_dir_all(self.root().join(".cr")).unwrap();
        fs::write(self.root().join(".cr/config.yaml"), config).unwrap();
    }

    /// The sequence number of the current chain head, zero when empty.
    pub fn head_sequence(&self) -> u64 {
        let head = run_success(self.command().args(["audit", "head", "--json"]));
        let head: serde_json::Value = serde_json::from_str(&head).unwrap();
        head["sequence"].as_u64().unwrap()
    }

    /// The current chain head hash, absent when the chain is empty.
    pub fn head_hash(&self) -> Option<String> {
        let head = run_success(self.command().args(["audit", "head", "--json"]));
        let head: serde_json::Value = serde_json::from_str(&head).unwrap();
        head["hash"].as_str().map(str::to_owned)
    }

    pub fn record_path(&self, collection: &str, id: &str) -> PathBuf {
        self.root().join(format!("records/{collection}/{id}.md"))
    }

    pub fn read_record(&self, collection: &str, id: &str) -> Option<Vec<u8>> {
        fs::read(self.record_path(collection, id)).ok()
    }

    /// Put a record into an exact byte state, or remove it entirely.
    pub fn put_record(&self, collection: &str, id: &str, contents: Option<&[u8]>) {
        let path = self.record_path(collection, id);
        match contents {
            Some(contents) => {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, contents).unwrap();
            }
            None => match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("could not remove {}: {error}", path.display()),
            },
        }
    }

    pub fn pending_path(&self) -> PathBuf {
        self.root().join(PENDING_PATH)
    }

    pub fn read_pending(&self) -> Option<Vec<u8>> {
        fs::read(self.pending_path()).ok()
    }

    pub fn put_pending(&self, contents: &[u8]) {
        fs::write(self.pending_path(), contents).unwrap();
    }

    pub fn clear_pending(&self) {
        let _ = fs::remove_file(self.pending_path());
    }

    pub fn segments_path(&self) -> PathBuf {
        self.root().join(SEGMENTS_PATH)
    }

    /// Every audit segment, ordered by sequence.
    pub fn segments(&self) -> Vec<PathBuf> {
        let mut segments: Vec<_> = fs::read_dir(self.segments_path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("jsonl"))
            .collect();
        segments.sort();
        segments
    }

    /// Every stored line of the journal, in chain order.
    pub fn journal_lines(&self) -> Vec<String> {
        self.segments()
            .into_iter()
            .flat_map(|path| {
                fs::read_to_string(path)
                    .unwrap()
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Occupy the name the next segment will take, so an append cannot publish.
    fn block_next_segment(&self, sequence: u64) -> PathBuf {
        let path = self.segments_path().join(format!("{sequence:020}.jsonl"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// Run `arguments` with the next audit segment blocked.
    ///
    /// The command writes its pending file and its record and then fails to
    /// append, leaving the database exactly as a crash between the record
    /// write and the journal append would.
    pub fn interrupt(&self, collection: &str, id: &str, arguments: &[&str]) -> Interruption {
        self.interrupt_with(collection, id, |_| {}, arguments)
    }

    /// The configured form of [`Self::interrupt`], for mutations that need
    /// process-local environment such as an external encryption keyring.
    pub fn interrupt_with(
        &self,
        collection: &str,
        id: &str,
        configure: impl FnOnce(&mut Command),
        arguments: &[&str],
    ) -> Interruption {
        let previous_sequence = self.head_sequence();
        let before = self.read_record(collection, id);
        let blocked = self.block_next_segment(previous_sequence + 1);

        let mut command = self.command();
        configure(&mut command);
        let stderr = run_failure(command.args(arguments));

        let pending = self
            .read_pending()
            .expect("an interrupted mutation must retain its pending file");
        let after = self.read_record(collection, id);
        fs::remove_dir(&blocked).unwrap();

        assert_eq!(
            self.head_sequence_unrecovered(),
            previous_sequence,
            "the interrupted event must not be in the journal"
        );

        Interruption {
            pending,
            before,
            after,
            previous_sequence,
            stderr,
        }
    }

    /// The head sequence read straight off the segments, without asking `cr`,
    /// which would run recovery and change the state under inspection.
    pub fn head_sequence_unrecovered(&self) -> u64 {
        self.journal_lines().len() as u64
    }

    /// Restore the database to the state a crash at `point` would leave.
    pub fn restore(&self, interruption: &Interruption, collection: &str, id: &str, point: Point) {
        match point {
            Point::PendingWritten => {
                self.put_record(collection, id, interruption.before.as_deref());
                self.put_pending(&interruption.pending);
            }
            Point::RecordReplaced => {
                self.put_record(collection, id, interruption.after.as_deref());
                self.put_pending(&interruption.pending);
            }
        }
    }
}

/// The two interruption points a test can materialise directly.
///
/// The third — the event appended but the pending file not yet removed — is
/// reached by letting recovery run from [`Point::RecordReplaced`] and then
/// putting the captured pending bytes back, and the fourth is an ordinary
/// completed mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Point {
    /// Pending file written, record not yet changed.
    PendingWritten,
    /// Record changed, event not yet appended.
    RecordReplaced,
}

/// Decode a captured pending file into its JSON object.
pub fn pending_json(bytes: &[u8]) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::from_slice(bytes).unwrap() {
        serde_json::Value::Object(fields) => fields,
        other => panic!("pending mutation was not an object: {other}"),
    }
}

/// Re-encode a pending object, so a test can corrupt one field at a time.
pub fn pending_bytes(fields: &serde_json::Map<String, serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(fields).unwrap()
}
