//! Durable audit events and operational projections. Markdown remains editable.
//!
//! SQLite owns the audit state, never a plaintext projection of protected data.
//! Normal operations read indexed committed state; `verify` independently replays
//! exact event bytes. The caller's filesystem writer lock coordinates publication
//! of Markdown with the durable pending row across the two SQLite transactions.

use super::*;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::time::Duration;

pub(crate) const PATH: &str = ".cr/audit.sqlite";
const APPLICATION_ID: i64 = 0x63726175;
const SCHEMA_VERSION: i64 = 1;
const LABEL: &str = "the SQLite audit database";

pub(super) struct Store {
    connection: Connection,
    // Retain the checked parent; SQLite itself still opens through its VFS,
    // so this does not make its path operations descriptor-relative.
    _directory: paths::Directory,
}

impl Store {
    pub(super) fn create(root: &Path, relative: &Path) -> Result<Self> {
        if paths::entry_kind(root, relative, LABEL)?.is_some() {
            return Err(conflict("the SQLite audit destination already exists"));
        }
        // Only schema initialization uses this small staging file. A crash
        // leaves an unselected artifact that the next attempt may discard.
        let staging = Path::new(".cr/audit.sqlite.init");
        for suffix in ["-wal", "-shm", "-journal", ""] {
            let path = PathBuf::from(format!("{}{suffix}", staging.display()));
            if paths::entry_kind(root, &path, LABEL)?.is_some() {
                paths::remove_file(root, &path, LABEL)?;
            }
        }
        paths::write_new(root, staging, &[], LABEL)?;
        let store = Self::connect(root, staging, false)?;
        store.connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             BEGIN IMMEDIATE;
             CREATE TABLE head (singleton INTEGER PRIMARY KEY CHECK(singleton=1), sequence INTEGER NOT NULL, hash TEXT, version INTEGER);
             INSERT INTO head VALUES (1,0,NULL,NULL);
             CREATE TABLE events (sequence INTEGER PRIMARY KEY, hash TEXT NOT NULL, payload TEXT NOT NULL, collection TEXT NOT NULL, record_id TEXT NOT NULL, transition TEXT NOT NULL);
             CREATE INDEX events_record ON events(collection,record_id,sequence DESC);
             CREATE INDEX events_collection ON events(collection,sequence DESC);
             CREATE TABLE record_states (collection TEXT NOT NULL, record_id TEXT NOT NULL, sequence INTEGER NOT NULL REFERENCES events(sequence), state TEXT NOT NULL, activity TEXT, PRIMARY KEY(collection,record_id)) WITHOUT ROWID;
             CREATE TABLE idempotency (principal TEXT NOT NULL, operation TEXT NOT NULL, collection TEXT NOT NULL, record_id TEXT NOT NULL, key_hash TEXT NOT NULL, request_hash TEXT NOT NULL, sequence INTEGER NOT NULL REFERENCES events(sequence), files TEXT NOT NULL, PRIMARY KEY(principal,operation,collection,record_id,key_hash)) WITHOUT ROWID;
             CREATE TABLE agent_values (kind TEXT NOT NULL, value TEXT NOT NULL, sequence INTEGER NOT NULL REFERENCES events(sequence), PRIMARY KEY(kind,value,sequence)) WITHOUT ROWID;
             CREATE TABLE principals (principal TEXT PRIMARY KEY, sequence INTEGER NOT NULL REFERENCES events(sequence)) WITHOUT ROWID;
             CREATE TABLE protected_events (sequence INTEGER PRIMARY KEY REFERENCES events(sequence));
             CREATE TABLE pending (singleton INTEGER PRIMARY KEY CHECK(singleton=1), payload TEXT NOT NULL);
             COMMIT;"
        ).context("could not initialize SQLite audit storage")?;
        store
            .connection
            .pragma_update(None, "application_id", APPLICATION_ID)?;
        store
            .connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        store
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        drop(store);
        // The empty schema is small; publish it atomically using the same
        // descriptor-relative durable primitive as all other CR files.
        let schema = paths::read(root, staging, LABEL)?;
        paths::write_new(root, relative, &schema, LABEL)?;
        paths::remove_file(root, staging, LABEL)?;
        Self::connect(root, relative, true)
    }

    pub(super) fn open(root: &Path) -> Result<Self> {
        Self::connect(root, Path::new(PATH), true)
    }

    fn connect(root: &Path, relative: &Path, validate: bool) -> Result<Self> {
        let directory = paths::open_directory(root, Path::new(".cr"), LABEL)?;
        // Check all SQLite-managed entries, including sidecars, before SQLite
        // can open them. NOFOLLOW also refuses a symlink swapped onto the main
        // file between this check and SQLite's open.
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = PathBuf::from(format!("{}{suffix}", relative.display()));
            match paths::entry_kind(root, &path, LABEL)? {
                Some(EntryKind::File) => {}
                None if !suffix.is_empty() => {}
                None => return Err(audit_integrity("the SQLite audit database is missing")),
                Some(kind) => return Err(paths::refuse_entry(LABEL, kind)),
            }
        }
        let connection = Connection::open_with_flags(
            root.join(relative),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| audit_integrity("could not open the SQLite audit database"))?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "trusted_schema", false)?;
        if validate {
            let application: i64 =
                connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
            let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if application != APPLICATION_ID || version != SCHEMA_VERSION {
                return Err(audit_integrity(
                    "unsupported SQLite audit schema or database identity",
                ));
            }
        }
        Ok(Self {
            connection,
            _directory: directory,
        })
    }

    pub(super) fn chain(&self) -> Result<ChainState> {
        let (entries, hash, version): (u64, Option<String>, Option<u32>) = self
            .connection
            .query_row(
                "SELECT sequence,hash,version FROM head WHERE singleton=1",
                [],
                |r| Ok((read_sequence(r, 0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|_| audit_integrity("the SQLite audit head is invalid"))?;
        match self.event(entries)? {
            None if entries == 0 && hash.is_none() && version.is_none() => {}
            Some(event)
                if Some(&event.entry.hash) == hash.as_ref()
                    && Some(event.entry.payload.version) == version => {}
            _ => {
                return Err(audit_integrity(
                    "the SQLite audit head does not match its event",
                ));
            }
        }
        Ok(ChainState {
            entries,
            head_hash: hash,
            head_version: version,
            idempotency_identities: HashSet::new(),
        })
    }

    pub(super) fn event(&self, sequence: u64) -> Result<Option<StoredEntry>> {
        let row: Option<(String, String)> = self
            .connection
            .query_row(
                "SELECT hash,payload FROM events WHERE sequence=?1",
                [sql_sequence(sequence)?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(hash, payload)| {
            let stored = parse_line(stored_line(&hash, &payload)?.as_bytes())?;
            if stored.entry.payload.sequence != sequence {
                return Err(audit_integrity("indexed audit event has changed sequence"));
            }
            Ok(stored)
        })
        .transpose()
    }

    pub(super) fn state(&self, collection: &str, id: &str) -> Result<Option<AuditedRecordState>> {
        let row: Option<(u64, String)> = self
            .connection
            .query_row(
                "SELECT sequence,state FROM record_states WHERE collection=?1 AND record_id=?2",
                params![collection, id],
                |r| Ok((read_sequence(r, 0)?, r.get(1)?)),
            )
            .optional()?;
        row.map(|(sequence, raw)| {
            let state: AuditedRecordState = serde_json::from_str(&raw)
                .map_err(|_| audit_integrity("invalid indexed audit record state"))?;
            let event = self
                .event(sequence)?
                .ok_or_else(|| audit_integrity("indexed audit state has no backing event"))?;
            if event.entry.payload.record.collection != collection
                || event.entry.payload.record.id != id
                || event.entry.payload.after_hash != state.hash
            {
                return Err(audit_integrity(
                    "indexed audit record state does not match its event",
                ));
            }
            Ok(state)
        })
        .transpose()
    }

    pub(super) fn states(&self, collection: Option<&str>) -> Result<AuditedRecordStates> {
        let query = if collection.is_some() {
            "SELECT collection,record_id,state FROM record_states WHERE collection=?1"
        } else {
            "SELECT collection,record_id,state FROM record_states WHERE ?1 IS NULL"
        };
        let mut statement = self.connection.prepare(query)?;
        let rows = statement.query_map([collection], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        let mut states = AuditedRecordStates::new();
        for row in rows {
            let (collection, id, state) = row?;
            states.insert(
                (collection, id),
                serde_json::from_str(&state)
                    .map_err(|_| audit_integrity("invalid indexed audit state"))?,
            );
        }
        Ok(states)
    }

    pub(super) fn admission(&self, records: Option<&[(&str, &str)]>) -> Result<Admission> {
        let chain = self.chain()?;
        let states = match records {
            None => self.states(None)?,
            Some(records) => {
                let mut states = AuditedRecordStates::new();
                for &(collection, id) in records {
                    if let Some(state) = self.state(collection, id)? {
                        states.insert((collection.to_owned(), id.to_owned()), state);
                    }
                }
                states
            }
        };
        let mut journal = VerifiedJournal::new();
        journal.walk.expected_sequence = chain.entries + 1;
        journal.walk.previous_hash = chain.head_hash;
        journal.walk.previous_version = chain.head_version;
        journal.states = Arc::new(states);
        Ok(Admission { journal })
    }

    pub(super) fn pending(&self) -> Result<Option<Vec<u8>>> {
        self.connection
            .query_row("SELECT payload FROM pending WHERE singleton=1", [], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .map(|v| v.map(String::into_bytes))
            .map_err(Into::into)
    }

    pub(super) fn store_pending(&self, pending: &PendingMutation) -> Result<()> {
        self.connection.execute(
            "INSERT INTO pending VALUES(1,?1)",
            [serde_json::to_string(pending)?],
        )?;
        Ok(())
    }

    pub(super) fn clear_pending(&self) -> Result<()> {
        self.connection.execute("DELETE FROM pending", [])?;
        Ok(())
    }

    /// Caller holds filesystem writer coordination. This transaction never
    /// includes filesystem work or a full-history replay.
    pub(super) fn append(&mut self, entry: &PreparedEntry) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        Self::insert(&transaction, entry)?;
        transaction.commit()?;
        Ok(())
    }

    fn insert(connection: &Connection, entry: &PreparedEntry) -> Result<()> {
        let (sequence, hash, version): (u64, Option<String>, Option<u32>) = connection.query_row(
            "SELECT sequence,hash,version FROM head WHERE singleton=1",
            [],
            |r| Ok((read_sequence(r, 0)?, r.get(1)?, r.get(2)?)),
        )?;
        if entry.parsed.sequence != sequence + 1
            || entry.parsed.previous_hash != hash
            || event_hash(entry.payload.as_bytes()) != entry.hash
        {
            return Err(audit_integrity(
                "audit event does not extend the current chain head",
            ));
        }
        if let Some(version) = version {
            verify_version_progress(version, entry.parsed.version, entry.parsed.sequence)?;
        }
        let collection = &entry.parsed.record.collection;
        let id = &entry.parsed.record.id;
        let previous: Option<String> = connection
            .query_row(
                "SELECT state FROM record_states WHERE collection=?1 AND record_id=?2",
                params![collection, id],
                |r| r.get(0),
            )
            .optional()?;
        let previous: Option<AuditedRecordState> =
            previous.map(|raw| serde_json::from_str(&raw)).transpose()?;
        let before = previous
            .as_ref()
            .and_then(|state| state.document.as_ref())
            .and_then(audit_document_encryption_metadata);
        let deleted_files = previous
            .as_ref()
            .map(|s| idempotency_file_versions(&s.files))
            .unwrap_or_default();
        let key = (collection.clone(), id.clone());
        let mut states = AuditedRecordStates::new();
        if let Some(previous) = previous {
            states.insert(key.clone(), previous);
        }
        let event = AuditEntry {
            hash: entry.hash.clone(),
            payload: entry.parsed.clone(),
        };
        replay_entry(&mut states, &event)?;
        let state = states.get(&key).expect("replay retains tombstones");
        let after = state
            .document
            .as_ref()
            .and_then(audit_document_encryption_metadata);
        let transition = AuditEncryptionTransition { before, after };
        connection.execute(
            "INSERT INTO events VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                sql_sequence(entry.parsed.sequence)?,
                entry.hash,
                entry.payload,
                collection,
                id,
                serde_json::to_string(&transition)?
            ],
        )?;
        let activity: Option<String> = connection
            .query_row(
                "SELECT activity FROM record_states WHERE collection=?1 AND record_id=?2",
                params![collection, id],
                |r| r.get(0),
            )
            .optional()?
            .flatten();
        let mut activity_map = CollectionsActivity::new();
        if let Some(activity) = activity {
            activity_map
                .entry(collection.clone())
                .or_default()
                .insert(id.clone(), serde_json::from_str(&activity)?);
        }
        track_activity(&mut activity_map, &event);
        let activity = activity_map
            .get(collection)
            .and_then(|c| c.get(id))
            .map(serde_json::to_string)
            .transpose()?;
        connection.execute("INSERT INTO record_states VALUES(?1,?2,?3,?4,?5) ON CONFLICT(collection,record_id) DO UPDATE SET sequence=excluded.sequence,state=excluded.state,activity=excluded.activity",params![collection,id,sql_sequence(entry.parsed.sequence)?,serde_json::to_string(state)?,activity])?;
        if let Some(retry) = &entry.parsed.idempotency {
            let files = if entry.parsed.action == AuditAction::Delete {
                deleted_files
            } else {
                idempotency_file_versions(&state.files)
            };
            connection
                .execute(
                    "INSERT INTO idempotency VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        retry.principal,
                        retry.operation,
                        collection,
                        id,
                        retry.key_hash,
                        retry.request_hash,
                        sql_sequence(entry.parsed.sequence)?,
                        serde_json::to_string(&files)?
                    ],
                )
                .map_err(|_| audit_integrity("duplicate or invalid audit idempotency identity"))?;
        }
        for (kind, value) in agent_values(&entry.parsed) {
            connection.execute(
                "INSERT INTO agent_values VALUES(?1,?2,?3)",
                params![kind, value, sql_sequence(entry.parsed.sequence)?],
            )?;
        }
        for principal in external_principals(&entry.parsed) {
            connection.execute(
                "INSERT OR IGNORE INTO principals VALUES(?1,?2)",
                params![principal, sql_sequence(entry.parsed.sequence)?],
            )?;
        }
        if transition.before.as_ref().is_some_and(|m| m.has_envelopes)
            || transition.after.as_ref().is_some_and(|m| m.has_envelopes)
        {
            connection.execute(
                "INSERT INTO protected_events VALUES(?1)",
                [sql_sequence(entry.parsed.sequence)?],
            )?;
        }
        connection.execute(
            "UPDATE head SET sequence=?1,hash=?2,version=?3 WHERE singleton=1",
            params![
                sql_sequence(entry.parsed.sequence)?,
                entry.hash,
                entry.parsed.version
            ],
        )?;
        // Keep pending through external anchor/signature publication. Recovery
        // recognizes an already committed event without appending it twice.
        Ok(())
    }

    pub(super) fn idempotency_result(
        &self,
        principal: &str,
        operation: &str,
        collection: &str,
        id: &str,
        key_hash: &str,
        request_hash: &str,
    ) -> Result<Option<(AuditIdempotencyResult, BundleFiles)>> {
        let row: Option<(u64, String, String)> = self
            .connection
            .query_row(
                "SELECT sequence,request_hash,files FROM idempotency
                 WHERE principal=?1 AND operation=?2 AND collection=?3 AND record_id=?4 AND key_hash=?5",
                params![principal, operation, collection, id, key_hash],
                |r| Ok((read_sequence(r, 0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((sequence, request, files)) = row else {
            return Ok(None);
        };
        let event = self
            .event(sequence)?
            .ok_or_else(|| audit_integrity("indexed retry event is missing"))?;
        let retry = event
            .entry
            .payload
            .idempotency
            .ok_or_else(|| audit_integrity("indexed retry event has no result"))?;
        if retry.principal != principal
            || retry.operation != operation
            || retry.key_hash != key_hash
            || retry.request_hash != request
            || event.entry.payload.record.collection != collection
            || event.entry.payload.record.id != id
        {
            return Err(audit_integrity(
                "indexed retry identity does not match its event",
            ));
        }
        if request != request_hash {
            return Err(idempotency_conflict(format!(
                "idempotency key was already used for a different {operation} request on record {collection}/{id}"
            )));
        }
        Ok(Some((retry.result, serde_json::from_str(&files)?)))
    }

    pub(super) fn history(
        &self,
        limit: usize,
        before: Option<u64>,
        filter: AuditFilter<'_>,
        mut visible: impl FnMut(&AuditEntry) -> Result<bool>,
    ) -> Result<AuditHistory> {
        let mut query =
            String::from("SELECT e.sequence,e.hash,e.payload,e.transition FROM events e");
        let mut arguments: Vec<rusqlite::types::Value> = Vec::new();
        for (kind, value) in [("agent", filter.agent), ("session", filter.session)] {
            if let Some(value) = value {
                // kind is a fixed program constant, never caller SQL.
                query.push_str(&format!(" JOIN agent_values {kind} ON {kind}.sequence=e.sequence AND {kind}.kind='{kind}' AND {kind}.value=?"));
                arguments.push(value.to_owned().into());
            }
        }
        query.push_str(" WHERE e.sequence < ?");
        arguments.push(
            before
                .and_then(|v| i64::try_from(v).ok())
                .unwrap_or(i64::MAX)
                .into(),
        );
        if let Some(collection) = filter.collection {
            query.push_str(" AND e.collection=?");
            arguments.push(collection.to_owned().into());
        }
        if let Some(id) = filter.id {
            query.push_str(" AND e.record_id=?");
            arguments.push(id.to_owned().into());
        }
        query.push_str(" ORDER BY e.sequence DESC");
        let mut statement = self.connection.prepare(&query)?;
        let mut rows = statement.query(rusqlite::params_from_iter(arguments))?;
        let mut history = AuditHistory {
            entries: Vec::new(),
            encryption_transitions: HashMap::new(),
        };
        while let Some(row) = rows.next()? {
            let sequence = read_sequence(row, 0)?;
            let hash: String = row.get(1)?;
            let payload: String = row.get(2)?;
            let transition: String = row.get(3)?;
            let stored = parse_line(stored_line(&hash, &payload)?.as_bytes())?;
            if stored.entry.payload.sequence != sequence {
                return Err(audit_integrity(
                    "indexed history sequence disagrees with its event",
                ));
            }
            if !filter.matches(&stored.entry.payload) || !visible(&stored.entry)? {
                continue;
            }
            let transition: AuditEncryptionTransition = serde_json::from_str(&transition)?;
            if !transition.is_empty() {
                history.encryption_transitions.insert(sequence, transition);
            }
            history.entries.push(stored.entry);
            if limit > 0 && history.entries.len() == limit {
                break;
            }
        }
        Ok(history)
    }

    pub(super) fn activity(&self, include: impl Fn(&str) -> bool) -> Result<CollectionsActivity> {
        self.activity_for(None, include)
    }
    pub(super) fn activity_for(
        &self,
        collection: Option<&str>,
        include: impl Fn(&str) -> bool,
    ) -> Result<CollectionsActivity> {
        let mut collections = CollectionsActivity::new();
        let query = if collection.is_some() {
            "SELECT collection,record_id,activity FROM record_states WHERE collection=?1 AND activity IS NOT NULL"
        } else {
            "SELECT collection,record_id,activity FROM record_states WHERE ?1 IS NULL AND activity IS NOT NULL"
        };
        let mut statement = self.connection.prepare(query)?;
        let rows = statement.query_map([collection], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (collection, id, activity) = row?;
            if include(&collection) {
                collections
                    .entry(collection)
                    .or_default()
                    .insert(id, serde_json::from_str(&activity)?);
            }
        }
        Ok(collections)
    }

    pub(super) fn stream(
        &self,
        mut visitor: impl FnMut(&AuditEntry, &str) -> Result<()>,
    ) -> Result<ChainState> {
        #[cfg(test)]
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(calls.get() + 1));
        let mut walk = ChainWalk::new();
        let mut statement = self
            .connection
            .prepare("SELECT sequence,hash,payload FROM events ORDER BY sequence")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence = read_sequence(row, 0)?;
            let hash: String = row.get(1)?;
            let payload: String = row.get(2)?;
            if sequence != walk.expected_sequence {
                return Err(audit_integrity("audit sequence gap"));
            }
            walk.line(
                Path::new(PATH),
                stored_line(&hash, &payload)?
                    .trim_end_matches('\n')
                    .as_bytes(),
                &mut visitor,
            )?;
        }
        let chain = walk.finish();
        let indexed = self.chain()?;
        if chain.entries != indexed.entries
            || chain.head_hash != indexed.head_hash
            || chain.head_version != indexed.head_version
        {
            return Err(audit_integrity(
                "the SQLite audit head differs from independent replay",
            ));
        }
        Ok(chain)
    }

    pub(super) fn check_projections(&self, expected: &AuditedRecordStates) -> Result<()> {
        let stored = self.states(None)?;
        if stored.len() != expected.len() {
            return Err(audit_integrity(
                "SQLite audited-state projection has missing or extra records",
            ));
        }
        for (key, state) in expected {
            if stored.get(key).map(serde_json::to_value).transpose()?
                != Some(serde_json::to_value(state)?)
            {
                return Err(audit_integrity(
                    "SQLite audited-state projection differs from independent replay",
                ));
            }
        }
        let invalid_sequences: bool = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM record_states s
             WHERE sequence != (SELECT max(sequence) FROM events e
                                WHERE e.collection=s.collection AND e.record_id=s.record_id))",
            [],
            |r| r.get(0),
        )?;
        if invalid_sequences {
            return Err(audit_integrity(
                "SQLite record state has an outdated event sequence",
            ));
        }
        let integrity: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(audit_integrity("SQLite audit integrity check failed"));
        }
        Ok(())
    }

    pub(super) fn principal_used(&self, principal: &str) -> Result<bool> {
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE principal=?1)",
            [principal],
            |r| r.get(0),
        )?)
    }

    pub(super) fn contains_protected(&self) -> Result<bool> {
        Ok(self
            .connection
            .query_row("SELECT EXISTS(SELECT 1 FROM protected_events)", [], |r| {
                r.get(0)
            })?)
    }

    /// A single WAL snapshot covers events, head, and all derived projections.
    /// Filesystem consistency still belongs to the caller's coordination lock.
    pub(super) fn verified_states(
        &self,
        approvals: bool,
    ) -> Result<(AuditedRecordStates, ChainState)> {
        let snapshot = self.connection.unchecked_transaction()?;
        let mut states = AuditedRecordStates::new();
        let mut activity = CollectionsActivity::new();
        let mut retry_count = 0i64;
        let mut agent_count = 0i64;
        let mut principals = BTreeMap::new();
        let mut protected_count = 0i64;
        let chain = self.stream(|entry, payload| {
            if approvals {
                verify_approved_changes(entry, payload)?;
            }
            let key = (
                entry.payload.record.collection.clone(),
                entry.payload.record.id.clone(),
            );
            let previous = states.get(&key);
            let before = previous
                .and_then(|s| s.document.as_ref())
                .and_then(audit_document_encryption_metadata);
            let deleted_files = previous
                .map(|s| idempotency_file_versions(&s.files))
                .unwrap_or_default();
            replay_entry(&mut states, entry)?;
            track_activity(&mut activity, entry);
            let state = states.get(&key).expect("replay retains tombstones");
            let after = state
                .document
                .as_ref()
                .and_then(audit_document_encryption_metadata);
            let transition = AuditEncryptionTransition { before, after };
            let sequence = sql_sequence(entry.payload.sequence)?;
            let (collection, id, raw): (String, String, String) = self.connection.query_row(
                "SELECT collection,record_id,transition FROM events WHERE sequence=?1",
                [sequence],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            if (collection, id) != key
                || serde_json::from_str::<AuditEncryptionTransition>(&raw)? != transition
            {
                return Err(audit_integrity(
                    "SQLite event metadata differs from independent replay",
                ));
            }
            if let Some(retry) = &entry.payload.idempotency {
                retry_count += 1;
                let expected_files = if entry.payload.action == AuditAction::Delete {
                    deleted_files
                } else {
                    idempotency_file_versions(&state.files)
                };
                let found = self.idempotency_result(
                    &retry.principal,
                    &retry.operation,
                    &key.0,
                    &key.1,
                    &retry.key_hash,
                    &retry.request_hash,
                )?;
                if found.as_ref().map(|(_, files)| files) != Some(&expected_files) {
                    return Err(audit_integrity(
                        "SQLite retry projection differs from independent replay",
                    ));
                }
                let indexed: i64 = self.connection.query_row(
                    "SELECT sequence FROM idempotency
                     WHERE principal=?1 AND operation=?2 AND collection=?3 AND record_id=?4 AND key_hash=?5",
                    params![retry.principal, retry.operation, key.0, key.1, retry.key_hash],
                    |r| r.get(0),
                )?;
                if indexed != sequence {
                    return Err(audit_integrity(
                        "SQLite retry sequence differs from independent replay",
                    ));
                }
            }
            for (kind, value) in agent_values(&entry.payload) {
                agent_count += 1;
                let found: bool = self.connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM agent_values WHERE kind=?1 AND value=?2 AND sequence=?3)",
                    params![kind, value, sequence],
                    |r| r.get(0),
                )?;
                if !found {
                    return Err(audit_integrity(
                        "SQLite agent projection differs from independent replay",
                    ));
                }
            }
            for principal in external_principals(&entry.payload) {
                principals.entry(principal).or_insert(sequence);
            }
            let protected = transition.before.as_ref().is_some_and(|m| m.has_envelopes)
                || transition.after.as_ref().is_some_and(|m| m.has_envelopes);
            let found: bool = self.connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protected_events WHERE sequence=?1)",
                [sequence],
                |r| r.get(0),
            )?;
            if protected != found {
                return Err(audit_integrity(
                    "SQLite encryption projection differs from independent replay",
                ));
            }
            protected_count += i64::from(protected);
            Ok(())
        })?;
        self.check_projections(&states)?;
        // Empty collection maps are a replay detail, not an activity row.
        activity.retain(|_, records| !records.is_empty());
        if serde_json::to_value(activity)? != serde_json::to_value(self.activity(|_| true)?)? {
            return Err(audit_integrity(
                "SQLite activity projection differs from independent replay",
            ));
        }
        for (table, count) in [
            ("idempotency", retry_count),
            ("agent_values", agent_count),
            ("principals", principals.len() as i64),
            ("protected_events", protected_count),
        ] {
            let actual: i64 =
                self.connection
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
            if actual != count {
                return Err(audit_integrity("SQLite index has missing or extra entries"));
            }
        }
        for (principal, sequence) in principals {
            let actual: i64 = self.connection.query_row(
                "SELECT sequence FROM principals WHERE principal=?1",
                [principal],
                |r| r.get(0),
            )?;
            if actual != sequence {
                return Err(audit_integrity(
                    "SQLite principal projection differs from independent replay",
                ));
            }
        }
        if self
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .exists([])?
        {
            return Err(audit_integrity("SQLite audit foreign key check failed"));
        }
        snapshot.commit()?;
        Ok((states, chain))
    }

    pub(super) fn import(&mut self, legacy: &AuditLog<'_>) -> Result<AuditHead> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let chain = legacy.verify_chain(|event, payload| {
            let previous: Option<(String, String)> = transaction
                .query_row(
                    "SELECT hash,payload FROM events WHERE sequence=?1",
                    [sql_sequence(event.payload.sequence)?],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((hash, bytes)) = previous {
                if hash != event.hash || bytes != payload {
                    return Err(conflict(
                        "the SQLite migration destination does not match legacy history",
                    ));
                }
                return Ok(());
            }
            let prepared = PreparedEntry {
                hash: event.hash.clone(),
                payload: payload.to_owned(),
                parsed: event.payload.clone(),
                change_digest: change_set_hash(payload)?,
                admission: None,
            };
            Self::insert(&transaction, &prepared)
        })?;
        transaction.commit()?;
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        Ok(AuditHead {
            sequence: chain.entries,
            hash: chain.head_hash,
        })
    }
}

fn sql_sequence(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| audit_integrity("audit sequence exceeds SQLite integer range"))
}
fn read_sequence(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}

fn agent_values(payload: &AuditPayload) -> std::collections::BTreeSet<(&'static str, String)> {
    fn visit(
        agent: &crate::attribution::AuditAgent,
        values: &mut std::collections::BTreeSet<(&'static str, String)>,
    ) {
        values.insert(("agent", agent.id.clone()));
        if let Some(session) = &agent.session {
            values.insert(("session", session.clone()));
        }
        for delegate in agent.via.iter().flatten() {
            visit(delegate, values);
        }
    }
    let mut values = std::collections::BTreeSet::new();
    if let Some(agent) = &payload.agent {
        visit(agent, &mut values);
    }
    values
}
fn external_principals(payload: &AuditPayload) -> std::collections::BTreeSet<String> {
    let mut values = std::collections::BTreeSet::new();
    if let Some(access) = &payload.access {
        values.insert(access.principal.clone());
        if let Some(identity) = &access.impersonated_by {
            values.insert(identity.principal.clone());
        }
    } else if let Ok(principal) = principal_id(&payload.actor) {
        values.insert(principal);
    }
    if payload.record.collection == USERS_COLLECTION {
        values.remove(&payload.record.id);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, JournalVerification};

    #[test]
    fn fresh_and_serving_operations_never_replay_unrelated_history() {
        let root = tempfile::tempdir().unwrap();
        let db = Database::init(root.path())
            .unwrap()
            .with_journal_verification(JournalVerification::Resume)
            .with_server_cache();
        for i in 0..32 {
            db.create("items", &i.to_string(), &[], "").unwrap();
        }
        VERIFY_CHAIN_CALLS.with(|calls| calls.set(0));
        for _ in 0..130 {
            db.update("items", "0", &[], None).unwrap();
        }
        let fresh = Database::discover(Some(root.path())).unwrap();
        fresh.update("items", "0", &[], None).unwrap();
        let admission = fresh.audit().admit_records(&[("items", "0")]).unwrap();
        assert_eq!(admission.states().len(), 1);
        assert_eq!(
            fresh.audit_recent(10, AuditFilter::all()).unwrap().len(),
            10
        );
        fresh.get("items", "0").unwrap();
        let activity = fresh.audit().record_activity("items").unwrap();
        assert_eq!(activity.len(), 32);
        VERIFY_CHAIN_CALLS.with(|calls| assert_eq!(calls.get(), 0));
        fresh.audit_verify(None).unwrap();
        VERIFY_CHAIN_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    }

    #[test]
    fn visibility_is_applied_before_counting_a_history_page() {
        let root = tempfile::tempdir().unwrap();
        let db = Database::init(root.path()).unwrap();
        for id in ["visible", "hidden", "hidden-two"] {
            db.create("items", id, &[], "").unwrap();
        }
        let history = Store::open(root.path())
            .unwrap()
            .history(1, None, AuditFilter::all(), |event| {
                Ok(event.payload.record.id == "visible")
            })
            .unwrap();
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].payload.sequence, 1);
    }
}
