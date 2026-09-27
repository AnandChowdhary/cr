//! Whether `cr serve` can answer requests that read the database.
//!
//! `/health` says the process is running. Readiness is what a load balancer or
//! an orchestrator asks before sending the process traffic: the database is
//! still where the server opened it, its configuration still loads, nothing
//! interrupted is waiting to be recovered, and the verified journal the server
//! keeps still describes the journal on disk.
//!
//! Every check is cheap, and none of them waits or repairs. Nothing here walks
//! the journal from the first event, waits for a lock, or recovers a pending
//! mutation or sync run: a probe that did any of those would be slowest, or
//! stuck behind a writer, exactly when the server is busiest, and would turn a
//! question into a write. The one thing a probe may start is the server's
//! first walk of the journal, when nobody else has; see [`JournalWarmUp`].

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use crate::{Database, audit::JournalProbe};

/// One readiness check, in the order they are reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadinessCheck {
    Database,
    Config,
    AuditRecovery,
    SyncRecovery,
    Journal,
}

impl ReadinessCheck {
    /// The stable name a probe response uses.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Config => "config",
            Self::AuditRecovery => "audit_recovery",
            Self::SyncRecovery => "sync_recovery",
            Self::Journal => "journal",
        }
    }
}

/// Why one check did not pass.
pub(crate) struct ReadinessFailure {
    /// A stable code naming the condition, and all a caller is told. It never
    /// carries a path, a record, a sync, or a count.
    pub(crate) code: &'static str,
    /// What happened, for the server log alone.
    pub(crate) detail: String,
}

impl ReadinessFailure {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    fn from_error(code: &'static str, error: &anyhow::Error) -> Self {
        Self::new(code, format!("{error:#}"))
    }
}

/// Every check that ran, in order, with why it failed if it did.
pub(crate) struct Readiness {
    pub(crate) checks: Vec<(ReadinessCheck, Option<ReadinessFailure>)>,
}

impl Readiness {
    pub(crate) fn ready(&self) -> bool {
        self.checks.iter().all(|(_, failure)| failure.is_none())
    }
}

const WARM_UP_IDLE: u8 = 0;
const WARM_UP_RUNNING: u8 = 1;
const WARM_UP_FINISHED: u8 = 2;

/// The walk that fills the server's verified journal before a request has to
/// wait for it.
///
/// `cr serve` starts it as soon as it is listening, and readiness reports the
/// journal as warming until it returns, because until then every request that
/// reads audited state waits on it. A router `serve` did not start — a test,
/// an embedding — has no such walk, so its first probe starts the same one
/// rather than reporting a journal nobody is going to verify. There is only
/// ever one: a walk that failed is not retried by probes, which would make a
/// broken journal cost a whole walk per probe. The next request that reads
/// the journal walks it again, as it always has.
#[derive(Debug, Default)]
pub(crate) struct JournalWarmUp {
    state: AtomicU8,
}

impl JournalWarmUp {
    /// Walk the journal on the blocking pool, unless a walk has already been
    /// started. Must be called inside the server's runtime.
    pub(crate) fn start(self: &Arc<Self>, database: Database) {
        if self
            .state
            .compare_exchange(
                WARM_UP_IDLE,
                WARM_UP_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return;
        }
        let warm_up = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            // Finished however the walk ends, a panic included, so a probe
            // never reports a walk as running that is not.
            let _finished = WarmUpFinished(&warm_up);
            // A failure is left to the request that needs the journal, which
            // walks it again and reports why, exactly as it would have without
            // this; readiness reports the journal as unverified meanwhile.
            let _ = database.audit().record_states();
        });
    }

    fn state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
}

struct WarmUpFinished<'a>(&'a JournalWarmUp);

impl Drop for WarmUpFinished<'_> {
    fn drop(&mut self) {
        self.0.state.store(WARM_UP_FINISHED, Ordering::Release);
    }
}

/// Run every check against the database the server opened.
///
/// When the database directory itself cannot be reached, that is the only
/// check reported: every other one reads beneath it, and would either fail for
/// the same reason or, worse, pass because a file they look for is absent.
pub(crate) fn assess(database: &Database, warm_up: &Arc<JournalWarmUp>) -> Readiness {
    if let Err(error) = database.reachable() {
        return Readiness {
            checks: vec![(
                ReadinessCheck::Database,
                Some(ReadinessFailure::from_error("database_unreachable", &error)),
            )],
        };
    }
    let audit = database.audit();
    let config = database
        .configuration_loads()
        .err()
        .map(|error| ReadinessFailure::from_error("config_invalid", &error));
    let audit_recovery = match audit.interrupted_mutation() {
        Ok(false) => None,
        Ok(true) => Some(ReadinessFailure::new(
            "pending_mutation",
            "an interrupted mutation is waiting for recovery; the next request that reads the audit journal, or any cr command, finishes or discards it",
        )),
        Err(error) => Some(ReadinessFailure::from_error(
            "audit_recovery_unreadable",
            &error,
        )),
    };
    let sync_recovery = match database.waiting_sync_run() {
        Ok(None) => None,
        Ok(Some(name)) => Some(ReadinessFailure::new(
            "interrupted_sync_run",
            format!(
                "sync '{name}' has a run that never finished; inspect it with 'cr sync recover {name} --check'"
            ),
        )),
        Err(error) => Some(ReadinessFailure::from_error(
            "sync_recovery_unreadable",
            &error,
        )),
    };
    Readiness {
        checks: vec![
            (ReadinessCheck::Database, None),
            (ReadinessCheck::Config, config),
            (ReadinessCheck::AuditRecovery, audit_recovery),
            (ReadinessCheck::SyncRecovery, sync_recovery),
            (ReadinessCheck::Journal, journal(database, warm_up)),
        ],
    }
}

/// Whether the server holds a verified walk of the journal that the newest
/// event on disk still continues.
fn journal(database: &Database, warm_up: &Arc<JournalWarmUp>) -> Option<ReadinessFailure> {
    let warming = || {
        ReadinessFailure::new(
            "journal_warming",
            "the server has not finished verifying the audit journal it started with",
        )
    };
    let state = warm_up.state();
    match database.audit().probe_journal() {
        Ok(JournalProbe::Consistent) => None,
        // Somebody is using the walk, and a probe does not wait for them.
        // Before the warm-up has returned that is the warm-up, or a request
        // waiting on it; afterwards it is a request bringing the walk up to
        // date, and the last walk stands until it has.
        Ok(JournalProbe::Busy) => (state == WARM_UP_RUNNING).then(warming),
        Ok(JournalProbe::Unverified) => match state {
            WARM_UP_IDLE => {
                warm_up.start(database.clone());
                Some(warming())
            }
            WARM_UP_RUNNING => Some(warming()),
            _ => Some(ReadinessFailure::new(
                "journal_unverified",
                "the last walk of the audit journal failed; the next request that reads the journal walks it again and logs why",
            )),
        },
        Ok(JournalProbe::Changed) => Some(ReadinessFailure::new(
            "journal_changed",
            "the newest audit event on disk is behind, or differs from, the head this server verified; 'cr audit verify' reports why",
        )),
        Err(error) => Some(ReadinessFailure::from_error("journal_unreadable", &error)),
    }
}
