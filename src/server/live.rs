//! Browser invalidations, rather than a second API for rendering records.
//!
//! One lazy observer per router resumes the verified journal once a second,
//! including commits from other processes. A watch channel retains only its
//! latest snapshot: slow browsers cannot accumulate an unbounded event queue.
//! Each subscriber compares its own readable records, so hidden changes reveal
//! neither record identifiers nor the database-wide journal sequence. Every
//! connection starts with a reset; reconnects therefore recover missed changes
//! without treating this best-effort UI feed as a durable audit subscription.

use std::{collections::BTreeMap, convert::Infallible, sync::Mutex, time::Duration};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream;
use tokio::{sync::watch, task::JoinHandle};

use super::{
    AccessAction, AccessResource, ApiError, ApiResult, AppState, Arc, Database, HeaderMap, Method,
    PoisonError, REQUEST_IDENTITY, RecordActivity, Response, State, Uri, anyhow, header,
    request_database, request_identity,
};
use crate::{AuditHead, audit::CollectionsActivity};

#[derive(Clone)]
struct Snapshot {
    head: AuditHead,
    activity: CollectionsActivity,
    versions: BTreeMap<(String, String), Option<String>>,
}

#[derive(Clone, Default)]
enum Signal {
    #[default]
    Starting,
    Snapshot(Arc<Snapshot>),
    Unavailable,
    Stopped,
}

pub(super) struct Updates {
    sender: watch::Sender<Signal>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl Default for Updates {
    fn default() -> Self {
        Self {
            sender: watch::channel(Signal::Starting).0,
            task: Mutex::default(),
        }
    }
}

impl Updates {
    fn subscribe(&self, state: AppState) -> watch::Receiver<Signal> {
        let mut task = self.task.lock().unwrap_or_else(PoisonError::into_inner);
        let receiver = self.sender.subscribe();
        if task.as_ref().is_none_or(JoinHandle::is_finished)
            && !matches!(*self.sender.borrow(), Signal::Stopped)
        {
            *task = Some(tokio::spawn(observe(state)));
        }
        receiver
    }

    pub(super) fn stop(&self) {
        self.sender.send_replace(Signal::Stopped);
    }
}

async fn observe(state: AppState) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let updates = &state.live_updates;
        {
            let mut task = updates.task.lock().unwrap_or_else(PoisonError::into_inner);
            if updates.sender.receiver_count() == 0 {
                *task = None;
                return;
            }
            if matches!(*updates.sender.borrow(), Signal::Stopped) {
                return;
            }
        }
        let previous = match &*updates.sender.borrow() {
            Signal::Snapshot(snapshot) => Some(snapshot.head.clone()),
            _ => None,
        };
        let database = state.database();
        let result = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let audit = database.audit();
            // The head and activity must describe one commit, including when
            // a CLI writer happens to append between these two reads.
            let _lock = audit.lock()?;
            let head = audit.cached_head()?;
            if previous.as_ref() == Some(&head) {
                return Ok(None);
            }
            Ok(Some(Snapshot {
                head,
                activity: audit.collections_activity(|_| true)?,
                versions: audit
                    .record_states()?
                    .iter()
                    .map(|(key, state)| (key.clone(), state.hash.clone()))
                    .collect(),
            }))
        })
        .await;
        // Do not let a walk finishing during shutdown reopen the feed.
        if matches!(*updates.sender.borrow(), Signal::Stopped) {
            return;
        }
        match result {
            Ok(Ok(Some(snapshot))) => {
                updates
                    .sender
                    .send_replace(Signal::Snapshot(Arc::new(snapshot)));
            }
            Ok(Ok(None)) => {}
            _ => {
                updates.sender.send_replace(Signal::Unavailable);
            }
        }
    }
}

#[derive(PartialEq, Eq)]
struct VisibleRecord {
    activity: RecordActivity,
    version: Option<String>,
    updatable: bool,
}

type Readable = BTreeMap<(String, String), VisibleRecord>;

fn readable(database: &Database, snapshot: &Snapshot) -> anyhow::Result<Readable> {
    let mut records = Readable::new();
    let access_controlled = database.access_enabled()?;
    for (collection, activity) in &snapshot.activity {
        for (id, activity) in activity {
            let resource = AccessResource::record(collection, id);
            if !access_controlled || database.access_allowed(AccessAction::Read, &resource)? {
                records.insert(
                    (collection.clone(), id.clone()),
                    VisibleRecord {
                        activity: activity.clone(),
                        version: snapshot
                            .versions
                            .get(&(collection.clone(), id.clone()))
                            .cloned()
                            .flatten(),
                        updatable: !access_controlled
                            || database.access_allowed(AccessAction::Update, &resource)?,
                    },
                );
            }
        }
    }
    Ok(records)
}

struct Session {
    state: AppState,
    headers: HeaderMap,
    receiver: watch::Receiver<Signal>,
    readable: Option<Readable>,
    first: bool,
    finished: bool,
    authenticate: tokio::time::Interval,
}

impl Session {
    // A streaming response outlives the request's task-local identity. Resolve
    // it explicitly each time, including token revocation, suspended users,
    // and expiry of the Cloudflare assertion that opened this connection.
    async fn database(&self) -> ApiResult<Database> {
        let identity = request_identity(
            &self.state,
            &Method::GET,
            &Uri::from_static("/api/v1/events"),
            &self.headers,
        )
        .await?;
        REQUEST_IDENTITY
            .scope(identity, async {
                request_database(&self.state, &self.headers)
            })
            .await
    }
}

pub(super) async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    // Refuse invalid perspectives before committing the response's 200 status.
    request_database(&state, &headers)?;
    let receiver = state.live_updates.subscribe(state.clone());
    let session = Session {
        state,
        headers,
        receiver,
        readable: None,
        first: true,
        finished: false,
        authenticate: tokio::time::interval(Duration::from_secs(15)),
    };
    let stream = stream::unfold(session, |mut session| async move {
        loop {
            if session.finished {
                return None;
            }
            if session.first {
                session.first = false;
            } else {
                tokio::select! {
                    changed = session.receiver.changed() => {
                        if changed.is_err() { return None; }
                    }
                    _ = session.authenticate.tick() => {
                        if session.database().await.is_err() {
                            session.finished = true;
                            return Some((Ok::<_, Infallible>(Event::default().event("unavailable").data("{}")), session));
                        }
                        continue;
                    }
                }
            }
            let signal = session.receiver.borrow_and_update().clone();
            let snapshot = match signal {
                Signal::Starting => continue,
                Signal::Stopped => return None,
                Signal::Unavailable => {
                    session.finished = true;
                    return Some((
                        Ok(Event::default().event("unavailable").data("{}")),
                        session,
                    ));
                }
                Signal::Snapshot(snapshot) => snapshot,
            };
            let current = match session.database().await {
                Ok(database) => tokio::task::spawn_blocking(move || readable(&database, &snapshot))
                    .await
                    .map_err(|error| ApiError::internal(anyhow!(error)))
                    .and_then(|result| result.map_err(ApiError::from_domain)),
                Err(error) => Err(error),
            };
            let Ok(current) = current else {
                session.finished = true;
                return Some((
                    Ok(Event::default().event("unavailable").data("{}")),
                    session,
                ));
            };
            let event = match session.readable.replace(current) {
                None => Event::default().event("reset").data("{}"),
                Some(previous) => {
                    let current = session.readable.as_ref().expect("readable was replaced");
                    let collections = previous
                        .keys()
                        .chain(current.keys())
                        .filter(|key| previous.get(*key) != current.get(*key))
                        .map(|(collection, _)| collection)
                        .collect::<std::collections::BTreeSet<_>>();
                    if collections.is_empty() {
                        continue;
                    }
                    Event::default()
                        .event("change")
                        .json_data(collections)
                        .expect("string collection names serialize")
                }
            };
            return Some((Ok(event), session));
        }
    });
    use axum::response::IntoResponse as _;
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
        .headers_mut()
        .insert("x-accel-buffering", "no".parse().expect("static header"));
    Ok(response)
}
