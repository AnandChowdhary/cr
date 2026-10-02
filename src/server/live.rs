//! Browser invalidations, rather than a second API for rendering records.
//!
//! Collection subscriptions reconcile source snapshots and current permissions
//! once a second. Their reset generation closes the page/subscription race
//! without refreshing an unchanged page. Unscoped clients keep the legacy lazy
//! journal observer and latest-only watch channel. Neither feed reveals hidden
//! record identifiers or the database-wide sequence; this is a best-effort UI
//! invalidation feed rather than a durable audit subscription.

use std::{collections::BTreeMap, convert::Infallible, sync::Mutex, time::Duration};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream;
use tokio::{sync::watch, task::JoinHandle};

use super::{
    AccessAction, AccessResource, ApiError, ApiResult, AppState, Arc, Database, HeaderMap, Method,
    PoisonError, REQUEST_IDENTITY, RawQuery, Record, RecordActivity, Response, State, Uri, anyhow,
    header, json, parse_query, request_database_async, request_identity, run_metadata_database,
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
    let candidates = snapshot
        .activity
        .iter()
        .flat_map(|(collection, activity)| {
            activity
                .iter()
                .map(move |(id, activity)| (collection, id, activity))
        })
        .collect::<Vec<_>>();
    let resources = candidates
        .iter()
        .map(|(collection, id, _)| AccessResource::record(*collection, *id))
        .collect::<Vec<_>>();
    let readable = database.access_allowed_many(AccessAction::Read, &resources)?;
    let updatable = database.access_allowed_many(AccessAction::Update, &resources)?;
    let mut records = Readable::new();
    for (index, (collection, id, activity)) in candidates.into_iter().enumerate() {
        if readable[index] {
            records.insert(
                (collection.clone(), id.clone()),
                VisibleRecord {
                    activity: activity.clone(),
                    version: snapshot
                        .versions
                        .get(&(collection.clone(), id.clone()))
                        .cloned()
                        .flatten(),
                    updatable: updatable[index],
                },
            );
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
                request_database_async(&self.state, &self.headers).await
            })
            .await
    }
}

/// A MAC over this perspective's readable collection, including live
/// policies and update rights. Neither a global sequence nor hidden IDs is
/// sent to a subscriber. The page uses the same token before pagination.
pub(super) fn generation(
    database: &Database,
    collection: &str,
    records: &[Record],
    activity: &BTreeMap<String, RecordActivity>,
    secret: &str,
) -> anyhow::Result<String> {
    use base64::Engine as _;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let resources = records
        .iter()
        .map(|record| AccessResource::record(collection, &record.id))
        .collect::<Vec<_>>();
    let updatable = database.access_allowed_many(AccessAction::Update, &resources)?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts every key length");
    mac.update(b"cr:live:collection:v1\0");
    mac.update(database.current_read_policy_version(collection)?.as_bytes());
    for (record, updatable) in records.iter().zip(updatable) {
        mac.update(&serde_json::to_vec(&(
            &record.id,
            &record.version,
            activity.get(&record.id),
            updatable,
        ))?);
    }
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

#[derive(Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Subscription {
    collection: Option<String>,
}

struct ScopedSession {
    state: AppState,
    headers: HeaderMap,
    collection: String,
    generation: Option<String>,
    interval: tokio::time::Interval,
    finished: bool,
}

async fn scoped_events(
    state: AppState,
    headers: HeaderMap,
    collection: String,
) -> ApiResult<Response> {
    crate::database::validate_component(&collection, "collection")
        .map_err(ApiError::from_domain)?;
    let requested = collection.clone();
    run_metadata_database(&state, &headers, move |database| {
        if database
            .collection_models()?
            .iter()
            .any(|model| model.name == requested)
        {
            Ok(())
        } else {
            Err(crate::DomainError::view_not_found(&requested).into())
        }
    })
    .await?;
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let session = ScopedSession {
        state,
        headers,
        collection,
        generation: None,
        interval,
        finished: false,
    };
    let stream = stream::unfold(session, |mut session| async move {
        loop {
            if session.finished {
                return None;
            }
            session.interval.tick().await;
            if matches!(*session.state.live_updates.sender.borrow(), Signal::Stopped) {
                return None;
            }
            let identity = request_identity(
                &session.state,
                &Method::GET,
                &Uri::from_static("/api/v1/events"),
                &session.headers,
            )
            .await;
            let collection = session.collection.clone();
            let secret = Arc::clone(&session.state.csrf_token);
            let current = match identity {
                Ok(identity) => {
                    REQUEST_IDENTITY
                        .scope(
                            identity,
                            run_metadata_database(
                                &session.state,
                                &session.headers,
                                move |database| {
                                    let records = database.list(&collection, &[])?;
                                    if records.is_empty()
                                        && !database
                                            .collection_models()?
                                            .iter()
                                            .any(|model| model.name == collection)
                                    {
                                        return Ok(None);
                                    }
                                    let activity = database.record_activity(&collection)?;
                                    generation(database, &collection, &records, &activity, &secret)
                                        .map(Some)
                                },
                            ),
                        )
                        .await
                }
                Err(error) => Err(error),
            };
            let current = match current {
                Ok(Some(current)) => current,
                Ok(None) => {
                    session.finished = true;
                    return Some((
                        Ok::<_, Infallible>(
                            Event::default()
                                .event("change")
                                .json_data([&session.collection])
                                .expect("collection serializes"),
                        ),
                        session,
                    ));
                }
                Err(_) => {
                    session.finished = true;
                    return Some((
                        Ok::<_, Infallible>(Event::default().event("unavailable").data("{}")),
                        session,
                    ));
                }
            };
            let event = match session.generation.replace(current.clone()) {
                None => Event::default()
                    .event("reset")
                    .json_data(json!({ "generation": current }))
                    .expect("generation serializes"),
                Some(previous) if previous != current => Event::default()
                    .event("change")
                    .json_data([&session.collection])
                    .expect("collection serializes"),
                Some(_) => continue,
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

pub(super) async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> ApiResult<Response> {
    let subscription: Subscription = parse_query(raw)?;
    if let Some(collection) = subscription.collection {
        return scoped_events(state, headers, collection).await;
    }
    // Refuse invalid perspectives before committing the response's 200 status.
    request_database_async(&state, &headers).await?;
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
