//! `GET /ready`: whether a server can answer requests that read its database.
//!
//! `/health` only says the process is running. Readiness says whether the
//! database behind it is usable right now, cheaply and without waiting: the
//! directory is reachable, the configuration loads, no interrupted mutation or
//! sync run is waiting for recovery, and the verified journal the server keeps
//! is still continued by the newest event on disk.
//!
//! Every test here drives a real failure a probe must notice — a mutation
//! interrupted by the fault injection in `tests/common/fault.rs`, a sync run
//! stopped partway, a configuration edited into something `cr` cannot load, a
//! journal that lost its head — and requires that the answer names the check
//! and a stable code and nothing else, then that it recovers. A probe is public,
//! so no answer may carry a path, a record, a sync, or a count.

mod common;

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::{TestDatabase, fault::FaultDatabase, run_failure, run_success};
use cr::{
    Assignment, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

/// Every check, in the order a `503` lists them.
const CHECKS: [&str; 5] = [
    "database",
    "config",
    "audit_recovery",
    "sync_recovery",
    "journal",
];

/// Every code a failing check may carry.
const CODES: [&str; 10] = [
    "database_unreachable",
    "config_invalid",
    "pending_mutation",
    "audit_recovery_unreadable",
    "interrupted_sync_run",
    "sync_recovery_unreadable",
    "journal_warming",
    "journal_unverified",
    "journal_changed",
    "journal_unreadable",
];

struct Answer {
    status: StatusCode,
    request_id: Option<String>,
    text: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap()
    }

    /// `(name, code)` of every failing check.
    fn failures(&self) -> Vec<(String, String)> {
        self.json()["checks"]
            .as_array()
            .map(|checks| {
                checks
                    .iter()
                    .filter(|check| check["ok"] == false)
                    .map(|check| {
                        (
                            check["name"].as_str().unwrap().to_owned(),
                            check["code"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_ready(&self) {
        assert_eq!(self.status, StatusCode::OK, "{}", self.text);
        assert_eq!(self.json(), json!({ "status": "ready" }));
    }

    /// Not ready because of exactly one check, every other one listed as
    /// passing, and nothing in the answer but names, codes, and the request ID.
    fn assert_not_ready(&self, name: &str, code: &str, root: &Path) {
        assert_eq!(
            self.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "{}",
            self.text
        );
        let body = self.json();
        assert_eq!(body["status"], "not_ready");
        assert_eq!(
            self.failures(),
            vec![(name.to_owned(), code.to_owned())],
            "{}",
            self.text
        );
        let checks = body["checks"].as_array().unwrap();
        let names = checks
            .iter()
            .map(|check| check["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(names, CHECKS, "every check runs, in order");
        for check in checks {
            let fields = check.as_object().unwrap();
            let allowed = if check["ok"] == true {
                &["name", "ok"][..]
            } else {
                &["name", "ok", "code"][..]
            };
            assert!(
                fields.keys().all(|key| allowed.contains(&key.as_str())),
                "a check says more than its name and code: {check}"
            );
            if let Some(code) = check["code"].as_str() {
                assert!(CODES.contains(&code), "undocumented code {code}");
            }
        }
        assert_eq!(
            body["request_id"].as_str(),
            self.request_id.as_deref(),
            "the answer names the request its log lines are under"
        );
        assert_private(&self.text, root);
    }
}

/// Nothing about where the database lives, or what is in it, reaches a probe.
fn assert_private(text: &str, root: &Path) {
    assert!(!text.contains(root.to_str().unwrap()), "{text}");
    for fragment in ["/", "\\", ".cr", ".json", "records", "segment", "os error"] {
        assert!(!text.contains(fragment), "{fragment:?} in {text}");
    }
}

async fn request(app: &Router, method: Method, uri: &str) -> Answer {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let request_id = response
        .headers()
        .get("x-request-id")
        .map(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Answer {
        status,
        request_id,
        text: String::from_utf8(body.to_vec()).unwrap(),
    }
}

async fn probe(app: &Router) -> Answer {
    request(app, Method::GET, "/ready").await
}

/// Probe until the journal has finished its first walk, and return the first
/// answer that is not `journal_warming`.
async fn settled(app: &Router) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let answer = probe(app).await;
        let warming = answer
            .failures()
            .iter()
            .any(|(_, code)| code == "journal_warming");
        if !warming {
            return answer;
        }
        assert!(
            Instant::now() < deadline,
            "the journal never finished warming"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Probe until the server is not ready, for an answer that depends on a lock
/// being free.
///
/// A lock belongs to an open file, and a child that another test thread is
/// spawning shares every open file with this process until it execs. So a
/// lock this process has just released, or one a probe took for an instant,
/// can stay held for that instant, and the probe rightly takes the pending
/// file or ledger for the holder's.
async fn once_unlocked(app: &Router) -> Answer {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let answer = probe(app).await;
        if answer.status != StatusCode::OK {
            return answer;
        }
        assert!(Instant::now() < deadline, "still ready: {}", answer.text);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn app(root: &Path) -> Router {
    router(
        Database::discover(Some(root)).unwrap(),
        ServerConfig::default(),
    )
    .unwrap()
}

/// Take a lock the way a `cr` process inside that section holds it.
fn hold(path: &Path) -> File {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    lock.lock().unwrap();
    lock
}

#[tokio::test]
async fn a_healthy_database_is_ready_once_its_journal_is_verified() {
    let database = TestDatabase::new("ready-healthy");
    run_success(
        database
            .command()
            .args(["create", "deals", "acme", "--set", "status=open"]),
    );
    // Public like `/health`, even where every other route needs a token: a
    // load balancer's probe cannot attach one.
    let app = router(
        Database::discover(Some(database.root())).unwrap(),
        ServerConfig {
            api_token: Some("secret-token".into()),
            ..ServerConfig::default()
        },
    )
    .unwrap();
    assert_eq!(
        request(&app, Method::GET, "/deals").await.status,
        StatusCode::UNAUTHORIZED
    );

    // Nothing has verified the journal yet, so the first probe starts the
    // walk `cr serve` would have started when it began listening, and says so.
    let first = probe(&app).await;
    first.assert_not_ready("journal", "journal_warming", database.root());
    let ready = settled(&app).await;
    ready.assert_ready();
    assert!(ready.request_id.is_some());

    // `/health` is liveness and is unchanged.
    let health = request(&app, Method::GET, "/health").await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json(), json!({ "status": "ok" }));

    let wrong_method = request(&app, Method::POST, "/ready").await;
    assert_eq!(wrong_method.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn a_pending_mutation_is_not_ready_until_something_recovers_it() {
    let database = FaultDatabase::new("ready-pending");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=screening"]),
    );
    let app = app(database.root());
    settled(&app).await.assert_ready();

    // A `cr` process stopped after writing its record and before appending
    // the event, as a crash there would.
    database.interrupt(
        "items",
        "one",
        &["update", "items", "one", "--set", "stage=won"],
    );
    assert!(database.read_pending().is_some());
    let not_ready = once_unlocked(&app).await;
    not_ready.assert_not_ready("audit_recovery", "pending_mutation", database.root());
    assert!(!not_ready.text.contains("items"), "{}", not_ready.text);

    // Every mutation writes that file while it holds the audit lock, so while
    // somebody holds the lock the file is theirs, not an interruption. The
    // probe does not wait for the lock to find out.
    let lock = hold(&database.root().join(".cr/audit/lock"));
    probe(&app).await.assert_ready();
    drop(lock);
    once_unlocked(&app).await.assert_not_ready(
        "audit_recovery",
        "pending_mutation",
        database.root(),
    );

    // Readiness never recovers anything itself. The next request that reads
    // the journal does, as it always has.
    assert!(database.read_pending().is_some());
    let head = request(&app, Method::GET, "/api/v1/audit/head").await;
    assert_eq!(head.status, StatusCode::OK, "{}", head.text);
    assert_eq!(head.json()["sequence"], 2);
    assert!(database.read_pending().is_none());
    probe(&app).await.assert_ready();
}

#[tokio::test]
async fn a_configuration_cr_cannot_load_is_not_ready() {
    let database = TestDatabase::new("ready-config");
    let app = app(database.root());
    settled(&app).await.assert_ready();

    // `cr init` writes no configuration, and none means the defaults.
    let config = database.root().join(".cr/config.yaml");
    assert!(!config.exists());
    // The server keeps the last configuration that loaded, so it could go on
    // answering; the next `cr` command, and the next start, could not.
    for (contents, why) in [
        ("version: [\n", "not YAML"),
        ("version: 2\ndata_dir: records\n", "an unsupported format"),
        (
            "version: 1\ndata_dir: records\nsurprise: true\n",
            "an unknown key",
        ),
        (
            "version: 1\ndata_dir: records\naudit:\n  segment_max_events: 0\n",
            "an invalid limit",
        ),
    ] {
        fs::write(&config, contents).unwrap();
        let answer = probe(&app).await;
        answer.assert_not_ready("config", "config_invalid", database.root());
        assert!(!answer.text.contains("YAML"), "{why}: {}", answer.text);
    }

    fs::write(&config, "version: 1\ndata_dir: records\n").unwrap();
    probe(&app).await.assert_ready();
    fs::remove_file(&config).unwrap();
    probe(&app).await.assert_ready();
}

#[tokio::test]
async fn an_interrupted_sync_run_is_not_ready_until_it_is_recovered() {
    let database = TestDatabase::new("ready-sync");
    let scripts = database.root().join("scripts");
    fs::create_dir_all(&scripts).unwrap();
    fs::write(
        scripts.join("partial.sh"),
        r#"#!/bin/sh
printf '%s\n' '{"type":"upsert","collection":"notes","id":"first","front_matter":{"n":1},"markdown":"first\n"}'
printf '%s\n' '{"type":"upsert","collection":"blocked","id":"second","front_matter":{"n":2},"markdown":"second\n"}'
printf '%s\n' '{"type":"checkpoint","state":{"cursor":"page-2"}}'
"#,
    )
    .unwrap();
    run_success(database.command().args([
        "sync",
        "create",
        "partial",
        "--",
        "sh",
        "scripts/partial.sh",
    ]));
    let app = app(database.root());
    settled(&app).await.assert_ready();

    // A regular file where the `blocked` collection directory has to go makes
    // the second operation fail after the first has been committed, which
    // leaves the run's ledger behind.
    fs::create_dir_all(database.root().join("records")).unwrap();
    fs::write(database.root().join("records/blocked"), "").unwrap();
    run_failure(database.command().args(["sync", "run", "partial"]));
    fs::remove_file(database.root().join("records/blocked")).unwrap();

    let not_ready = once_unlocked(&app).await;
    not_ready.assert_not_ready("sync_recovery", "interrupted_sync_run", database.root());
    assert!(!not_ready.text.contains("partial"), "{}", not_ready.text);

    // A run keeps its ledger on disk while it applies, holding the sync
    // application lock. While somebody holds it, the ledger may be theirs.
    let lock = hold(&database.root().join(".cr/sync/locks/application.lock"));
    probe(&app).await.assert_ready();
    drop(lock);
    once_unlocked(&app).await.assert_not_ready(
        "sync_recovery",
        "interrupted_sync_run",
        database.root(),
    );

    run_success(database.command().args(["sync", "recover", "partial"]));
    probe(&app).await.assert_ready();
}

/// A database whose journal starts a new segment every two events.
fn segmented(root: &Path) -> Database {
    Database::init(root).unwrap();
    fs::write(
        root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\naudit:\n  segment_max_events: 2\n",
    )
    .unwrap();
    let database = Database::discover(Some(root)).unwrap();
    for id in ["alpha", "beta", "gamma"] {
        database
            .create(
                "deals",
                id,
                &[Assignment::from_str("status=open").unwrap()],
                "",
            )
            .unwrap();
    }
    database
}

/// Rewrite a file in place without changing its length or modification time.
fn rewrite(path: &Path, contents: &[u8]) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(contents).unwrap();
    file.set_modified(modified).unwrap();
}

#[tokio::test]
async fn the_journal_is_ready_while_the_newest_event_continues_the_verified_walk() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("database");
    let database = segmented(&root);
    let app = router(database, ServerConfig::default()).unwrap();
    settled(&app).await.assert_ready();

    let segments = root.join(".cr/audit/segments");
    let newest = segments.join("00000000000000000003.jsonl");
    let sealed = segments.join("00000000000000000001.jsonl");
    let newest_bytes = fs::read(&newest).unwrap();
    let sealed_bytes = fs::read(&sealed).unwrap();

    // The journal lost the head this server verified.
    fs::remove_file(&newest).unwrap();
    probe(&app)
        .await
        .assert_not_ready("journal", "journal_changed", &root);
    fs::write(&newest, &newest_bytes).unwrap();
    probe(&app).await.assert_ready();

    // Its newest event cannot be read.
    let mut damaged = newest_bytes.clone();
    damaged.extend_from_slice(b"not an event\n");
    fs::write(&newest, &damaged).unwrap();
    probe(&app)
        .await
        .assert_not_ready("journal", "journal_unreadable", &root);
    fs::write(&newest, &newest_bytes).unwrap();
    probe(&app).await.assert_ready();

    // Events appended by another process since are not an inconsistency: the
    // next reader verifies them.
    let appender = Database::discover(Some(&root)).unwrap();
    appender
        .create(
            "deals",
            "delta",
            &[Assignment::from_str("status=open").unwrap()],
            "",
        )
        .unwrap();
    probe(&app).await.assert_ready();

    // A forgery below the head is the next read's to find, not a probe's,
    // because finding it means reading every segment. Once a read has, the
    // walk is gone and the probe says so rather than walking it again.
    std::thread::sleep(Duration::from_millis(20));
    let forged = String::from_utf8(sealed_bytes.clone())
        .unwrap()
        .replacen("\"open\"", "\"shut\"", 1);
    rewrite(&sealed, forged.as_bytes());
    probe(&app).await.assert_ready();
    let page = request(&app, Method::GET, "/deals").await;
    assert_eq!(page.status, StatusCode::INTERNAL_SERVER_ERROR);
    probe(&app)
        .await
        .assert_not_ready("journal", "journal_unverified", &root);

    rewrite(&sealed, &sealed_bytes);
    let page = request(&app, Method::GET, "/deals").await;
    assert_eq!(page.status, StatusCode::OK);
    probe(&app).await.assert_ready();
}

#[tokio::test]
async fn an_unreachable_database_directory_is_the_only_answer() {
    let database = TestDatabase::new("ready-unreachable");
    let app = app(database.root());
    settled(&app).await.assert_ready();

    let moved = database.root().with_file_name("moved-aside");
    fs::rename(database.root().join(".cr"), &moved).unwrap();
    let answer = probe(&app).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    // Every other check reads beneath it, and would only repeat the failure,
    // or pass because what it looks for is absent.
    assert_eq!(
        answer.json()["checks"],
        json!([{ "name": "database", "ok": false, "code": "database_unreachable" }])
    );
    assert_private(&answer.text, database.root());
    // A probe creates nothing, so it cannot paper over what it reported.
    assert!(!database.root().join(".cr").exists());

    fs::rename(&moved, database.root().join(".cr")).unwrap();
    probe(&app).await.assert_ready();
}
