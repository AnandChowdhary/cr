//! The server keeps the verified journal between requests, and still notices
//! when it is forged.
//!
//! `cr serve` verifies the audit chain once and afterwards only the events
//! appended since, instead of re-hashing the whole history on every page. That
//! must not cost what the hashing is for. These tests forge an event in place
//! while a server is running — the same length, the modification time put back
//! — once in the newest segment and once in one sealed long ago, and require the
//! next request to be refused, then served again once the journal is restored.
//!
//! What the cache trusts instead of re-hashing, and the narrow case it does not
//! catch, is written down beside `JournalCache` in `src/audit.rs`.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    str::FromStr,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode},
};
use cr::{
    Assignment, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn get(app: &Router, uri: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// A database whose journal starts a new segment every two events, so it has
/// segments that are sealed as well as one still being appended to.
fn database(root: &Path) -> Database {
    Database::init(root).unwrap();
    fs::write(
        root.join(".cr/config.yaml"),
        "version: 1\ndata_dir: records\naudit:\n  segment_max_events: 2\n",
    )
    .unwrap();
    Database::discover(Some(root)).unwrap()
}

fn create(database: &Database, id: &str, status: &str) {
    database
        .create(
            "deals",
            id,
            &[Assignment::from_str(&format!("status={status}")).unwrap()],
            "",
        )
        .unwrap();
}

/// Rewrite a segment in place without changing its length or its modification
/// time, which leaves the file's bytes and its change time as the only
/// evidence.
fn rewrite(path: &Path, contents: &[u8]) {
    let modified = fs::metadata(path).unwrap().modified().unwrap();
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(contents).unwrap();
    file.set_modified(modified).unwrap();
}

#[tokio::test]
async fn a_journal_forged_while_the_server_runs_is_refused_on_the_next_request() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("database");
    let database = database(&root);
    for (id, status) in [("alpha", "open"), ("beta", "open"), ("gamma", "won")] {
        create(&database, id, status);
    }
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let (status, page) = get(&app, "/deals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("/deals/records/gamma"));

    // Written behind the server's back, as the CLI would: the server verifies
    // the one new event and shows the record.
    create(&database, "delta", "open");
    let (status, page) = get(&app, "/deals").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("/deals/records/delta"));

    let segments = root.join(".cr/audit/segments");
    for (segment, which) in [
        ("00000000000000000003.jsonl", "the newest segment"),
        ("00000000000000000001.jsonl", "a sealed segment"),
    ] {
        let path = segments.join(segment);
        let original = fs::read(&path).unwrap();
        let forged = String::from_utf8(original.clone())
            .unwrap()
            .replacen("\"open\"", "\"shut\"", 1);
        assert_ne!(forged.as_bytes(), original, "{which} has nothing to forge");
        // A forgery in the same clock tick as the segment's last write could
        // keep its change time on a coarse filesystem clock; see `JournalCache`.
        std::thread::sleep(Duration::from_millis(20));
        rewrite(&path, forged.as_bytes());

        for uri in ["/deals", "/api/v1/collections/deals/records"] {
            let (status, _) = get(&app, uri).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{which}: {uri} served a forged journal"
            );
        }
        // The index is how a reader reaches the page that explains a failure,
        // so it reports one as a dash where the count would be rather than as
        // an error page of its own.
        let (status, index) = get(&app, "/?summary=inline").await;
        assert_eq!(status, StatusCode::OK, "{which}");
        assert!(
            index.contains("cr-view-count\"><span class=\"text-gray-400\">—<"),
            "{which}: the index counted a forged journal"
        );

        rewrite(&path, &original);
        let (status, page) = get(&app, "/deals").await;
        assert_eq!(status, StatusCode::OK, "{which}: not served once restored");
        assert!(page.contains("/deals/records/delta"));
    }
}
