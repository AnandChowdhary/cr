//! An update that changes nothing records nothing.
//!
//! A `cr update`, REST `PATCH` or `PUT`, or record form save whose result is
//! byte for byte the record it read — front matter, Markdown, and a bundle's
//! supporting files — appends no audit event and writes no file, not even the
//! saved walk. It answers exactly as a recorded update would, with the current
//! record and its version, and it is refused for everything a recorded update
//! is refused for. A keyed update is the exception: its event is what lets a
//! retry return the original result, so it is still recorded.

mod common;

use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use axum::{
    Router,
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use common::{TestDatabase, run_failure, run_success};
use cr::{
    Assignment, Database,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

/// Every file in the database, with its inode, so a file rewritten with the
/// bytes it already had still counts as written.
fn snapshot(root: &Path) -> BTreeMap<PathBuf, (u64, Vec<u8>)> {
    fn collect(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, (u64, Vec<u8>)>) {
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(root, &path, files);
            } else {
                let relative = path.strip_prefix(root).unwrap().to_path_buf();
                let inode = fs::metadata(&path).unwrap().ino();
                files.insert(relative, (inode, fs::read(&path).unwrap()));
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

fn json(command: &mut Command) -> Value {
    serde_json::from_str(&run_success(command)).unwrap()
}

fn head(database: &TestDatabase) -> u64 {
    json(database.command().args(["audit", "head", "--json"]))["sequence"]
        .as_u64()
        .unwrap()
}

#[test]
fn an_unchanged_update_writes_nothing_and_answers_like_a_recorded_one() {
    let database = TestDatabase::new("unchanged-update");
    run_success(database.command().args([
        "create",
        "items",
        "one",
        "--set",
        "stage=open",
        "--set",
        "owner.name=Ada",
        "--body",
        "Notes\n",
    ]));
    // A recorded update first, so the saved walk exists and is what an
    // unchanged update would rewrite.
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=screening"]),
    );
    let current = json(database.command().args(["get", "items", "one", "--json"]));
    let before = snapshot(&database.root);
    assert!(before.contains_key(Path::new(".cr/cache/verified-journal.json")));

    for arguments in [
        &["--set", "stage=screening"][..],
        &["--set", "owner.name=Ada", "--body", "Notes\n"],
        // A message describes a change; alone it is not one.
        &["--set", "stage=screening", "--message", "Still screening"],
        &[
            "--set",
            "stage=screening",
            "--expected-record-hash",
            current["version"].as_str().unwrap(),
        ],
    ] {
        let answer = json(
            database
                .command()
                .args(["update", "items", "one"])
                .args(arguments)
                .arg("--json"),
        );
        assert_eq!(answer, current, "{arguments:?}");
        assert_eq!(snapshot(&database.root), before, "{arguments:?}");
    }
    let text = run_success(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=screening",
    ]));
    assert_eq!(text.trim(), "items/one");
    assert_eq!(snapshot(&database.root), before);
    assert_eq!(head(&database), 2);

    // A preview of it still describes the empty change set it would be.
    let preview = json(database.command().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=screening",
        "--preview",
        "--json",
    ]));
    assert_eq!(preview["changes"], json!([]));
    assert_eq!(preview["before_hash"], preview["after_hash"]);

    // An update that changes something is recorded as it always was.
    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=won"]),
    );
    assert_eq!(head(&database), 3);
    let log = json(
        database
            .command()
            .args(["audit", "log", "items", "one", "--json"]),
    );
    assert_eq!(log[0]["action"], "update");
    assert_eq!(log[0]["changes"][0]["path"], "/attributes/stage");
    assert_ne!(snapshot(&database.root), before);
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn an_unchanged_update_is_refused_for_everything_a_recorded_one_is() {
    let database = TestDatabase::new("unchanged-refusals");
    let owner = |command: &mut Command| {
        command.env("CR_ACTOR", "Owner <owner@example.com>");
    };
    let mut command = database.command();
    owner(&mut command);
    run_success(command.args([
        "access",
        "init",
        "--name",
        "Owner",
        "--email",
        "owner@example.com",
    ]));
    let as_owner = || {
        let mut command = database.command();
        owner(&mut command);
        command
    };
    run_success(as_owner().args(["create", "items", "one", "--set", "stage=open"]));
    let stale = json(as_owner().args(["get", "items", "one", "--json"]))["version"]
        .as_str()
        .unwrap()
        .to_owned();
    run_success(as_owner().args(["update", "items", "one", "--set", "stage=won"]));
    run_success(as_owner().args([
        "user",
        "add",
        "reader@example.com",
        "--name",
        "Reader",
        "--email",
        "reader@example.com",
    ]));
    run_success(as_owner().args([
        "access",
        "grant",
        "reader@example.com",
        "viewer",
        "collection:items",
    ]));
    let before = snapshot(&database.root);

    let failure = run_failure(as_owner().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=won",
        "--expected-record-hash",
        &stale,
    ]));
    assert!(
        failure.contains("record items/one changed since the expected version"),
        "{failure}"
    );
    assert_eq!(snapshot(&database.root), before);

    let failure = run_failure(as_owner().args([
        "update",
        "items",
        "one",
        "--set",
        "stage=won",
        "--authorization",
        "interactive",
        "--approved-changes",
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    ]));
    assert!(
        failure.contains("record items/one does not match the approved change set"),
        "{failure}"
    );
    assert_eq!(snapshot(&database.root), before);

    // A signing key a recorded update could not sign with refuses this too.
    let failure = run_failure(
        as_owner()
            .env("CR_AUDIT_SIGNING_KEY", database.root.join("missing.key"))
            .args(["update", "items", "one", "--set", "stage=won"]),
    );
    assert!(
        failure.contains("CR_AUDIT_SIGNING_KEY could not be used"),
        "{failure}"
    );
    assert_eq!(snapshot(&database.root), before);

    let mut reader = database.command();
    reader.env("CR_ACTOR", "Reader <reader@example.com>");
    let failure = run_failure(reader.args(["update", "items", "one", "--set", "stage=won"]));
    assert!(
        failure.contains("cannot update record:items/one"),
        "{failure}"
    );
    assert_eq!(snapshot(&database.root), before);

    // A record edited outside `cr` is not its audited state, and an update
    // that would leave it as it is does not launder it.
    let path = database.root.join("records/items/one.md");
    let edited = fs::read_to_string(&path).unwrap().replace("won", "lost");
    fs::write(&path, edited).unwrap();
    let before = snapshot(&database.root);
    let failure = run_failure(as_owner().args(["update", "items", "one", "--set", "stage=lost"]));
    assert!(
        failure.contains("record items/one does not match its latest audited state"),
        "{failure}"
    );
    assert_eq!(snapshot(&database.root), before);
}

#[test]
fn a_keyed_unchanged_update_is_recorded_so_its_retry_returns_the_same_result() {
    const KEY: &str = "unchanged-retry-key-0001";
    let database = TestDatabase::new("unchanged-keyed");
    run_success(
        database
            .command()
            .args(["create", "items", "one", "--set", "stage=open"]),
    );
    let keyed = [
        "update",
        "items",
        "one",
        "--set",
        "stage=open",
        "--idempotency-key",
        KEY,
        "--json",
    ];
    let first = json(database.command().args(keyed));
    assert_eq!(head(&database), 2);
    let log = json(
        database
            .command()
            .args(["audit", "log", "items", "one", "--json"]),
    );
    assert_eq!(log[0]["changes"], json!([]));
    assert_eq!(log[0]["before_hash"], log[0]["after_hash"]);
    assert_eq!(log[0]["idempotency"]["result"]["version"], first["version"]);

    run_success(
        database
            .command()
            .args(["update", "items", "one", "--set", "stage=won"]),
    );
    assert_eq!(head(&database), 3);

    // The retry answers with the original result and changes nothing, rather
    // than setting the stage back.
    let retry = json(database.command().args(keyed));
    assert_eq!(retry, first);
    assert_eq!(head(&database), 3);
    let current = json(database.command().args(["get", "items", "one", "--json"]));
    assert_eq!(current["attributes"]["stage"], "won");
    run_success(database.command().args(["audit", "verify"]));
}

#[test]
fn an_unchanged_bundle_update_writes_nothing_and_a_changed_file_still_records() {
    let database = TestDatabase::new("unchanged-bundle");
    fs::write(
        database.root.join(".cr/config.yaml"),
        "version: 1\ncollections:\n  skills:\n    layout: bundle\n    entry: SKILL.md\n",
    )
    .unwrap();
    let sources = database.root.join("sources");
    fs::create_dir_all(&sources).unwrap();
    let same = sources.join("same.py");
    let other = sources.join("other.py");
    fs::write(&same, "print('hi')\n").unwrap();
    fs::write(&other, "print('bye')\n").unwrap();
    let file = |source: &Path| format!("scripts/run.py={}", source.display());
    run_success(database.command().args([
        "create",
        "skills",
        "pdf",
        "--set",
        "name=pdf",
        "--file",
        &file(&same),
    ]));
    let current = json(database.command().args(["get", "skills", "pdf", "--json"]));
    let before = snapshot(&database.root);

    let answer = json(database.command().args([
        "update",
        "skills",
        "pdf",
        "--set",
        "name=pdf",
        "--file",
        &file(&same),
        "--json",
    ]));
    assert_eq!(answer, current);
    assert_eq!(snapshot(&database.root), before);
    assert_eq!(head(&database), 1);

    run_success(
        database
            .command()
            .args(["update", "skills", "pdf", "--file", &file(&other)]),
    );
    assert_eq!(head(&database), 2);
    run_success(database.command().args(["audit", "verify"]));
}

async fn send(app: &Router, method: Method, uri: &str, body: Option<(&str, String)>) -> Response {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match body {
        Some((content_type, body)) => {
            builder = builder.header(header::CONTENT_TYPE, content_type);
            body
        }
        None => String::new(),
    };
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let etag = response
        .headers()
        .get(header::ETAG)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Response {
        status,
        etag,
        body: String::from_utf8(body.to_vec()).unwrap(),
    }
}

struct Response {
    status: StatusCode,
    etag: Option<String>,
    body: String,
}

fn form_field<'a>(html: &'a str, name: &str) -> &'a str {
    let marker = format!("name=\"{name}\" value=\"");
    let rest = html
        .split_once(&marker)
        .unwrap_or_else(|| panic!("{name} missing from HTML:\n{html}"))
        .1;
    rest.split_once('"').unwrap().0
}

#[tokio::test]
async fn unchanged_patch_put_and_form_saves_write_nothing() {
    let temporary = tempfile::tempdir().unwrap();
    let database = Database::init(temporary.path().join("unchanged-http")).unwrap();
    database
        .create(
            "items",
            "one",
            &[Assignment::from_str("stage=open").unwrap()],
            "First",
        )
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let uri = "/api/v1/collections/items/records/one";
    let current = send(&app, Method::GET, uri, None).await;
    let etag = current.etag.clone().unwrap();
    let before = snapshot(database.root());

    let patched = send(
        &app,
        Method::PATCH,
        uri,
        Some((
            "application/json",
            json!({ "front_matter": { "stage": "open" } }).to_string(),
        )),
    )
    .await;
    assert_eq!(patched.status, StatusCode::OK, "{}", patched.body);
    assert_eq!(patched.body, current.body);
    assert_eq!(patched.etag.as_deref(), Some(etag.as_str()));
    assert_eq!(snapshot(database.root()), before);

    let replacement = json!({ "front_matter": { "stage": "open" }, "markdown": "First" });
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::IF_MATCH, &etag)
        .body(Body::from(replacement.to_string()))
        .unwrap();
    let replaced = app.clone().oneshot(request).await.unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);
    assert_eq!(replaced.headers()[header::ETAG], etag.as_str());
    assert_eq!(snapshot(database.root()), before);

    let page = send(&app, Method::GET, "/items/records/one", None).await;
    let saved = send(
        &app,
        Method::POST,
        "/items/records/one",
        Some((
            "application/x-www-form-urlencoded",
            form_urlencoded::Serializer::new(String::new())
                .append_pair("_csrf", form_field(&page.body, "_csrf"))
                .append_pair(
                    "_expected_record_hash",
                    form_field(&page.body, "_expected_record_hash"),
                )
                .append_pair("front_matter", "stage: open\n")
                .append_pair("markdown", "First")
                .finish(),
        )),
    )
    .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    assert_eq!(snapshot(database.root()), before);

    // A stale version is refused although nothing would change.
    request = Request::builder()
        .method(Method::PATCH)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::IF_MATCH,
            "\"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
        )
        .body(Body::from(
            json!({ "front_matter": { "stage": "open" } }).to_string(),
        ))
        .unwrap();
    let stale = app.clone().oneshot(request).await.unwrap();
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(snapshot(database.root()), before);
    assert_eq!(database.audit_head().unwrap().sequence, 1);

    // And a PATCH that changes something is recorded.
    let changed = send(
        &app,
        Method::PATCH,
        uri,
        Some((
            "application/json",
            json!({ "front_matter": { "stage": "won" } }).to_string(),
        )),
    )
    .await;
    assert_eq!(changed.status, StatusCode::OK, "{}", changed.body);
    assert_eq!(database.audit_head().unwrap().sequence, 2);
}
