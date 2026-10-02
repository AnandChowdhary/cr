//! Streaming invalidations include external commits, but never hidden records.

use std::{str::FromStr, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use cr::{
    AccessResource, Assignment, Database, Role, UserKind, ViewLayout,
    server::{ServerConfig, router},
};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn connect(app: &Router, headers: &[(&str, &str)]) -> Body {
    let mut request = Request::builder().uri("/api/v1/events");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    response.into_body()
}

async fn event(body: &mut Body) -> String {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let frame = body.frame().await.expect("stream ended").unwrap();
            if let Ok(data) = frame.into_data() {
                let text = String::from_utf8(data.to_vec()).unwrap();
                if text.contains("event:") {
                    return text;
                }
            }
        }
    })
    .await
    .expect("no event arrived")
}

fn changed(text: &str) -> Vec<String> {
    assert!(text.contains("event: change"), "{text}");
    let data = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    serde_json::from_str(data).unwrap()
}

fn create(database: &Database, collection: &str, id: &str) {
    database
        .create(
            collection,
            id,
            &[Assignment::from_str("status=open").unwrap()],
            "",
        )
        .unwrap();
}

#[tokio::test]
async fn external_creates_updates_deletes_and_reconnects_refresh_both_subscribers() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path()).unwrap();
    create(&database, "tasks", "one");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let mut first = connect(&app, &[]).await;
    let mut second = connect(&app, &[]).await;
    assert!(event(&mut first).await.contains("event: reset"));
    assert!(event(&mut second).await.contains("event: reset"));

    // An independently discovered database behaves like a separate CLI writer.
    let external = Database::discover(Some(temp.path())).unwrap();
    create(&external, "tasks", "two");
    assert_eq!(changed(&event(&mut first).await), ["tasks"]);
    assert_eq!(changed(&event(&mut second).await), ["tasks"]);
    external
        .update(
            "tasks",
            "one",
            &[Assignment::from_str("status=done").unwrap()],
            None,
        )
        .unwrap();
    assert_eq!(changed(&event(&mut first).await), ["tasks"]);
    assert_eq!(changed(&event(&mut second).await), ["tasks"]);
    external.delete("tasks", "two").unwrap();
    assert_eq!(changed(&event(&mut first).await), ["tasks"]);
    assert_eq!(changed(&event(&mut second).await), ["tasks"]);
    drop(first);
    drop(second);
    create(&external, "tasks", "missed");
    let mut reconnected = connect(&app, &[("last-event-id", "old-cursor")]).await;
    assert!(event(&mut reconnected).await.contains("event: reset"));
}

#[tokio::test]
async fn hidden_changes_are_silent_and_revoked_visibility_invalidates_existing_results() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path())
        .unwrap()
        .with_actor("Owner <owner@example.com>")
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    create(&database, "tasks", "public");
    create(&database, "tasks", "secret");
    database
        .add_user(
            "reader@example.com",
            "Reader",
            Some("reader@example.com"),
            UserKind::Human,
        )
        .unwrap();
    let resource = AccessResource::record("tasks", "public");
    database
        .grant_access("reader@example.com", resource.clone(), Role::Viewer)
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let mut body = connect(&app, &[("cookie", "cr_perspective=reader%40example.com")]).await;
    assert!(event(&mut body).await.contains("event: reset"));
    database
        .update(
            "tasks",
            "secret",
            &[Assignment::from_str("status=hidden-change").unwrap()],
            None,
        )
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1400), body.frame())
            .await
            .is_err(),
        "a hidden change emitted an event"
    );
    database
        .update(
            "tasks",
            "public",
            &[Assignment::from_str("status=done").unwrap()],
            None,
        )
        .unwrap();
    let update = event(&mut body).await;
    assert_eq!(changed(&update), ["tasks"]);
    assert!(
        !update.contains("public") && !update.contains("secret") && !update.contains("sequence")
    );
    // A viewer becoming an editor changes controls even when the record's
    // contents and read permission stay the same.
    database
        .grant_access("reader@example.com", resource.clone(), Role::Editor)
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
    database
        .revoke_access("reader@example.com", &resource)
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
}

#[tokio::test]
async fn filesystem_edits_are_not_accepted_or_announced_until_explicitly_saved() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path()).unwrap();
    create(&database, "tasks", "one");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let mut body = connect(&app, &[]).await;
    assert!(event(&mut body).await.contains("event: reset"));
    let file = temp.path().join("records/tasks/one.md");
    let original = std::fs::read_to_string(&file).unwrap();
    std::fs::write(file, format!("{original}\nHand-edited note\n")).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1400), body.frame())
            .await
            .is_err()
    );
    assert_eq!(database.audit_head().unwrap().sequence, 1);
    database
        .save(&["tasks/one".to_owned()], false, Some("Reviewed edit"))
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
}

#[tokio::test]
async fn revoked_tokens_terminate_the_feed_and_cannot_reconnect() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path())
        .unwrap()
        .with_actor("Owner <owner@example.com>")
        .unwrap();
    database
        .initialize_access(Some("Owner"), Some("owner@example.com"))
        .unwrap();
    let (token, _) = database
        .issue_token("owner@example.com", None, None)
        .unwrap();
    let app = router(
        database.clone(),
        ServerConfig {
            require_token: true,
            ..ServerConfig::default()
        },
    )
    .unwrap();
    let authorization = format!("Bearer {}", token.token.as_str());
    let mut body = connect(&app, &[("authorization", &authorization)]).await;
    assert!(event(&mut body).await.contains("event: reset"));
    database
        .revoke_token("owner@example.com", &token.stored.id)
        .unwrap();
    assert!(event(&mut body).await.contains("event: unavailable"));
    assert!(body.frame().await.is_none());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/events")
                .header("authorization", authorization)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn result_fragments_keep_the_live_subscription_metadata() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path()).unwrap();
    create(&database, "tasks", "one");
    database
        .create_view_with_layout(
            "board",
            Some("Tasks"),
            "tasks",
            vec![],
            vec![],
            25,
            ViewLayout::Kanban,
            Some("status".to_owned()),
        )
        .unwrap();
    let app = router(database, ServerConfig::default()).unwrap();
    for uri in ["/tasks", "/board"] {
        for fragment in [false, true] {
            let mut request = Request::builder().uri(uri);
            if fragment {
                request = request
                    .header("hx-request", "true")
                    .header("hx-target", "cr-view-table");
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let html = String::from_utf8(body.to_vec()).unwrap();
            assert!(html.contains("data-live-collection=\"tasks\""));
            assert!(html.contains("data-live-key=\""));
            if !fragment {
                assert!(html.contains("data-live-status=\"true\" hidden"));
            }
        }
    }
}

async fn connect_scoped(app: &Router, collection: &str, headers: &[(&str, &str)]) -> Body {
    let mut request = Request::builder().uri(format!("/api/v1/events?collection={collection}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body()
}

#[tokio::test]
async fn scoped_resets_match_the_page_and_detect_unaudited_content_and_renames() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path()).unwrap();
    create(&database, "tasks", "one");
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    let generation = page
        .split("data-live-generation=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let mut body = connect_scoped(&app, "tasks", &[]).await;
    let reset = event(&mut body).await;
    let data: serde_json::Value = serde_json::from_str(
        reset
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["generation"], generation);
    create(&database, "unrelated", "other");
    assert!(
        tokio::time::timeout(Duration::from_millis(1200), body.frame())
            .await
            .is_err()
    );
    // Exact reconciliation notices even an edit that restores its modification
    // timestamp and never updates the audit head.
    let file = temp.path().join("records/tasks/one.md");
    let modified = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::fs::write(&file, "---\nstatus: hand-edited\n---\nDirect note").unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
    assert_eq!(database.audit_head().unwrap().sequence, 2);
    std::fs::rename(&file, temp.path().join("records/tasks/renamed.md")).unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/tasks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let page = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(page.contains("/tasks/records/renamed"));
    assert!(!page.contains("/tasks/records/one\""));
}

#[tokio::test]
async fn scoped_subscriptions_refuse_hidden_collections_and_keep_hidden_updates_silent() {
    let temp = tempfile::tempdir().unwrap();
    let database = Database::init(temp.path())
        .unwrap()
        .with_actor("Owner <owner@example.com>")
        .unwrap();
    database.initialize_access(None, None).unwrap();
    database
        .add_user("reader@example.com", "Reader", None, UserKind::Human)
        .unwrap();
    create(&database, "tasks", "public");
    create(&database, "tasks", "secret");
    create(&database, "hidden", "hidden");
    let resource = AccessResource::record("tasks", "public");
    database
        .grant_access("reader@example.com", resource.clone(), Role::Viewer)
        .unwrap();
    let app = router(database.clone(), ServerConfig::default()).unwrap();
    let cookie = "cr_perspective=reader%40example.com";
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/events?collection=hidden")
                .header("cookie", cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::NOT_FOUND);
    let mut body = connect_scoped(&app, "tasks", &[("cookie", cookie)]).await;
    assert!(event(&mut body).await.contains("event: reset"));
    database
        .update("tasks", "secret", &["status=hidden".parse().unwrap()], None)
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1200), body.frame())
            .await
            .is_err()
    );
    database
        .grant_access("reader@example.com", resource.clone(), Role::Editor)
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
    database
        .revoke_access("reader@example.com", &resource)
        .unwrap();
    assert_eq!(changed(&event(&mut body).await), ["tasks"]);
    assert!(body.frame().await.is_none());
}
