//! `--sort` with several keys on `list`, `search`, and `backlinks`. The
//! comparison itself is unit-tested in `src/sort.rs`; these tests pin the
//! command-line spelling, the one-key `--desc` it keeps working, and the
//! refusals.

mod common;

use serde_json::Value;

use common::{TestDatabase, run_failure, run_success};

fn ids(output: &str) -> Vec<String> {
    output
        .lines()
        .map(|line| {
            let path = line.split('\t').next().unwrap();
            path.rsplit('/')
                .next()
                .unwrap()
                .trim_end_matches(".md")
                .to_owned()
        })
        .collect()
}

/// Deals with ties on every field and gaps in each: two open deals of 20000
/// and two of 5000, one won deal without a value, one deal without a stage,
/// and owners on some.
fn pipeline(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    run_success(database.command().args(["create", "companies", "acme"]));
    for (id, fields) in [
        ("a", vec!["stage=won", "value=5000", "owner=ada"]),
        ("b", vec!["stage=open", "value=20000", "owner=ada"]),
        ("c", vec!["stage=open", "value=5000"]),
        ("d", vec!["stage=open", "value=20000", "owner=bo"]),
        ("e", vec!["stage=won"]),
        ("f", vec!["value=100"]),
        ("g", vec!["stage=open", "value=5000", "owner=ada"]),
    ] {
        let mut command = database.command();
        command.args(["create", "deals", id]);
        for field in fields {
            command.args(["--set", field]);
        }
        run_success(&mut command);
        run_success(
            database
                .command()
                .args(["link", "deals", id, "company", "companies", "acme"]),
        );
    }
    database
}

fn list(database: &TestDatabase, sort: &[&str]) -> Vec<String> {
    let mut command = database.command();
    command.args(["list", "deals"]).args(sort);
    ids(&run_success(&mut command))
}

#[test]
fn keys_are_compared_in_order_with_missing_values_last_and_ids_breaking_ties() {
    let database = pipeline("sort-keys");

    // Two keys: the value orders each stage, and the ID orders equal values.
    assert_eq!(
        list(&database, &["--sort", "stage", "--sort", "value:desc"]),
        ["b", "d", "c", "g", "a", "e", "f"]
    );
    // Comma-separated is the same sort as repeated.
    assert_eq!(
        list(&database, &["--sort", "stage,value:desc"]),
        list(&database, &["--sort", "stage", "--sort", "value:desc"])
    );
    // A third key orders what the first two leave tied, and a record without
    // it follows those with it.
    assert_eq!(
        list(&database, &["--sort", "stage,value:desc,owner"]),
        ["b", "d", "g", "c", "a", "e", "f"]
    );
    // Mixed directions, with missing values last in the descending key too.
    assert_eq!(
        list(&database, &["--sort", "stage:desc", "--sort", "owner:desc"]),
        ["a", "e", "d", "b", "g", "c", "f"]
    );
    assert_eq!(
        list(&database, &["--sort", "value", "--sort", "stage:DESC"]),
        ["f", "a", "c", "g", "b", "d", "e"]
    );
    // The record keys sort too, and an explicit :asc is the default.
    assert_eq!(
        list(&database, &["--sort", "stage:asc", "--sort", "$id:desc"]),
        ["g", "d", "c", "b", "e", "a", "f"]
    );

    let json: Value = serde_json::from_str(&run_success(database.command().args([
        "list",
        "deals",
        "--sort",
        "stage,value:desc",
        "--select",
        "$id",
        "--json",
    ])))
    .unwrap();
    assert_eq!(json[0]["$id"], "b");
    assert_eq!(json[6]["$id"], "f");
}

#[test]
fn a_single_key_sorts_as_it_always_did() {
    let database = pipeline("sort-single");
    let descending = ["b", "d", "a", "c", "g", "f", "e"];
    assert_eq!(list(&database, &["--sort", "value", "--desc"]), descending);
    assert_eq!(list(&database, &["--sort", "value:desc"]), descending);
    assert_eq!(list(&database, &["--sort=value", "--desc"]), descending);
    assert_eq!(
        list(&database, &["--sort", "value"]),
        ["f", "a", "c", "g", "b", "d", "e"]
    );
    // Without --sort the order is the collection's own.
    assert_eq!(list(&database, &[]), ["a", "b", "c", "d", "e", "f", "g"]);
}

#[test]
fn search_and_backlinks_take_the_same_keys() {
    let database = pipeline("sort-search");
    let searched = run_success(database.command().args([
        "search",
        "deals",
        "--path",
        "--sort",
        "stage",
        "--sort",
        "value:desc",
    ]));
    assert_eq!(ids(&searched), ["b", "d", "c", "g", "a", "e", "f"]);

    let backlinks = run_success(database.command().args([
        "backlinks",
        "companies",
        "acme",
        "--sort",
        "stage:desc,owner:desc",
    ]));
    assert_eq!(ids(&backlinks), ["a", "e", "d", "b", "g", "c", "f"]);
    assert!(backlinks.lines().all(|line| line.ends_with("\tcompany")));
}

#[test]
fn ambiguous_duplicate_and_excess_keys_are_refused() {
    let database = pipeline("sort-refused");
    let refused = |arguments: &[&str]| -> Value {
        let mut command = database.command();
        command
            .args(["list", "deals", "--json-errors"])
            .args(arguments);
        let stderr = run_failure(&mut command);
        let error: Value = serde_json::from_str(stderr.trim()).unwrap_or_else(|error| {
            panic!("{arguments:?} did not fail with a JSON error: {error}\n{stderr}")
        });
        assert_eq!(error["error"]["code"], "validation_failed", "{arguments:?}");
        error
    };
    let message = |arguments: &[&str]| -> String {
        refused(arguments)["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned()
    };

    // --desc means one key descending; with more, or with a key that already
    // says its direction, it could mean several things.
    for arguments in [
        &["--sort", "stage", "--sort", "value", "--desc"][..],
        &["--sort", "stage,value", "--desc"],
        &["--sort", "value:asc", "--desc"],
    ] {
        assert!(
            message(arguments).starts_with("--desc applies only to a single sort key"),
            "{arguments:?}"
        );
    }
    assert_eq!(
        message(&["--sort", "a,b,c,d,e,f"]),
        "a sort can have at most 5 keys, not 6"
    );
    assert_eq!(
        message(&["--sort", "value", "--sort", "value:desc"]),
        "sort field 'value' is given more than once"
    );
    assert_eq!(
        message(&["--sort=-value"]),
        "sort key '-value' starts with '-'; write 'value:desc' to sort descending"
    );
    assert_eq!(
        message(&["--sort", "stage,,value"]),
        "sort field cannot be empty"
    );
    assert!(message(&["--sort", "stage,owner..email"]).contains("empty segment"));
    assert!(message(&["--sort", "stage,$created_at"]).contains("comes from audit history"));

    // Five keys are allowed.
    assert_eq!(
        list(&database, &["--sort", "stage,value:desc,owner,$path,$id"]),
        ["b", "d", "g", "c", "a", "e", "f"]
    );
}
