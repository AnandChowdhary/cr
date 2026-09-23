//! `cr count` — counting records and summarizing fields. The arithmetic and
//! ordering are unit-tested in `src/aggregate.rs`; these tests pin the command,
//! its filters, and its output formats.

mod common;

use common::{TestDatabase, run_failure, run_success};
use serde_json::{Value, json};

fn pipeline(name: &str) -> TestDatabase {
    let database = TestDatabase::new(name);
    for (id, fields) in [
        ("a", vec!["stage=open", "value=1000", "close=2027-03-01"]),
        ("b", vec!["stage=won", "value=2500", "close=2026-12-01"]),
        ("c", vec!["stage=open", "value=4000"]),
        ("d", vec!["value=10"]),
    ] {
        let mut command = database.command();
        command.args(["create", "deals", id]);
        for field in fields {
            command.args(["--set", field]);
        }
        run_success(&mut command);
    }
    database
}

#[test]
fn count_prints_a_table_of_totals_or_groups() {
    let database = pipeline("count-table");
    assert_eq!(
        run_success(database.command().args(["count", "deals"])),
        "count\n4\n"
    );
    assert_eq!(
        run_success(database.command().args([
            "count", "deals", "--by", "stage", "--sum", "value", "--avg", "value", "--min",
            "close",
        ])),
        "stage\tcount\tsum(value)\tavg(value)\tmin(close)\nopen\t2\t5000\t2500.0\t2027-03-01\nwon\t1\t2500\t2500.0\t2026-12-01\n\t1\t10\t10.0\t\n"
    );
    assert_eq!(
        run_success(database.command().args(["count", "nothing"])),
        "count\n0\n"
    );
}

#[test]
fn count_json_marks_the_missing_group_and_applies_filters() {
    let database = pipeline("count-json");
    let summary: Value = serde_json::from_str(&run_success(database.command().args([
        "count",
        "deals",
        "--filter",
        "value >= 1000",
        "--by",
        "stage",
        "--sum",
        "value",
        "--max",
        "close,value",
        "--json",
    ])))
    .unwrap();
    assert_eq!(
        summary,
        json!({
            "count": 3,
            "by": "stage",
            "sum": { "value": 7500 },
            "max": { "close": "2027-03-01", "value": 4000 },
            "groups": [
                { "value": "open", "count": 2, "sum": { "value": 5000 }, "max": { "close": "2027-03-01", "value": 4000 } },
                { "value": "won", "count": 1, "sum": { "value": 2500 }, "max": { "close": "2026-12-01", "value": 2500 } }
            ]
        })
    );
    let with_missing: Value = serde_json::from_str(&run_success(database.command().args([
        "count",
        "deals",
        "--where-expr",
        "value<100",
        "--by",
        "stage",
        "--json",
    ])))
    .unwrap();
    assert_eq!(
        with_missing["groups"],
        json!([{ "missing": true, "count": 1 }])
    );
}

#[test]
fn count_refuses_fields_it_cannot_aggregate() {
    let database = pipeline("count-refusals");
    let error = run_failure(database.command().args(["count", "deals", "--by", "$id"]));
    assert!(error.contains("name a front matter field"), "{error}");
    let error = run_failure(database.command().args(["count", "deals", "--sum", "a..b"]));
    assert!(error.contains("a..b"), "{error}");
}
