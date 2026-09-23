//! `cr count` — counting records and summarizing their fields.
//!
//! An aggregation counts the records it is given and, for each field named,
//! sums and averages its numeric values and finds its smallest and largest
//! values. With a `by` field it does all of that once per distinct value of
//! that field as well. It reads front matter only, so a result never carries a
//! record body.
//!
//! `sum` and `avg` use numbers only: a value of any other type, and a missing
//! field, is skipped, so `avg` is the mean of the numbers that are there. The
//! sum of no numbers is `0` and their average `null`. `min` and `max` use every
//! present, non-null value, ordered exactly as `--sort` orders them, so they
//! work on ISO dates and names as well as numbers.

use std::cmp::Ordering;

use anyhow::Result;
use serde_json::{Map, Number as JsonNumber, Value as JsonValue, json};
use yaml_serde::Value;

use crate::{
    database::Record,
    error::invalid,
    value::{compare_yaml_values, get_path, parse_path},
};

/// What to compute over a set of records.
#[derive(Clone, Debug, Default)]
pub struct Aggregation {
    by: Option<FieldName>,
    sum: Vec<FieldName>,
    avg: Vec<FieldName>,
    min: Vec<FieldName>,
    max: Vec<FieldName>,
}

#[derive(Clone, Debug)]
struct FieldName {
    name: String,
    path: Vec<String>,
}

impl FieldName {
    fn parse(name: &str) -> Result<Self> {
        let name = name.trim();
        if name.starts_with('$') {
            return Err(invalid(format!(
                "'{name}' cannot be aggregated; name a front matter field"
            )));
        }
        Ok(Self {
            name: name.to_owned(),
            path: parse_path(name)?,
        })
    }
}

impl Aggregation {
    /// Build an aggregation from field names, each list comma-separated or
    /// given more than once.
    pub fn new<S: AsRef<str>>(
        by: Option<&str>,
        sum: &[S],
        avg: &[S],
        min: &[S],
        max: &[S],
    ) -> Result<Self> {
        let fields = |lists: &[S]| -> Result<Vec<FieldName>> {
            let mut fields: Vec<FieldName> = Vec::new();
            for list in lists {
                for name in list.as_ref().split(',') {
                    let field = FieldName::parse(name)?;
                    if !fields.iter().any(|existing| existing.name == field.name) {
                        fields.push(field);
                    }
                }
            }
            Ok(fields)
        };
        Ok(Self {
            by: by.map(FieldName::parse).transpose()?,
            sum: fields(sum)?,
            avg: fields(avg)?,
            min: fields(min)?,
            max: fields(max)?,
        })
    }

    /// Summarize `records`.
    pub fn run(&self, records: &[Record]) -> Summary {
        let total = self.metrics(records.iter());
        let groups = self.by.as_ref().map(|by| {
            let mut keys: Vec<Option<&Value>> = Vec::new();
            for record in records {
                let key = get_path(&record.attributes, &by.path);
                if !keys.contains(&key) {
                    keys.push(key);
                }
            }
            // Present values in the order `--sort` uses, and missing last.
            keys.sort_by(|left, right| match (left, right) {
                (Some(left), Some(right)) => compare_yaml_values(left, right),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            });
            keys.into_iter()
                .map(|key| Group {
                    key: key.cloned(),
                    metrics: self.metrics(
                        records
                            .iter()
                            .filter(|record| get_path(&record.attributes, &by.path) == key),
                    ),
                })
                .collect()
        });
        Summary {
            by: self.by.as_ref().map(|by| by.name.clone()),
            total,
            groups,
        }
    }

    fn metrics<'a>(&self, records: impl Iterator<Item = &'a Record> + Clone) -> Metrics {
        let values = |field: &FieldName| {
            records
                .clone()
                .filter_map(|record| get_path(&record.attributes, &field.path))
                .collect::<Vec<_>>()
        };
        let numbers = |field: &FieldName| {
            values(field)
                .into_iter()
                .filter_map(|value| match value {
                    Value::Number(number) => Some(number.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        };
        let extreme = |field: &FieldName, wanted: Ordering| {
            values(field)
                .into_iter()
                .filter(|value| !matches!(value, Value::Null))
                .reduce(|best, value| {
                    if compare_yaml_values(value, best) == wanted {
                        value
                    } else {
                        best
                    }
                })
                .cloned()
        };
        Metrics {
            count: records.clone().count(),
            sum: self
                .sum
                .iter()
                .map(|field| (field.name.clone(), sum(&numbers(field))))
                .collect(),
            avg: self
                .avg
                .iter()
                .map(|field| {
                    let numbers = numbers(field);
                    let average = (!numbers.is_empty()).then(|| {
                        numbers.iter().map(number_as_f64).sum::<f64>() / numbers.len() as f64
                    });
                    (field.name.clone(), average.and_then(JsonNumber::from_f64))
                })
                .collect(),
            min: self
                .min
                .iter()
                .map(|field| (field.name.clone(), extreme(field, Ordering::Less)))
                .collect(),
            max: self
                .max
                .iter()
                .map(|field| (field.name.clone(), extreme(field, Ordering::Greater)))
                .collect(),
        }
    }
}

/// The sum of `numbers`, exact while they are all integers.
fn sum(numbers: &[yaml_serde::Number]) -> JsonNumber {
    let integers: Option<i128> = numbers.iter().try_fold(0_i128, |total, number| {
        let value = number
            .as_i64()
            .map(i128::from)
            .or_else(|| number.as_u64().map(i128::from))?;
        total.checked_add(value)
    });
    if let Some(total) = integers {
        if let Ok(total) = i64::try_from(total) {
            return JsonNumber::from(total);
        }
        if let Ok(total) = u64::try_from(total) {
            return JsonNumber::from(total);
        }
    }
    let total: f64 = numbers.iter().map(number_as_f64).sum();
    JsonNumber::from_f64(total).unwrap_or_else(|| JsonNumber::from(0))
}

fn number_as_f64(number: &yaml_serde::Number) -> f64 {
    number
        .as_f64()
        .or_else(|| number.as_i64().map(|value| value as f64))
        .or_else(|| number.as_u64().map(|value| value as f64))
        .unwrap_or(0.0)
}

#[derive(Clone, Debug)]
struct Metrics {
    count: usize,
    sum: Vec<(String, JsonNumber)>,
    avg: Vec<(String, Option<JsonNumber>)>,
    min: Vec<(String, Option<Value>)>,
    max: Vec<(String, Option<Value>)>,
}

impl Metrics {
    fn json(&self) -> Result<Map<String, JsonValue>> {
        let mut object = Map::new();
        object.insert("count".to_owned(), json!(self.count));
        let section = |pairs: Vec<(String, JsonValue)>| -> JsonValue {
            JsonValue::Object(pairs.into_iter().collect())
        };
        if !self.sum.is_empty() {
            object.insert(
                "sum".to_owned(),
                section(
                    self.sum
                        .iter()
                        .map(|(name, total)| (name.clone(), JsonValue::Number(total.clone())))
                        .collect(),
                ),
            );
        }
        if !self.avg.is_empty() {
            object.insert(
                "avg".to_owned(),
                section(
                    self.avg
                        .iter()
                        .map(|(name, average)| {
                            (
                                name.clone(),
                                average.clone().map_or(JsonValue::Null, JsonValue::Number),
                            )
                        })
                        .collect(),
                ),
            );
        }
        for (key, extremes) in [("min", &self.min), ("max", &self.max)] {
            if !extremes.is_empty() {
                let pairs = extremes
                    .iter()
                    .map(|(name, value)| Ok((name.clone(), yaml_json(name, value.as_ref())?)))
                    .collect::<Result<Vec<_>>>()?;
                object.insert(key.to_owned(), section(pairs));
            }
        }
        Ok(object)
    }

    /// The cells after the group key, in header order.
    fn cells(&self) -> Result<Vec<String>> {
        let mut cells = vec![self.count.to_string()];
        cells.extend(self.sum.iter().map(|(_, total)| total.to_string()));
        cells.extend(self.avg.iter().map(|(_, average)| {
            average
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default()
        }));
        for extremes in [&self.min, &self.max] {
            for (name, value) in extremes {
                cells.push(cell(&yaml_json(name, value.as_ref())?));
            }
        }
        Ok(cells)
    }

    fn headers(&self) -> Vec<String> {
        let mut headers = vec!["count".to_owned()];
        for (label, names) in [
            (
                "sum",
                self.sum.iter().map(|(name, _)| name).collect::<Vec<_>>(),
            ),
            ("avg", self.avg.iter().map(|(name, _)| name).collect()),
            ("min", self.min.iter().map(|(name, _)| name).collect()),
            ("max", self.max.iter().map(|(name, _)| name).collect()),
        ] {
            headers.extend(names.into_iter().map(|name| format!("{label}({name})")));
        }
        headers
    }
}

fn yaml_json(name: &str, value: Option<&Value>) -> Result<JsonValue> {
    value.map_or(Ok(JsonValue::Null), |value| {
        serde_json::to_value(value).map_err(|error| {
            invalid(format!(
                "a value of field '{name}' cannot be represented as JSON: {error}"
            ))
        })
    })
}

/// One cell of a tab-separated table, escaped as `--select` rows are.
fn cell(value: &JsonValue) -> String {
    let text = match value {
        JsonValue::Null => return String::new(),
        JsonValue::String(text) => text.clone(),
        other => other.to_string(),
    };
    text.replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// One distinct value of the `by` field and what was computed for it.
#[derive(Clone, Debug)]
struct Group {
    /// `None` for the records that do not have the field.
    key: Option<Value>,
    metrics: Metrics,
}

/// The result of an aggregation.
#[derive(Clone, Debug)]
pub struct Summary {
    by: Option<String>,
    total: Metrics,
    groups: Option<Vec<Group>>,
}

impl Summary {
    /// The records counted.
    pub fn count(&self) -> usize {
        self.total.count
    }

    /// The whole result: the totals, and with a `by` field a `groups` list in
    /// which each group has its `value`, or `missing: true` for the records
    /// without the field.
    pub fn json(&self) -> Result<JsonValue> {
        let mut object = self.total.json()?;
        if let (Some(by), Some(groups)) = (&self.by, &self.groups) {
            object.insert("by".to_owned(), json!(by));
            let groups = groups
                .iter()
                .map(|group| {
                    let mut entry = Map::new();
                    match &group.key {
                        Some(key) => {
                            entry.insert("value".to_owned(), yaml_json(by, Some(key))?);
                        }
                        None => {
                            entry.insert("missing".to_owned(), JsonValue::Bool(true));
                        }
                    }
                    entry.extend(group.metrics.json()?);
                    Ok(JsonValue::Object(entry))
                })
                .collect::<Result<Vec<_>>>()?;
            object.insert("groups".to_owned(), JsonValue::Array(groups));
        }
        Ok(JsonValue::Object(object))
    }

    /// A tab-separated table with a header row: one row per group, or one
    /// row of totals without a `by` field. A missing group key and a missing
    /// result are empty cells.
    pub fn table(&self) -> Result<String> {
        let mut lines = Vec::new();
        match (&self.by, &self.groups) {
            (Some(by), Some(groups)) => {
                let mut header = vec![cell(&JsonValue::String(by.clone()))];
                header.extend(self.total.headers());
                lines.push(header.join("\t"));
                for group in groups {
                    let mut row = vec![match &group.key {
                        Some(key) => cell(&yaml_json(by, Some(key))?),
                        None => String::new(),
                    }];
                    row.extend(group.metrics.cells()?);
                    lines.push(row.join("\t"));
                }
            }
            _ => {
                lines.push(self.total.headers().join("\t"));
                lines.push(self.total.cells()?.join("\t"));
            }
        }
        Ok(lines.join("\n") + "\n")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;
    use yaml_serde::Mapping;

    use super::Aggregation;
    use crate::database::Record;

    fn records() -> Vec<Record> {
        [
            ("a", "stage: open\nvalue: 1000\nclose: 2027-03-01\n"),
            ("b", "stage: won\nvalue: 2500\nclose: 2026-12-01\n"),
            ("c", "stage: open\nvalue: 1.5\nclose: null\n"),
            ("d", "value: unknown\n"),
            ("e", "stage: open\n"),
        ]
        .into_iter()
        .map(|(id, front_matter)| Record {
            collection: "deals".to_owned(),
            id: id.to_owned(),
            path: PathBuf::from(format!("records/deals/{id}.md")),
            version: String::new(),
            attributes: yaml_serde::from_str::<Mapping>(front_matter).unwrap(),
            body: String::new(),
        })
        .collect()
    }

    #[test]
    fn totals_count_every_record_and_summarize_only_usable_values() {
        let aggregation =
            Aggregation::new(None, &["value"], &["value"], &["close,value"], &["close"]).unwrap();
        assert_eq!(
            aggregation.run(&records()).json().unwrap(),
            json!({
                "count": 5,
                "sum": { "value": 3501.5 },
                "avg": { "value": 1167.1666666666667 },
                "min": { "close": "2026-12-01", "value": 1.5 },
                "max": { "close": "2027-03-01" }
            })
        );
    }

    #[test]
    fn groups_follow_sort_order_with_missing_last() {
        let aggregation =
            Aggregation::new(Some("stage"), &["value"], &["value"], &[], &[]).unwrap();
        let summary = aggregation.run(&records());
        assert_eq!(
            summary.json().unwrap()["groups"],
            json!([
                { "value": "open", "count": 3, "sum": { "value": 1001.5 }, "avg": { "value": 500.75 } },
                { "value": "won", "count": 1, "sum": { "value": 2500 }, "avg": { "value": 2500.0 } },
                { "missing": true, "count": 1, "sum": { "value": 0 }, "avg": { "value": null } }
            ])
        );
        assert_eq!(
            summary.table().unwrap(),
            "stage\tcount\tsum(value)\tavg(value)\nopen\t3\t1001.5\t500.75\nwon\t1\t2500\t2500.0\n\t1\t0\t\n"
        );
    }

    #[test]
    fn integer_sums_stay_exact_and_fields_are_validated() {
        // 2^62 three times fits a u64 exactly; five times does not, and
        // becomes a float rather than wrapping.
        let sum_of = |copies: usize| {
            let big: Vec<Record> = (0..copies)
                .map(|index| Record {
                    collection: "deals".to_owned(),
                    id: index.to_string(),
                    path: PathBuf::new(),
                    version: String::new(),
                    attributes: yaml_serde::from_str::<Mapping>("value: 4611686018427387904\n")
                        .unwrap(),
                    body: String::new(),
                })
                .collect();
            Aggregation::new::<&str>(None, &["value"], &[], &[], &[])
                .unwrap()
                .run(&big)
                .json()
                .unwrap()["sum"]["value"]
                .to_string()
        };
        assert_eq!(sum_of(3), "13835058055282163712");
        assert_eq!(sum_of(5), "2.305843009213694e+19");
        assert_eq!(
            Aggregation::new::<&str>(None, &[], &[], &[], &[])
                .unwrap()
                .run(&records())
                .table()
                .unwrap(),
            "count\n5\n"
        );
        assert!(Aggregation::new::<&str>(Some("$id"), &[], &[], &[], &[]).is_err());
        assert!(Aggregation::new(None, &["a..b"], &[], &[], &[]).is_err());
    }
}
