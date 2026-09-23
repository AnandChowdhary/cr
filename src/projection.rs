//! `--select` — returning only chosen fields of each record.
//!
//! A projection is an ordered list of selectors: dotted front matter paths,
//! and `$id`, `$collection`, `$path`, `$version`, and `$body` for the parts of
//! a record that are not front matter. It turns a record into a flat object
//! keyed by the selectors as written, or into one tab-separated row, so
//! `cr list deals --select '$id,value'` is directly usable from a shell.
//!
//! A missing field is left out of the object rather than written as `null`, so
//! a projection keeps the distinction between absent and null that
//! `--filter` draws; in a row it is an empty cell.

use std::{fmt, str::FromStr};

use anyhow::Result;
use serde_json::{Map, Value as JsonValue};
use yaml_serde::Value;

use crate::{
    database::Record,
    error::invalid,
    value::{get_path, parse_path},
};

/// A parsed `--select` list.
#[derive(Clone, Debug, PartialEq)]
pub struct Projection {
    selectors: Vec<Selector>,
}

#[derive(Clone, Debug, PartialEq)]
struct Selector {
    /// The selector as written, which is also its key in the output.
    name: String,
    part: Part,
}

#[derive(Clone, Debug, PartialEq)]
enum Part {
    Field(Vec<String>),
    Id,
    Collection,
    Path,
    Version,
    Body,
}

impl Projection {
    /// Combine several `--select` values, each a comma-separated list, into
    /// one projection in the order given, without repeats.
    pub fn from_lists<S: AsRef<str>>(lists: &[S]) -> Result<Option<Self>> {
        let mut selectors: Vec<Selector> = Vec::new();
        for list in lists {
            for selector in list.as_ref().parse::<Self>()?.selectors {
                if !selectors
                    .iter()
                    .any(|existing| existing.name == selector.name)
                {
                    selectors.push(selector);
                }
            }
        }
        Ok((!selectors.is_empty()).then_some(Self { selectors }))
    }

    /// The selectors as written, in order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.selectors.iter().map(|selector| selector.name.as_str())
    }

    /// The selected parts of `record` as a flat object keyed by selector,
    /// leaving out fields the record does not have.
    pub fn object(&self, record: &Record) -> Result<Map<String, JsonValue>> {
        let mut object = Map::new();
        for selector in &self.selectors {
            if let Some(value) = selector.json(record)? {
                object.insert(selector.name.clone(), value);
            }
        }
        Ok(object)
    }

    /// The selected parts of `record` as one tab-separated line.
    ///
    /// Strings are written as they are, other values as compact JSON, and a
    /// missing field as an empty cell. Backslashes, tabs, carriage returns,
    /// and newlines inside a value are escaped as `\\`, `\t`, `\r`, and `\n`
    /// so every record stays on one line.
    pub fn row(&self, record: &Record) -> Result<String> {
        let cells = self
            .selectors
            .iter()
            .map(|selector| {
                Ok(match selector.json(record)? {
                    None => String::new(),
                    Some(JsonValue::String(text)) => escape_cell(&text),
                    Some(other) => escape_cell(&other.to_string()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(cells.join("\t"))
    }
}

impl Selector {
    fn json(&self, record: &Record) -> Result<Option<JsonValue>> {
        let text = |text: &str| Ok(Some(JsonValue::String(text.to_owned())));
        match &self.part {
            Part::Id => text(&record.id),
            Part::Collection => text(&record.collection),
            Part::Path => text(&record.path.to_string_lossy()),
            Part::Version => text(&record.version),
            Part::Body => text(&record.body),
            Part::Field(path) => get_path(&record.attributes, path)
                .map(|value| yaml_to_json(&self.name, value))
                .transpose(),
        }
    }
}

fn yaml_to_json(name: &str, value: &Value) -> Result<JsonValue> {
    serde_json::to_value(value).map_err(|error| {
        invalid(format!(
            "field '{name}' cannot be represented as JSON: {error}"
        ))
    })
}

fn escape_cell(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\t' => escaped.push_str("\\t"),
            '\r' => escaped.push_str("\\r"),
            '\n' => escaped.push_str("\\n"),
            other => escaped.push(other),
        }
    }
    escaped
}

impl FromStr for Projection {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let selectors = input
            .split(',')
            .map(str::trim)
            .map(|name| {
                let part = match name {
                    "" => {
                        return Err(invalid(format!(
                            "'{input}' has an empty selector; separate fields with single commas"
                        )));
                    }
                    "$id" => Part::Id,
                    "$collection" => Part::Collection,
                    "$path" => Part::Path,
                    "$version" => Part::Version,
                    "$body" => Part::Body,
                    _ if name.starts_with('$') => {
                        return Err(invalid(format!(
                            "'{name}' cannot be selected; the record fields are $id, $collection, $path, $version, and $body"
                        )));
                    }
                    _ => Part::Field(parse_path(name)?),
                };
                Ok(Selector {
                    name: name.to_owned(),
                    part,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { selectors })
    }
}

impl fmt::Display for Projection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.names().collect::<Vec<_>>().join(","))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use serde_json::json;
    use yaml_serde::Mapping;

    use super::Projection;
    use crate::database::Record;

    fn record() -> Record {
        Record {
            collection: "deals".to_owned(),
            id: "acme".to_owned(),
            path: PathBuf::from("records/deals/acme.md"),
            version: "sha256:abc".to_owned(),
            attributes: yaml_serde::from_str::<Mapping>(
                "name: \"Acme\\tCorp\"\nvalue: 25000\nowner:\n  name: Ada\nnotes: null\ntags: [a, b]\n",
            )
            .unwrap(),
            body: "Line one\nLine two\n".to_owned(),
        }
    }

    fn projection(lists: &[&str]) -> Projection {
        Projection::from_lists(lists).unwrap().unwrap()
    }

    #[test]
    fn objects_are_flat_keyed_by_selector_and_omit_missing_fields() {
        let object = projection(&["$id, value", "owner.name,notes,missing,tags,$collection"])
            .object(&record())
            .unwrap();
        assert_eq!(
            serde_json::Value::Object(object),
            json!({
                "$id": "acme",
                "value": 25000,
                "owner.name": "Ada",
                "notes": null,
                "tags": ["a", "b"],
                "$collection": "deals"
            })
        );
    }

    #[test]
    fn rows_escape_values_to_stay_on_one_line() {
        assert_eq!(
            projection(&["$id,name,value,missing,notes,tags,$body"])
                .row(&record())
                .unwrap(),
            "acme\tAcme\\tCorp\t25000\t\tnull\t[\"a\",\"b\"]\tLine one\\nLine two\\n"
        );
    }

    #[test]
    fn selectors_keep_their_first_position_and_reject_unknown_names() {
        assert_eq!(
            projection(&["value,$id", "$id,$version,value"]).to_string(),
            "value,$id,$version"
        );
        assert!(Projection::from_lists::<&str>(&[]).unwrap().is_none());
        let error = "$nope".parse::<Projection>().unwrap_err().to_string();
        assert!(
            error.contains("$id, $collection, $path, $version, and $body"),
            "{error}"
        );
        let error = "a,,b".parse::<Projection>().unwrap_err().to_string();
        assert!(error.contains("empty selector"), "{error}");
        assert!("a..b".parse::<Projection>().is_err());
    }
}
