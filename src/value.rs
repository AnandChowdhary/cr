use std::{cmp::Ordering, fmt, str::FromStr};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value as JsonValue, json};
use yaml_serde::{Mapping, Value};

use crate::error::{DomainError, invalid};

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Assignment {
    path: Vec<String>,
    value: Value,
}

impl Assignment {
    /// Apply this dotted-path assignment to a YAML mapping.
    pub fn apply(&self, attributes: &mut Mapping) -> Result<()> {
        set_path(attributes, &self.path, self.value.clone())
    }

    /// Whether this assignment targets a child of one top-level namespace.
    pub(crate) fn targets_nested(&self, namespace: &str) -> bool {
        self.path.len() > 1 && self.path.first().is_some_and(|part| part == namespace)
    }

    pub(crate) fn targets_field(&self, field: &str) -> bool {
        self.path.len() == 1 && self.path.first().is_some_and(|part| part == field)
    }

    pub(crate) fn matches(&self, attributes: &Mapping) -> bool {
        get_path(attributes, &self.path) == Some(&self.value)
    }

    /// A lossless JSON-shaped representation used only for request hashing.
    ///
    /// YAML values are tagged explicitly because JSON object keys cannot
    /// distinguish `true` from `"true"` and cannot represent sequence or map
    /// keys at all. Keeping the path and value separate also avoids depending
    /// on `Assignment`'s serde representation as part of the durable contract.
    pub(crate) fn idempotency_value(&self) -> Result<JsonValue> {
        Ok(json!({
            "path": self.path,
            "value": canonical_yaml_value(&self.value)?,
        }))
    }
}

/// Encode every YAML type into an unambiguous, deterministically ordered tree
/// that serde_json can serialize without treating a YAML map as a JSON object.
pub(crate) fn canonical_yaml_value(value: &Value) -> Result<JsonValue> {
    Ok(match value {
        Value::Null => json!({ "type": "null" }),
        Value::Bool(value) => json!({ "type": "bool", "value": value }),
        Value::Number(value) => {
            let kind = if value.is_i64() {
                "i64"
            } else if value.is_u64() {
                "u64"
            } else {
                "f64"
            };
            json!({ "type": "number", "kind": kind, "value": value.to_string() })
        }
        Value::String(value) => json!({ "type": "string", "value": value }),
        Value::Sequence(values) => json!({
            "type": "sequence",
            "value": values
                .iter()
                .map(canonical_yaml_value)
                .collect::<Result<Vec<_>>>()?,
        }),
        Value::Mapping(mapping) => {
            let mut entries = mapping
                .iter()
                .map(|(key, value)| {
                    let key = canonical_yaml_value(key)?;
                    let value = canonical_yaml_value(value)?;
                    let order = serde_json::to_vec(&key)
                        .context("could not canonicalize a YAML mapping key")?;
                    Ok((order, key, value))
                })
                .collect::<Result<Vec<_>>>()?;
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            json!({
                "type": "mapping",
                "value": entries
                    .into_iter()
                    .map(|(_, key, value)| json!([key, value]))
                    .collect::<Vec<_>>(),
            })
        }
        Value::Tagged(tagged) => json!({
            "type": "tagged",
            "tag": tagged.tag.to_string(),
            "value": canonical_yaml_value(&tagged.value)?,
        }),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilterOperator {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    IsEmpty,
    IsNotEmpty,
}

impl FilterOperator {
    pub fn requires_value(self) -> bool {
        !matches!(self, Self::IsEmpty | Self::IsNotEmpty)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Equal => "eq",
            Self::NotEqual => "ne",
            Self::GreaterThan => "gt",
            Self::GreaterThanOrEqual => "gte",
            Self::LessThan => "lt",
            Self::LessThanOrEqual => "lte",
            Self::Contains => "contains",
            Self::NotContains => "not-contains",
            Self::StartsWith => "starts-with",
            Self::EndsWith => "ends-with",
            Self::IsEmpty => "is-empty",
            Self::IsNotEmpty => "is-not-empty",
        }
    }
}

impl fmt::Display for FilterOperator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct FilterExpression {
    path: Vec<String>,
    operator: FilterOperator,
    value: Option<Value>,
}

impl FilterExpression {
    pub fn new(path: &str, operator: FilterOperator, raw_value: &str) -> Result<Self> {
        let path = parse_path(path)?;
        let value = if operator.requires_value() {
            Some(parse_filter_value(raw_value)?)
        } else {
            if !raw_value.trim().is_empty() {
                return Err(invalid(format!(
                    "operator '{operator}' does not accept a value"
                )));
            }
            None
        };
        Ok(Self {
            path,
            operator,
            value,
        })
    }

    pub fn operator(&self) -> FilterOperator {
        self.operator
    }

    pub fn matches(&self, attributes: &Mapping) -> bool {
        let current = get_path(attributes, &self.path);
        match self.operator {
            FilterOperator::IsEmpty => value_is_empty(current),
            FilterOperator::IsNotEmpty => !value_is_empty(current),
            FilterOperator::Equal => current == self.value.as_ref(),
            FilterOperator::NotEqual => current
                .zip(self.value.as_ref())
                .is_some_and(|(current, expected)| current != expected),
            FilterOperator::GreaterThan => self
                .ordering(current)
                .is_some_and(|ordering| ordering == Ordering::Greater),
            FilterOperator::GreaterThanOrEqual => self
                .ordering(current)
                .is_some_and(|ordering| ordering != Ordering::Less),
            FilterOperator::LessThan => self
                .ordering(current)
                .is_some_and(|ordering| ordering == Ordering::Less),
            FilterOperator::LessThanOrEqual => self
                .ordering(current)
                .is_some_and(|ordering| ordering != Ordering::Greater),
            FilterOperator::Contains => self.contains(current),
            FilterOperator::NotContains => current.is_some() && !self.contains(current),
            FilterOperator::StartsWith => {
                self.string_match(current, |current, expected| current.starts_with(expected))
            }
            FilterOperator::EndsWith => {
                self.string_match(current, |current, expected| current.ends_with(expected))
            }
        }
    }

    fn ordering(&self, current: Option<&Value>) -> Option<Ordering> {
        match (current?, self.value.as_ref()?) {
            (Value::Number(left), Value::Number(right)) => {
                number_as_f64(left).partial_cmp(&number_as_f64(right))
            }
            (Value::String(left), Value::String(right)) => Some(left.cmp(right)),
            _ => None,
        }
    }

    fn contains(&self, current: Option<&Value>) -> bool {
        match (current, self.value.as_ref()) {
            (Some(Value::String(current)), Some(Value::String(expected))) => {
                current.contains(expected)
            }
            (Some(Value::Sequence(current)), Some(expected)) => current.contains(expected),
            _ => false,
        }
    }

    fn string_match(&self, current: Option<&Value>, predicate: fn(&str, &str) -> bool) -> bool {
        match (current, self.value.as_ref()) {
            (Some(Value::String(current)), Some(Value::String(expected))) => {
                predicate(current, expected)
            }
            _ => false,
        }
    }
}

impl From<Assignment> for FilterExpression {
    fn from(assignment: Assignment) -> Self {
        Self {
            path: assignment.path,
            operator: FilterOperator::Equal,
            value: Some(assignment.value),
        }
    }
}

impl FromStr for FilterExpression {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let operators = [
            (" is-not-empty", FilterOperator::IsNotEmpty),
            (" not-contains ", FilterOperator::NotContains),
            (" starts-with ", FilterOperator::StartsWith),
            (" ends-with ", FilterOperator::EndsWith),
            (" is-empty", FilterOperator::IsEmpty),
            (" contains ", FilterOperator::Contains),
            ("!=", FilterOperator::NotEqual),
            (">=", FilterOperator::GreaterThanOrEqual),
            ("<=", FilterOperator::LessThanOrEqual),
            ("=", FilterOperator::Equal),
            (">", FilterOperator::GreaterThan),
            ("<", FilterOperator::LessThan),
        ];
        let (position, token, operator) = operators
            .iter()
            .filter_map(|(token, operator)| input.find(token).map(|position| (position, *token, *operator)))
            .min_by_key(|(position, token, _)| (*position, std::cmp::Reverse(token.len())))
            .context(DomainError::Invalid(
                "expected a filter expression such as value>=10000, name contains Acme, or owner is-empty"
                    .to_owned(),
            ))?;
        let path = input[..position].trim();
        let raw_value = input[position + token.len()..].trim();
        Self::new(path, operator, raw_value)
    }
}

fn parse_filter_value(raw_value: &str) -> Result<Value> {
    if raw_value.is_empty() {
        Ok(Value::String(String::new()))
    } else {
        yaml_serde::from_str(raw_value).with_context(|| {
            DomainError::Invalid(format!("'{raw_value}' is not a valid YAML value"))
        })
    }
}

fn value_is_empty(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(value)) => value.is_empty(),
        Some(Value::Sequence(value)) => value.is_empty(),
        Some(Value::Mapping(value)) => value.is_empty(),
        _ => false,
    }
}

fn number_as_f64(number: &yaml_serde::Number) -> f64 {
    number
        .as_i64()
        .map(|value| value as f64)
        .or_else(|| number.as_u64().map(|value| value as f64))
        .or_else(|| number.as_f64())
        .expect("YAML numbers are representable as integers or floats")
}

pub fn compare_yaml_values(left: &Value, right: &Value) -> Ordering {
    match (left, right) {
        (Value::Null, Value::Null) => Ordering::Equal,
        (Value::Bool(left), Value::Bool(right)) => left.cmp(right),
        (Value::Number(left), Value::Number(right)) => number_as_f64(left)
            .partial_cmp(&number_as_f64(right))
            .unwrap_or(Ordering::Equal),
        (Value::String(left), Value::String(right)) => left.cmp(right),
        (Value::Sequence(left), Value::Sequence(right)) => left
            .iter()
            .zip(right)
            .map(|(left, right)| compare_yaml_values(left, right))
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or_else(|| left.len().cmp(&right.len())),
        _ => value_type_rank(left)
            .cmp(&value_type_rank(right))
            .then_with(|| serialized_sort_value(left).cmp(&serialized_sort_value(right))),
    }
}

fn value_type_rank(value: &Value) -> u8 {
    match value {
        Value::Null => 0,
        Value::Bool(_) => 1,
        Value::Number(_) => 2,
        Value::String(_) => 3,
        Value::Sequence(_) => 4,
        Value::Mapping(_) => 5,
        _ => 6,
    }
}

fn serialized_sort_value(value: &Value) -> String {
    yaml_serde::to_string(value).unwrap_or_default()
}

impl FromStr for Assignment {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let (key, raw_value) = input.split_once('=').context(DomainError::Invalid(
            "expected KEY=YAML (for example, stage=interview)".to_owned(),
        ))?;
        let path = parse_path(key)?;
        let value = parse_filter_value(raw_value)?;

        Ok(Self { path, value })
    }
}

pub(crate) fn parse_path(input: &str) -> Result<Vec<String>> {
    if input.is_empty() {
        return Err(invalid("field path cannot be empty"));
    }

    let path: Vec<_> = input.split('.').map(str::to_owned).collect();
    if path.iter().any(|part| part.is_empty()) {
        return Err(invalid(format!(
            "field path '{input}' contains an empty segment"
        )));
    }
    Ok(path)
}

pub(crate) fn get_path<'a>(attributes: &'a Mapping, path: &[String]) -> Option<&'a Value> {
    let (first, rest) = path.split_first()?;
    let mut current = attributes.get(Value::String(first.clone()))?;

    for segment in rest {
        let Value::Mapping(mapping) = current else {
            return None;
        };
        current = mapping.get(Value::String(segment.clone()))?;
    }

    Some(current)
}

pub(crate) fn remove_path(attributes: &mut Mapping, path: &[String]) -> bool {
    let Some((first, rest)) = path.split_first() else {
        return false;
    };
    let key = Value::String(first.clone());
    if rest.is_empty() {
        return attributes.remove(&key).is_some();
    }
    let Some(Value::Mapping(child)) = attributes.get_mut(&key) else {
        return false;
    };
    remove_path(child, rest)
}

fn set_path(attributes: &mut Mapping, path: &[String], value: Value) -> Result<()> {
    let (first, rest) = path.split_first().context(DomainError::Invalid(
        "field path must contain at least one segment".to_owned(),
    ))?;
    let key = Value::String(first.clone());

    if rest.is_empty() {
        attributes.insert(key, value);
        return Ok(());
    }

    if !attributes.contains_key(&key) {
        attributes.insert(key.clone(), Value::Mapping(Mapping::new()));
    }

    let child = attributes.get_mut(&key).expect("field was just inserted");
    let Value::Mapping(mapping) = child else {
        return Err(invalid(format!(
            "cannot set a nested field below non-object field '{first}'"
        )));
    };

    set_path(mapping, rest, value)
}

#[cfg(test)]
mod tests {
    use super::{
        Assignment, FilterExpression, FilterOperator, canonical_yaml_value, compare_yaml_values,
        parse_path, remove_path,
    };
    use std::{cmp::Ordering, str::FromStr};
    use yaml_serde::{Mapping, Value};

    #[test]
    fn parses_typed_yaml_values() {
        assert_eq!(
            Assignment::from_str("active=true").unwrap().value,
            Value::Bool(true)
        );
        assert!(matches!(
            Assignment::from_str("score=42").unwrap().value,
            Value::Number(_)
        ));
        assert!(matches!(
            Assignment::from_str("tags=[rust, cli]").unwrap().value,
            Value::Sequence(_)
        ));
    }

    #[test]
    fn applies_dotted_paths() {
        let assignment = Assignment::from_str("contact.email=jane@example.com").unwrap();
        let mut attributes = Mapping::new();
        assignment.apply(&mut attributes).unwrap();

        assert_eq!(
            attributes["contact"]["email"],
            Value::String("jane@example.com".into())
        );
    }

    #[test]
    fn preserves_quoted_and_empty_strings_and_null() {
        assert_eq!(
            Assignment::from_str("code=\"001\"").unwrap().value,
            Value::String("001".into())
        );
        assert_eq!(
            Assignment::from_str("empty=").unwrap().value,
            Value::String(String::new())
        );
        assert_eq!(
            Assignment::from_str("nothing=null").unwrap().value,
            Value::Null
        );
    }

    #[test]
    fn rejects_invalid_assignments_and_paths() {
        assert!(Assignment::from_str("stage").is_err());
        assert!(Assignment::from_str("=interview").is_err());
        assert!(Assignment::from_str("contact..email=x").is_err());
        assert!(Assignment::from_str("tags=[").is_err());
    }

    #[test]
    fn nested_assignment_cannot_replace_a_scalar_parent() {
        let mut attributes = Mapping::new();
        attributes.insert("contact".into(), "unknown".into());
        let before = attributes.clone();

        let error = Assignment::from_str("contact.email=jane@example.com")
            .unwrap()
            .apply(&mut attributes)
            .unwrap_err();

        assert!(error.to_string().contains("below non-object"));
        assert_eq!(attributes, before);
    }

    #[test]
    fn typed_nested_filters_match_exactly() {
        let mut attributes = Mapping::new();
        Assignment::from_str("metrics.score=42")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();

        assert!(
            Assignment::from_str("metrics.score=42")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            !Assignment::from_str("metrics.score=\"42\"")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            !Assignment::from_str("metrics.missing=42")
                .unwrap()
                .matches(&attributes)
        );
    }

    #[test]
    fn filter_expressions_compare_typed_numbers_and_iso_dates() {
        let mut attributes = Mapping::new();
        Assignment::from_str("value=12000")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();
        Assignment::from_str("expected_close=2027-03-15")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();

        assert!(
            FilterExpression::from_str("value>10000")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            FilterExpression::from_str("value<=12000")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            !FilterExpression::from_str("value>12000")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            FilterExpression::from_str("expected_close<2028-01-01")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            !FilterExpression::from_str("value>\"10000\"")
                .unwrap()
                .matches(&attributes)
        );
    }

    #[test]
    fn filter_expressions_support_string_array_and_empty_operators() {
        let mut attributes = Mapping::new();
        Assignment::from_str("name=Acme annual renewal")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();
        Assignment::from_str("tags=[enterprise, renewal]")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();
        Assignment::from_str("notes=\"\"")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();

        for expression in [
            "name contains annual",
            "name starts-with Acme",
            "name ends-with renewal",
            "tags contains enterprise",
            "notes is-empty",
            "owner is-empty",
            "name is-not-empty",
            "name!=Globex",
        ] {
            assert!(
                FilterExpression::from_str(expression)
                    .unwrap()
                    .matches(&attributes),
                "filter did not match: {expression}"
            );
        }
        assert!(
            !FilterExpression::from_str("owner!=Maya")
                .unwrap()
                .matches(&attributes)
        );
        assert!(
            !FilterExpression::from_str("tags not-contains enterprise")
                .unwrap()
                .matches(&attributes)
        );
    }

    #[test]
    fn filter_expression_parsing_reports_invalid_shapes() {
        assert!(FilterExpression::from_str("value").is_err());
        assert!(FilterExpression::from_str("=100").is_err());
        assert!(FilterExpression::from_str("owner is-empty Maya").is_err());
        assert_eq!(
            FilterExpression::from_str("value>=100").unwrap().operator(),
            FilterOperator::GreaterThanOrEqual
        );
    }

    #[test]
    fn yaml_sorting_is_typed_and_deterministic() {
        assert_eq!(
            compare_yaml_values(&Value::Number(2.into()), &Value::Number(10.into())),
            Ordering::Less
        );
        assert_eq!(
            compare_yaml_values(&Value::String("10".into()), &Value::String("2".into())),
            Ordering::Less
        );
        assert_eq!(
            compare_yaml_values(
                &Value::Sequence(vec![1.into(), 2.into()]),
                &Value::Sequence(vec![1.into(), 3.into()])
            ),
            Ordering::Less
        );
        assert_eq!(
            compare_yaml_values(&Value::Bool(false), &Value::Number(0.into())),
            Ordering::Less
        );
    }

    #[test]
    fn idempotency_yaml_encoding_is_typed_and_orders_composite_keys() {
        assert_ne!(
            canonical_yaml_value(&Value::Bool(true)).unwrap(),
            canonical_yaml_value(&Value::String("true".to_owned())).unwrap()
        );

        let sequence_key = Value::Sequence(vec![Value::String("part".to_owned())]);
        let mut first = Mapping::new();
        first.insert(sequence_key.clone(), Value::Number(1.into()));
        first.insert(Value::Bool(true), Value::Number(2.into()));
        let mut second = Mapping::new();
        second.insert(Value::Bool(true), Value::Number(2.into()));
        second.insert(sequence_key, Value::Number(1.into()));

        let first = canonical_yaml_value(&Value::Mapping(first)).unwrap();
        let second = canonical_yaml_value(&Value::Mapping(second)).unwrap();
        assert_eq!(first, second);
        assert_eq!(first["type"], "mapping");
        assert!(
            first["value"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry[0]["type"] == "sequence")
        );
    }

    #[test]
    fn removes_existing_dotted_fields_without_affecting_siblings() {
        let mut attributes = Mapping::new();
        Assignment::from_str("contact.email=jane@example.com")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();
        Assignment::from_str("contact.phone=123")
            .unwrap()
            .apply(&mut attributes)
            .unwrap();

        assert!(remove_path(
            &mut attributes,
            &parse_path("contact.email").unwrap()
        ));
        assert!(!remove_path(
            &mut attributes,
            &parse_path("contact.missing").unwrap()
        ));
        assert_eq!(attributes["contact"]["phone"], Value::Number(123.into()));
    }
}
