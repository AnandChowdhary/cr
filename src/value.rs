use std::str::FromStr;

use anyhow::{bail, Context, Result};
use yaml_serde::{Mapping, Value};

#[derive(Clone, Debug, PartialEq)]
pub struct Assignment {
    path: Vec<String>,
    value: Value,
}

impl Assignment {
    pub(crate) fn apply(&self, attributes: &mut Mapping) -> Result<()> {
        set_path(attributes, &self.path, self.value.clone())
    }

    pub(crate) fn matches(&self, attributes: &Mapping) -> bool {
        get_path(attributes, &self.path) == Some(&self.value)
    }
}

impl FromStr for Assignment {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self> {
        let (key, raw_value) = input
            .split_once('=')
            .context("expected KEY=YAML (for example, stage=interview)")?;
        let path = parse_path(key)?;
        let value = if raw_value.is_empty() {
            Value::String(String::new())
        } else {
            yaml_serde::from_str(raw_value)
                .with_context(|| format!("'{raw_value}' is not a valid YAML value"))?
        };

        Ok(Self { path, value })
    }
}

pub(crate) fn parse_path(input: &str) -> Result<Vec<String>> {
    if input.is_empty() {
        bail!("field path cannot be empty");
    }

    let path: Vec<_> = input.split('.').map(str::to_owned).collect();
    if path.iter().any(|part| part.is_empty()) {
        bail!("field path '{input}' contains an empty segment");
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
    let (first, rest) = path
        .split_first()
        .context("field path must contain at least one segment")?;
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
        bail!("cannot set a nested field below non-object field '{first}'");
    };

    set_path(mapping, rest, value)
}

#[cfg(test)]
mod tests {
    use super::{parse_path, remove_path, Assignment};
    use std::str::FromStr;
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

        assert!(Assignment::from_str("metrics.score=42")
            .unwrap()
            .matches(&attributes));
        assert!(!Assignment::from_str("metrics.score=\"42\"")
            .unwrap()
            .matches(&attributes));
        assert!(!Assignment::from_str("metrics.missing=42")
            .unwrap()
            .matches(&attributes));
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
