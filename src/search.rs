use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};

use crate::{value::parse_path, Record};

/// The part of a Markdown record searched by [`SearchQuery`].
#[derive(Clone, Debug)]
pub enum SearchTarget {
    /// Search the exact Markdown file, including YAML front matter and body.
    Document,
    /// Search all parsed YAML front matter, excluding the Markdown body.
    FrontMatter,
    /// Search one front matter value selected with a dotted field path.
    Field(String),
    /// Search only the Markdown body.
    Body,
    /// Search the database-relative Markdown path.
    Path,
}

/// A compiled, reusable text query over Markdown records.
#[derive(Clone, Debug)]
pub struct SearchQuery {
    matcher: Regex,
    target: SearchTarget,
}

impl SearchQuery {
    pub fn new(
        pattern: &str,
        target: SearchTarget,
        regexp: bool,
        ignore_case: bool,
    ) -> Result<Self> {
        if let SearchTarget::Field(path) = &target {
            parse_path(path)?;
        }
        let expression = if regexp {
            pattern.to_owned()
        } else {
            regex::escape(pattern)
        };
        let matcher = RegexBuilder::new(&expression)
            .case_insensitive(ignore_case)
            .build()
            .with_context(|| format!("invalid search regular expression '{pattern}'"))?;
        Ok(Self { matcher, target })
    }

    pub(crate) fn matches(&self, record: &Record, raw_document: &str) -> Result<bool> {
        let searchable;
        let candidate = match &self.target {
            SearchTarget::Document => raw_document,
            SearchTarget::FrontMatter => {
                searchable = yaml_serde::to_string(&record.attributes)
                    .context("could not serialize front matter for search")?;
                &searchable
            }
            SearchTarget::Field(path) => {
                let Some(value) = record.field(path)? else {
                    return Ok(false);
                };
                if let yaml_serde::Value::String(value) = value {
                    return Ok(self.matcher.is_match(value));
                }
                searchable = yaml_serde::to_string(value)
                    .with_context(|| format!("could not serialize field '{path}' for search"))?;
                &searchable
            }
            SearchTarget::Body => &record.body,
            SearchTarget::Path => {
                searchable = record.path.to_string_lossy().into_owned();
                &searchable
            }
        };
        Ok(self.matcher.is_match(candidate))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use yaml_serde::Mapping;

    use super::{SearchQuery, SearchTarget};
    use crate::{Assignment, Record};

    fn record() -> Record {
        let mut attributes = Mapping::new();
        "contact.city=Amsterdam"
            .parse::<Assignment>()
            .unwrap()
            .apply(&mut attributes)
            .unwrap();
        Record {
            collection: "companies".into(),
            id: "acme".into(),
            path: PathBuf::from("records/companies/acme.md"),
            attributes,
            body: "Priority account [VIP].".into(),
        }
    }

    #[test]
    fn literals_do_not_treat_regex_characters_as_syntax() {
        let record = record();
        let query = SearchQuery::new("[VIP]", SearchTarget::Body, false, false).unwrap();
        assert!(query.matches(&record, "unused").unwrap());
    }

    #[test]
    fn regex_case_and_dotted_field_matching_are_explicit() {
        let record = record();
        let query = SearchQuery::new(
            "^amster.*$",
            SearchTarget::Field("contact.city".into()),
            true,
            true,
        )
        .unwrap();
        assert!(query.matches(&record, "unused").unwrap());

        let case_sensitive =
            SearchQuery::new("amsterdam", SearchTarget::Document, false, false).unwrap();
        assert!(!case_sensitive
            .matches(&record, "city: Amsterdam\n")
            .unwrap());
    }

    #[test]
    fn invalid_regular_expressions_are_rejected() {
        let error = SearchQuery::new("[", SearchTarget::Document, true, false).unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid search regular expression"));

        let error = SearchQuery::new("anything", SearchTarget::Field("a..b".into()), false, false)
            .unwrap_err();
        assert!(error.to_string().contains("contains an empty segment"));
    }
}
