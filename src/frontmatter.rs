use anyhow::{Context, Result, bail};
use yaml_serde::{Mapping, Value};

use crate::error::invalid;

#[derive(Clone, Debug)]
pub(crate) struct Document {
    pub attributes: Mapping,
    pub body: String,
}

impl Document {
    pub fn parse(input: &str) -> Result<Self> {
        let mut lines = input.split_inclusive('\n');
        let first = lines.next().context("record is empty")?;
        if trim_line_ending(first) != "---" {
            bail!("record must begin with a YAML front matter delimiter ('---')");
        }

        let yaml_start = first.len();
        let mut offset = yaml_start;

        for line in lines {
            if trim_line_ending(line) == "---" {
                let yaml = &input[yaml_start..offset];
                let attributes = if yaml.trim().is_empty() {
                    Mapping::new()
                } else {
                    match yaml_serde::from_str::<Value>(yaml)
                        .context("front matter is not valid YAML")?
                    {
                        Value::Mapping(mapping) => mapping,
                        _ => bail!("front matter must be a YAML mapping"),
                    }
                };

                return Ok(Self {
                    attributes,
                    body: input[offset + line.len()..].to_owned(),
                });
            }

            offset += line.len();
        }

        bail!("record is missing its closing front matter delimiter ('---')")
    }

    /// Write the document as Markdown, refusing front matter whose YAML would
    /// not read back as exactly these attributes.
    pub fn render(&self) -> Result<String> {
        let yaml = yaml_serde::to_string(&self.attributes)
            .context("could not serialize record front matter")?;
        let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);
        // The emitter ends a literal block scalar whose last line break is a
        // line or paragraph separator (U+2028, U+2029) with that character
        // rather than '\n'. YAML reads either as a line break, but the
        // delimiter search reads only '\n', so the closing delimiter would
        // share the YAML's last line. The added break is a trailing empty line,
        // which the scalar's default clipping drops.
        let line_end = if yaml.ends_with('\n') { "" } else { "\n" };
        let rendered = format!("---\n{yaml}{line_end}---\n{}", self.body);

        // The emitter also writes a few strings that hold those separators
        // beside other line breaks in a form that reads back as a different
        // string. Refusing them here is better than writing a record whose
        // front matter changes, or stops parsing, the next time it is read.
        match Self::parse(&rendered) {
            Ok(reparsed)
                if reparsed.attributes == self.attributes && reparsed.body == self.body =>
            {
                Ok(rendered)
            }
            _ => Err(invalid(
                "front matter holds a string YAML cannot store exactly, such as one ending in a line or paragraph separator (U+2028, U+2029) after other line breaks",
            )),
        }
    }

    pub fn from_audit_value(value: &serde_json::Value) -> Result<Self> {
        let object = value
            .as_object()
            .context("audited document state is not an object")?;
        if object.len() != 2 || !object.contains_key("attributes") || !object.contains_key("body") {
            bail!("audited document state must contain only attributes and body");
        }
        let attributes = serde_json::from_value(object["attributes"].clone())
            .context("audited front matter cannot be decoded")?;
        let body = object["body"]
            .as_str()
            .context("audited Markdown body is not a string")?
            .to_owned();
        Ok(Self { attributes, body })
    }
}

fn trim_line_ending(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

#[cfg(test)]
mod properties;

#[cfg(test)]
mod tests {
    use super::Document;
    use yaml_serde::Value;

    #[test]
    fn round_trip_preserves_the_markdown_body() {
        let input = "---\r\nname: Jane\r\nstage: screen\r\n---\r\n# Jane\n\nNotes.\n";
        let document = Document::parse(input).unwrap();

        assert_eq!(document.attributes["stage"], Value::String("screen".into()));
        assert_eq!(document.body, "# Jane\n\nNotes.\n");

        let rendered = document.render().unwrap();
        assert!(rendered.starts_with("---\nname: Jane\nstage: screen\n---\n"));
        assert!(rendered.ends_with("# Jane\n\nNotes.\n"));
    }

    #[test]
    fn rejects_content_without_front_matter() {
        let error = Document::parse("# Just Markdown\n").unwrap_err();
        assert!(error.to_string().contains("must begin"));
    }

    #[test]
    fn supports_empty_front_matter_and_a_delimiter_in_the_body() {
        let input = "---\n---\n# Note\n\n---\nThis is body content.\n";
        let document = Document::parse(input).unwrap();

        assert!(document.attributes.is_empty());
        assert_eq!(document.body, "# Note\n\n---\nThis is body content.\n");
    }

    #[test]
    fn supports_a_closing_delimiter_at_end_of_file() {
        let document = Document::parse("---\nname: Empty body\n---").unwrap();
        assert_eq!(
            document.attributes["name"],
            Value::String("Empty body".into())
        );
        assert!(document.body.is_empty());
    }

    #[test]
    fn rejects_non_mapping_front_matter() {
        let error = Document::parse("---\n- one\n- two\n---\n").unwrap_err();
        assert!(error.to_string().contains("must be a YAML mapping"));
    }

    #[test]
    fn rejects_a_missing_closing_delimiter() {
        let error = Document::parse("---\nname: Jane\n").unwrap_err();
        assert!(error.to_string().contains("missing its closing"));
    }

    /// Found by `properties::generated_documents_round_trip_exactly`. The
    /// emitter ended the YAML with the separator instead of '\n', so the
    /// closing delimiter was written onto the value's last line and the
    /// document could not be read back.
    #[test]
    fn a_value_ending_in_a_line_separator_after_a_line_break_keeps_the_delimiter_on_its_own_line() {
        for separator in ['\u{2028}', '\u{2029}'] {
            let mut document = Document::parse("---\n---\nBody\n").unwrap();
            let value = format!("first\nsecond{separator}");
            document
                .attributes
                .insert("notes".into(), Value::String(value.clone()));
            let rendered = document.render().unwrap();
            assert!(rendered.ends_with(&format!("{separator}\n---\nBody\n")));
            let parsed = Document::parse(&rendered).unwrap();
            assert_eq!(parsed.attributes["notes"], Value::String(value));
            assert_eq!(parsed.body, "Body\n");
        }
    }

    /// The emitter writes this string in a form that reads back as a different
    /// one, so it is refused as invalid input rather than stored changed.
    #[test]
    fn a_value_with_a_line_separator_after_two_line_breaks_is_refused_as_invalid() {
        let mut document = Document::parse("---\n---\n").unwrap();
        document
            .attributes
            .insert("notes".into(), Value::String("first\n\n\u{2028}".into()));
        let error = document.render().unwrap_err();
        assert!(
            matches!(
                crate::DomainError::of(&error),
                Some(crate::DomainError::Invalid(_))
            ),
            "{error:#}"
        );
        assert!(error.to_string().contains("U+2028"), "{error}");
    }

    #[test]
    fn round_trips_nested_and_null_values() {
        let input = "---\nactive: true\nscore: 42\nnothing: null\ntags: [rust, cli]\ncontact:\n  city: Amsterdam\n---\nBody\n";
        let first = Document::parse(input).unwrap();
        let second = Document::parse(&first.render().unwrap()).unwrap();

        assert_eq!(second.attributes, first.attributes);
        assert_eq!(second.body, "Body\n");
    }
}
