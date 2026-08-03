use anyhow::{bail, Context, Result};
use yaml_serde::{Mapping, Value};

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

    pub fn render(&self) -> Result<String> {
        let yaml = yaml_serde::to_string(&self.attributes)
            .context("could not serialize record front matter")?;
        let yaml = yaml.strip_prefix("---\n").unwrap_or(&yaml);

        Ok(format!("---\n{}---\n{}", yaml, self.body))
    }
}

fn trim_line_ending(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

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

    #[test]
    fn round_trips_nested_and_null_values() {
        let input = "---\nactive: true\nscore: 42\nnothing: null\ntags: [rust, cli]\ncontact:\n  city: Amsterdam\n---\nBody\n";
        let first = Document::parse(input).unwrap();
        let second = Document::parse(&first.render().unwrap()).unwrap();

        assert_eq!(second.attributes, first.attributes);
        assert_eq!(second.body, "Body\n");
    }
}
