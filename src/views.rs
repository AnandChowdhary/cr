use std::{collections::BTreeMap, fs, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    database::{validate_component, write_new},
    value::parse_path,
    Assignment, Database, SortDirection,
};

const VIEW_FORMAT_VERSION: u32 = 1;
const DEFAULT_VIEW_PAGE_SIZE: usize = 50;
const MAX_VIEW_PAGE_SIZE: usize = 1_000;
const MAX_VIEW_FILTER_GROUPS: usize = 20;
const MAX_VIEW_GROUP_EXPRESSIONS: usize = 20;
const RESERVED_VIEW_NAMES: &[&str] = &["api", "audit", "health", "openapi.json"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ViewDefinition {
    pub name: String,
    pub version: u32,
    pub title: String,
    pub collection: String,
    pub filters: Vec<String>,
    pub where_expr: Vec<String>,
    pub filter_groups: Vec<ViewFilterGroup>,
    pub columns: Vec<String>,
    pub layout: ViewLayout,
    pub group_by: Option<String>,
    pub sort_by: Option<String>,
    pub sort_direction: SortDirection,
    pub page_size: usize,
    pub saved: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewLayout {
    #[default]
    Table,
    Kanban,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ViewPredicateMatch {
    #[default]
    All,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ViewFilterGroup {
    #[serde(default, rename = "match")]
    pub match_mode: ViewPredicateMatch,
    pub expressions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredViewDefinition {
    version: u32,
    title: String,
    collection: String,
    #[serde(default)]
    filters: Vec<String>,
    #[serde(default)]
    where_expr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    filter_groups: Vec<ViewFilterGroup>,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    layout: ViewLayout,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sort_by: Option<String>,
    #[serde(default, skip_serializing_if = "is_ascending")]
    sort_direction: SortDirection,
    #[serde(default = "default_page_size")]
    page_size: usize,
}

impl Database {
    pub fn create_view(
        &self,
        name: &str,
        title: Option<&str>,
        collection: &str,
        filters: Vec<String>,
        columns: Vec<String>,
        page_size: usize,
    ) -> Result<ViewDefinition> {
        self.create_view_with_layout(
            name,
            title,
            collection,
            filters,
            columns,
            page_size,
            ViewLayout::Table,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_view_with_layout(
        &self,
        name: &str,
        title: Option<&str>,
        collection: &str,
        filters: Vec<String>,
        columns: Vec<String>,
        page_size: usize,
        layout: ViewLayout,
        group_by: Option<String>,
    ) -> Result<ViewDefinition> {
        self.create_view_with_options(
            name,
            title,
            collection,
            filters,
            Vec::new(),
            Vec::new(),
            columns,
            page_size,
            layout,
            group_by,
            None,
            SortDirection::Asc,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_view_with_options(
        &self,
        name: &str,
        title: Option<&str>,
        collection: &str,
        filters: Vec<String>,
        where_expr: Vec<String>,
        filter_groups: Vec<ViewFilterGroup>,
        columns: Vec<String>,
        page_size: usize,
        layout: ViewLayout,
        group_by: Option<String>,
        sort_by: Option<String>,
        sort_direction: SortDirection,
    ) -> Result<ViewDefinition> {
        validate_view_name(name)?;
        validate_component(collection, "collection")?;
        let title = title.unwrap_or(name).trim();
        if title.is_empty() {
            bail!("view title cannot be empty");
        }

        let stored = StoredViewDefinition {
            version: VIEW_FORMAT_VERSION,
            title: title.to_owned(),
            collection: collection.to_owned(),
            filters,
            where_expr,
            filter_groups,
            columns,
            layout,
            group_by,
            sort_by,
            sort_direction,
            page_size,
        };
        validate_stored(name, &stored)?;

        let path = self.view_path(name);
        let serialized = yaml_serde::to_string(&stored).context("could not serialize view")?;
        write_new(&path, serialized.as_bytes())
            .with_context(|| format!("could not create view '{name}'"))?;
        Ok(to_public(name, stored, true))
    }

    pub fn view(&self, name: &str) -> Result<ViewDefinition> {
        validate_component(name, "view")?;
        let path = self.view_path(name);
        if path.exists() {
            return self.read_view(name);
        }

        if self
            .collection_models()?
            .into_iter()
            .any(|model| model.name == name)
        {
            return Ok(automatic_view(name));
        }
        bail!("view '{name}' does not exist")
    }

    pub fn views(&self) -> Result<Vec<ViewDefinition>> {
        let mut views: BTreeMap<String, ViewDefinition> = self
            .collection_models()?
            .into_iter()
            .filter(|model| !RESERVED_VIEW_NAMES.contains(&model.name.as_str()))
            .map(|model| {
                let name = model.name;
                (name.clone(), automatic_view(&name))
            })
            .collect();

        let directory = self.root().join(".cr/views");
        let metadata = match fs::symlink_metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(views.into_values().collect())
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("could not inspect view directory {}", directory.display())
                })
            }
        };
        if !metadata.file_type().is_dir() {
            bail!("view path {} must be a directory", directory.display());
        }

        let mut names = Vec::new();
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("could not read view directory {}", directory.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_file()
                || entry.path().extension().and_then(|value| value.to_str()) != Some("yaml")
            {
                continue;
            }
            let name = entry
                .path()
                .file_stem()
                .and_then(|value| value.to_str())
                .context("view filename is not valid UTF-8")?
                .to_owned();
            validate_view_name(&name)?;
            names.push(name);
        }
        names.sort();
        for name in names {
            views.insert(name.clone(), self.read_view(&name)?);
        }
        Ok(views.into_values().collect())
    }

    fn read_view(&self, name: &str) -> Result<ViewDefinition> {
        validate_view_name(name)?;
        let path = self.view_path(name);
        let metadata =
            fs::symlink_metadata(&path).with_context(|| format!("view '{name}' does not exist"))?;
        if !metadata.file_type().is_file() {
            bail!("view path {} must be a regular file", path.display());
        }
        let serialized =
            fs::read_to_string(&path).with_context(|| format!("could not read view '{name}'"))?;
        let stored: StoredViewDefinition = yaml_serde::from_str(&serialized)
            .with_context(|| format!("view '{name}' is not valid YAML"))?;
        validate_stored(name, &stored)?;
        Ok(to_public(name, stored, true))
    }

    fn view_path(&self, name: &str) -> PathBuf {
        self.root().join(".cr/views").join(format!("{name}.yaml"))
    }
}

fn validate_view_name(name: &str) -> Result<()> {
    validate_component(name, "view")?;
    if RESERVED_VIEW_NAMES.contains(&name) {
        bail!("view name '{name}' is reserved by the HTTP server");
    }
    Ok(())
}

fn validate_stored(name: &str, view: &StoredViewDefinition) -> Result<()> {
    if view.version != VIEW_FORMAT_VERSION {
        bail!(
            "view '{name}' uses unsupported format version {} (expected {})",
            view.version,
            VIEW_FORMAT_VERSION
        );
    }
    if view.title.trim().is_empty() {
        bail!("view '{name}' title cannot be empty");
    }
    validate_component(&view.collection, "collection")?;
    if !(1..=MAX_VIEW_PAGE_SIZE).contains(&view.page_size) {
        bail!("view '{name}' page_size must be between 1 and {MAX_VIEW_PAGE_SIZE}");
    }
    for filter in &view.filters {
        Assignment::from_str(filter)
            .with_context(|| format!("view '{name}' has invalid filter '{filter}'"))?;
    }
    for expression in &view.where_expr {
        crate::FilterExpression::from_str(expression)
            .with_context(|| format!("view '{name}' has invalid where_expr '{expression}'"))?;
    }
    if view.filter_groups.len() > MAX_VIEW_FILTER_GROUPS {
        bail!("view '{name}' can contain at most {MAX_VIEW_FILTER_GROUPS} filter groups");
    }
    for (index, group) in view.filter_groups.iter().enumerate() {
        if group.expressions.is_empty() {
            bail!("view '{name}' filter group {} cannot be empty", index + 1);
        }
        if group.expressions.len() > MAX_VIEW_GROUP_EXPRESSIONS {
            bail!(
                "view '{name}' filter group {} can contain at most {MAX_VIEW_GROUP_EXPRESSIONS} expressions",
                index + 1
            );
        }
        for expression in &group.expressions {
            crate::FilterExpression::from_str(expression).with_context(|| {
                format!(
                    "view '{name}' filter group {} has invalid expression '{expression}'",
                    index + 1
                )
            })?;
        }
    }
    for column in &view.columns {
        parse_path(column)
            .with_context(|| format!("view '{name}' has invalid column '{column}'"))?;
    }
    match (view.sort_by.as_deref(), view.sort_direction) {
        (None, SortDirection::Desc) => {
            bail!("view '{name}' sort_direction requires sort_by")
        }
        (Some(field), _) if field.trim().is_empty() => {
            bail!("view '{name}' sort_by cannot be empty")
        }
        (Some(field), _) if !matches!(field, "$id" | "$collection" | "$path") => {
            parse_path(field)
                .with_context(|| format!("view '{name}' has invalid sort_by field '{field}'"))?;
        }
        _ => {}
    }
    match (view.layout, view.group_by.as_deref()) {
        (ViewLayout::Table, Some(_)) => {
            bail!("view '{name}' group_by is only valid for the kanban layout")
        }
        (ViewLayout::Kanban, None) => {
            bail!("view '{name}' using the kanban layout requires group_by")
        }
        (ViewLayout::Kanban, Some(field)) => {
            parse_path(field)
                .with_context(|| format!("view '{name}' has invalid group_by field '{field}'"))?;
        }
        (ViewLayout::Table, None) => {}
    }
    Ok(())
}

fn automatic_view(collection: &str) -> ViewDefinition {
    ViewDefinition {
        name: collection.to_owned(),
        version: VIEW_FORMAT_VERSION,
        title: collection.replace(['-', '_'], " "),
        collection: collection.to_owned(),
        filters: Vec::new(),
        where_expr: Vec::new(),
        filter_groups: Vec::new(),
        columns: Vec::new(),
        layout: ViewLayout::Table,
        group_by: None,
        sort_by: None,
        sort_direction: SortDirection::Asc,
        page_size: DEFAULT_VIEW_PAGE_SIZE,
        saved: false,
    }
}

fn to_public(name: &str, stored: StoredViewDefinition, saved: bool) -> ViewDefinition {
    ViewDefinition {
        name: name.to_owned(),
        version: stored.version,
        title: stored.title,
        collection: stored.collection,
        filters: stored.filters,
        where_expr: stored.where_expr,
        filter_groups: stored.filter_groups,
        columns: stored.columns,
        layout: stored.layout,
        group_by: stored.group_by,
        sort_by: stored.sort_by,
        sort_direction: stored.sort_direction,
        page_size: stored.page_size,
        saved,
    }
}

const fn default_page_size() -> usize {
    DEFAULT_VIEW_PAGE_SIZE
}

fn is_ascending(direction: &SortDirection) -> bool {
    *direction == SortDirection::Asc
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn saved_views_override_automatic_collection_views() {
        let temporary = tempdir().unwrap();
        let database = Database::init(temporary.path().join("database")).unwrap();
        database
            .create("deals", "one", &[], "")
            .expect("record should create a collection");
        database
            .create_view(
                "deals",
                Some("Open deals"),
                "deals",
                vec!["status=open".into()],
                vec!["name".into(), "status".into()],
                25,
            )
            .unwrap();

        let views = database.views().unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].title, "Open deals");
        assert!(views[0].saved);
        assert_eq!(views[0].layout, ViewLayout::Table);
        assert_eq!(views[0].group_by, None);
        assert_eq!(views[0].sort_by, None);
        assert_eq!(views[0].sort_direction, SortDirection::Asc);
        assert_eq!(database.view("deals").unwrap(), views[0]);
    }

    #[test]
    fn kanban_views_store_the_grouping_field_and_legacy_views_default_to_tables() {
        let temporary = tempdir().unwrap();
        let database = Database::init(temporary.path().join("database")).unwrap();
        let kanban = database
            .create_view_with_options(
                "pipeline",
                Some("Sales pipeline"),
                "deals",
                vec![],
                vec!["value>=10000".into()],
                vec![ViewFilterGroup {
                    match_mode: ViewPredicateMatch::Any,
                    expressions: vec!["stage=proposal".into(), "stage=negotiation".into()],
                }],
                vec!["name".into(), "value".into()],
                200,
                ViewLayout::Kanban,
                Some("stage".into()),
                Some("value".into()),
                SortDirection::Desc,
            )
            .unwrap();
        assert_eq!(kanban.layout, ViewLayout::Kanban);
        assert_eq!(kanban.group_by.as_deref(), Some("stage"));
        assert_eq!(kanban.sort_by.as_deref(), Some("value"));
        assert_eq!(kanban.sort_direction, SortDirection::Desc);
        assert_eq!(kanban.where_expr, ["value>=10000"]);
        assert_eq!(kanban.filter_groups.len(), 1);
        assert_eq!(kanban.filter_groups[0].match_mode, ViewPredicateMatch::Any);
        let stored = fs::read_to_string(database.root().join(".cr/views/pipeline.yaml")).unwrap();
        assert!(stored.contains("layout: kanban"));
        assert!(stored.contains("group_by: stage"));
        assert!(stored.contains("- value>=10000"));
        assert!(stored.contains("filter_groups:"));
        assert!(stored.contains("match: any"));
        assert!(stored.contains("- stage=proposal"));
        assert!(stored.contains("sort_by: value"));
        assert!(stored.contains("sort_direction: desc"));

        fs::write(
            database.root().join(".cr/views/legacy.yaml"),
            "version: 1\ntitle: Legacy\ncollection: deals\n",
        )
        .unwrap();
        let legacy = database.view("legacy").unwrap();
        assert_eq!(legacy.layout, ViewLayout::Table);
        assert_eq!(legacy.group_by, None);
        assert!(legacy.where_expr.is_empty());
        assert!(legacy.filter_groups.is_empty());
        assert_eq!(legacy.sort_by, None);
        assert_eq!(legacy.sort_direction, SortDirection::Asc);
    }

    #[test]
    fn invalid_and_reserved_view_definitions_are_rejected() {
        let temporary = tempdir().unwrap();
        let database = Database::init(temporary.path().join("database")).unwrap();

        assert!(database
            .create_view("api", None, "deals", vec![], vec![], 50)
            .unwrap_err()
            .to_string()
            .contains("reserved"));
        assert!(database
            .create_view("audit", None, "deals", vec![], vec![], 50)
            .unwrap_err()
            .to_string()
            .contains("reserved"));
        assert!(database
            .create_view("bad", None, "deals", vec!["status".into()], vec![], 50)
            .unwrap_err()
            .to_string()
            .contains("invalid filter"));
        assert!(database
            .create_view(
                "bad",
                None,
                "deals",
                vec![],
                vec!["owner..email".into()],
                50
            )
            .unwrap_err()
            .to_string()
            .contains("invalid column"));
        assert!(database
            .create_view_with_options(
                "bad-sort",
                None,
                "deals",
                vec![],
                vec![],
                vec![],
                vec![],
                50,
                ViewLayout::Table,
                None,
                Some("owner..email".into()),
                SortDirection::Asc,
            )
            .unwrap_err()
            .to_string()
            .contains("invalid sort_by"));
        assert!(database
            .create_view_with_options(
                "missing-sort",
                None,
                "deals",
                vec![],
                vec![],
                vec![],
                vec![],
                50,
                ViewLayout::Table,
                None,
                None,
                SortDirection::Desc,
            )
            .unwrap_err()
            .to_string()
            .contains("requires sort_by"));
        assert!(database
            .create_view_with_options(
                "empty-group",
                None,
                "deals",
                vec![],
                vec![],
                vec![ViewFilterGroup {
                    match_mode: ViewPredicateMatch::All,
                    expressions: vec![],
                }],
                vec![],
                50,
                ViewLayout::Table,
                None,
                None,
                SortDirection::Asc,
            )
            .unwrap_err()
            .to_string()
            .contains("cannot be empty"));
        assert!(database
            .create_view_with_layout(
                "missing-group",
                None,
                "deals",
                vec![],
                vec![],
                50,
                ViewLayout::Kanban,
                None,
            )
            .unwrap_err()
            .to_string()
            .contains("requires group_by"));
        assert!(database
            .create_view_with_layout(
                "table-group",
                None,
                "deals",
                vec![],
                vec![],
                50,
                ViewLayout::Table,
                Some("stage".into()),
            )
            .unwrap_err()
            .to_string()
            .contains("only valid for the kanban layout"));
        assert!(database
            .create_view_with_layout(
                "bad-group",
                None,
                "deals",
                vec![],
                vec![],
                50,
                ViewLayout::Kanban,
                Some("owner..team".into()),
            )
            .unwrap_err()
            .to_string()
            .contains("invalid group_by"));
    }

    #[test]
    fn databases_created_before_views_existed_get_automatic_and_saved_views() {
        let temporary = tempdir().unwrap();
        let database = Database::init(temporary.path().join("database")).unwrap();
        database.create("deals", "one", &[], "").unwrap();
        fs::remove_dir(database.root().join(".cr/views")).unwrap();

        assert_eq!(database.views().unwrap()[0].name, "deals");
        database
            .create_view("open-deals", None, "deals", vec![], vec![], 50)
            .unwrap();
        assert!(database.root().join(".cr/views/open-deals.yaml").is_file());
    }
}
