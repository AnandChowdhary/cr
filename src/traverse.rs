//! Following relations outward from one record.
//!
//! A traversal is breadth-first, bounded by an explicit depth and a fixed
//! record budget, and visits each record at most once, so a cycle ends where it
//! closes rather than looping. A reference to a record that does not exist, or
//! that the caller may not read, is reported as such and not followed: a
//! traversal never fails because of what it found, only because of where it
//! started.

use std::collections::HashMap;

use anyhow::Result;
use serde::Serialize;
use serde_json::{Map, Value as JsonValue, json};

use crate::{
    database::{Database, Record, relation_references, validate_component},
    error::{DomainError, invalid},
    projection::Projection,
};

/// The deepest traversal a caller may ask for.
pub const MAX_TRAVERSAL_DEPTH: usize = 10;

/// The most records one traversal visits before it stops and says so.
pub const MAX_TRAVERSAL_RECORDS: usize = 1000;

/// What a traversal found at the end of a reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalStatus {
    /// The record exists and was read.
    Found,
    /// No record exists there.
    Missing,
    /// The caller may not read the record, so nothing is said about it.
    Forbidden,
    /// The record exists but could not be read or parsed.
    Unreadable,
}

impl TraversalStatus {
    /// The stable lowercase label used in output.
    pub fn label(self) -> &'static str {
        match self {
            Self::Found => "found",
            Self::Missing => "missing",
            Self::Forbidden => "forbidden",
            Self::Unreadable => "unreadable",
        }
    }
}

/// One record a traversal reached.
#[derive(Clone, Debug)]
pub struct TraversalNode {
    pub collection: String,
    pub id: String,
    /// Relations followed from the start to reach it; the start is zero.
    pub depth: usize,
    pub status: TraversalStatus,
    /// Present exactly when the status is [`TraversalStatus::Found`].
    pub record: Option<Record>,
    /// The edge this record was first reached through, which is where a tree
    /// rendering expands it. `None` for the start.
    pub reached_by: Option<usize>,
}

impl TraversalNode {
    /// `collection/id`.
    pub fn reference(&self) -> String {
        format!("{}/{}", self.collection, self.id)
    }
}

/// One followed reference, by index into [`Traversal::nodes`].
#[derive(Clone, Debug)]
pub struct TraversalEdge {
    pub from: usize,
    pub relation: String,
    pub to: usize,
}

/// Everything a traversal reached, in the order it reached it.
#[derive(Clone, Debug)]
pub struct Traversal {
    /// The start first, then every record in breadth-first order.
    pub nodes: Vec<TraversalNode>,
    /// Every reference followed, in the order each record stores them.
    pub edges: Vec<TraversalEdge>,
    /// The depth that was asked for.
    pub depth: usize,
    /// Whether [`MAX_TRAVERSAL_RECORDS`] stopped the traversal early.
    pub truncated: bool,
}

impl Traversal {
    /// The edges leaving one node, in the order its record stores them, each
    /// with whether it is the edge its target was first reached through.
    pub fn edges_from(&self, node: usize) -> impl Iterator<Item = (&TraversalEdge, bool)> {
        self.edges
            .iter()
            .enumerate()
            .filter(move |(_, edge)| edge.from == node)
            .map(|(index, edge)| (edge, self.nodes[edge.to].reached_by == Some(index)))
    }

    /// A flat rendering: every node once, and every edge by reference.
    ///
    /// With a projection, each record carries only the selected fields, under
    /// `fields`, instead of its path, version, and front matter.
    pub fn graph_json(&self, projection: Option<&Projection>) -> Result<JsonValue> {
        let nodes = self
            .nodes
            .iter()
            .map(|node| {
                let mut object = node_json(node, projection)?;
                object.insert("depth".to_owned(), json!(node.depth));
                Ok(JsonValue::Object(object))
            })
            .collect::<Result<Vec<_>>>()?;
        let edges: Vec<_> = self
            .edges
            .iter()
            .map(|edge| {
                json!({
                    "from": self.nodes[edge.from].reference(),
                    "relation": edge.relation,
                    "to": self.nodes[edge.to].reference(),
                })
            })
            .collect();
        Ok(json!({
            "root": self.nodes[0].reference(),
            "depth": self.depth,
            "truncated": self.truncated,
            "nodes": nodes,
            "edges": edges,
        }))
    }

    /// A nested rendering: each record expanded with its front matter where it
    /// was first reached, under `links` keyed by relation, and every later
    /// reference to it a stub marked `seen`. A projection applies as it does
    /// to [`Self::graph_json`].
    pub fn tree_json(&self, projection: Option<&Projection>) -> Result<JsonValue> {
        let mut tree = self.subtree_json(0, projection)?;
        tree.insert("depth".to_owned(), json!(self.depth));
        tree.insert("truncated".to_owned(), json!(self.truncated));
        Ok(JsonValue::Object(tree))
    }

    fn subtree_json(
        &self,
        index: usize,
        projection: Option<&Projection>,
    ) -> Result<Map<String, JsonValue>> {
        let mut object = node_json(&self.nodes[index], projection)?;
        let mut links: Map<String, JsonValue> = Map::new();
        for (edge, expands) in self.edges_from(index) {
            let child = if expands {
                self.subtree_json(edge.to, projection)?
            } else {
                let mut stub = reference_json(&self.nodes[edge.to]);
                stub.insert("seen".to_owned(), JsonValue::Bool(true));
                stub
            };
            match links
                .entry(edge.relation.clone())
                .or_insert_with(|| JsonValue::Array(Vec::new()))
            {
                JsonValue::Array(targets) => targets.push(JsonValue::Object(child)),
                _ => unreachable!("every relation entry is created as an array"),
            }
        }
        if !links.is_empty() {
            object.insert("links".to_owned(), JsonValue::Object(links));
        }
        Ok(object)
    }

    /// An indented plain-text tree, one reference per line.
    pub fn render_text(&self) -> String {
        let mut output = format!("{}\n", self.nodes[0].reference());
        self.render_children(0, 1, &mut output);
        if self.truncated {
            output.push_str(&format!(
                "(stopped after {MAX_TRAVERSAL_RECORDS} records)\n"
            ));
        }
        output
    }

    fn render_children(&self, index: usize, indent: usize, output: &mut String) {
        for (edge, expands) in self.edges_from(index) {
            let target = &self.nodes[edge.to];
            let note = match (target.status, expands) {
                (TraversalStatus::Found, true) => "",
                (TraversalStatus::Found, false) => " (shown above)",
                (TraversalStatus::Missing, _) => " (missing)",
                (TraversalStatus::Forbidden, _) => " (not readable)",
                (TraversalStatus::Unreadable, _) => " (unreadable)",
            };
            output.push_str(&format!(
                "{}{}: {}{note}\n",
                "  ".repeat(indent),
                edge.relation,
                target.reference()
            ));
            if expands {
                self.render_children(edge.to, indent + 1, output);
            }
        }
    }
}

fn reference_json(node: &TraversalNode) -> Map<String, JsonValue> {
    let mut object = Map::new();
    object.insert("collection".to_owned(), json!(node.collection));
    object.insert("id".to_owned(), json!(node.id));
    object.insert("status".to_owned(), json!(node.status.label()));
    object
}

fn node_json(
    node: &TraversalNode,
    projection: Option<&Projection>,
) -> Result<Map<String, JsonValue>> {
    let mut object = reference_json(node);
    if let (Some(record), Some(projection)) = (&node.record, projection) {
        object.insert(
            "fields".to_owned(),
            JsonValue::Object(projection.object(record)?),
        );
    } else if let Some(record) = &node.record {
        object.insert(
            "path".to_owned(),
            json!(record.path.to_string_lossy().into_owned()),
        );
        object.insert("version".to_owned(), json!(record.version));
        let front_matter = serde_json::to_value(&record.attributes).map_err(|error| {
            invalid(format!(
                "record {} has front matter that cannot be represented as JSON: {error}",
                node.reference()
            ))
        })?;
        object.insert("front_matter".to_owned(), front_matter);
    }
    Ok(object)
}

impl Database {
    /// Follow relations outward from `collection/id` for up to `depth` steps.
    ///
    /// `relations` limits which relation names are followed, at every step;
    /// empty follows them all. The start must exist and be readable, exactly
    /// as for [`Database::get`]. Every record after it is read with the same
    /// authorization, and a reference that cannot be followed becomes a node
    /// saying why rather than an error.
    pub fn traverse(
        &self,
        collection: &str,
        id: &str,
        relations: &[String],
        depth: usize,
    ) -> Result<Traversal> {
        validate_component(collection, "collection")?;
        validate_component(id, "id")?;
        for relation in relations {
            validate_component(relation, "relation")?;
        }
        if !(1..=MAX_TRAVERSAL_DEPTH).contains(&depth) {
            return Err(invalid(format!(
                "traversal depth must be between 1 and {MAX_TRAVERSAL_DEPTH}"
            )));
        }

        let mut audited_states = None;
        let start = self.get_with_audited_cache(collection, id, &mut audited_states)?;
        let mut nodes = vec![TraversalNode {
            collection: collection.to_owned(),
            id: id.to_owned(),
            depth: 0,
            status: TraversalStatus::Found,
            record: Some(start),
            reached_by: None,
        }];
        let mut seen = HashMap::from([((collection.to_owned(), id.to_owned()), 0)]);
        let mut edges = Vec::new();
        let mut truncated = false;

        let mut next = 0;
        while next < nodes.len() {
            let current = next;
            next += 1;
            if nodes[current].depth == depth {
                continue;
            }
            let Some(record) = &nodes[current].record else {
                continue;
            };
            let references: Vec<_> = relation_references(&record.attributes)
                .into_iter()
                .filter(|(relation, _, _)| {
                    relations.is_empty() || relations.iter().any(|name| name == relation)
                })
                .collect();
            let child_depth = nodes[current].depth + 1;
            for (relation, target_collection, target_id) in references {
                let key = (target_collection, target_id);
                let to = match seen.get(&key) {
                    Some(&index) => index,
                    None => {
                        if nodes.len() >= MAX_TRAVERSAL_RECORDS {
                            truncated = true;
                            continue;
                        }
                        let index = nodes.len();
                        let (status, record) =
                            self.read_for_traversal(&key.0, &key.1, &mut audited_states);
                        nodes.push(TraversalNode {
                            collection: key.0.clone(),
                            id: key.1.clone(),
                            depth: child_depth,
                            status,
                            record,
                            reached_by: Some(edges.len()),
                        });
                        seen.insert(key, index);
                        index
                    }
                };
                edges.push(TraversalEdge {
                    from: current,
                    relation,
                    to,
                });
            }
        }

        Ok(Traversal {
            nodes,
            edges,
            depth,
            truncated,
        })
    }

    fn read_for_traversal(
        &self,
        collection: &str,
        id: &str,
        audited_states: &mut Option<std::sync::Arc<crate::audit::AuditedRecordStates>>,
    ) -> (TraversalStatus, Option<Record>) {
        match self.get_with_audited_cache(collection, id, audited_states) {
            Ok(record) => (TraversalStatus::Found, Some(record)),
            Err(error) => (
                match DomainError::of(&error) {
                    Some(DomainError::NotFound(_)) => TraversalStatus::Missing,
                    Some(DomainError::Forbidden(_)) => TraversalStatus::Forbidden,
                    _ => TraversalStatus::Unreadable,
                },
                None,
            ),
        }
    }
}
