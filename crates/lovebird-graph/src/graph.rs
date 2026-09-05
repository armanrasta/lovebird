//! In-memory directed asset graph.

use lovebird_common::{AssetEdge, AssetNode, Relationship};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    MissingNode(String),
    DuplicateNode(String),
}

impl std::fmt::Display for GraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GraphError::MissingNode(id) => write!(f, "missing node '{id}'"),
            GraphError::DuplicateNode(id) => write!(f, "duplicate node '{id}'"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Directed asset graph. Edges point `from → to` (capability / reachability).
#[derive(Debug, Clone, Default)]
pub struct AssetGraph {
    nodes: HashMap<String, AssetNode>,
    /// adjacency: from → list of (to, relationship)
    adj: HashMap<String, Vec<(String, Relationship)>>,
}

impl AssetGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: AssetNode) -> Result<(), GraphError> {
        if self.nodes.contains_key(&node.id) {
            return Err(GraphError::DuplicateNode(node.id));
        }
        self.adj.entry(node.id.clone()).or_default();
        self.nodes.insert(node.id.clone(), node);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: AssetEdge) -> Result<(), GraphError> {
        if !self.nodes.contains_key(&edge.from) {
            return Err(GraphError::MissingNode(edge.from));
        }
        if !self.nodes.contains_key(&edge.to) {
            return Err(GraphError::MissingNode(edge.to));
        }
        self.adj.entry(edge.from).or_default().push((edge.to, edge.relationship));
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&AssetNode> {
        self.nodes.get(id)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &AssetNode> {
        self.nodes.values()
    }

    pub fn edges(&self) -> impl Iterator<Item = (&str, &str, Relationship)> {
        self.adj.iter().flat_map(|(from, outs)| {
            outs.iter().map(move |(to, rel)| (from.as_str(), to.as_str(), *rel))
        })
    }

    pub fn crown_jewels(&self) -> Vec<&AssetNode> {
        self.nodes.values().filter(|n| n.crown_jewel).collect()
    }

    /// Outgoing neighbors `(to, relationship)` from `from`.
    pub fn outgoing(&self, from: &str) -> &[(String, Relationship)] {
        self.adj.get(from).map_or(&[], Vec::as_slice)
    }

    /// BFS reachable node ids from `start` (including start if present).
    pub fn reachable(&self, start: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        if !self.nodes.contains_key(start) {
            return seen;
        }
        let mut q = VecDeque::new();
        q.push_back(start.to_string());
        seen.insert(start.to_string());
        while let Some(cur) = q.pop_front() {
            if let Some(outs) = self.adj.get(&cur) {
                for (to, _) in outs {
                    if seen.insert(to.clone()) {
                        q.push_back(to.clone());
                    }
                }
            }
        }
        seen
    }

    /// Shortest path by hop count; `None` if unreachable.
    pub fn shortest_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        if !self.nodes.contains_key(from) || !self.nodes.contains_key(to) {
            return None;
        }
        if from == to {
            return Some(vec![from.to_string()]);
        }
        let mut prev: HashMap<String, String> = HashMap::new();
        let mut q = VecDeque::new();
        let mut seen = HashSet::new();
        q.push_back(from.to_string());
        seen.insert(from.to_string());
        while let Some(cur) = q.pop_front() {
            if let Some(outs) = self.adj.get(&cur) {
                for (nxt, _) in outs {
                    if seen.insert(nxt.clone()) {
                        prev.insert(nxt.clone(), cur.clone());
                        if nxt == to {
                            return Some(reconstruct_path(&prev, from, to));
                        }
                        q.push_back(nxt.clone());
                    }
                }
            }
        }
        None
    }
}

fn reconstruct_path(prev: &HashMap<String, String>, from: &str, to: &str) -> Vec<String> {
    let mut path = vec![to.to_string()];
    let mut cur = to;
    while cur != from {
        if let Some(p) = prev.get(cur) {
            path.push(p.clone());
            cur = p;
        } else {
            break;
        }
    }
    path.reverse();
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovebird_common::AssetType;

    fn node(id: &str, crown: bool, sens: u8) -> AssetNode {
        AssetNode {
            id: id.into(),
            r#type: AssetType::Host,
            sensitivity: sens,
            crown_jewel: crown,
            attributes: HashMap::new(),
        }
    }

    #[test]
    fn reachability_and_shortest_path() {
        let mut g = AssetGraph::new();
        g.add_node(node("a", false, 10)).expect("a");
        g.add_node(node("b", false, 20)).expect("b");
        g.add_node(node("c", true, 90)).expect("c");
        g.add_edge(AssetEdge {
            from: "a".into(),
            to: "b".into(),
            relationship: Relationship::CanAccess,
        })
        .expect("ab");
        g.add_edge(AssetEdge {
            from: "b".into(),
            to: "c".into(),
            relationship: Relationship::CanAccess,
        })
        .expect("bc");

        let r = g.reachable("a");
        assert!(r.contains("a") && r.contains("b") && r.contains("c"));
        assert_eq!(g.shortest_path("a", "c"), Some(vec!["a".into(), "b".into(), "c".into()]));
    }
}
