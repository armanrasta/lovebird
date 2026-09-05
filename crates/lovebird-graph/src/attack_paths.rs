//! Ranked attack-path discovery.

use crate::graph::AssetGraph;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackPath {
    pub hops: Vec<String>,
    /// Higher is more severe: sum of node sensitivities along the path.
    pub severity: u32,
}

/// Find up to `limit` simple paths from `from` to `to`, ranked by severity desc then hop count asc.
pub fn find_attack_paths(
    graph: &AssetGraph,
    from: &str,
    to: &str,
    limit: usize,
) -> Vec<AttackPath> {
    if limit == 0 {
        return Vec::new();
    }
    if graph.get(from).is_none() || graph.get(to).is_none() {
        return Vec::new();
    }

    let mut found = Vec::new();
    let mut stack = vec![vec![from.to_string()]];

    while let Some(path) = stack.pop() {
        let Some(cur) = path.last() else {
            continue;
        };
        if cur == to {
            let severity =
                path.iter().filter_map(|id| graph.get(id)).map(|n| u32::from(n.sensitivity)).sum();
            found.push(AttackPath { hops: path, severity });
            if found.len() >= limit * 4 {
                // collect a few extra then rank/truncate
                break;
            }
            continue;
        }
        if path.len() > 12 {
            continue;
        }
        for (t, _) in graph.outgoing(cur) {
            if path.iter().any(|p| p == t) {
                continue; // simple paths only
            }
            let mut next = path.clone();
            next.push(t.clone());
            stack.push(next);
        }
    }

    found.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.hops.len().cmp(&b.hops.len())));
    found.truncate(limit);
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{GraphDocument, build_graph};
    use lovebird_common::{AssetEdge, AssetNode, AssetType, Relationship};
    use std::collections::HashMap;

    #[test]
    fn finds_path_to_crown_jewel() {
        let g = build_graph(GraphDocument {
            nodes: vec![
                AssetNode {
                    id: "a".into(),
                    r#type: AssetType::User,
                    sensitivity: 5,
                    crown_jewel: false,
                    attributes: HashMap::new(),
                },
                AssetNode {
                    id: "b".into(),
                    r#type: AssetType::Host,
                    sensitivity: 20,
                    crown_jewel: false,
                    attributes: HashMap::new(),
                },
                AssetNode {
                    id: "cj".into(),
                    r#type: AssetType::Secret,
                    sensitivity: 100,
                    crown_jewel: true,
                    attributes: HashMap::new(),
                },
            ],
            edges: vec![
                AssetEdge {
                    from: "a".into(),
                    to: "b".into(),
                    relationship: Relationship::CanAccess,
                },
                AssetEdge {
                    from: "b".into(),
                    to: "cj".into(),
                    relationship: Relationship::CanAccess,
                },
            ],
        })
        .expect("g");
        let paths = find_attack_paths(&g, "a", "cj", 3);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].hops, vec!["a", "b", "cj"]);
    }
}
