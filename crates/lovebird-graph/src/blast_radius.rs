//! Blast-radius scoring from a principal node.

use crate::graph::AssetGraph;

/// Deterministic blast-radius summary.
///
/// Score formula (documented for NFR/tests):
/// ```text
/// score = clamp01(
///     0.45 * (reachable_count.min(40) / 40) +
///     0.35 * (max_sensitivity / 100) +
///     0.20 * (1 if any crown jewel reachable else 0)
/// )
/// ```
/// Start node is included in the reachable set.
#[derive(Debug, Clone, PartialEq)]
pub struct BlastRadius {
    pub from: String,
    pub reachable_count: usize,
    pub max_sensitivity: u8,
    pub crown_jewel_reachable: bool,
    pub blast_radius_score: f64,
    pub reachable_ids: Vec<String>,
}

pub fn compute_blast_radius(graph: &AssetGraph, from: &str) -> BlastRadius {
    let set = graph.reachable(from);
    let mut max_sensitivity = 0_u8;
    let mut crown = false;
    let mut ids: Vec<String> = set.iter().cloned().collect();
    ids.sort();

    for id in &ids {
        if let Some(n) = graph.get(id) {
            max_sensitivity = max_sensitivity.max(n.sensitivity);
            if n.crown_jewel {
                crown = true;
            }
        }
    }

    let count = ids.len();
    let reach_capped = u8::try_from(count.min(40)).unwrap_or(40);
    let reach_term = f64::from(reach_capped) / 40.0;
    let sens_term = f64::from(max_sensitivity) / 100.0;
    let crown_term = if crown { 1.0 } else { 0.0 };
    let mut score = 0.45 * reach_term + 0.35 * sens_term + 0.20 * crown_term;
    if score > 1.0 {
        score = 1.0;
    }

    BlastRadius {
        from: from.to_string(),
        reachable_count: count,
        max_sensitivity,
        crown_jewel_reachable: crown,
        blast_radius_score: score,
        reachable_ids: ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::build_graph;
    use lovebird_common::{AssetEdge, AssetNode, AssetType, Relationship};
    use std::collections::HashMap;

    fn fixture() -> AssetGraph {
        build_graph(crate::builder::GraphDocument {
            nodes: vec![
                AssetNode {
                    id: "alice".into(),
                    r#type: AssetType::User,
                    sensitivity: 10,
                    crown_jewel: false,
                    attributes: HashMap::new(),
                },
                AssetNode {
                    id: "jump".into(),
                    r#type: AssetType::Host,
                    sensitivity: 40,
                    crown_jewel: false,
                    attributes: HashMap::new(),
                },
                AssetNode {
                    id: "payroll-db".into(),
                    r#type: AssetType::Database,
                    sensitivity: 95,
                    crown_jewel: true,
                    attributes: HashMap::new(),
                },
            ],
            edges: vec![
                AssetEdge {
                    from: "alice".into(),
                    to: "jump".into(),
                    relationship: Relationship::CanAccess,
                },
                AssetEdge {
                    from: "jump".into(),
                    to: "payroll-db".into(),
                    relationship: Relationship::CanAccess,
                },
            ],
        })
        .expect("fixture")
    }

    #[test]
    fn hand_built_blast_radius_numbers() {
        let g = fixture();
        let br = compute_blast_radius(&g, "alice");
        assert_eq!(br.reachable_count, 3);
        assert_eq!(br.max_sensitivity, 95);
        assert!(br.crown_jewel_reachable);
        // 0.45*(3/40) + 0.35*(95/100) + 0.20 = 0.03375 + 0.3325 + 0.20 = 0.56625
        assert!((br.blast_radius_score - 0.56625).abs() < 1e-9);
    }
}
