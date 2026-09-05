//! Maps blast-radius / resource facts into flat `graph.*` keys.

use crate::blast_radius::compute_blast_radius;
use crate::graph::AssetGraph;
use lovebird_common::Request;
use serde_json::{Number, Value};
use std::collections::HashMap;

pub struct GraphContextExtractor;

impl GraphContextExtractor {
    /// Extract context for a principal acting on a resource.
    pub fn extract(
        graph: &AssetGraph,
        principal_id: &str,
        resource_id: &str,
    ) -> HashMap<String, Value> {
        let br = compute_blast_radius(graph, principal_id);
        let resource_sensitivity = graph.get(resource_id).map_or(0, |n| n.sensitivity);

        let mut out = HashMap::new();
        out.insert("graph.blast_radius_score".into(), json_f64(br.blast_radius_score));
        out.insert("graph.crown_jewel_reachable".into(), Value::Bool(br.crown_jewel_reachable));
        out.insert(
            "graph.resource_sensitivity".into(),
            Value::Number(Number::from(resource_sensitivity)),
        );
        out
    }
}

pub fn enrich_request(
    mut request: Request,
    graph: &AssetGraph,
    principal_id: &str,
    resource_id: &str,
) -> Request {
    for (k, v) in GraphContextExtractor::extract(graph, principal_id, resource_id) {
        request.context.insert(k, v);
    }
    request
}

fn json_f64(v: f64) -> Value {
    Number::from_f64(v).map_or(Value::Number(Number::from(0)), Value::Number)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{GraphDocument, build_graph};
    use lovebird_common::{
        AssetEdge, AssetNode, AssetType, Effect, Operator, Policy, Principal, Relationship,
        Resource, Rule,
    };
    use lovebird_engine::Evaluator;

    fn fixture() -> AssetGraph {
        build_graph(GraphDocument {
            nodes: vec![
                AssetNode {
                    id: "alice".into(),
                    r#type: AssetType::User,
                    sensitivity: 10,
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
            edges: vec![AssetEdge {
                from: "alice".into(),
                to: "payroll-db".into(),
                relationship: Relationship::CanAccess,
            }],
        })
        .expect("fixture")
    }

    #[test]
    fn graph_context_changes_decision() {
        let g = fixture();
        let deny_cj = Policy {
            id: "deny-crown".into(),
            effect: Effect::Deny,
            description: "Deny when crown jewel reachable".into(),
            priority: 40,
            actions: vec!["read".into()],
            r#match: vec![vec![Rule {
                field: "graph.crown_jewel_reachable".into(),
                operator: Operator::Equals,
                value: Value::Bool(true),
            }]],
            policy_language_version: "1".into(),
        };
        let allow = Policy {
            id: "allow-read".into(),
            effect: Effect::Allow,
            description: "Allow read".into(),
            priority: 1,
            actions: vec!["read".into()],
            r#match: vec![vec![Rule {
                field: "action".into(),
                operator: Operator::Equals,
                value: Value::String("read".into()),
            }]],
            policy_language_version: "1".into(),
        };

        let base = Request {
            principal: Principal { id: "alice".into(), roles: vec![], attributes: HashMap::new() },
            action: "read".into(),
            resource: Resource {
                r#type: "database".into(),
                id: "payroll-db".into(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
        };

        let isolated = Request {
            principal: Principal { id: "bob".into(), roles: vec![], attributes: HashMap::new() },
            action: "read".into(),
            resource: Resource {
                r#type: "database".into(),
                id: "payroll-db".into(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
        };

        // bob not in graph → no reachability → crown false
        let bob_req = enrich_request(isolated, &g, "bob", "payroll-db");
        let alice_req = enrich_request(base, &g, "alice", "payroll-db");
        let ev = Evaluator::new();
        let policies = vec![deny_cj, allow];
        assert_eq!(ev.evaluate(&bob_req, &policies).effect, Effect::Allow);
        assert_eq!(ev.evaluate(&alice_req, &policies).effect, Effect::Deny);
    }
}
