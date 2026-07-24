//! Shadow evaluation and dry-run / impact helpers.

use crate::evaluator::Evaluator;
use crate::types::{Decision, Effect, Policy, Request};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowReport {
    pub actual: Decision,
    pub shadow: Decision,
    pub agree: bool,
}

impl Evaluator {
    /// Evaluate production policies and shadow policies independently; compare effects.
    pub fn evaluate_shadow(
        &self,
        request: &Request,
        production: &[Policy],
        shadow: &[Policy],
    ) -> ShadowReport {
        let actual = self.evaluate(request, production);
        let shadow_decision = self.evaluate(request, shadow);
        ShadowReport {
            agree: actual.effect == shadow_decision.effect,
            actual,
            shadow: shadow_decision,
        }
    }
}

/// One historical request used for dry-run / impact estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficRecord {
    pub request: Request,
    /// Effect that was in force when this traffic was recorded (or baseline eval).
    pub prior_effect: Effect,
    #[serde(default)]
    pub principal_hint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DryRunReport {
    pub total: usize,
    pub unchanged: usize,
    pub newly_denied: usize,
    pub newly_allowed: usize,
    pub affected_principals: Vec<String>,
}

/// Replay traffic against a candidate policy set and diff vs `prior_effect`.
pub fn dry_run(
    evaluator: &Evaluator,
    policies: &[Policy],
    traffic: &[TrafficRecord],
) -> DryRunReport {
    let mut report = DryRunReport { total: traffic.len(), ..DryRunReport::default() };
    let mut principals = Vec::new();

    for rec in traffic {
        let decision = evaluator.evaluate(&rec.request, policies);
        match (rec.prior_effect, decision.effect) {
            (a, b) if a == b => report.unchanged += 1,
            (Effect::Allow, Effect::Deny) => {
                report.newly_denied += 1;
                principals.push(
                    rec.principal_hint.clone().unwrap_or_else(|| rec.request.principal.id.clone()),
                );
            }
            (Effect::Deny, Effect::Allow) => {
                report.newly_allowed += 1;
                principals.push(
                    rec.principal_hint.clone().unwrap_or_else(|| rec.request.principal.id.clone()),
                );
            }
            _ => report.unchanged += 1,
        }
    }

    principals.sort();
    principals.dedup();
    report.affected_principals = principals;
    report
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDiffEntry {
    pub policy_id: String,
    pub change: String,
    pub detail: String,
}

/// Structural diff of two policy sets keyed by policy id.
pub fn diff_policies(old: &[Policy], new: &[Policy]) -> Vec<PolicyDiffEntry> {
    use std::collections::HashMap;
    let old_map: HashMap<&str, &Policy> = old.iter().map(|p| (p.id.as_str(), p)).collect();
    let new_map: HashMap<&str, &Policy> = new.iter().map(|p| (p.id.as_str(), p)).collect();

    let mut entries = Vec::new();

    for (id, np) in &new_map {
        match old_map.get(id) {
            None => entries.push(PolicyDiffEntry {
                policy_id: (*id).into(),
                change: "added".into(),
                detail: format!("effect={:?} priority={}", np.effect, np.priority),
            }),
            Some(op) => {
                if op.priority != np.priority {
                    entries.push(PolicyDiffEntry {
                        policy_id: (*id).into(),
                        change: "priority".into(),
                        detail: format!("{} → {}", op.priority, np.priority),
                    });
                }
                if op.effect != np.effect {
                    entries.push(PolicyDiffEntry {
                        policy_id: (*id).into(),
                        change: "effect".into(),
                        detail: format!("{:?} → {:?}", op.effect, np.effect),
                    });
                }
                if op.actions != np.actions {
                    entries.push(PolicyDiffEntry {
                        policy_id: (*id).into(),
                        change: "actions".into(),
                        detail: format!("{:?} → {:?}", op.actions, np.actions),
                    });
                }
                let old_m = serde_json::to_string(&op.r#match).unwrap_or_default();
                let new_m = serde_json::to_string(&np.r#match).unwrap_or_default();
                if old_m != new_m {
                    entries.push(PolicyDiffEntry {
                        policy_id: (*id).into(),
                        change: "match".into(),
                        detail: "match rules changed".into(),
                    });
                }
            }
        }
    }

    for id in old_map.keys() {
        if !new_map.contains_key(id) {
            entries.push(PolicyDiffEntry {
                policy_id: (*id).into(),
                change: "removed".into(),
                detail: String::new(),
            });
        }
    }

    entries.sort_by(|a, b| a.policy_id.cmp(&b.policy_id).then(a.change.cmp(&b.change)));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Operator, Principal, Resource, Rule};
    use serde_json::json;
    use std::collections::HashMap;

    fn req(id: &str, role: &str) -> Request {
        Request {
            principal: Principal {
                id: id.into(),
                roles: vec![role.into()],
                attributes: HashMap::new(),
            },
            action: "read".into(),
            resource: Resource {
                r#type: "doc".into(),
                id: "d1".into(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
        }
    }

    fn allow_admin() -> Policy {
        Policy {
            id: "allow-admin".into(),
            effect: Effect::Allow,
            description: "a".into(),
            priority: 10,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule {
                field: "principal.roles".into(),
                operator: Operator::Contains,
                value: json!("admin"),
            }]],
        }
    }

    #[test]
    fn shadow_detects_disagreement() {
        let ev = Evaluator::new();
        let prod = [allow_admin()];
        let shadow: [Policy; 0] = [];
        let report = ev.evaluate_shadow(&req("a", "admin"), &prod, &shadow);
        assert!(!report.agree);
        assert_eq!(report.actual.effect, Effect::Allow);
        assert_eq!(report.shadow.effect, Effect::Deny);
    }

    #[test]
    fn dry_run_counts_newly_denied() {
        let ev = Evaluator::new();
        let traffic = [TrafficRecord {
            request: req("alice", "admin"),
            prior_effect: Effect::Allow,
            principal_hint: None,
        }];
        // Empty policies → default deny → newly denied
        let report = dry_run(&ev, &[], &traffic);
        assert_eq!(report.newly_denied, 1);
        assert_eq!(report.affected_principals, vec!["alice".to_string()]);
    }

    #[test]
    fn diff_detects_priority_change() {
        let old = allow_admin();
        let mut new = allow_admin();
        new.priority = 99;
        let d = diff_policies(std::slice::from_ref(&old), std::slice::from_ref(&new));
        assert!(d.iter().any(|e| e.change == "priority"));
    }
}
