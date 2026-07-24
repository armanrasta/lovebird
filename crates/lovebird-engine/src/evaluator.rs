use crate::operators::{self, MatchResult};
use crate::resolver::{resolve_field, substitute_placeholders};
use crate::types::{
    AlmostMatched, Decision, Effect, Explanation, Operator, Policy, PolicyEvalTrace, Request, Rule,
};
use serde_json::Value;

/// Pure, synchronous, deterministic policy evaluator.
#[derive(Debug, Default, Clone)]
pub struct Evaluator {
    /// When true, populate `Decision.explanation` (Explain Mode).
    pub explain: bool,
}

impl Evaluator {
    pub fn new() -> Self {
        Self { explain: false }
    }

    #[must_use]
    pub fn with_explain(mut self, explain: bool) -> Self {
        self.explain = explain;
        self
    }

    /// Evaluate `request` against `policies` per PROJECT.md §5:
    /// 1. Filter by `actions` scope (empty = all)
    /// 2. Sort by `priority` descending
    /// 3. First matching Deny → deny (denies checked before allows)
    /// 4. First matching Allow → allow
    /// 5. Nothing matches → default deny
    pub fn evaluate(&self, request: &Request, policies: &[Policy]) -> Decision {
        let mut applicable: Vec<&Policy> = policies
            .iter()
            .filter(|p| p.actions.is_empty() || p.actions.iter().any(|a| a == &request.action))
            .collect();

        applicable.sort_by_key(|p| std::cmp::Reverse(p.priority));

        let mut evaluated = Vec::new();
        let mut almost: Vec<AlmostMatched> = Vec::new();
        let mut deny_hit: Option<(&Policy, Vec<String>)> = None;
        let mut allow_hit: Option<(&Policy, Vec<String>)> = None;

        for policy in &applicable {
            let (matched, match_why, almost_missing) = Self::match_policy(request, policy);
            evaluated.push(PolicyEvalTrace {
                policy_id: policy.id.clone(),
                effect: policy.effect,
                matched,
            });

            if matched {
                match policy.effect {
                    Effect::Deny if deny_hit.is_none() => {
                        deny_hit = Some((policy, match_why));
                    }
                    Effect::Allow if allow_hit.is_none() => {
                        allow_hit = Some((policy, match_why));
                    }
                    _ => {}
                }
            } else if let Some(missing) = almost_missing
                && almost.len() < 8
            {
                almost.push(AlmostMatched { id: policy.id.clone(), missing });
            }
        }

        // Deny overrides allow regardless of relative priority among the two sets;
        // within each set, higher priority wins (we recorded the first after sort).
        if let Some((policy, why)) = deny_hit {
            return self.finish(Effect::Deny, Some(policy.id.clone()), evaluated, why, almost);
        }

        if let Some((policy, why)) = allow_hit {
            return self.finish(Effect::Allow, Some(policy.id.clone()), evaluated, why, almost);
        }

        self.finish(Effect::Deny, None, evaluated, Vec::new(), almost)
    }

    fn finish(
        &self,
        effect: Effect,
        matched_policy: Option<String>,
        evaluated: Vec<PolicyEvalTrace>,
        why: Vec<String>,
        almost: Vec<AlmostMatched>,
    ) -> Decision {
        let explanation = if self.explain {
            Some(Explanation {
                matched_policy: matched_policy.clone(),
                why: if matched_policy.is_none() && why.is_empty() {
                    vec!["default deny: no policy matched".into()]
                } else {
                    why
                },
                policies_that_almost_matched: almost,
            })
        } else {
            None
        };

        Decision { effect, matched_policy, evaluated, explanation, signature: None }
    }

    /// Returns (matched, why lines, almost-missing reason).
    fn match_policy(request: &Request, policy: &Policy) -> (bool, Vec<String>, Option<String>) {
        if policy.r#match.is_empty() {
            return (
                true,
                vec![format!("policy '{}' has empty match (matches all)", policy.id)],
                None,
            );
        }

        let mut best_almost: Option<String> = None;

        for (or_idx, and_group) in policy.r#match.iter().enumerate() {
            let mut group_why = Vec::new();
            let mut failed: Option<String> = None;
            let mut passed = 0usize;

            for rule in and_group {
                match Self::match_rule(request, rule) {
                    Ok(detail) => {
                        passed += 1;
                        group_why.push(detail);
                    }
                    Err(reason) => {
                        failed = Some(reason);
                    }
                }
            }

            if failed.is_none() && passed == and_group.len() {
                return (true, group_why, None);
            }

            // Almost matched: all but one AND clause passed
            if and_group.len() > 1 && passed + 1 == and_group.len() {
                if let Some(reason) = failed {
                    best_almost = Some(format!("OR-group {or_idx}: {reason}"));
                }
            } else if and_group.len() == 1
                && let Some(reason) = failed
            {
                best_almost.get_or_insert(reason);
            }
        }

        (false, Vec::new(), best_almost)
    }

    fn match_rule(request: &Request, rule: &Rule) -> Result<String, String> {
        let field_present = resolve_field(request, &rule.field).is_some();
        let target = substitute_placeholders(&rule.value, request);

        let result = match rule.operator {
            Operator::Exists => operators::apply_exists(field_present),
            Operator::NotExists => operators::apply_not_exists(field_present),
            other => {
                let Some(resolved) = resolve_field(request, &rule.field) else {
                    return Err(format!("field '{}' not present", rule.field));
                };
                match other {
                    Operator::Equals => operators::apply_equals(&resolved, &target),
                    Operator::NotEquals => operators::apply_not_equals(&resolved, &target),
                    Operator::In => operators::apply_in(&resolved, &target),
                    Operator::NotIn => operators::apply_not_in(&resolved, &target),
                    Operator::Contains => operators::apply_contains(&resolved, &target),
                    Operator::NotContains => operators::apply_not_contains(&resolved, &target),
                    Operator::StartsWith => operators::apply_starts_with(&resolved, &target),
                    Operator::EndsWith => operators::apply_ends_with(&resolved, &target),
                    Operator::GreaterThan => operators::apply_greater_than(&resolved, &target),
                    Operator::LessThan => operators::apply_less_than(&resolved, &target),
                    Operator::Regex => operators::apply_regex(&resolved, &target),
                    Operator::Exists | Operator::NotExists => unreachable!(),
                }
            }
        };

        let detail = format_rule_detail(rule, &target, result, field_present);
        if result.is_match() { Ok(detail) } else { Err(detail) }
    }
}

fn format_rule_detail(
    rule: &Rule,
    target: &Value,
    result: MatchResult,
    field_present: bool,
) -> String {
    let status = if result.is_match() { "✓ matched" } else { "✗ not matched" };
    if matches!(rule.operator, Operator::Exists | Operator::NotExists) {
        format!("{} {:?} (present={}) {}", rule.field, rule.operator, field_present, status)
    } else {
        format!("{} {:?} {} {}", rule.field, rule.operator, target, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Operator, Principal, Resource, Rule};
    use serde_json::json;
    use std::collections::HashMap;

    fn req(action: &str, role: &str) -> Request {
        Request {
            principal: Principal {
                id: "u1".into(),
                roles: vec![role.into()],
                attributes: HashMap::new(),
            },
            action: action.into(),
            resource: Resource {
                r#type: "doc".into(),
                id: "r1".into(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
        }
    }

    fn policy(
        id: &str,
        effect: Effect,
        priority: i64,
        actions: &[&str],
        field: &str,
        op: Operator,
        value: Value,
    ) -> Policy {
        Policy {
            id: id.into(),
            effect,
            description: id.into(),
            priority,
            actions: actions.iter().map(|s| (*s).to_string()).collect(),
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule { field: field.into(), operator: op, value }]],
        }
    }

    #[test]
    fn default_deny_when_nothing_matches() {
        let d = Evaluator::new().evaluate(&req("read", "user"), &[]);
        assert_eq!(d.effect, Effect::Deny);
        assert!(d.matched_policy.is_none());
    }

    #[test]
    fn deny_overrides_higher_priority_allow() {
        // Lower-priority deny still wins over higher-priority allow (deny-overrides).
        let policies = vec![
            policy(
                "allow-admins",
                Effect::Allow,
                100,
                &[],
                "principal.roles",
                Operator::Contains,
                json!("admin"),
            ),
            policy(
                "deny-admins",
                Effect::Deny,
                1,
                &[],
                "principal.roles",
                Operator::Contains,
                json!("admin"),
            ),
        ];
        let d = Evaluator::new().evaluate(&req("read", "admin"), &policies);
        assert_eq!(d.effect, Effect::Deny);
        assert_eq!(d.matched_policy.as_deref(), Some("deny-admins"));
    }

    #[test]
    fn allow_when_no_deny_matches() {
        let policies = vec![
            policy(
                "deny-write",
                Effect::Deny,
                10,
                &["write"],
                "principal.roles",
                Operator::Contains,
                json!("admin"),
            ),
            policy(
                "allow-read",
                Effect::Allow,
                5,
                &["read"],
                "principal.roles",
                Operator::Contains,
                json!("admin"),
            ),
        ];
        let d = Evaluator::new().evaluate(&req("read", "admin"), &policies);
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.matched_policy.as_deref(), Some("allow-read"));
    }

    #[test]
    fn actions_scope_filters_policies() {
        let policies = vec![policy(
            "write-only",
            Effect::Allow,
            0,
            &["write"],
            "principal.id",
            Operator::Equals,
            json!("u1"),
        )];
        let d = Evaluator::new().evaluate(&req("read", "admin"), &policies);
        assert_eq!(d.effect, Effect::Deny);
    }

    #[test]
    fn higher_priority_deny_selected_among_denies() {
        let policies = vec![
            policy("low-deny", Effect::Deny, 1, &[], "principal.id", Operator::Equals, json!("u1")),
            policy(
                "high-deny",
                Effect::Deny,
                100,
                &[],
                "principal.id",
                Operator::Equals,
                json!("u1"),
            ),
        ];
        let d = Evaluator::new().evaluate(&req("read", "x"), &policies);
        assert_eq!(d.matched_policy.as_deref(), Some("high-deny"));
        assert_eq!(d.effect, Effect::Deny);
    }

    #[test]
    fn explain_mode_populates_rationale() {
        let policies = vec![policy(
            "allow-admins",
            Effect::Allow,
            0,
            &[],
            "principal.roles",
            Operator::Contains,
            json!("admin"),
        )];
        let d = Evaluator::new().with_explain(true).evaluate(&req("read", "admin"), &policies);
        let expl = d.explanation.expect("explanation");
        assert_eq!(expl.matched_policy.as_deref(), Some("allow-admins"));
        assert!(!expl.why.is_empty());
    }

    #[test]
    fn or_and_nesting() {
        let p = Policy {
            id: "or-test".into(),
            effect: Effect::Allow,
            description: "or".into(),
            priority: 0,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![
                vec![Rule {
                    field: "principal.roles".into(),
                    operator: Operator::Contains,
                    value: json!("admin"),
                }],
                vec![Rule {
                    field: "principal.roles".into(),
                    operator: Operator::Contains,
                    value: json!("root"),
                }],
            ],
        };
        let d = Evaluator::new().evaluate(&req("read", "root"), &[p]);
        assert_eq!(d.effect, Effect::Allow);
    }
}
