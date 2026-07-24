//! Semantic policy linter — warnings beyond schema validation.
//!
//! Validation answers "is this legal?"; lint answers "is this wise?"

use crate::types::{Effect, Operator, Policy, Rule};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Warning,
    Suggestion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub severity: LintSeverity,
    pub policy_id: Option<String>,
    pub message: String,
}

impl fmt::Display for LintFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = match self.severity {
            LintSeverity::Warning => "WARNING",
            LintSeverity::Suggestion => "SUGGESTION",
        };
        match &self.policy_id {
            Some(id) => write!(f, "{tag} policy '{id}': {}", self.message),
            None => write!(f, "{tag}: {}", self.message),
        }
    }
}

/// Run all lint rules over a policy set (never fails hard — returns findings).
pub fn lint_policies(policies: &[Policy]) -> Vec<LintFinding> {
    let mut findings = Vec::new();
    findings.extend(lint_broad_allow_default_priority(policies));
    findings.extend(lint_duplicate_conditions(policies));
    findings.extend(lint_identical_match_blocks(policies));
    findings.extend(lint_suspicious_regex(policies));
    findings.extend(lint_empty_match_allow_all(policies));
    findings
}

fn lint_broad_allow_default_priority(policies: &[Policy]) -> Vec<LintFinding> {
    policies
        .iter()
        .filter(|p| {
            p.effect == Effect::Allow && p.actions.is_empty() && p.priority == 0
        })
        .map(|p| LintFinding {
            severity: LintSeverity::Warning,
            policy_id: Some(p.id.clone()),
            message: "broad allow (all actions) with default priority 0 — may be overridden unexpectedly or override too little".into(),
        })
        .collect()
}

fn rule_key(rule: &Rule) -> String {
    format!("{}|{:?}|{}", rule.field, rule.operator, compact_json(&rule.value))
}

fn compact_json(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "?".into())
}

fn lint_duplicate_conditions(policies: &[Policy]) -> Vec<LintFinding> {
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    for p in policies {
        for group in &p.r#match {
            for rule in group {
                seen.entry(rule_key(rule)).or_default().push(p.id.clone());
            }
        }
    }

    let mut out = Vec::new();
    for (_key, ids) in seen {
        let mut unique = ids;
        unique.sort();
        unique.dedup();
        if unique.len() > 1 {
            out.push(LintFinding {
                severity: LintSeverity::Warning,
                policy_id: None,
                message: format!("identical condition appears in policies: {}", unique.join(", ")),
            });
        }
    }
    out
}

fn match_fingerprint(p: &Policy) -> String {
    let mut parts = Vec::new();
    for group in &p.r#match {
        let mut g: Vec<String> = group.iter().map(rule_key).collect();
        g.sort();
        parts.push(g.join("&"));
    }
    parts.sort();
    parts.join("||")
}

fn lint_identical_match_blocks(policies: &[Policy]) -> Vec<LintFinding> {
    let mut by_fp: HashMap<String, Vec<String>> = HashMap::new();
    for p in policies {
        if p.r#match.is_empty() {
            continue;
        }
        by_fp.entry(match_fingerprint(p)).or_default().push(p.id.clone());
    }
    by_fp
        .into_values()
        .filter(|ids| ids.len() > 1)
        .map(|ids| LintFinding {
            severity: LintSeverity::Suggestion,
            policy_id: None,
            message: format!(
                "policies share identical match blocks (possible duplicates): {}",
                ids.join(", ")
            ),
        })
        .collect()
}

fn lint_suspicious_regex(policies: &[Policy]) -> Vec<LintFinding> {
    let mut out = Vec::new();
    for p in policies {
        for (or_i, group) in p.r#match.iter().enumerate() {
            for (and_i, rule) in group.iter().enumerate() {
                if rule.operator != Operator::Regex {
                    continue;
                }
                let Some(pat) = rule.value.as_str() else {
                    continue;
                };
                // Heuristic: nested quantifiers like (a+)+ or (a*)*
                if pat.contains("+)+")
                    || pat.contains("*)*")
                    || pat.contains("+)*")
                    || pat.contains("*)+")
                {
                    out.push(LintFinding {
                        severity: LintSeverity::Warning,
                        policy_id: Some(p.id.clone()),
                        message: format!(
                            "match[{or_i}][{and_i}]: regex looks catastrophic (nested quantifiers) — ReDoS risk"
                        ),
                    });
                }
            }
        }
    }
    out
}

fn lint_empty_match_allow_all(policies: &[Policy]) -> Vec<LintFinding> {
    policies
        .iter()
        .filter(|p| p.r#match.is_empty() && p.effect == Effect::Allow)
        .map(|p| LintFinding {
            severity: LintSeverity::Suggestion,
            policy_id: Some(p.id.clone()),
            message: "empty match with allow — matches all requests in action scope".into(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Rule;
    use serde_json::json;

    fn pol(id: &str, effect: Effect, priority: i64, field: &str, val: Value) -> Policy {
        Policy {
            id: id.into(),
            effect,
            description: id.into(),
            priority,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule {
                field: field.into(),
                operator: Operator::Equals,
                value: val,
            }]],
        }
    }

    #[test]
    fn warns_on_broad_allow() {
        let findings = lint_policies(&[pol("a", Effect::Allow, 0, "principal.id", json!("x"))]);
        assert!(findings.iter().any(|f| f.message.contains("broad allow")));
    }

    #[test]
    fn detects_duplicate_conditions() {
        let findings = lint_policies(&[
            pol("p1", Effect::Allow, 1, "principal.id", json!("x")),
            pol("p2", Effect::Deny, 2, "principal.id", json!("x")),
        ]);
        assert!(findings.iter().any(|f| f.message.contains("identical condition")));
    }
}
