use crate::types::{Operator, POLICY_LANGUAGE_VERSION, Policy};
use regex::Regex;
use std::fmt;

/// A single actionable validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub policy_id: String,
    pub field: String,
    pub reason: String,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "policy '{}': {} — {}", self.policy_id, self.field, self.reason)
    }
}

impl std::error::Error for ValidationError {}

/// Known field paths from PROJECT.md §5, including session.* / graph.* prefixes.
pub fn is_known_field_path(path: &str) -> bool {
    const EXACT: &[&str] = &[
        "action",
        "principal.id",
        "principal.roles",
        "principal.attributes",
        "resource.type",
        "resource.id",
        "resource.attributes",
        "context",
        "session.anomaly_score",
        "session.impossible_travel_detected",
        "session.failed_auth_count",
        "session.request_count",
        "session.requests_last_minute",
        "graph.blast_radius_score",
        "graph.crown_jewel_reachable",
        "graph.resource_sensitivity",
    ];

    if EXACT.contains(&path) {
        return true;
    }
    path.starts_with("principal.attributes.")
        || path.starts_with("resource.attributes.")
        || path.starts_with("context.")
        || path.starts_with("session.")
        || path.starts_with("graph.")
}

/// Validate a single policy; returns all errors found (never fail-fast).
pub fn validate_single_policy(policy: &Policy) -> Vec<ValidationError> {
    let mut errors = Vec::new();

    if policy.id.trim().is_empty() {
        errors.push(ValidationError {
            policy_id: policy.id.clone(),
            field: "id".into(),
            reason: "policy id must not be empty".into(),
        });
    }

    if policy.description.trim().is_empty() {
        errors.push(ValidationError {
            policy_id: policy.id.clone(),
            field: "description".into(),
            reason: "description is required and must not be empty".into(),
        });
    }

    // Major version mismatch fails validation; unknown future majors are rejected.
    let major = policy.policy_language_version.split('.').next().unwrap_or("");
    let supported_major = POLICY_LANGUAGE_VERSION.split('.').next().unwrap_or("1");
    if major != supported_major {
        errors.push(ValidationError {
            policy_id: policy.id.clone(),
            field: "policy_language_version".into(),
            reason: format!(
                "unsupported policy language version '{}' (engine supports major {})",
                policy.policy_language_version, supported_major
            ),
        });
    }

    for (or_idx, and_group) in policy.r#match.iter().enumerate() {
        if and_group.is_empty() {
            errors.push(ValidationError {
                policy_id: policy.id.clone(),
                field: format!("match[{or_idx}]"),
                reason: "AND-group must not be empty".into(),
            });
            continue;
        }

        for (and_idx, rule) in and_group.iter().enumerate() {
            let field_loc = format!("match[{or_idx}][{and_idx}].field");
            if rule.field.trim().is_empty() {
                errors.push(ValidationError {
                    policy_id: policy.id.clone(),
                    field: field_loc.clone(),
                    reason: "field path must not be empty".into(),
                });
            } else if !is_known_field_path(&rule.field) {
                errors.push(ValidationError {
                    policy_id: policy.id.clone(),
                    field: field_loc,
                    reason: format!("unknown field path '{}'", rule.field),
                });
            }

            if matches!(rule.operator, Operator::Regex) {
                match rule.value.as_str() {
                    Some(pattern) => {
                        if let Err(e) = Regex::new(pattern) {
                            errors.push(ValidationError {
                                policy_id: policy.id.clone(),
                                field: format!("match[{or_idx}][{and_idx}].value"),
                                reason: format!("invalid regex pattern: {e}"),
                            });
                        }
                    }
                    None => {
                        errors.push(ValidationError {
                            policy_id: policy.id.clone(),
                            field: format!("match[{or_idx}][{and_idx}].value"),
                            reason: "Regex operator requires a string pattern".into(),
                        });
                    }
                }
            }

            if matches!(rule.operator, Operator::In | Operator::NotIn) && !rule.value.is_array() {
                errors.push(ValidationError {
                    policy_id: policy.id.clone(),
                    field: format!("match[{or_idx}][{and_idx}].value"),
                    reason: format!("{:?} operator requires an array value", rule.operator),
                });
            }
        }
    }

    errors
}

/// Validate all policies; collect every error across the set (FR3).
pub fn validate_policies(policies: &[Policy]) -> Result<(), Vec<ValidationError>> {
    let mut all = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    for policy in policies {
        if !seen_ids.insert(policy.id.clone()) {
            all.push(ValidationError {
                policy_id: policy.id.clone(),
                field: "id".into(),
                reason: "duplicate policy id".into(),
            });
        }
        all.extend(validate_single_policy(policy));
    }

    if all.is_empty() { Ok(()) } else { Err(all) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Effect, Rule};
    use serde_json::json;

    fn bare_policy(id: &str) -> Policy {
        Policy {
            id: id.into(),
            effect: Effect::Allow,
            description: "ok".into(),
            priority: 0,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule {
                field: "principal.id".into(),
                operator: Operator::Equals,
                value: json!("x"),
            }]],
        }
    }

    #[test]
    fn accepts_valid_policy() {
        assert!(validate_policies(&[bare_policy("p1")]).is_ok());
    }

    #[test]
    fn collects_multiple_errors() {
        let bad = Policy {
            id: String::new(),
            effect: Effect::Deny,
            description: String::new(),
            priority: 0,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule {
                field: "not.a.real.field".into(),
                operator: Operator::Regex,
                value: json!("[unterminated"),
            }]],
        };
        let err = validate_policies(&[bad]).unwrap_err();
        assert!(err.len() >= 3);
    }

    #[test]
    fn rejects_invalid_regex_at_validation_time() {
        let mut p = bare_policy("re");
        p.r#match[0][0].operator = Operator::Regex;
        p.r#match[0][0].value = json!("(unclosed");
        let err = validate_single_policy(&p);
        assert!(err.iter().any(|e| e.reason.contains("invalid regex")));
    }

    #[test]
    fn known_session_and_graph_paths() {
        assert!(is_known_field_path("session.anomaly_score"));
        assert!(is_known_field_path("graph.blast_radius_score"));
        assert!(is_known_field_path("context.hour"));
        assert!(!is_known_field_path("foo.bar"));
    }

    #[test]
    fn duplicate_ids() {
        let err = validate_policies(&[bare_policy("same"), bare_policy("same")]).unwrap_err();
        assert!(err.iter().any(|e| e.reason.contains("duplicate")));
    }
}
