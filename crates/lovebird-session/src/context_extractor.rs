//! Maps [`SessionState`] into flat `session.*` keys for the engine resolver.

use lovebird_common::{Request, SessionState};
use serde_json::{Number, Value};
use std::collections::HashMap;

/// Extracts evaluator context from session state (FR6).
pub struct SessionContextExtractor;

impl SessionContextExtractor {
    pub fn extract(state: &SessionState) -> HashMap<String, Value> {
        let mut out = HashMap::new();
        out.insert("session.anomaly_score".into(), json_f64(state.anomaly_score));
        out.insert(
            "session.impossible_travel_detected".into(),
            Value::Bool(state.impossible_travel_detected),
        );
        out.insert(
            "session.failed_auth_count".into(),
            Value::Number(Number::from(state.failed_auth_count)),
        );
        out.insert(
            "session.request_count".into(),
            Value::Number(Number::from(state.request_count)),
        );
        out.insert(
            "session.requests_last_minute".into(),
            Value::Number(Number::from(state.requests_last_minute)),
        );
        out
    }
}

/// Merge session fields into a request's context (overwrites same keys).
pub fn enrich_request(mut request: Request, state: &SessionState) -> Request {
    for (k, v) in SessionContextExtractor::extract(state) {
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
    use lovebird_common::{Effect, Operator, Policy, Principal, Resource, Rule};
    use lovebird_engine::Evaluator;

    #[test]
    fn extract_flat_keys() {
        let state = SessionState {
            principal_id: "u".into(),
            anomaly_score: 0.8,
            impossible_travel_detected: true,
            failed_auth_count: 2,
            request_count: 9,
            requests_last_minute: 3,
        };
        let ctx = SessionContextExtractor::extract(&state);
        assert_eq!(ctx.get("session.impossible_travel_detected"), Some(&Value::Bool(true)));
        assert!(ctx.contains_key("session.anomaly_score"));
    }

    #[test]
    fn session_context_changes_decision() {
        let deny_high = Policy {
            id: "deny-anomaly".into(),
            effect: Effect::Deny,
            description: "Deny high anomaly".into(),
            priority: 50,
            actions: vec!["read".into()],
            r#match: vec![vec![Rule {
                field: "session.anomaly_score".into(),
                operator: Operator::GreaterThan,
                value: Value::Number(Number::from_f64(0.7).expect("num")),
            }]],
            policy_language_version: "1".into(),
        };
        let allow = Policy {
            id: "allow-all-read".into(),
            effect: Effect::Allow,
            description: "Allow reads by default for test".into(),
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
            principal: Principal {
                id: "u1".into(),
                roles: vec!["user".into()],
                attributes: HashMap::new(),
            },
            action: "read".into(),
            resource: Resource {
                r#type: "doc".into(),
                id: "d1".into(),
                attributes: HashMap::new(),
            },
            context: HashMap::new(),
        };

        let calm = enrich_request(
            base.clone(),
            &SessionState {
                principal_id: "u1".into(),
                anomaly_score: 0.1,
                ..SessionState::default()
            },
        );
        let hot = enrich_request(
            base,
            &SessionState {
                principal_id: "u1".into(),
                anomaly_score: 0.9,
                ..SessionState::default()
            },
        );

        let policies = vec![deny_high, allow];
        let ev = Evaluator::new();
        let d_calm = ev.evaluate(&calm, &policies);
        let d_hot = ev.evaluate(&hot, &policies);
        assert_eq!(d_calm.effect, Effect::Allow);
        assert_eq!(d_hot.effect, Effect::Deny);
    }
}
