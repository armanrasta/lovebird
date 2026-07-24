//! High-volume stress tests — must stay green under CI `stress_` filter.

use crate::evaluator::Evaluator;
use crate::impact::{TrafficRecord, diff_policies, dry_run};
use crate::linter::lint_policies;
use crate::resolver::{resolve_field, substitute_placeholders};
use crate::signer::DecisionSigner;
use crate::types::{Effect, Operator, Policy, Principal, Request, Resource, Rule};
use crate::validation::validate_policies;
use serde_json::{Value, json};
use std::collections::HashMap;

fn policy(id: &str, effect: Effect, priority: i64, role: &str) -> Policy {
    Policy {
        id: id.into(),
        effect,
        description: id.into(),
        priority,
        actions: vec![],
        policy_language_version: "1".into(),
        r#match: vec![vec![Rule {
            field: "principal.roles".into(),
            operator: Operator::Contains,
            value: json!(role),
        }]],
    }
}

fn request(id: &str, role: &str, action: &str) -> Request {
    Request {
        principal: Principal {
            id: id.into(),
            roles: vec![role.into()],
            attributes: HashMap::new(),
        },
        action: action.into(),
        resource: Resource { r#type: "doc".into(), id: "r1".into(), attributes: HashMap::new() },
        context: HashMap::from([("hour".into(), Value::from(14))]),
    }
}

#[test]
fn stress_evaluate_ten_thousand_requests() {
    let policies: Vec<Policy> = (0..200)
        .map(|i| {
            if i % 3 == 0 {
                policy(&format!("deny-{i}"), Effect::Deny, i, "banned")
            } else {
                policy(&format!("allow-{i}"), Effect::Allow, i, "admin")
            }
        })
        .collect();

    assert!(validate_policies(&policies).is_ok());
    let ev = Evaluator::new().with_explain(true);

    for n in 0..10_000 {
        let role = if n % 17 == 0 { "banned" } else { "admin" };
        let req = request(&format!("u{n}"), role, if n % 2 == 0 { "read" } else { "write" });
        let d = ev.evaluate(&req, &policies);
        if role == "banned" {
            assert_eq!(d.effect, Effect::Deny);
        } else {
            assert_eq!(d.effect, Effect::Allow);
        }
        assert!(d.explanation.is_some());
    }
}

#[test]
fn stress_placeholders_and_resolve_paths() {
    let req = request("alice", "admin", "read");
    for i in 0..5_000 {
        let path = match i % 7 {
            0 => "principal.id",
            1 => "principal.roles",
            2 => "action",
            3 => "resource.type",
            4 => "context.hour",
            5 => "session.missing",
            _ => "graph.missing",
        };
        let _ = resolve_field(&req, path);
        let v = Value::String(format!("id={{{{principal.id}}}}-{i}"));
        let out = substitute_placeholders(&v, &req);
        assert!(out.as_str().is_some_and(|s| s.contains("alice")));
    }
}

#[test]
fn stress_sign_verify_batch() {
    let signer = DecisionSigner::generate();
    let policies = [policy("allow-admin", Effect::Allow, 1, "admin")];
    let ev = Evaluator::new().with_explain(true);

    for n in 0..500 {
        let req = request(&format!("p{n}"), "admin", "read");
        let decision = ev.evaluate(&req, &policies);
        let entry = signer.sign(&req, &decision);
        assert!(DecisionSigner::verify_entry(&entry).is_ok(), "signature verify failed at {n}");
    }
}

#[test]
fn stress_dry_run_and_shadow_and_lint() {
    let prod = vec![policy("allow-admin", Effect::Allow, 10, "admin")];
    let shadow = vec![policy("deny-admin", Effect::Deny, 10, "admin")];
    let _ = lint_policies(&prod);

    let mut traffic = Vec::new();
    for n in 0..1_000 {
        traffic.push(TrafficRecord {
            request: request(&format!("u{n}"), "admin", "read"),
            prior_effect: Effect::Allow,
            principal_hint: None,
        });
    }

    let ev = Evaluator::new();
    let report = dry_run(&ev, &shadow, &traffic);
    assert_eq!(report.newly_denied, 1_000);

    let mut disagree = 0usize;
    for rec in &traffic {
        if !ev.evaluate_shadow(&rec.request, &prod, &shadow).agree {
            disagree += 1;
        }
    }
    assert_eq!(disagree, 1_000);

    let mut newer = prod.clone();
    if let Some(p) = newer.first_mut() {
        p.priority = 99;
    }
    let diffs = diff_policies(&prod, &newer);
    assert!(!diffs.is_empty());
}
