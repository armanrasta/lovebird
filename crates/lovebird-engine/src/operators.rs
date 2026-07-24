//! Operator implementations with documented type-coercion rules.
//!
//! # Coercion table (decision for issue #16)
//! - Type mismatches never panic; they return `false` (except Exists/NotExists).
//! - `Equals` / `NotEquals`: JSON value equality after resolving; no string↔number coercion.
//! - `In` / `NotIn`: field value is a member of the target array (or string in string array).
//! - `Contains` / `NotContains`: substring for strings; membership for arrays/lists.
//! - `StartsWith` / `EndsWith`: string-only; else `false`.
//! - `GreaterThan` / `LessThan`: numeric only when both sides are JSON numbers; else `false`.
//! - `Exists` / `NotExists`: based on field presence, ignore target value.
//! - `Regex`: target must be a string pattern; applied against string form of field.

use crate::resolver::ResolvedValue;
use serde_json::Value;

/// Result of applying an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchResult {
    True,
    False,
    /// Field was absent — only meaningful for Exists/NotExists.
    FieldAbsent,
}

impl MatchResult {
    pub fn is_match(self) -> bool {
        matches!(self, MatchResult::True)
    }
}

fn as_str(resolved: &ResolvedValue<'_>) -> Option<String> {
    match resolved {
        ResolvedValue::Str(s) => Some((*s).to_owned()),
        ResolvedValue::Json(Value::String(s)) => Some(s.clone()),
        ResolvedValue::Json(Value::Number(n)) => Some(n.to_string()),
        ResolvedValue::Json(Value::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

fn as_number(resolved: &ResolvedValue<'_>) -> Option<f64> {
    match resolved {
        ResolvedValue::Json(Value::Number(n)) => n.as_f64(),
        ResolvedValue::Str(s) => s.parse().ok(),
        _ => None,
    }
}

fn target_number(target: &Value) -> Option<f64> {
    match target {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn resolved_equals_value(resolved: &ResolvedValue<'_>, target: &Value) -> bool {
    match resolved {
        ResolvedValue::Str(s) => target.as_str() == Some(*s),
        ResolvedValue::ListOfStr(list) => match target {
            Value::Array(arr) => {
                arr.len() == list.len()
                    && arr.iter().zip(list.iter()).all(|(a, b)| a.as_str() == Some(b.as_str()))
            }
            Value::String(s) => list.len() == 1 && list.first().is_some_and(|item| item == s),
            _ => false,
        },
        ResolvedValue::Map(_) => false,
        ResolvedValue::Json(v) => *v == target,
    }
}

fn list_contains_value(list: &[String], target: &Value) -> bool {
    match target {
        Value::String(s) => list.iter().any(|item| item == s),
        Value::Number(n) => {
            let s = n.to_string();
            list.iter().any(|item| item == &s)
        }
        _ => false,
    }
}

fn array_contains(arr: &[Value], needle: &Value) -> bool {
    arr.iter().any(|v| v == needle)
}

pub fn apply_equals(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    if resolved_equals_value(resolved, target) { MatchResult::True } else { MatchResult::False }
}

pub fn apply_not_equals(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    if resolved_equals_value(resolved, target) { MatchResult::False } else { MatchResult::True }
}

pub fn apply_in(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let Value::Array(arr) = target else {
        return MatchResult::False;
    };
    let matched = match resolved {
        ResolvedValue::Str(s) => arr.iter().any(|v| v.as_str() == Some(*s)),
        ResolvedValue::Json(v) => array_contains(arr, v),
        ResolvedValue::ListOfStr(list) => {
            list.iter().all(|item| arr.iter().any(|v| v.as_str() == Some(item.as_str())))
        }
        ResolvedValue::Map(_) => false,
    };
    if matched { MatchResult::True } else { MatchResult::False }
}

pub fn apply_not_in(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    match apply_in(resolved, target) {
        MatchResult::True => MatchResult::False,
        MatchResult::False => MatchResult::True,
        MatchResult::FieldAbsent => MatchResult::FieldAbsent,
    }
}

pub fn apply_contains(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let matched = match resolved {
        ResolvedValue::Str(s) => target.as_str().is_some_and(|t| s.contains(t)),
        ResolvedValue::ListOfStr(list) => list_contains_value(list, target),
        ResolvedValue::Json(Value::String(s)) => target.as_str().is_some_and(|t| s.contains(t)),
        ResolvedValue::Json(Value::Array(arr)) => array_contains(arr, target),
        _ => false,
    };
    if matched { MatchResult::True } else { MatchResult::False }
}

pub fn apply_not_contains(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    match apply_contains(resolved, target) {
        MatchResult::True => MatchResult::False,
        MatchResult::False => MatchResult::True,
        MatchResult::FieldAbsent => MatchResult::FieldAbsent,
    }
}

pub fn apply_starts_with(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let Some(field) = as_str(resolved) else {
        return MatchResult::False;
    };
    let Some(prefix) = target.as_str() else {
        return MatchResult::False;
    };
    if field.starts_with(prefix) { MatchResult::True } else { MatchResult::False }
}

pub fn apply_ends_with(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let Some(field) = as_str(resolved) else {
        return MatchResult::False;
    };
    let Some(suffix) = target.as_str() else {
        return MatchResult::False;
    };
    if field.ends_with(suffix) { MatchResult::True } else { MatchResult::False }
}

pub fn apply_exists(field_present: bool) -> MatchResult {
    if field_present { MatchResult::True } else { MatchResult::False }
}

pub fn apply_not_exists(field_present: bool) -> MatchResult {
    if field_present { MatchResult::False } else { MatchResult::True }
}

pub fn apply_greater_than(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let (Some(left), Some(right)) = (as_number(resolved), target_number(target)) else {
        return MatchResult::False;
    };
    if left > right { MatchResult::True } else { MatchResult::False }
}

pub fn apply_less_than(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let (Some(left), Some(right)) = (as_number(resolved), target_number(target)) else {
        return MatchResult::False;
    };
    if left < right { MatchResult::True } else { MatchResult::False }
}

pub fn apply_regex(resolved: &ResolvedValue<'_>, target: &Value) -> MatchResult {
    let Some(pattern) = target.as_str() else {
        return MatchResult::False;
    };
    let Some(haystack) = as_str(resolved) else {
        return MatchResult::False;
    };
    // Compile per-call for now; validation caches/rejects invalid patterns.
    // Invalid patterns at eval time → false (never panic).
    match regex::Regex::new(pattern) {
        Ok(re) => {
            if re.is_match(&haystack) {
                MatchResult::True
            } else {
                MatchResult::False
            }
        }
        Err(_) => MatchResult::False,
    }
}
