use crate::types::Request;
use serde_json::Value;
use std::collections::HashMap;

pub enum ResolvedValue<'a> {
    Str(&'a str),
    ListOfStr(&'a [String]),
    Map(&'a HashMap<String, Value>),
    Json(&'a Value),
}

pub fn resolve_field<'a>(request: &'a Request, field_path: &str) -> Option<ResolvedValue<'a>> {
    match field_path {
        "action" => Some(ResolvedValue::Str(&request.action)),

        "principal.id" => Some(ResolvedValue::Str(&request.principal.id)),
        "principal.roles" => Some(ResolvedValue::ListOfStr(&request.principal.roles)),
        "principal.attributes" => Some(ResolvedValue::Map(&request.principal.attributes)),

        "resource.type" => Some(ResolvedValue::Str(&request.resource.r#type)),
        "resource.id" => Some(ResolvedValue::Str(&request.resource.id)),
        "resource.attributes" => Some(ResolvedValue::Map(&request.resource.attributes)),

        "context" => Some(ResolvedValue::Map(&request.context)),

        other => {
            if let Some(key) = other.strip_prefix("principal.attributes.") {
                request.principal.attributes.get(key).map(ResolvedValue::Json)
            } else if let Some(key) = other.strip_prefix("resource.attributes.") {
                request.resource.attributes.get(key).map(ResolvedValue::Json)
            } else if let Some(key) = other.strip_prefix("context.") {
                request.context.get(key).map(ResolvedValue::Json)
            } else {
                None
            }
        }
    }
}

pub fn substitute_placeholders(value: &Value, request: &Request) -> Value {
    match value {
        Value::String(s) => {
            if s.starts_with("{{") && s.ends_with("}}") && s.matches("{{").count() == 1 {
                // Single placeholder -> resolve to native value
                let path = &s[2..s.len() - 2];
                resolve_field(request, path)
                    .map(|rv| match rv {
                        ResolvedValue::Str(s) => Value::String(s.to_owned()),
                        ResolvedValue::ListOfStr(list) => {
                            Value::Array(list.iter().map(|s| Value::String(s.clone())).collect())
                        }
                        ResolvedValue::Map(_) => Value::Null,
                        ResolvedValue::Json(v) => v.clone(),
                    })
                    .unwrap_or(Value::Null)
            } else {
                // String with embedded placeholders
                Value::String(replace_embedded_placeholders(s, request))
            }
        }
        Value::Array(arr) => {
            Value::Array(arr.iter().map(|v| substitute_placeholders(v, request)).collect())
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(k.clone(), substitute_placeholders(v, request));
            }
            Value::Object(new_map)
        }
        other => other.clone(),
    }
}

fn replace_embedded_placeholders(s: &str, request: &Request) -> String {
    let mut result = String::new();
    let mut start = 0;
    while let Some(open) = s[start..].find("{{") {
        let abs_open = start + open;
        result.push_str(&s[start..abs_open]);
        if let Some(close) = s[abs_open..].find("}}") {
            let abs_close = abs_open + close + 2;
            let path = &s[abs_open + 2..abs_close - 2];
            if let Some(rv) = resolve_field(request, path) {
                match rv {
                    ResolvedValue::Str(val) => result.push_str(val),
                    ResolvedValue::Json(v) => result.push_str(&v.to_string()),
                    _ => {}
                }
            }
            start = abs_close;
        } else {
            result.push_str(&s[abs_open..]);
            break;
        }
    }
    result.push_str(&s[start..]);
    result
}