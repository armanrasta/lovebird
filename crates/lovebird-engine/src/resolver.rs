use crate::types::Request;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum ResolvedValue<'a> {
    Str(&'a str),
    ListOfStr(&'a [String]),
    Map(&'a HashMap<String, Value>),
    Json(&'a Value),
}

fn lookup_namespaced<'a>(
    context: &'a HashMap<String, Value>,
    prefix: &str,
    rest: &str,
) -> Option<ResolvedValue<'a>> {
    // Flat key: "session.anomaly_score"
    let flat = format!("{prefix}.{rest}");
    if let Some(v) = context.get(&flat) {
        return Some(ResolvedValue::Json(v));
    }
    // Nested object: context["session"]["anomaly_score"]
    if let Some(Value::Object(map)) = context.get(prefix) {
        return map.get(rest).map(ResolvedValue::Json);
    }
    None
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
            } else if let Some(rest) = other.strip_prefix("session.") {
                lookup_namespaced(&request.context, "session", rest)
            } else if let Some(rest) = other.strip_prefix("graph.") {
                lookup_namespaced(&request.context, "graph", rest)
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
                resolve_field(request, path).map_or(Value::Null, |rv| match rv {
                    ResolvedValue::Str(s) => Value::String(s.to_owned()),
                    ResolvedValue::ListOfStr(list) => {
                        Value::Array(list.iter().map(|s| Value::String(s.clone())).collect())
                    }
                    ResolvedValue::Map(_) => Value::Null,
                    ResolvedValue::Json(v) => v.clone(),
                })
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
                    ResolvedValue::Json(v) => match v {
                        Value::String(s) => result.push_str(s),
                        other => result.push_str(&other.to_string()),
                    },
                    ResolvedValue::ListOfStr(list) => result.push_str(&list.join(",")),
                    ResolvedValue::Map(_) => {}
                }
            }
            start = abs_close;
        } else {
            // Unclosed `{{` — keep the remainder literally and stop.
            result.push_str(&s[abs_open..]);
            return result;
        }
    }
    result.push_str(&s[start..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Principal, Request, Resource};
    use std::collections::HashMap;

    fn sample_request() -> Request {
        let mut attrs = HashMap::new();
        attrs.insert("owner".into(), Value::String("alice".into()));
        let mut context = HashMap::new();
        context.insert("hour".into(), Value::from(23));
        context.insert("session.anomaly_score".into(), Value::from(0.9));

        Request {
            principal: Principal {
                id: "alice".into(),
                roles: vec!["admin".into()],
                attributes: attrs,
            },
            action: "read".into(),
            resource: Resource {
                r#type: "doc".into(),
                id: "doc-1".into(),
                attributes: HashMap::new(),
            },
            context,
        }
    }

    #[test]
    fn resolves_basic_fields() {
        let req = sample_request();
        assert!(matches!(resolve_field(&req, "principal.id"), Some(ResolvedValue::Str("alice"))));
        assert!(matches!(resolve_field(&req, "action"), Some(ResolvedValue::Str("read"))));
    }

    #[test]
    fn whole_string_placeholder_preserves_type() {
        let req = sample_request();
        let v = substitute_placeholders(&Value::String("{{context.hour}}".into()), &req);
        assert_eq!(v, Value::from(23));
    }

    #[test]
    fn embedded_placeholder_coerces_to_string() {
        let req = sample_request();
        let v = substitute_placeholders(&Value::String("user={{principal.id}}".into()), &req);
        assert_eq!(v, Value::String("user=alice".into()));
    }

    #[test]
    fn malformed_placeholder_does_not_loop() {
        let req = sample_request();
        let v = substitute_placeholders(&Value::String("hello {{unclosed".into()), &req);
        assert_eq!(v, Value::String("hello {{unclosed".into()));
    }

    #[test]
    fn resolves_session_flat_key() {
        let req = sample_request();
        assert!(matches!(
            resolve_field(&req, "session.anomaly_score"),
            Some(ResolvedValue::Json(Value::Number(_)))
        ));
    }

    #[test]
    fn adversarial_inputs_do_not_panic() {
        let req = sample_request();
        let long = "a".repeat(10_000);
        let weird_paths = [
            "",
            ".",
            "..",
            "principal.",
            "principal.attributes.",
            "context.",
            "session.",
            "graph.",
            "{{",
            long.as_str(),
            "principal.attributes.\0",
            "context.🚀",
        ];
        for path in weird_paths {
            let _ = resolve_field(&req, path);
        }

        let weird_values = [
            Value::String(String::new()),
            Value::String("{{".into()),
            Value::String("{{}}".into()),
            Value::String("{{principal.id}}{{principal.id}}".into()),
            Value::String(format!("x{}y", "{{".repeat(100))),
            Value::Array(vec![Value::String("{{principal.id}}".into()); 50]),
            Value::Object(serde_json::Map::from_iter([(
                "k".into(),
                Value::String("{{context.hour}}".into()),
            )])),
            Value::Null,
        ];
        for v in &weird_values {
            let _ = substitute_placeholders(v, &req);
        }
    }

    #[test]
    fn request_json_roundtrip_smoke() {
        let req = sample_request();
        let encoded = serde_json::to_string(&req).expect("serialize");
        let decoded: Request = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.principal.id, "alice");
    }
}
