use serde::{ Serialize, Deserialize };
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub principal: Principal,
    pub action: String, // add action struct later
    pub resource: Resource,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub r#type: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Query {

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub effect: Effect,
    pub description: String,

    pub r#match: Vec<Vec<Rule>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub field: String,
    pub operator: Operator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Operator {
    Equals,
    NotEquals,
    In,
    Contains,
    StartsWith,
    Exists,
}

impl Request {
    pub fn dummy() -> Self {
        let mut attrs = HashMap::new();
        attrs.insert("dummy_key".into(), serde_json::Value::String("dummy".into()));

        Request {
            principal: Principal {
                id: "dummy-id".into(),
                roles: vec!("dummy-role".into()),
                attributes: attrs.clone(),
            },
            action: "dummy-action".into(),
            resource: Resource {
                r#type: "dummy-type".into(),
                id: "dummy-resource-id".into(),
                attributes: attrs.clone(),
            },
            context: attrs,
        }
    }
}