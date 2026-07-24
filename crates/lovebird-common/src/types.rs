use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Project-wide error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LovebirdError {
    Validation(String),
    Evaluation(String),
    Audit(String),
    Other(String),
}

impl fmt::Display for LovebirdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(m) | Self::Evaluation(m) | Self::Audit(m) | Self::Other(m) => {
                write!(f, "{m}")
            }
        }
    }
}

impl std::error::Error for LovebirdError {}

pub type Result<T> = std::result::Result<T, LovebirdError>;

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub principal: Principal,
    pub action: String,
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

/// Current policy language version. Additive changes bump minor semantics;
/// removing/renaming operators is a major bump that fails validation.
pub const POLICY_LANGUAGE_VERSION: &str = "1";

fn default_policy_language_version() -> String {
    POLICY_LANGUAGE_VERSION.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub effect: Effect,
    pub description: String,
    /// Higher priority wins on conflict. Default `0`.
    #[serde(default)]
    pub priority: i64,
    /// Action scope; empty means all actions.
    #[serde(default)]
    pub actions: Vec<String>,
    /// Policy language version this file was authored against.
    #[serde(default = "default_policy_language_version")]
    pub policy_language_version: String,
    /// Outer Vec = OR, inner Vec = AND.
    pub r#match: Vec<Vec<Rule>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub field: String,
    pub operator: Operator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    NotEquals,
    In,
    NotIn,
    Contains,
    NotContains,
    StartsWith,
    EndsWith,
    Exists,
    NotExists,
    GreaterThan,
    LessThan,
    Regex,
}

/// Outcome of a single policy evaluation against a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub effect: Effect,
    /// Policy id that produced the decision, or `None` for default deny.
    pub matched_policy: Option<String>,
    /// Ordered evaluation trace (for audit / explain).
    #[serde(default)]
    pub evaluated: Vec<PolicyEvalTrace>,
    /// Structured rationale (Explain Mode).
    #[serde(default)]
    pub explanation: Option<Explanation>,
    /// Optional signature filled by DecisionSigner.
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvalTrace {
    pub policy_id: String,
    pub effect: Effect,
    pub matched: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Explanation {
    pub matched_policy: Option<String>,
    #[serde(default)]
    pub why: Vec<String>,
    #[serde(default)]
    pub policies_that_almost_matched: Vec<AlmostMatched>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlmostMatched {
    pub id: String,
    pub missing: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    Engine,
    Session,
    Graph,
    Ct,
    Honeypot,
    Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: AlertSeverity,
    pub source: AlertSource,
    pub message: String,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetType {
    User,
    Service,
    Host,
    Database,
    Bucket,
    Secret,
    Network,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Relationship {
    Owns,
    CanAccess,
    MemberOf,
    Trusts,
    Contains,
    ConnectedTo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetNode {
    pub id: String,
    pub r#type: AssetType,
    #[serde(default)]
    pub sensitivity: u8,
    #[serde(default)]
    pub crown_jewel: bool,
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEdge {
    pub from: String,
    pub to: String,
    pub relationship: Relationship,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionState {
    pub principal_id: String,
    #[serde(default)]
    pub anomaly_score: f64,
    #[serde(default)]
    pub impossible_travel_detected: bool,
    #[serde(default)]
    pub failed_auth_count: u32,
    #[serde(default)]
    pub request_count: u64,
    #[serde(default)]
    pub requests_last_minute: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    AwsKey,
    DbCredential,
    ApiKey,
    Jwt,
    EnvFile,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HoneyToken {
    pub id: String,
    pub token_type: TokenType,
    pub value: String,
    #[serde(default)]
    pub triggered: bool,
}

/// Independently verifiable audit record for a decision.
///
/// Verifiable from this struct + the signer's public key alone (FR5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub decision_effect: Effect,
    pub matched_policy: Option<String>,
    pub principal_id: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    /// Hex-encoded SHA-256 of the canonical signed payload (excluding signature).
    pub payload_hash: String,
    /// Hex-encoded Ed25519 signature over the canonical payload.
    #[serde(default)]
    pub signature: Option<String>,
    /// Hex-encoded 32-byte Ed25519 public key that produced `signature`.
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub explanation: Option<Explanation>,
}

impl Request {
    pub fn dummy() -> Self {
        let mut attrs = HashMap::new();
        attrs.insert("dummy_key".into(), serde_json::Value::String("dummy".into()));

        Request {
            principal: Principal {
                id: "dummy-id".into(),
                roles: vec!["dummy-role".into()],
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
