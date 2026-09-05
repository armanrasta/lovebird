//! Evaluate sidecar — load policies, serve `/health` and `/api/v1/authz/evaluate`.
//!
//! No authentication. Bind loopback only unless the operator overrides `--bind`.
//! Threat model: `docs/THREAT-MODEL.md`.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use axum::routing::{get, post};
use lovebird_engine::{Decision, Effect, Evaluator, Policy, Request, validate_policies};
use serde::Serialize;
use std::path::Path;
use std::sync::Arc;

/// 8 MiB cap on evaluate / batch bodies (T4).
pub const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub policies: Arc<Vec<Policy>>,
    pub evaluator: Evaluator,
}

#[derive(Debug, Serialize)]
pub struct HealthBody {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct PolicySummary {
    pub id: String,
    pub priority: i64,
    pub effect: Effect,
}

#[derive(Debug, Serialize)]
pub struct PolicyList {
    pub policies: Vec<PolicySummary>,
}

#[derive(Debug)]
pub enum LoadError {
    Io(String),
    Parse(String),
    Validation(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(m) | LoadError::Parse(m) | LoadError::Validation(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for LoadError {}

/// Load a policy file (array or single object) and validate before serving.
pub fn load_policies(path: &Path) -> Result<Vec<Policy>, LoadError> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| LoadError::Io(format!("reading {}: {e}", path.display())))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| LoadError::Parse(format!("parsing {}: {e}", path.display())))?;
    let policies: Vec<Policy> = if value.is_array() {
        serde_json::from_value(value)
            .map_err(|e| LoadError::Parse(format!("deserializing {}: {e}", path.display())))?
    } else {
        let p: Policy = serde_json::from_value(value)
            .map_err(|e| LoadError::Parse(format!("deserializing {}: {e}", path.display())))?;
        vec![p]
    };
    validate_policies(&policies).map_err(|errs| {
        let msg = errs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join("; ");
        LoadError::Validation(msg)
    })?;
    Ok(policies)
}

pub fn app_state(policies: Vec<Policy>, explain: bool) -> AppState {
    AppState { policies: Arc::new(policies), evaluator: Evaluator::new().with_explain(explain) }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/authz/evaluate", post(evaluate))
        .route("/api/v1/authz/evaluate/batch", post(evaluate_batch))
        .route("/api/v1/policies", get(list_policies))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

async fn health() -> Json<HealthBody> {
    Json(HealthBody { status: "ok" })
}

async fn evaluate(State(state): State<AppState>, Json(request): Json<Request>) -> Json<Decision> {
    Json(state.evaluator.evaluate(&request, state.policies.as_ref()))
}

async fn evaluate_batch(
    State(state): State<AppState>,
    Json(requests): Json<Vec<Request>>,
) -> Json<Vec<Decision>> {
    let decisions =
        requests.iter().map(|req| state.evaluator.evaluate(req, state.policies.as_ref())).collect();
    Json(decisions)
}

async fn list_policies(State(state): State<AppState>) -> impl IntoResponse {
    let policies = state
        .policies
        .iter()
        .map(|p| PolicySummary { id: p.id.clone(), priority: p.priority, effect: p.effect })
        .collect();
    (StatusCode::OK, Json(PolicyList { policies }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn fixture_state() -> AppState {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/policies/allow-admins.json");
        let policies = load_policies(&path).expect("fixture policies");
        app_state(policies, false)
    }

    async fn json_body(res: axum::http::Response<Body>) -> (StatusCode, Value) {
        let status = res.status();
        let bytes = res.into_body().collect().await.expect("body").to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, value)
    }

    #[tokio::test]
    async fn health_ok() {
        let app = router(fixture_state());
        let res = app
            .oneshot(HttpRequest::builder().uri("/health").body(Body::empty()).expect("req"))
            .await
            .expect("oneshot");
        let (status, body) = json_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");
    }

    #[tokio::test]
    async fn evaluate_admin_allow() {
        let app = router(fixture_state());
        let payload = json!({
            "principal": { "id": "alice", "roles": ["admin"] },
            "action": "read",
            "resource": { "type": "doc", "id": "d1" },
            "context": {}
        });
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/authz/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        let (status, body) = json_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["effect"], "allow");
        assert_eq!(body["matched_policy"], "allow-admins");
    }

    #[tokio::test]
    async fn evaluate_unknown_default_deny() {
        let app = router(fixture_state());
        let payload = json!({
            "principal": { "id": "eve", "roles": ["guest"] },
            "action": "read",
            "resource": { "type": "doc", "id": "d1" }
        });
        let res = app
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/authz/evaluate")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        let (status, body) = json_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["effect"], "deny");
    }

    #[tokio::test]
    async fn batch_and_policy_list() {
        let app = router(fixture_state());
        let payload = json!([
            {
                "principal": { "id": "alice", "roles": ["admin"] },
                "action": "read",
                "resource": { "type": "doc", "id": "d1" }
            },
            {
                "principal": { "id": "eve", "roles": ["guest"] },
                "action": "read",
                "resource": { "type": "doc", "id": "d1" }
            }
        ]);
        let res = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri("/api/v1/authz/evaluate/batch")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .expect("req"),
            )
            .await
            .expect("oneshot");
        let (status, body) = json_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().map(Vec::len), Some(2));
        assert_eq!(body[0]["effect"], "allow");
        assert_eq!(body[1]["effect"], "deny");

        let res = app
            .oneshot(
                HttpRequest::builder().uri("/api/v1/policies").body(Body::empty()).expect("req"),
            )
            .await
            .expect("oneshot");
        let (status, body) = json_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["policies"].as_array().is_some_and(|p| !p.is_empty()));
    }

    #[test]
    fn bad_policy_file_fails_fast() {
        let err = load_policies(Path::new("/no/such/lovebird-policies.json"));
        assert!(matches!(err, Err(LoadError::Io(_))));
    }
}
