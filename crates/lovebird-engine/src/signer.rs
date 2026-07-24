//! Decision signing and audit verification (Ed25519).
//!
//! Decision for issue #14: Ed25519 over HMAC-SHA256 — asymmetric verification
//! without shared secrets, federation-ready, small static footprint.

use crate::types::{AuditEntry, Decision, Effect, Explanation, LovebirdError, Request, Result};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Signs decisions into independently verifiable [`AuditEntry`] records.
pub struct DecisionSigner {
    signing_key: SigningKey,
}

impl DecisionSigner {
    /// Generate a fresh keypair (uses OS RNG — only for key generation, not evaluation).
    pub fn generate() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    /// Construct from a 32-byte secret key.
    pub fn from_secret_bytes(secret: &[u8; 32]) -> Self {
        Self { signing_key: SigningKey::from_bytes(secret) }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Build and sign an [`AuditEntry`] from a request + decision.
    pub fn sign(&self, request: &Request, decision: &Decision) -> AuditEntry {
        let mut entry = AuditEntry {
            decision_effect: decision.effect,
            matched_policy: decision.matched_policy.clone(),
            principal_id: request.principal.id.clone(),
            action: request.action.clone(),
            resource_type: request.resource.r#type.clone(),
            resource_id: request.resource.id.clone(),
            payload_hash: String::new(),
            signature: None,
            public_key: Some(self.public_key_hex()),
            explanation: decision.explanation.clone(),
        };

        let payload = canonical_payload(&entry);
        entry.payload_hash = hex::encode(Sha256::digest(payload.as_bytes()));
        let sig = self.signing_key.sign(payload.as_bytes());
        entry.signature = Some(hex::encode(sig.to_bytes()));
        entry
    }

    /// Verify an audit entry using the public key embedded in the entry (or override).
    pub fn verify_entry(entry: &AuditEntry) -> Result<()> {
        let pk_hex = entry
            .public_key
            .as_deref()
            .ok_or_else(|| LovebirdError::Audit("audit entry missing public_key".into()))?;
        let pk_bytes = decode_32(pk_hex)?;
        Self::verify_with_public_key(entry, &pk_bytes)
    }

    pub fn verify_with_public_key(entry: &AuditEntry, public_key: &[u8; 32]) -> Result<()> {
        let sig_hex = entry
            .signature
            .as_deref()
            .ok_or_else(|| LovebirdError::Audit("audit entry missing signature".into()))?;
        let sig_bytes = decode_64(sig_hex)?;
        let verifying = VerifyingKey::from_bytes(public_key)
            .map_err(|e| LovebirdError::Audit(format!("invalid public key: {e}")))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let payload = canonical_payload(entry);
        let expected_hash = hex::encode(Sha256::digest(payload.as_bytes()));
        if expected_hash != entry.payload_hash {
            return Err(LovebirdError::Audit(
                "payload_hash does not match canonical payload".into(),
            ));
        }

        verifying
            .verify(payload.as_bytes(), &signature)
            .map_err(|e| LovebirdError::Audit(format!("signature verification failed: {e}")))
    }
}

/// Deterministic, field-ordered payload string (no JSON key iteration).
fn canonical_payload(entry: &AuditEntry) -> String {
    let effect = match entry.decision_effect {
        Effect::Allow => "allow",
        Effect::Deny => "deny",
    };
    let matched = entry.matched_policy.as_deref().unwrap_or("");
    let expl = canonicalize_explanation(entry.explanation.as_ref());
    format!(
        "v1|effect={effect}|policy={matched}|principal={}|action={}|rtype={}|rid={}|expl={expl}",
        entry.principal_id, entry.action, entry.resource_type, entry.resource_id
    )
}

fn canonicalize_explanation(expl: Option<&Explanation>) -> String {
    let Some(e) = expl else {
        return String::new();
    };
    let matched = e.matched_policy.as_deref().unwrap_or("");
    let why = e.why.join(";");
    let almost = e
        .policies_that_almost_matched
        .iter()
        .map(|a| format!("{}:{}", a.id, a.missing))
        .collect::<Vec<_>>()
        .join(";");
    format!("{matched}|{why}|{almost}")
}

fn decode_32(hex_str: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| LovebirdError::Audit(format!("invalid hex: {e}")))?;
    bytes.try_into().map_err(|_| LovebirdError::Audit("expected 32 bytes".into()))
}

fn decode_64(hex_str: &str) -> Result<[u8; 64]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| LovebirdError::Audit(format!("invalid hex: {e}")))?;
    bytes.try_into().map_err(|_| LovebirdError::Audit("expected 64 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evaluator::Evaluator;
    use crate::types::{Operator, Policy, Principal, Resource, Rule};
    use serde_json::json;
    use std::collections::HashMap;

    fn sample() -> (Request, Decision) {
        let request = Request {
            principal: Principal {
                id: "alice".into(),
                roles: vec!["admin".into()],
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
        let policies = [Policy {
            id: "allow-admins".into(),
            effect: Effect::Allow,
            description: "admins".into(),
            priority: 0,
            actions: vec![],
            policy_language_version: "1".into(),
            r#match: vec![vec![Rule {
                field: "principal.roles".into(),
                operator: Operator::Contains,
                value: json!("admin"),
            }]],
        }];
        let decision = Evaluator::new().with_explain(true).evaluate(&request, &policies);
        (request, decision)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = DecisionSigner::generate();
        let (request, decision) = sample();
        let entry = signer.sign(&request, &decision);
        assert!(DecisionSigner::verify_entry(&entry).is_ok());
    }

    #[test]
    fn tamper_breaks_verification() {
        let signer = DecisionSigner::generate();
        let (request, decision) = sample();
        let mut entry = signer.sign(&request, &decision);
        entry.principal_id = "eve".into();
        assert!(DecisionSigner::verify_entry(&entry).is_err());
    }
}
