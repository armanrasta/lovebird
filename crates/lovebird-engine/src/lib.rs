//! Lovebird decision engine — pure, synchronous, deterministic.
//!
//! No network I/O. Inject wall-clock / session / graph facts via `Request.context`.
//! Key generation for [`DecisionSigner`] may use OS RNG; evaluation itself does not.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod evaluator;
pub mod impact;
pub mod linter;
pub mod operators;
pub mod resolver;
pub mod signer;
#[cfg(test)]
mod stress;
pub mod types;
pub mod validation;

pub use evaluator::Evaluator;
pub use impact::{
    DryRunReport, PolicyDiffEntry, ShadowReport, TrafficRecord, diff_policies, dry_run,
};
pub use linter::{LintFinding, LintSeverity, lint_policies};
pub use signer::DecisionSigner;
pub use types::*;
pub use validation::{
    ValidationError, is_known_field_path, validate_policies, validate_single_policy,
};
