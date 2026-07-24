//! Shared language types for Lovebird — Layer 1 foundation.
//!
//! No logic, no network, no side effects. Every crate depends downward on this.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod types;

pub use types::*;
