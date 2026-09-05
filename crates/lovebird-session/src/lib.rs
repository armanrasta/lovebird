//! Temporal / behavioral session tracking — Phase 1.
//!
//! Deterministic heuristics only (no ML). Wall-clock and geo are injected by the
//! caller so evaluation stays replayable (NFR1).

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod analyzer;
pub mod context_extractor;
pub mod store;

pub use analyzer::{BehaviorAnalyzer, BehaviorConfig};
pub use context_extractor::{SessionContextExtractor, enrich_request};
pub use store::{EventKind, SessionEvent, SessionStore};
