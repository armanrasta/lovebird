//! Asset relationship graph — Phase 2.
//!
//! Builds an in-memory directed graph from `AssetNode` / `AssetEdge`,
//! computes blast radius / attack paths, and extracts flat `graph.*` context.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod attack_paths;
pub mod blast_radius;
pub mod builder;
pub mod context_extractor;
pub mod graph;

pub use attack_paths::{AttackPath, find_attack_paths};
pub use blast_radius::{BlastRadius, compute_blast_radius};
pub use builder::{GraphDocument, load_graph_json};
pub use context_extractor::{GraphContextExtractor, enrich_request};
pub use graph::{AssetGraph, GraphError};
