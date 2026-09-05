//! Load graphs from JSON documents.

use crate::graph::{AssetGraph, GraphError};
use lovebird_common::{AssetEdge, AssetNode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphDocument {
    pub nodes: Vec<AssetNode>,
    #[serde(default)]
    pub edges: Vec<AssetEdge>,
}

/// Build an [`AssetGraph`] from a JSON string.
pub fn load_graph_json(json: &str) -> Result<AssetGraph, LoadError> {
    let doc: GraphDocument = serde_json::from_str(json).map_err(LoadError::Json)?;
    build_graph(doc)
}

pub fn build_graph(doc: GraphDocument) -> Result<AssetGraph, LoadError> {
    let mut g = AssetGraph::new();
    for n in doc.nodes {
        g.add_node(n).map_err(LoadError::Graph)?;
    }
    for e in doc.edges {
        g.add_edge(e).map_err(LoadError::Graph)?;
    }
    Ok(g)
}

#[derive(Debug)]
pub enum LoadError {
    Json(serde_json::Error),
    Graph(GraphError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Json(e) => write!(f, "graph JSON: {e}"),
            LoadError::Graph(e) => write!(f, "graph: {e}"),
        }
    }
}

impl std::error::Error for LoadError {}
