//! Lovebird evaluate sidecar. See `docs/THREAT-MODEL.md`.

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]

use anyhow::{Context, Result};
use clap::Parser;
use lovebird_server::{app_state, load_policies, router};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(
    name = "lovebird-server",
    version,
    about = "Lovebird localhost evaluate sidecar (no authn)"
)]
struct Cli {
    /// Policy JSON file (array or single object). Validated before bind.
    #[arg(long, env = "LOVEBIRD_POLICIES")]
    policies: PathBuf,
    /// Bind address. Default is loopback — do not expose without a trusted proxy.
    #[arg(long, env = "LOVEBIRD_BIND", default_value = "127.0.0.1:8080")]
    bind: String,
    /// Populate Decision.explanation
    #[arg(long, env = "LOVEBIRD_EXPLAIN", default_value_t = false)]
    explain: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let policies = load_policies(&cli.policies).with_context(|| {
        format!("fail-fast: invalid or unreadable policies ({})", cli.policies.display())
    })?;
    let addr: SocketAddr =
        cli.bind.parse().with_context(|| format!("invalid --bind address '{}'", cli.bind))?;

    let n = policies.len();
    let app = router(app_state(policies, cli.explain));
    let listener = TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
    let actual = listener.local_addr().with_context(|| format!("local_addr after bind {addr}"))?;
    eprintln!("lovebird-server listening on {actual}  policies={n}  (no authn — loopback assumed)");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server exited")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
