# Supply-chain policy

Lovebird targets air-gapped / auditable builds (NFR3, NFR4).

## Rules

1. **Prefer crates.io version pins** in `[workspace.dependencies]`. No `branch = "master"` / `"main"`.
2. Git dependencies are allowed only with a **pinned commit or tag** and a one-line reason in this file.
3. After `cargo fetch` (or vendoring), `cargo build --offline --workspace` must succeed.
4. New dependencies require a short note here (why, license, alternatives considered).

## Current exceptions

None. All workspace dependencies are crates.io version pins.

## Current pinned dependencies (workspace)

| Crate | Why |
|---|---|
| `serde` / `serde_json` | Policy/request serialization |
| `regex` | `Regex` operator + validation |
| `ed25519-dalek` / `rand` / `sha2` / `hex` | DecisionSigner / AuditEntry (FR5) |
| `clap` | `lovebird-cli` |
| `anyhow` | CLI error reporting only (not in engine) |
