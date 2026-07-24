# CI matrix

Harsh gates run on every push/PR. Failures are intentional — fix the code, do not weaken the workflow.

## Jobs

| Job | Where | What |
|---|---|---|
| `fmt` | Ubuntu | `cargo fmt --check` |
| `clippy` | Ubuntu | Deny unwrap/panic/todo/indexing; pedantic warnings |
| `test-os` | **Ubuntu, macOS, Windows** (+ Ubuntu beta) | build + test + stress |
| `test-debian` | **Debian Bookworm** container | build + test + stress |
| `test-centos` | **CentOS Stream 9** container | build + test + stress |
| `docs` | Ubuntu | `cargo doc -D warnings` |
| `audit` | Ubuntu | `cargo audit --deny warnings` |
| `cli-smoke` | Ubuntu, macOS, Windows | full CLI surface via `scripts/ci-cli-smoke.sh` |

CentOS Linux is EOL; Stream 9 is the RHEL-family stand-in.

## Local equivalent

```bash
cargo fmt --all -- --check
cargo clippy --workspace --lib --bins -- -D warnings -D clippy::unwrap_used
cargo test --workspace
cargo test -p lovebird-engine stress_
bash scripts/ci-cli-smoke.sh
```
