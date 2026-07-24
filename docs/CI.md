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

### Distro notes

- **CentOS Linux is EOL.** We test **CentOS Stream 9** as the RHEL-family stand-in.
- Stream images ship `curl-minimal`. Installing full `curl` requires `dnf install --allowerasing` so the packages can replace each other (otherwise CI fails with a conflict).
- Debian jobs `apt-get install` build-essential + curl before rustup.

## Why so many OS targets?

Lovebird’s pitch includes air-gapped / embedded / gov environments. If the engine only ever builds on one Ubuntu runner, that pitch is theatre. The matrix is meant to catch:

- path / `.exe` assumptions (Windows)
- case-sensitive FS and linker differences (macOS)
- older glibc / OpenSSL headers (Debian, CentOS Stream)

## Local equivalent

```bash
cargo fmt --all -- --check
cargo clippy --workspace --lib --bins -- -D warnings -D clippy::unwrap_used
cargo test --workspace
cargo test -p lovebird-engine stress_
bash scripts/ci-cli-smoke.sh
```

See also [`SYSTEM.md`](SYSTEM.md) for architecture and [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) for dependency rules.
