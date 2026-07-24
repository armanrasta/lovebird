<p align="center">
  <img src="docs/assets/lovebird-banner.png" alt="Lovebird" width="720"/>
</p>

<h1 align="center">Lovebird</h1>

<p align="center">
  <strong>Offline-first security decision engine.</strong><br/>
  One policy language. Graph + behavior context. Signed, explainable decisions.<br/>
  Embed in Rust today — serve any language tomorrow.
</p>

<p align="center">
  <a href="https://github.com/armanrasta/lovebird/actions/workflows/ci.yml"><img src="https://github.com/armanrasta/lovebird/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <img src="https://img.shields.io/badge/rust-edition%202024-orange" alt="Rust 2024"/>
  <img src="https://img.shields.io/badge/offline--first-yes-darkgreen" alt="Offline-first"/>
  <img src="https://img.shields.io/badge/license-see%20repo-lightgrey" alt="License"/>
</p>

---

## Why Lovebird

Most teams stitch **OPA + UEBA + graph tool + CT monitor + honeypot** and still don’t share one notion of *a decision*.

Lovebird is built so every answer is:

> *Should this principal do this action on this resource — given who they are, how they behave, what they can reach, and whether they’ve already poked our decoys?*

| Belief | Meaning |
|---|---|
| Context over rules | Not a slow if-statement — session/graph facts feed the same evaluator |
| Relationships are truth | Blast radius / crown jewels are first-class |
| Time changes everything | Behavioral baselining, not vibes |
| Zero trust in infra | No cloud required to decide |
| Every decision accountable | Explain Mode + Ed25519 audit entries |

**Not a SIEM. Not a firewall. Not SaaS.** A decision core you can embed or run beside your apps.

---

## Status (honest)

| Capability | State |
|---|---|
| Policy engine (13 operators, deny-overrides, default deny) | ✅ |
| Explain Mode | ✅ |
| Ed25519 signed `AuditEntry` | ✅ |
| Offline CLI (`validate` / `lint` / `test` / `dry-run` / `diff` / `shadow`) | ✅ |
| Harsh multi-OS CI (Ubuntu, macOS, Windows, Debian, CentOS Stream) | ✅ |
| HTTP server for Java/Python/Go | 🚧 stub |
| Session / graph / identity / honeypot | 🚧 planned |

Phase 0 foundation is usable as a **Rust library + CLI**. The rest of the vision is on the roadmap — see [`docs/PROJECT.md`](docs/PROJECT.md).

---

## Quick start

### CLI

```bash
cargo run -p lovebird-cli -- policy validate examples/policies/allow-admins.json
cargo run -p lovebird-cli -- policy test \
  examples/policies/allow-admins.json \
  examples/scenarios/basic.json --explain
cargo run -p lovebird-cli -- policy dry-run \
  examples/policies/allow-admins.json \
  --against examples/traffic/sample.jsonl
```

### Rust library

```rust
use lovebird_engine::{Effect, Evaluator, Policy, Request};

let policies: Vec<Policy> = serde_json::from_str(include_str!("policies.json"))?;
let request: Request = /* map from your auth layer */;

let decision = Evaluator::new()
    .with_explain(true)
    .evaluate(&request, &policies);

assert_eq!(decision.effect, Effect::Allow);
// decision.explanation / decision.matched_policy tell you why
```

### Policy shape

```json
{
  "id": "allow-admins",
  "effect": "allow",
  "description": "Admins may read",
  "priority": 10,
  "actions": ["read"],
  "match": [[
    { "field": "principal.roles", "operator": "contains", "value": "admin" }
  ]]
}
```

---

## Architecture (short)

```
┌─────────────────────────────────────────────┐
│  CLI · server (soon) · language SDKs (soon) │
├─────────────────────────────────────────────┤
│  lovebird-engine  — pure, sync, no I/O      │
├─────────────────────────────────────────────┤
│  session · graph · identity · CT · honeypot │
├─────────────────────────────────────────────┤
│  lovebird-common  — shared types            │
└─────────────────────────────────────────────┘
```

Details: [`docs/SYSTEM.md`](docs/SYSTEM.md)

---

## Docs

| Doc | What |
|---|---|
| [`docs/SYSTEM.md`](docs/SYSTEM.md) | Layers, data flow, what works |
| [`docs/PROJECT.md`](docs/PROJECT.md) | Vision, phases, requirements |
| [`docs/CI.md`](docs/CI.md) | Multi-OS CI matrix |
| [`docs/SUPPLY-CHAIN.md`](docs/SUPPLY-CHAIN.md) | Pinned deps / offline builds |

---

## Contributing / CI

PRs must stay green on a deliberately harsh pipeline (fmt, clippy-with-denies, stress tests, Debian + CentOS Stream + macOS + Windows).

```bash
cargo fmt --all -- --check
cargo test --workspace
bash scripts/ci-cli-smoke.sh
```

---

## Roadmap snapshot

1. Thin `lovebird-server` evaluate API  
2. Python / other language clients (#32)  
3. `lovebird-session` → `lovebird-graph`  
4. Threat model before honeypot/identity surfaces  

Issues: https://github.com/armanrasta/lovebird/issues

---

<p align="center">
  <em>Decide with context. Prove it with a signature.</em>
</p>
