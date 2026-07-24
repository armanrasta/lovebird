# Lovebird system overview

This document describes how the Lovebird system is structured today, what runs where, and how pieces talk to each other. For product vision and roadmap see [`PROJECT.md`](PROJECT.md). For dependency policy see [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md). For CI hosts see [`CI.md`](CI.md).

---

## 1. One-sentence system model

**Lovebird is a deterministic policy decision core** (`lovebird-engine`) plus optional collectors and interfaces that *inject context* and *expose decisions* — never the other way around.

```
Your app / CLI / server
        │
        ▼
   lovebird-engine   ← pure evaluate(Request, [Policy]) → Decision
        ▲
        │ context injected at call time
 session / graph / identity / CT / honeypot   (mostly not built yet)
```

---

## 2. Layered architecture

| Layer | Role | Crates today |
|---|---|---|
| **4 — Interfaces** | Humans & foreign languages talk here | `lovebird-cli` ✅ · `lovebird-server` stub · Python SDK planned (#32) |
| **3 — Decision engine** | Pure allow/deny + explain + sign | `lovebird-engine` ✅ |
| **2 — Signal collectors** | Build `session.*` / `graph.*` / identity / deception facts | `lovebird-ct` / `honeypot` stubs · session/graph/identity ❌ |
| **1 — Foundation** | Shared types, errors, audit shape | `lovebird-common` ✅ |

**Hard rule:** Layer 3 has no network I/O and no wall-clock reads. “Now”, geo, JWKS, CT results, etc. arrive inside `Request.context` (or namespaced `session.*` / `graph.*` keys).

---

## 3. Workspace map

```
lovebird/
├── crates/
│   ├── lovebird-common/     # types: Request, Policy, Decision, AuditEntry, …
│   ├── lovebird-engine/     # evaluator, operators, validation, linter, impact, signer
│   ├── lovebird-ct/         # CT monitor (scaffold)
│   └── lovebird-honeypot/   # deception server (scaffold)
├── lovebird-cli/            # offline operator binary (`lovebird`)
├── lovebird-server/         # HTTP/gRPC binary (stub — not serving yet)
├── examples/                # policies, scenarios, traffic JSONL
├── scripts/ci-cli-smoke.sh  # cross-OS CLI gate
└── docs/                    # PROJECT, SYSTEM, CI, SUPPLY-CHAIN
```

---

## 4. Runtime data flow (what exists)

### 4.1 Embedded (Rust) — works now

```
App builds Request { principal, action, resource, context }
     → Evaluator::evaluate(&request, &policies)
     → Decision { effect, matched_policy, explanation?, signature? }
     → optional DecisionSigner::sign → AuditEntry (Ed25519)
```

### 4.2 Offline CLI — works now

| Command | Purpose |
|---|---|
| `policy validate` | Schema + semantic validation (collect all errors) |
| `policy lint` | Warnings: broad allows, dupes, scary regex |
| `policy test` | Scenario regression (`expected_effect`) |
| `policy dry-run` | Replay traffic JSONL → newly denied/allowed |
| `policy diff` | Structural policy diff (+ optional impact) |
| `policy shadow-report` | Production vs shadow agreement % |
| `audit verify` | Verify Ed25519 `AuditEntry` |

### 4.3 Server / multi-language — planned

```
Java / Python / Go  --HTTP/gRPC-->  lovebird-server  -->  lovebird-engine
```

Same JSON `Request` / `Decision` shapes. Python client tracked in issue #32. Server must expose at least `POST /api/v1/authz/evaluate` before foreign SDKs are useful live.

---

## 5. Policy evaluation semantics

Documented contract (engine enforces):

1. Filter by `actions` (empty = all actions)
2. Sort by `priority` descending
3. **Deny overrides allow** — any matching deny wins (highest priority deny among denies)
4. Else first matching allow
5. Else **default deny**

Match structure: outer list = OR, inner list = AND.

Operators (13): `equals`, `not_equals`, `in`, `not_in`, `contains`, `not_contains`, `starts_with`, `ends_with`, `exists`, `not_exists`, `greater_than`, `less_than`, `regex`.

Type coercion: mismatches → `false` (never panic). Invalid regex fails at **validation**, not eval.

Placeholders: `{{principal.id}}` whole-string keeps JSON type; embedded in a larger string → string coerce.

---

## 6. Trust & accountability

| Mechanism | Status |
|---|---|
| Deterministic engine (no I/O) | ✅ |
| Explain Mode (`Evaluator::with_explain`) | ✅ |
| Ed25519 `DecisionSigner` / `AuditEntry` | ✅ |
| crates.io pins + `docs/SUPPLY-CHAIN.md` | ✅ |
| Offline `cargo build` after fetch | ✅ |
| Threat model for server/honeypot | ❌ (#18) |

**Strict intent:** a production audit trail should be a signed `AuditEntry`, not a log line.

---

## 7. Deployment shapes (target)

| Model | Shape | Status |
|---|---|---|
| Embedded library | `use lovebird_engine::…` in-process | ✅ Rust |
| Sidecar | `lovebird-server` on localhost | ❌ stub |
| Gateway | Perimeter evaluate | ❌ |
| Federated fabric | Multi-node policy sync | ❌ Phase 5 |

---

## 8. What is intentionally out of the system

- Bulk log storage / SIEM search
- Packet firewall / EDR
- Cloud resource crawling
- ML “confidence” scores as the authoritative effect
- Required SaaS / phone-home

Lovebird can sit **under** a SIEM as the decision core; it is not the SIEM.

---

## 9. Developer entry points

```bash
# Library
cargo test -p lovebird-engine

# CLI
cargo run -p lovebird-cli -- policy test \
  examples/policies/allow-admins.json \
  examples/scenarios/basic.json --explain

# Harsh local gate (subset of CI)
cargo fmt --all -- --check
cargo clippy --workspace --lib --bins -- -D warnings -D clippy::unwrap_used
cargo test --workspace
bash scripts/ci-cli-smoke.sh
```

---

## 10. Related docs

- [`PROJECT.md`](PROJECT.md) — vision, phases, requirements, open questions  
- [`CI.md`](CI.md) — multi-OS CI matrix and local equivalents  
- [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) — dependency pinning rules  
- GitHub issues — remaining Phase 0+ work (#18 threat model, #19 perf, #21 fuzz CLI, #32 Python, …)
