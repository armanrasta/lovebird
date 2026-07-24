# Lovebird — Project Documentation

**Version:** 0.1.0 (Phase 0 — Foundation)
**Status:** Phase 0 core path largely in place: engine + Explain Mode + DecisionSigner (Ed25519) + offline CLI (`policy validate`/`test`, `audit verify`) + crates.io pins + CI. Still missing: session/graph/identity/honeypot/server implementations, fuzz corpus, dry-run/shadow/linter polish.
**Document purpose:** Single source of truth for what Lovebird is, why it exists, what it needs, what exists today, what's missing, and how it gets built out.

---

## Table of Contents

1. [What Lovebird Is](#1-what-lovebird-is)
2. [Why It Needs to Exist](#2-why-it-needs-to-exist)
3. [Who It's For](#3-who-its-for)
4. [Architecture](#4-architecture)
5. [The Policy Language](#5-the-policy-language)
6. [Crate-by-Crate Specification](#6-crate-by-crate-specification)
7. [Current State of the Repository](#7-current-state-of-the-repository)
8. [Gaps and Risks](#8-gaps-and-risks)
9. [Requirements](#9-requirements)
10. [Deployment Models](#10-deployment-models)
11. [Development Phases / Roadmap](#11-development-phases--roadmap)
12. [Immediate Action Items](#12-immediate-action-items)
13. [Governance / Definition of Done](#13-governance--definition-of-done)
14. [Open Questions](#14-open-questions)

**Also see:** [`SYSTEM.md`](SYSTEM.md) (how the system fits together), [`CI.md`](CI.md) (multi-OS gates), [`SUPPLY-CHAIN.md`](SUPPLY-CHAIN.md) (dependency pins).

---

## 1. What Lovebird Is

> Lovebird is an embeddable, offline-first security decision engine that understands relationships between assets, learns from behavior over time, and enforces policy across distributed environments — compiled into a single binary that any engineer can trust, audit, and ship anywhere.

It is a policy/authorization engine (in the spirit of OPA or Cedar) extended with three things most policy engines treat as out-of-scope:

- **Graph context** — what can this principal actually reach, and how dangerous is that reach?
- **Behavioral/temporal context** — is this request normal for this principal, right now?
- **Deception & threat signal** — honeypots and CT monitoring that feed the same evaluator, so an "attacker showed up here yesterday" fact can change today's decision.

All of it is designed to compile into one static binary with no network dependency at runtime and a cryptographically verifiable audit trail.

### The Five Beliefs (non-negotiable design constraints)

| # | Belief | Practical implication |
|---|--------|------------------------|
| 1 | Context over rules | A rule engine alone is "a slow if-statement" — every decision must be able to consult session + graph context, not just the request body |
| 2 | Relationships are the truth | Security posture lives in the graph, not on individual nodes — `lovebird-graph` is a first-class citizen, not a bolt-on |
| 3 | Time changes everything | Decisions must be able to reason about history (`lovebird-session`), not just the current instant |
| 4 | Zero trust in the infrastructure | No cloud calls, no registry dependency at runtime, works fully air-gapped |
| 5 | Every decision is accountable | Decisions are signed and independently verifiable (`AuditEntry`), not just logged |

Any proposed feature should be tested against these five beliefs before it's accepted into the project.

### What Lovebird explicitly is NOT

- Not a SIEM (no log storage/search at scale)
- Not a firewall (no packet inspection)
- Not an EDR (no endpoint process monitoring)
- Not a cloud scanner (no automatic AWS/GCP/Azure crawling)
- Not an AI platform (intelligence is a layer, not the foundation)
- Not SaaS (never requires an external connection to function)

---

## 2. Why It Needs to Exist

Today, the personas below stitch together 4–6 separate tools (OPA/Cedar for policy, a SIEM for logs, Thinkst Canary for deception, a CT monitor, a UEBA product for behavior, a graph tool like BloodHound/JupiterOne for blast radius) — each with its own config language, its own deployment model, and no shared concept of "a decision." Lovebird's reason to exist is **consolidation without dumbing down**: one policy language, one audit format, one binary, that still lets each signal source (graph, session, CT, honeypot) contribute to the same evaluation.

The secondary reason to exist is **trust**. Most modern security tooling assumes a live cloud connection. Lovebird explicitly targets the environments where that assumption is false or actively dangerous (air-gapped networks, IoT/edge devices, defense contractors).

---

## 3. Who It's For

| Persona | Core need | Cannot tolerate |
|---|---|---|
| **Embedded Engineer** | Single binary, zero deps, full control, in-process decisions | 400MB JVM, cloud API calls, license servers |
| **Startup Security Engineer (team of 1)** | One tool, one config file, one audit log, instead of 5 separate products | Operational overhead of running OPA + SIEM + CT monitor + honeypot separately |
| **Defense / Gov Contractor** | Fully offline, every dependency auditable to source commit, cryptographic accountability | Any external network dependency, unauditable supply chain |
| **Security Researcher** | Honeypot producing structured, policy-graded intelligence | Alert-only honeypots with no context or exportability |

**Product implication:** these four personas want meaningfully different things (see [§8 Gaps and Risks](#8-gaps-and-risks)). Early messaging and the first shipped surface area should pick one, most likely the **Embedded Engineer / embeddable-library** persona, since `lovebird-engine` as a pure, dependency-light, deterministic library is achievable first and valuable standalone.

---

## 4. Architecture

Four layers, each depending only downward:

```
┌─────────────────────────────────────────────────────────────────────┐
│ LAYER 4: INTERFACES        HTTP API · gRPC · Admin UI · CLI · Webhooks │
├─────────────────────────────────────────────────────────────────────┤
│ LAYER 3: DECISION ENGINE   Policy Evaluator · Graph Reasoner ·        │
│                             Behavioral Analyzer · Signer · Alert Router│
├─────────────────────────────────────────────────────────────────────┤
│ LAYER 2: SIGNAL COLLECTORS CT Monitor · Honeypot · Identity Verifier ·│
│                             Asset Graph Builder · Session Tracker     │
├─────────────────────────────────────────────────────────────────────┤
│ LAYER 1: FOUNDATION        Common Types · Policy Language · Resolver ·│
│                             Validator · Audit Log · Crypto · Config   │
└─────────────────────────────────────────────────────────────────────┘
```

### Target workspace layout

```
lovebird/
├── crates/
│   ├── lovebird-common/       # shared types — Layer 1
│   ├── lovebird-engine/       # decision engine — Layer 3 (pure, sync, no I/O)
│   ├── lovebird-graph/        # asset relationship graph — Layer 2
│   ├── lovebird-session/      # behavioral/temporal tracking — Layer 2
│   ├── lovebird-identity/     # JWT/OIDC verification — Layer 2
│   ├── lovebird-ct/           # Certificate Transparency monitor — Layer 2
│   ├── lovebird-honeypot/     # deception server — Layer 2
│   └── lovebird-federation/   # multi-node coordination — Layer 4
├── lovebird-server/           # the binary — Layer 4
└── lovebird-cli/              # operator tool — Layer 4
```

**Key architectural rule:** `lovebird-engine` has no network access and is fully deterministic. Everything network-facing or stateful (graph loading, session tracking, CT polling, honeypot serving) lives in its own crate and *injects* context into the engine at evaluation time. This is what makes the "embed it anywhere" promise possible — an embedder can use just `lovebird-common` + `lovebird-engine` and skip everything else.

---

## 5. The Policy Language

A policy answers one question: *"For requests matching these conditions, what is the effect?"*

```jsonc
{
  "id":          "string, unique, human-readable",
  "effect":      "allow | deny",
  "description": "string — required, explains intent",
  "priority":    0,                 // higher wins on conflict
  "actions":     ["read", "write"], // scope; default = all actions
  "match": [              // outer array = OR
    [                     // inner array = AND
      { "field": "principal.roles", "operator": "contains", "value": "admin" },
      { "field": "resource.attributes.owner", "operator": "equals", "value": "{{principal.id}}" }
    ]
  ]
}
```

**Field paths available to rules:**
```
action
principal.id / principal.roles / principal.attributes.<key>
resource.type / resource.id / resource.attributes.<key>
context.<key>
session.anomaly_score / session.impossible_travel_detected /
  session.failed_auth_count / session.request_count
graph.blast_radius_score / graph.crown_jewel_reachable / graph.resource_sensitivity
```

**Operators (implemented):**
`Equals, NotEquals, In, NotIn, Contains, NotContains, StartsWith, EndsWith, Exists, NotExists, GreaterThan, LessThan, Regex`

**Operator coercion (locked):**
- Type mismatches never panic; they return `false` (except `Exists`/`NotExists`, which key on field presence).
- `Equals`/`NotEquals`: JSON value equality; no string↔number coercion.
- `In`/`NotIn`: membership in a target array.
- `Contains`/`NotContains`: substring for strings; membership for arrays/lists.
- `StartsWith`/`EndsWith`: string-only; else `false`.
- `GreaterThan`/`LessThan`: numeric when both sides parse as numbers; else `false`.
- `Regex`: invalid patterns are rejected at **validation** time; at eval time a bad pattern yields `false` (never panics).

**Placeholders:** `"{{path}}"` — whole-string placeholders preserve native type; placeholders embedded in a larger string coerce to string. Implemented in `resolver.rs`.

**Evaluation order:**
1. Filter policies by `actions` scope
2. Sort by `priority` descending
3. First matching **Deny** → immediate deny (nothing further evaluated)
4. First matching **Allow** (after all Denies are checked) → allow
5. Nothing matches → **default deny**

---

## 6. Crate-by-Crate Specification

### `lovebird-common` — shared language
No logic, no network, no side effects. Types: `Request`, `Principal`, `Resource`, `Policy`, `Rule`, `Effect`, `Operator`, `Decision`, `Alert` (+ `AlertSeverity`/`AlertSource`), `AssetNode`/`AssetEdge` (+ `AssetType`/`Relationship`), `SessionState`, `HoneyToken` (+ `TokenType`), `AuditEntry`. Single error enum `LovebirdError` with a project-wide `Result<T>` alias.

### `lovebird-engine` — the brain
Modules: `resolver` (done), `evaluator` (stub only), `operators` (not present), `validation` (stub only), `signer` (not present), `audit` (not present). Pure, synchronous, deterministic — the one crate every deployment model shares unchanged.

### `lovebird-graph` — relationships
`builder`, `graph` (add/query nodes+edges, reachability, shortest path), `blast_radius` (reachable/sensitive/crown-jewel scoring), `attack_paths` (ranked path discovery), `context_extractor` (packages graph facts as `graph.*` fields for the evaluator). **Not yet in the workspace.**

### `lovebird-session` — memory
`store` (concurrent in-memory session store), `analyzer` (anomaly scoring, impossible-travel detection, MFA-fatigue detection, velocity-spike detection, credential-stuffing detection), `context_extractor` (packages as `session.*` fields). **Not yet in the workspace.**

### `lovebird-identity` — trust verification
`jwt` (HMAC/RS256/ES256 verification, claims → `Principal`), `oidc` (JWKS caching/refresh), `enricher` (claim → attribute mapping). **Not yet in the workspace.**

### `lovebird-ct` — certificate watcher
`config`, `monitor` (polling loop against crt.sh), `similarity` (typosquat/homoglyph detection), `pre_cert_detector`, `baseline` (per-domain CA history — flags a technically-trusted CA if it's never issued for this domain before). **Scaffolded in workspace; body not implemented.**

### `lovebird-honeypot` — deception
`config`, `server` (actix-web decoy endpoints), `routes` (decoy handler → synthetic `Request` → engine grades severity → honey-token issued → alert emitted), `token_store`, `honey_credentials` (fake-but-realistic AWS keys, DB creds, API keys, JWTs, `.env` files), `attacker_profiler` (aggregates requests per IP into a sophistication/tooling profile). **Scaffolded in workspace; body not implemented.**

### `lovebird-federation` — distribution
`config`, `policy_sync` (push/pull/merge with priority-wins conflict resolution + provenance), `alert_aggregator`, `federated_query` (`who_accessed`, `where_is`, cross-node blast radius). **Not yet in the workspace. Phase 5 — lowest priority.**

### `lovebird-server` — the binary
`config` (loads `lovebird.json`, wires every optional module), `startup` (fail-fast validation before binding any port), `api` (REST surface listed below), `grpc` (streaming-capable equivalent), `state` (`AppState` holding `Arc`s to evaluator/graph/session/token-store/audit-log). **Scaffolded; only wiring, no implementation.**

REST surface (target):
```
POST   /api/v1/authz/evaluate
POST   /api/v1/authz/evaluate/batch
GET    /api/v1/policies
POST   /api/v1/policies/validate
GET    /api/v1/graph/blast-radius/{principal_id}
GET    /api/v1/graph/attack-paths/{from}/{to}
GET    /api/v1/alerts
GET    /api/v1/session/{principal_id}
DELETE /api/v1/session/{principal_id}
GET    /api/v1/honeypot/tokens
GET    /api/v1/honeypot/profiles
GET    /health
GET    /admin
```

### `lovebird-cli` — operator tool
`policy validate|test|list`, `graph load|blast-radius|attack-paths|crown-jewels`, `audit verify|inspect`, `simulate <scenario>` (regression testing for policy changes), `config validate`, `honeypot generate-token`, `version`. **Not yet in the workspace.**

---

## 7. Current State of the Repository

What actually exists today, cross-referenced against the spec above:

| Crate | In workspace? | Status |
|---|---|---|
| `lovebird-common` | ✅ | Shared types live here: `Request`, `Principal`, `Resource`, `Policy` (with `actions`/`priority`), `Rule`, `Effect`, all 13 `Operator`s, `Decision`, `Explanation`, `Alert`, `AssetNode`/`AssetEdge`, `SessionState`, `HoneyToken`, `AuditEntry`, `LovebirdError`. |
| `lovebird-engine` | ✅ | Compiles and has tests. `resolver` (field + placeholders, including `session.*`/`graph.*` via context), `operators` (all 13), `evaluator` (deny-overrides + Explain Mode), `validation` (collect-all errors, regex checked at validate time). |
| `lovebird-ct` | ✅ | Cargo.toml + empty `lib.rs`/stub `main.rs` only. No `config`/`monitor`/`similarity`/etc. modules. |
| `lovebird-honeypot` | ✅ | Same as above — Cargo.toml + stub only. |
| `lovebird-server` | ✅ | Cargo.toml + stub `main.rs` printing `"Hello, world!"`. No config loading, no API, no wiring. |
| `lovebird-graph` | ❌ | Not created. |
| `lovebird-session` | ❌ | Not created. |
| `lovebird-identity` | ❌ | Not created. |
| `lovebird-federation` | ❌ | Not created. |
| `lovebird-cli` | ❌ | Not created. |

**Net assessment:** Phase 0 core engine path is underway. `lovebird-common` + `lovebird-engine` compile with a unit test suite. Remaining Phase 0 work: supply-chain pinning, CLI (`policy validate`/`test`), fuzz/property tests, DecisionSigner/audit, and threat model before Phase 3/4.

---

## 8. Gaps and Risks

### 8.1 Recently fixed (kept for history)
- ~~`edition = "2024"` unstable~~ — Rust 2024 is stable on current toolchains (`rustc 1.96+`); keep `edition = "2024"`.
- ~~Empty/missing `evaluator.rs` / `validation.rs`~~ — implemented; crate compiles.
- ~~Only 6 of 13 operators~~ — all 13 implemented in `operators.rs` with documented coercion rules.
- ~~Types owned by engine~~ — relocated to `lovebird-common`; engine re-exports.

### 8.1b Remaining Phase 0 gaps
- Supply-chain pinning still uses floating git branches (see §8.2).
- No CLI yet (`lovebird-cli`).
- No DecisionSigner / signed AuditEntry yet (FR5).
- Fuzz/property coverage incomplete (NFR6).

### 8.2 Supply-chain / "Build Guarantee" contradiction
The blueprint promises: *"Every dependency is pinned to a specific Git commit … the build never touches a package registry … the full dependency tree is auditable to source code."* The current `Cargo.toml`/`Cargo.lock` instead point `serde`, `serde_json`, `tokio`, `proc-macro2`, `quote`, `syn`, `unicode-ident`, `anyhow`, `pin-project-lite` at **`branch = "master"`** of their upstream repos (not even a pinned commit — `Cargo.lock` does capture a specific commit hash today, but the *manifest* itself tracks a moving branch, so the next `cargo update` silently pulls unreviewed, unreleased upstream code). For the Defense/Gov persona this directly undermines the pitch. **Recommendation:** pin to tagged releases (or vendor via `cargo vendor`), and reserve git-branch dependencies for cases with a documented, reviewed reason.

### 8.3 Scope risk
The full blueprint is roughly **six separate funded-startup-sized products** (policy engine, UEBA/behavioral analytics, asset graph/attack-path analysis, CT monitoring, deception platform, identity verification) plus federation. Historically, projects at this ambition level die when phases 2–6 never ship because phase 0 isn't finished, or because effort gets spread thin across all six instead of making one excellent. **Recommendation:** Phase 0 (`lovebird-common` + `lovebird-engine` + CLI `policy test/validate`) should be shippable and genuinely excellent on its own before any other crate gets real implementation effort.

### 8.4 Persona conflict
- The **embedded/IoT persona** wants a minimal, sync, dependency-light library.
- The **gov-contractor persona** wants heavy auditability/compliance tooling (not currently scoped anywhere — no FedRAMP/compliance mapping exists in the doc).
- The **solo security engineer persona** wants batteries-included convenience (dashboards, one-command deploy) — in tension with "offline-first, no phone-home, zero dependencies."

These aren't fatal, but the first public release should target **one** persona's definition of "done," most likely the embedded engineer, since it's the cheapest to satisfy and the most differentiated.

### 8.5 "Learns from behavior" language risk
`lovebird-session`'s `BehaviorAnalyzer` as specified is deterministic heuristics (velocity thresholds, haversine-distance/time impossible-travel math, repeat-MFA counters) — not machine learning. This is a *good* design choice (explainable, auditable, no training data needed) but the marketing language ("learns from behavior over time") oversells it to an audience — security engineers — who will notice and discount the whole pitch on that basis. **Recommendation:** reframe as "behavioral baselining" rather than "learning."

### 8.6 Attack surface of Lovebird itself
Bundling actix-web + tokio + rustls + JWT/OIDC + CT polling + honeypot response generation + a graph engine into one 25MB static binary is achievable, but every one of those subsystems is new attack surface on a tool whose entire value proposition is "trust me in a hostile environment." No threat model for Lovebird's *own* server currently exists in the documentation. **Recommendation:** add one before Phase 3 (identity) and Phase 4 (honeypot) land, since those are the two highest-risk surfaces (an OIDC JWKS fetch path and an intentionally-attacker-facing honeypot server).

### 8.7 Missing from the blueprint entirely
- No compliance/certification story (SOC2/FedRAMP mapping) despite a named persona that will ask for it.
- No performance targets stated anywhere (p99 latency for `evaluate()`, max policies/graph size supported, memory ceiling for embedded targets).
- No versioning/compatibility policy for the policy language itself (what happens when `Operator` grows a 14th variant — do old policy files still validate?).
- No stated plan for policy authoring UX beyond raw JSON (the CLI has `policy validate/test`, but nothing for policy *authoring* until the Phase 6 VS Code extension).

---

## 9. Requirements

### 9.1 Functional requirements
- **FR1:** Given a `Request` and a set of `Policy` objects, `Evaluator::evaluate` must return a `Decision` per the evaluation order in §5, with zero panics for any well-formed input.
- **FR2:** All 13 spec'd operators must be implemented and unit-tested, including edge cases (`Regex` with an invalid pattern must be caught at validation time, not panic at evaluation time).
- **FR3:** `validate_policies` must collect *all* errors across all policies in one pass (not fail-fast), and every error must be actionable (which policy, which field, why).
- **FR4:** Placeholder substitution (already implemented in `resolver.rs`) must continue to preserve native JSON types for whole-string placeholders and coerce to string for embedded placeholders — this behavior is a contract other crates depend on.
- **FR5:** Every `Decision` must be signable via `DecisionSigner` and independently verifiable from the resulting `AuditEntry` alone, without needing the original `Request`/`Policy` set in hand.
- **FR6:** `lovebird-graph`, `lovebird-session`, `lovebird-identity` must each expose a `*ContextExtractor` that maps their domain state into flat `graph.*`/`session.*` fields consumable by `resolve_field` — no changes to the resolver should be needed as new context sources are added.
- **FR7:** The CLI must support offline `policy test` and `simulate` against local files with no network access, enabling regression testing of policy changes in CI.

### 9.2 Non-functional requirements
- **NFR1 (Determinism):** `lovebird-engine` must have no network I/O and no non-deterministic behavior (no wall-clock reads inside pure evaluation — inject "now" as part of context instead) so that the same `Request` + `Policy` set + context always yields the same `Decision`.
- **NFR2 (Portability):** Final binary must build for ARM and x86_64, run under `FROM scratch`, and target sub-25MB with musl static linking.
- **NFR3 (Offline build):** No build step may require network access once dependencies are vendored/pinned.
- **NFR4 (Auditability):** Every dependency must be traceable to reviewed source; no floating branch dependencies in the manifest (see §8.2).
- **NFR5 (Fail-fast startup):** `lovebird-server` must validate all configuration (policies, graph file, identity keys, peer addresses) before binding any network port.
- **NFR6 (Test coverage):** Phase 0 exit criteria requires a full test suite for `lovebird-engine` with zero known panics under fuzzed input before any other crate proceeds.
- **NFR7 (Documented performance envelope):** Before Phase 2 (graph) ships, publish target latency/throughput numbers for `evaluate()` at stated policy-set sizes, and memory ceiling for the embedded deployment model.

### 9.3 Explicitly out of scope (per §1)
Bulk log storage/search, packet-level inspection, endpoint process monitoring, automatic cloud resource discovery, any requirement on an external service to produce a decision.

---

## 10. Deployment Models

| Model | Shape | Best for |
|---|---|---|
| **Embedded library** | App imports `lovebird-engine` directly, in-process | IoT, edge, perf-critical services |
| **Sidecar** | Separate process, same host, called via HTTP/gRPC | Kubernetes, Docker Compose, polyglot services |
| **Gateway** | Sits at the perimeter, all traffic passes through | API gateways, zero-trust perimeters |
| **Federated fabric** | Multiple authoritative nodes, Git-synced policies, aggregated alerts | Multi-region, air-gapped, data-sovereign deployments |

All four share the same policy language and audit log format — a policy authored for the embedded model must work unchanged in the federated model.

---

## 11. Development Phases / Roadmap

| Phase | Goal | Deliverable | Exit criteria |
|---|---|---|---|
| **0 — Correctness** *(current)* | Engine is bulletproof | Full test suite passing, zero panics under any input | Nothing else ships until this is true |
| **1 — Temporal awareness** | Engine understands time/behavior | `lovebird-session` integrated; `session.*` fields live in rules; anomaly scoring + impossible-travel detection working | Session context provably changes decisions in test scenarios |
| **2 — Relationship awareness** | Engine understands asset connections | `lovebird-graph` integrated; blast radius computed on every decision; CLI graph commands working | Blast radius numbers verified against a hand-built test asset map |
| **3 — Identity verification** | Verify who is asking, not just what they claim | `lovebird-identity` integrated into server; JWT + OIDC verification; claim mapping | JWT/OIDC verification passes a standard conformance test suite |
| **4 — Deep deception** | Honeypot becomes an intelligence platform | Honey-credentials, attacker profiling, realistic fake environments, post-exfil tracking | Attacker profile output reviewed by a security researcher for realism/usefulness |
| **5 — Federation** | Scale across environments without centralizing data | Policy sync, alert aggregation, federated queries, multi-node e2e | Three-node cluster demonstrably converges policy state and answers federated queries |
| **6 — Ecosystem** | Others can build on Lovebird | CLI complete, gRPC SDK, policy library, VS Code extension | External (non-maintainer) contributor ships a policy pack without hand-holding |

---

## 12. Immediate Action Items

**Done:** relocate types to `lovebird-common`; implement `Evaluator` + Explain Mode; validation (collect-all); all 13 operators + coercion table; `Policy.actions`/`priority`; remove orphan root `src/main.rs`; correct stale §7/§8 claims.

**Done (this slice):** crates.io pins (`docs/SUPPLY-CHAIN.md`); `DecisionSigner` + `audit verify`; `lovebird-cli` (`policy validate`/`test`); CI offline gate; clippy deny unwrap/expect; policy language version field; launch persona = Embedded Engineer; confidence-score + multi-tenancy deferred.

**Remaining toward a real Phase 0 exit / Phase 1 start:**

1. Expand tests: per-operator units + property/fuzz (`#11`, `#21`).
2. Policy dry-run / diff / linter / shadow (`#20`–`#24`).
3. Threat model before Phase 3/4 (`#18`).
4. Performance envelope before Phase 2 (`#19`).
5. Implement `lovebird-session` then `lovebird-graph` (Phases 1–2).

---

## 13. Governance / Definition of Done

Every feature proposal should be run through this checklist before it's accepted (from the blueprint's "Single Truth" test):

- Does this make the decision more **correct**?
- Does this make the decision more **contextual**?
- Does this make the decision more **accountable**?
- Does this make the platform more **embeddable**?
- Does this make the build more **trustworthy**?

If the answer to all five is no, it does not belong in Lovebird.

**Per-crate definition of done** (minimum bar before a crate is considered "shipped," not just "scaffolded"):
- Public API documented with rustdoc, including examples
- Unit tests for every public function; property tests for anything parsing untrusted input
- No `unwrap()`/`expect()` on any path reachable from external input
- CLI or API entry point exists to exercise the crate without writing Rust
- Contributes at least one field/capability that flows into `Decision` (i.e., it's wired into the engine, not just present in the workspace)

---

## 14. Open Questions

These need answers before the corresponding phase starts — flagged rather than guessed at:

1. What's the compliance target (if any) for the Defense/Gov persona — FedRAMP, Common Criteria, something else — and does that change any architectural decision made now? *(Templates `#25` are the non-product answer for now.)*
2. What are the concrete performance targets (`evaluate()` p99 latency, max supported policy count, memory ceiling) for the embedded deployment model? *(Blocked on `#19`.)*
3. ~~Policy language versioning~~ — **decided:** `policy_language_version` on `Policy` (default `"1"`); major mismatch fails validation; additive operators are minor-compatible.
4. ~~Signing scheme~~ — **decided: Ed25519** (`DecisionSigner` in `lovebird-engine::signer`).
5. Federation trust model: how do peer nodes authenticate to each other, and what happens on policy merge conflicts beyond "higher priority wins" — is there a human-in-the-loop path for genuinely ambiguous merges?
6. What does "crown jewel" tagging governance look like — who's allowed to tag/untag an asset as a crown jewel, and is that itself an audited action?
7. ~~Launch persona~~ — **decided: Embedded Engineer** for Phases 0–2.
8. ~~Confidence / graduated effects~~ — **deferred/rejected for v1** (keep binary Effect; optional Advisory later).
9. ~~Multi-tenancy~~ — **out of scope for v1** (Not SaaS).

---

*This document should be updated as phases complete — treat §7 (Current State) and §12 (Immediate Action Items) as living sections that get revised every time a crate moves from scaffold to implemented.*