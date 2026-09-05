# Threat model — evaluate sidecar (v0)

Slice of #18 covering **only** `lovebird-server` as a localhost / private-network evaluate API. Identity, honeypot, CT, and federation stay out of scope until those surfaces exist.

## System under review

```
Caller (CLI, Python, Django, Spring, …)
        │  HTTP  (no authn in v0)
        ▼
lovebird-server   ← loads Policy[] at startup
        │
        ▼
lovebird-engine   ← no I/O, no wall-clock
```

The server binds after fail-fast policy load + `validate_policies`. It evaluates a fully formed `Request` JSON (caller may pre-fill `session.*` / `graph.*`). It does not load session/graph stores or fetch JWKS.

## Trust boundary

| Zone | Assumption |
|---|---|
| Process host | Operator controls the machine and the policy files on disk |
| Bind address | Default `127.0.0.1` — loopback only |
| Callers | Anyone who can reach the bound socket is authorized |

**v0 has no authentication.** That is intentional for an embed/sidecar on localhost. Binding to a public or shared interface without a reverse-proxy auth layer is **unsafe** and out of the supported deployment model.

## Assets

1. **Policy-set integrity** — wrong or attacker-written policies change every decision.
2. **Decision correctness** — a forged or truncated `Request` can produce a misleading allow/deny.
3. **Availability** — huge bodies or huge batches can stall the process.
4. **Confidentiality of policy ids / descriptions** — `GET /api/v1/policies` reveals loaded policy metadata (not secrets, but operational detail).

The engine does not hold secrets. Do not put credentials in policy JSON or request context.

## Threats and mitigations

| ID | Threat | Mitigation (v0) |
|---|---|---|
| T1 | Unauthenticated evaluate on a reachable NIC | Default bind `127.0.0.1`. Document as localhost-only. No internet exposure. |
| T2 | Tampered policy file on disk | Fail-fast validate before bind (NFR5). Operator owns file permissions. No hot-reload. |
| T3 | Malformed / hostile JSON | Serde decode; invalid body → 400. Engine never panics on well-typed input. |
| T4 | DoS via large body / batch | `DefaultBodyLimit` 8 MiB. Batch is a JSON array, not a stream. |
| T5 | SSRF / outbound from the decision path | Engine has no network I/O. Server does not fetch URLs from the request. |
| T6 | Confused deputy via injected context | Caller-supplied `session.*` / `graph.*` are treated as facts. Trust the caller, or enrich in-process later. |
| T7 | Default-allow surprise | Evaluation is deny-overrides and **default deny**. |
| T8 | Log leakage | v0 does not write request bodies to disk. Do not enable verbose proxies in front of evaluate. |

## Explicit non-goals (v0)

- OIDC / JWT verification (`lovebird-identity`)
- Honeypot / CT attack surface
- Federation peer auth
- Public internet exposure
- Multi-tenant isolation
- Signed audit emission from the HTTP path (use `DecisionSigner` in-process if needed)

## Operator checklist

- Keep `--bind` on loopback or a private overlay.
- Treat the policy file as trusted config (same as a firewall ruleset).
- Put a trusted proxy + auth in front if anything beyond localhost must call evaluate.
- Revisit this document before shipping identity (#18 remainder) or honeypot (Phase 4).
