#!/usr/bin/env bash
# Unix evaluate-sidecar smoke (loopback). Skipped on Windows in CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x target/debug/lovebird-server ]]; then
  BIN=target/debug/lovebird-server
elif [[ -x target/debug/lovebird-server.exe ]]; then
  echo "skip server smoke on Windows exe (use cargo tests)"
  exit 0
else
  echo "lovebird-server binary not found under target/debug/" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl required for server smoke" >&2
  exit 1
fi

PORT="${LOVEBIRD_SMOKE_PORT:-18080}"
BIND="127.0.0.1:${PORT}"
BASE="http://${BIND}"
LOG="${TMPDIR:-/tmp}/lovebird-server-smoke-$$.log"

cleanup() {
  if [[ -n "${PID:-}" ]] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

"$BIN" --policies examples/policies/allow-admins.json --bind "$BIND" >"$LOG" 2>&1 &
PID=$!

ok=0
for _ in $(seq 1 50); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "server exited before ready:" >&2
    cat "$LOG" >&2 || true
    exit 1
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "server did not become ready on $BIND" >&2
  cat "$LOG" >&2 || true
  exit 1
fi

health="$(curl -sf "$BASE/health")"
echo "$health" | grep -q '"status":"ok"'

allow="$(curl -sf -X POST "$BASE/api/v1/authz/evaluate" \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"alice","roles":["admin"]},"action":"read","resource":{"type":"doc","id":"d1"},"context":{}}')"
echo "$allow" | grep -q '"effect":"allow"'

deny="$(curl -sf -X POST "$BASE/api/v1/authz/evaluate" \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"eve","roles":["guest"]},"action":"read","resource":{"type":"doc","id":"d1"}}')"
echo "$deny" | grep -q '"effect":"deny"'

curl -sf "$BASE/api/v1/policies" | grep -q allow-admins

if command -v python3 >/dev/null 2>&1; then
  PYTHONPATH="$ROOT/clients/python" python3 - <<PY
from lovebird import LovebirdClient
c = LovebirdClient("$BASE")
assert c.health()["status"] == "ok"
d = c.evaluate({
    "principal": {"id": "alice", "roles": ["admin"]},
    "action": "read",
    "resource": {"type": "doc", "id": "d1"},
    "context": {},
})
assert d["effect"] == "allow", d
print("python client ok")
PY
fi

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

"$BIN" --policies examples/policies/session-guards.json --bind "$BIND" >"$LOG" 2>&1 &
PID=$!
ok=0
for _ in $(seq 1 50); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "session-guards server did not become ready" >&2
  cat "$LOG" >&2 || true
  exit 1
fi

hot="$(curl -sf -X POST "$BASE/api/v1/authz/evaluate" \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"u1","roles":["user"]},"action":"read","resource":{"type":"doc","id":"d1"},"context":{"session.anomaly_score":0.9}}')"
echo "$hot" | grep -q '"effect":"deny"'

calm="$(curl -sf -X POST "$BASE/api/v1/authz/evaluate" \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"u1","roles":["user"]},"action":"read","resource":{"type":"doc","id":"d1"},"context":{"session.anomaly_score":0.1}}')"
echo "$calm" | grep -q '"effect":"allow"'

if command -v python3 >/dev/null 2>&1; then
  PYTHONPATH="$ROOT/clients/python" python3 - <<PY
from lovebird import LovebirdClient
c = LovebirdClient("$BASE")
hot = c.evaluate({
    "principal": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"type": "doc", "id": "d1"},
    "context": {"session.anomaly_score": 0.9},
})
assert hot["effect"] == "deny", hot
print("python session-guards ok")
PY
fi

kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

"$BIN" --policies examples/policies/graph-guards.json --bind "$BIND" >"$LOG" 2>&1 &
PID=$!
ok=0
for _ in $(seq 1 50); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.1
done
if [[ "$ok" -ne 1 ]]; then
  echo "graph-guards server did not become ready" >&2
  cat "$LOG" >&2 || true
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHONPATH="$ROOT/clients/python" python3 - <<PY
from lovebird import LovebirdClient
c = LovebirdClient("$BASE")
deny = c.evaluate({
    "principal": {"id": "alice", "roles": []},
    "action": "read",
    "resource": {"type": "database", "id": "payroll-db"},
    "context": {
        "graph.blast_radius_score": 0.56625,
        "graph.crown_jewel_reachable": True,
        "graph.resource_sensitivity": 95,
    },
})
assert deny["effect"] == "deny", deny
allow = c.evaluate({
    "principal": {"id": "bob", "roles": []},
    "action": "read",
    "resource": {"type": "database", "id": "payroll-db"},
    "context": {
        "graph.blast_radius_score": 0.0,
        "graph.crown_jewel_reachable": False,
        "graph.resource_sensitivity": 95,
    },
})
assert allow["effect"] == "allow", allow
print("python graph-guards ok")
PY
fi

echo "OK — server smoke passed"
