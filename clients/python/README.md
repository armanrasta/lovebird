# lovebird Python client (v0)

Stdlib-only client for the evaluate sidecar. No PyO3 bindings.

```bash
# from repo root
cargo run -p lovebird-server -- --policies examples/policies/allow-admins.json --bind 127.0.0.1:8080
```

```bash
curl -s http://127.0.0.1:8080/health
curl -s -X POST http://127.0.0.1:8080/api/v1/authz/evaluate \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"alice","roles":["admin"]},"action":"read","resource":{"type":"doc","id":"d1"},"context":{}}'
```

```python
import sys
sys.path.insert(0, "clients/python")
from lovebird import LovebirdClient

c = LovebirdClient("http://127.0.0.1:8080")
print(c.health())
print(c.evaluate({
    "principal": {"id": "alice", "roles": ["admin"]},
    "action": "read",
    "resource": {"type": "doc", "id": "d1"},
    "context": {},
}))

# session / graph fields are caller-supplied facts
print(c.evaluate({
    "principal": {"id": "u1", "roles": ["user"]},
    "action": "read",
    "resource": {"type": "doc", "id": "d1"},
    "context": {"session.anomaly_score": 0.9},
}))
```

`session-guards` / `graph-guards` examples work the same way once the server is started with those policy files.
