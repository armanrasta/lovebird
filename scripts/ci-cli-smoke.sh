#!/usr/bin/env bash
# Portable CLI smoke + negative-path checks for CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -x target/debug/lovebird ]]; then
  BIN=target/debug/lovebird
elif [[ -x target/debug/lovebird.exe ]]; then
  BIN=target/debug/lovebird.exe
else
  echo "lovebird binary not found under target/debug/" >&2
  exit 1
fi

echo "==> using $BIN"

"$BIN" policy validate examples/policies/allow-admins.json
"$BIN" policy lint examples/policies/allow-admins.json
"$BIN" policy test examples/policies/allow-admins.json examples/scenarios/basic.json --explain
"$BIN" policy dry-run examples/policies/allow-admins.json --against examples/traffic/sample.jsonl
"$BIN" policy dry-run examples/policies/allow-admins.json --against examples/traffic/sample.jsonl --max-newly-denied 5
"$BIN" policy diff examples/policies/allow-admins.json examples/policies/allow-admins.json
"$BIN" policy shadow-report examples/policies/allow-admins.json examples/policies/allow-admins.json --against examples/traffic/sample.jsonl

MISSING="${TMPDIR:-/tmp}/does-not-exist-lovebird-$$.json"
if "$BIN" policy validate "$MISSING"; then
  echo "expected validate of missing file to fail" >&2
  exit 1
fi

if "$BIN" policy dry-run examples/policies/allow-admins.json --against examples/traffic/sample.jsonl --max-newly-denied 0; then
  echo "expected dry-run --max-newly-denied 0 to fail" >&2
  exit 1
fi

echo "OK — CLI smoke passed"
