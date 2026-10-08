#!/usr/bin/env bash
# End-to-end demo against the REAL local Anvil chain started by docker compose.
# Exits non-zero unless: a clean batch verifies, AND tampering with Ledger's SQLite index
# is detected (and the right record named), AND tampering with the Aegis-table copy is
# detected for a different, correctly-labelled reason.
set -euo pipefail
cd "$(dirname "$0")/.."

COUNT="${COUNT:-25}"
BASE="${LEDGER_URL:-http://127.0.0.1:8000}"

if [ "${NO_UP:-0}" != "1" ]; then
  docker compose up --build -d
fi

echo "== waiting for Ledger to become healthy at $BASE =="
ready=0
for _ in $(seq 1 120); do
  if curl -fsS "$BASE/health" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
if [ "$ready" != "1" ]; then
  echo "Ledger did not become healthy in time" >&2
  docker compose logs --no-color >&2 || true
  exit 1
fi

echo
echo "== tamper-detection demo (inside the ledger container, against Anvil) =="
OUT="$(mktemp)"
docker compose exec -T ledger ledger demo --count "$COUNT" | tee "$OUT"

# Belt and braces: do not trust the exit code alone.
for needle in "DEMO PASSED" "LEDGER_INDEX_MODIFIED" "SOURCE_DATA_MODIFIED" "tx hash" "gas used"; do
  if ! grep -q "$needle" "$OUT"; then
    echo "demo output is missing expected text: $needle" >&2
    exit 1
  fi
done

echo
echo "== HTTP API smoke test =="
curl -fsS -X POST "$BASE/collect/synthetic" -H 'content-type: application/json' -d '{"count": 5}' >/dev/null
curl -fsS -X POST "$BASE/anchor-now" >/dev/null
# the demo uses its own isolated index, so the service's first anchored record is id 1
STATUS="$(curl -fsS "$BASE/verify/1" | python3 -c 'import sys, json; print(json.load(sys.stdin)["status"])')"
echo "GET /verify/1 -> $STATUS"
[ "$STATUS" = "verified" ] || { echo "expected verified" >&2; exit 1; }
curl -fsS "$BASE/metrics" | grep -E '^ledger_(records_anchored_total|gas_spent_total) '

echo
echo "ALL DEMO CHECKS PASSED"
