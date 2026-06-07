#!/usr/bin/env bash
# Build + run the Cedar gateway and prove the AuthZEN endpoint allows a permitted tool and
# denies a destructive one. Requires Docker + jq + curl. First run builds the Cedar CLI, so
# it can take a few minutes.
set -euo pipefail
cd "$(dirname "$0")"

API="${CEDAR_API:-http://localhost:8080}"

cleanup() { docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose up -d --build

printf 'waiting for the gateway'
healthy=false
for _ in $(seq 1 60); do
  if curl -sf "$API/healthz" >/dev/null 2>&1; then healthy=true; break; fi
  printf '.'
  sleep 1
done
echo
if [ "$healthy" = false ]; then
  echo "Cedar gateway did not become healthy in time" >&2
  exit 1
fi

evaluate() {
  curl -sf "$API/access/v1/evaluation" -d "$(
    cat <<JSON
{ "subject": {"type": "agent", "id": "demo-agent"},
  "action": {"name": "tool_call.execute"},
  "resource": {"type": "tool", "id": "$1"} }
JSON
  )" | jq -r .decision
}

allowed=$(evaluate send_email)
denied=$(evaluate delete_database)
echo "send_email     -> $allowed (expect true)"
echo "delete_database -> $denied (expect false)"

if [ "$allowed" = "true" ] && [ "$denied" = "false" ]; then
  echo "SMOKE OK"
else
  echo "SMOKE FAILED" >&2
  exit 1
fi
