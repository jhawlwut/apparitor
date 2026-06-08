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
echo "send_email      -> $allowed (expect true)"
echo "delete_database -> $denied (expect false)"

# Batch endpoint: top-level subject/action are defaults; each entry overrides the resource.
evaluate_batch() {
  curl -sf "$API/access/v1/evaluations" -d "$(
    cat <<JSON
{ "subject": {"type": "agent", "id": "demo-agent"},
  "action": {"name": "tool_call.execute"},
  "evaluations": [ {"resource": {"type": "tool", "id": "$1"}},
                   {"resource": {"type": "tool", "id": "$2"}} ],
  "options": {"evaluations_semantic": "execute_all"} }
JSON
  )" | jq -r '[.evaluations[].decision] | join(",")'
}

batch_ok=$(evaluate_batch send_email read_file)
batch_mixed=$(evaluate_batch send_email delete_database)
echo "batch [send_email, read_file]       -> $batch_ok (expect true,true)"
echo "batch [send_email, delete_database] -> $batch_mixed (expect true,false)"

if [ "$allowed" = "true" ] && [ "$denied" = "false" ] &&
  [ "$batch_ok" = "true,true" ] && [ "$batch_mixed" = "true,false" ]; then
  echo "SMOKE OK"
else
  echo "SMOKE FAILED" >&2
  exit 1
fi
