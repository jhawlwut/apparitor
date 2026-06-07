#!/usr/bin/env bash
# Bring up OpenFGA, load the vendored model + tuples, and prove the AuthZEN evaluation
# endpoint allows a granted tool and denies an ungranted one. Requires Docker + jq + curl.
set -euo pipefail
cd "$(dirname "$0")"

API="${OPENFGA_API:-http://localhost:8080}"

cleanup() { docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker compose up -d

printf 'waiting for OpenFGA'
healthy=false
for _ in $(seq 1 30); do
  if curl -sf "$API/healthz" >/dev/null 2>&1; then healthy=true; break; fi
  printf '.'
  sleep 1
done
echo
if [ "$healthy" = false ]; then
  echo "OpenFGA did not become healthy within 30s" >&2
  exit 1
fi

# A store scopes the model and tuples; the AuthZEN endpoints live under it.
store_id=$(curl -sf "$API/stores" -d '{"name":"authzen-scanner-demo"}' | jq -r .id)
curl -sf "$API/stores/$store_id/authorization-models" --data-binary @model.json >/dev/null
curl -sf "$API/stores/$store_id/write" \
  -d "{\"writes\":{\"tuple_keys\":$(cat tuples.json)}}" >/dev/null
echo "store=$store_id loaded"

# AuthZEN single evaluation: action.name maps to the OpenFGA relation, resource type:id to
# the object, subject type:id to the user.
evaluate() {
  curl -sf "$API/stores/$store_id/access/v1/evaluation" -d "$(
    cat <<JSON
{ "subject": {"type": "agent", "id": "demo-agent"},
  "action": {"name": "can_execute"},
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
