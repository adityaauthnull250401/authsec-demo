#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/spire/docker-compose.spire.yml"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and complete the SPIFFE values." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${SPIFFE_ID:?SPIFFE_ID is required in .env}"

if [[ "$SPIFFE_ID" != spiffe://authsec.demo/* ]]; then
  echo "SPIFFE_ID must be inside the pinned spiffe://authsec.demo trust domain." >&2
  exit 2
fi

mkdir -p "$ROOT/.state/wheels" "$ROOT/.state/spire"
chmod 700 "$ROOT/.state" "$ROOT/.state/wheels" "$ROOT/.state/spire"

# Package the actual local SDK checkout for the isolated workload image. No
# demo code is copied into sdk-authsec and no unpublished fallback is invented.
rm -f "$ROOT/.state/wheels"/authsec_sdk-*.whl
rm -f "$ROOT/.state/wheels"/authsec_github_mcp_demo-*.whl
uv build --wheel --no-build-logs \
  --out-dir "$ROOT/.state/wheels" \
  "$ROOT/../authnull/sdk-authsec/packages/python-sdk"
uv build --wheel --no-build-logs --out-dir "$ROOT/.state/wheels" "$ROOT"
uv export --quiet \
  --frozen \
  --no-dev \
  --no-hashes \
  --no-header \
  --no-annotate \
  --no-emit-project \
  --no-emit-package authsec-sdk \
  --output-file "$ROOT/.state/wheels/requirements.txt"

# Freeze the exact SDK + demo wheels into the workload image before starting
# identity infrastructure. Later `pnpm agent:spiffe` never reaches back into
# the host checkout or resolves an unpublished package.
docker compose -f "$COMPOSE" build release-reporter

docker compose -f "$COMPOSE" up -d spire-server spire-oidc

server_ready=false
for _ in $(seq 1 30); do
  if docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server entry show >/dev/null 2>&1; then
    server_ready=true
    break
  fi
  sleep 1
done
if [[ "$server_ready" != "true" ]]; then
  docker compose -f "$COMPOSE" logs --no-color --tail=80 spire-server >&2
  echo "SPIRE Server did not become ready within 30 seconds." >&2
  exit 1
fi

# Pin the Agent's first connection to this demo Server's actual trust bundle.
# The bundle is public material, but the state directory remains private so
# the rest of the generated rehearsal state cannot accidentally be exposed.
docker compose -f "$COMPOSE" exec -T spire-server \
  /opt/spire/bin/spire-server bundle show -format pem \
  > "$ROOT/.state/spire/bootstrap-bundle.pem"
chmod 600 "$ROOT/.state/spire/bootstrap-bundle.pem"

AGENT_ID="spiffe://authsec.demo/agent/demo-host"
generate_join_token() {
  local token_output
  token_output="$(docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server token generate -spiffeID "$AGENT_ID")"
  SPIRE_JOIN_TOKEN="$(printf '%s\n' "$token_output" | awk -F': ' '/Token:/ {print $2; exit}')"
  if [[ -z "$SPIRE_JOIN_TOKEN" ]]; then
    echo "SPIRE Server did not return a join token." >&2
    return 1
  fi
  export SPIRE_JOIN_TOKEN
}

start_agent() {
  generate_join_token
  # The Server and the one-shot volume initializer are already complete above.
  # Starting only the Agent without dependency reconciliation avoids Compose
  # replacing the exited init container while the Server is live—a race that can
  # otherwise end with "No such container" during rapid demo restarts.
  docker compose -f "$COMPOSE" up -d --no-deps --force-recreate spire-agent
}

wait_for_agent() {
  local ready=false
  for _ in $(seq 1 30); do
    if docker compose -f "$COMPOSE" exec -T spire-agent \
      /opt/spire/bin/spire-agent healthcheck -socketPath /run/spire/sockets/agent.sock \
      >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ "$ready" == "true" ]]
}

reset_stale_agent_state() {
  local agent_data_volume agent_socket_volume

  # This cache contains only the local demo Agent's recoverable key/SVID state.
  # Preserve the Server volume: its CA, entries, and JWT signing state are the
  # public trust anchor registered with AuthSec.
  docker compose -f "$COMPOSE" rm -s -f spire-agent >/dev/null 2>&1 || true

  agent_data_volume="$(
    docker volume ls -q \
      --filter label=com.docker.compose.project=authsec-demo-spire \
      --filter label=com.docker.compose.volume=agent-data
  )"
  agent_socket_volume="$(
    docker volume ls -q \
      --filter label=com.docker.compose.project=authsec-demo-spire \
      --filter label=com.docker.compose.volume=agent-socket
  )"
  if [[ -z "$agent_data_volume" || -z "$agent_socket_volume" ]]; then
    echo "Could not resolve the demo-owned SPIRE Agent volumes for recovery." >&2
    return 1
  fi

  docker run --rm \
    --volume "$agent_data_volume:/agent-data" \
    --volume "$agent_socket_volume:/agent-socket" \
    busybox:1.37.0 \
    sh -c '
      find /agent-data -mindepth 1 -maxdepth 1 -exec rm -rf {} \;
      find /agent-socket -mindepth 1 -maxdepth 1 -exec rm -rf {} \;
      chown -R 1000:1000 /agent-data /agent-socket
    '
}

start_agent
agent_ready=false
if wait_for_agent; then
  agent_ready=true
else
  agent_logs="$(docker compose -f "$COMPOSE" logs --no-color --tail=120 spire-agent 2>&1 || true)"
  if grep -Fq "certificate signed by unknown authority" <<<"$agent_logs"; then
    echo "Detected stale SPIRE Agent trust state; re-attesting this demo Agent." >&2
    reset_stale_agent_state
    start_agent
    if wait_for_agent; then
      agent_ready=true
    fi
  fi
fi
if [[ "$agent_ready" != "true" ]]; then
  docker compose -f "$COMPOSE" logs --no-color --tail=80 spire-agent >&2
  echo "SPIRE Agent did not become ready within 30 seconds." >&2
  exit 1
fi

if ! docker compose -f "$COMPOSE" exec -T spire-server \
  /opt/spire/bin/spire-server entry show -spiffeID "$SPIFFE_ID" 2>/dev/null \
  | grep -Fq "$SPIFFE_ID"; then
  docker compose -f "$COMPOSE" exec -T spire-server \
    /opt/spire/bin/spire-server entry create \
    -parentID "$AGENT_ID" \
    -spiffeID "$SPIFFE_ID" \
    -selector unix:uid:0
fi

oidc_ready=false
for _ in $(seq 1 30); do
  if curl -fsS \
    -H "Host: spire-demo.mcpauthz.com" \
    http://127.0.0.1:8443/.well-known/openid-configuration \
    >/dev/null 2>&1; then
    oidc_ready=true
    break
  fi
  sleep 1
done
if [[ "$oidc_ready" != "true" ]]; then
  docker compose -f "$COMPOSE" logs --no-color --tail=80 spire-oidc >&2
  echo "SPIRE OIDC Discovery did not become ready within 30 seconds." >&2
  exit 1
fi

echo "SPIRE is ready: issuer=http://localhost:8443 workload=$SPIFFE_ID"
if [[ -z "${SPIFFE_CLIENT_ID:-}" ]]; then
  echo "SPIFFE_CLIENT_ID is not set yet; OIDC discovery is ready for AuthSec registration."
fi
