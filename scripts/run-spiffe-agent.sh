#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$ROOT/spire/docker-compose.spire.yml"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — complete setup.md before running the SPIFFE workload." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

: "${SPIFFE_ID:?SPIFFE_ID is required in .env}"

show_recovery() {
  cat >&2 <<EOF
The SPIFFE demo infrastructure is not ready.

Start the complete demo in Terminal A and keep it running:
  cd $ROOT
  pnpm share

Wait for "AuthSec demo is ready", then retry this command in Terminal B.
pnpm share:stop intentionally stops the SPIRE Server and Agent as well.
EOF
}

# The workload command deliberately uses --no-deps. Identity infrastructure is
# owned by the long-running `pnpm share` supervisor, so starting it implicitly
# here would create an untracked half-live demo and omit the public MCP tunnel.
running_services="$(
  docker compose -f "$COMPOSE" ps --services --status running 2>/dev/null || true
)"
if ! grep -Fxq "spire-server" <<<"$running_services" \
  || ! grep -Fxq "spire-agent" <<<"$running_services"; then
  show_recovery
  exit 2
fi

if ! docker compose -f "$COMPOSE" exec -T spire-agent \
  /opt/spire/bin/spire-agent healthcheck \
  -socketPath /run/spire/sockets/agent.sock >/dev/null 2>&1; then
  echo "The SPIRE Agent container is running but its Workload API is not healthy." >&2
  show_recovery
  exit 2
fi

if ! docker compose -f "$COMPOSE" exec -T spire-server \
  /opt/spire/bin/spire-server entry show -spiffeID "$SPIFFE_ID" 2>/dev/null \
  | grep -Fq "$SPIFFE_ID"; then
  echo "SPIRE has no registration entry for $SPIFFE_ID." >&2
  show_recovery
  exit 2
fi

exec docker compose \
  --env-file "$ENV_FILE" \
  -f "$COMPOSE" \
  --profile workload \
  run --rm --no-deps release-reporter "$@"
