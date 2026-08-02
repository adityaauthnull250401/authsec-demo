#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Missing $ENV_FILE — copy .env.example and complete setup.md." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

MCP_TUNNEL_CONFIG="${MCP_TUNNEL_CONFIG:-$HOME/.cloudflared/authsec-mcp-demo.yml}"
SPIRE_TUNNEL_CONFIG="${SPIRE_TUNNEL_CONFIG:-$HOME/.cloudflared/authsec-spire-demo.yml}"
DEMO_PORT="${DEMO_PORT:-8091}"
LOCK_DIR="$ROOT/.state/share.lock"
LOCK_OWNED=false
PIDS=()

cleanup() {
  trap - EXIT INT TERM
  for pid in "${PIDS[@]:-}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ "${DEMO_ENABLE_SPIRE:-false}" == "true" ]]; then
    docker compose -f "$ROOT/spire/docker-compose.spire.yml" down >/dev/null 2>&1 || true
  fi
  if [[ "$LOCK_OWNED" == "true" ]]; then
    [[ ! -f "$LOCK_DIR/pid" ]] || unlink "$LOCK_DIR/pid"
    rmdir "$LOCK_DIR" 2>/dev/null || true
  fi
}
trap cleanup EXIT
# Convert terminal signals into a normal shell exit; the EXIT trap then owns
# the cleanup exactly once instead of returning into the child-monitor loop.
trap 'exit 0' INT TERM

# Only one foreground share supervisor may own the origin and two tunnels.
# Atomic directory creation prevents concurrent `pnpm share` commands from
# racing through startup. Dead supervisors leave a safely recoverable lock.
mkdir -p "$ROOT/.state"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  existing_pid=""
  [[ ! -f "$LOCK_DIR/pid" ]] || existing_pid="$(<"$LOCK_DIR/pid")"
  if [[ "$existing_pid" =~ ^[0-9]+$ ]] && kill -0 "$existing_pid" 2>/dev/null; then
    echo "AuthSec demo is already managed by share supervisor PID $existing_pid." >&2
    echo "Use its terminal and press Ctrl-C, or run: pnpm share:stop" >&2
    exit 2
  fi
  echo "Removing stale AuthSec demo share lock." >&2
  [[ ! -f "$LOCK_DIR/pid" ]] || unlink "$LOCK_DIR/pid"
  rmdir "$LOCK_DIR" 2>/dev/null || {
    echo "Cannot recover stale share lock: $LOCK_DIR" >&2
    exit 2
  }
  mkdir "$LOCK_DIR"
fi
printf '%s\n' "$$" > "$LOCK_DIR/pid"
LOCK_OWNED=true

[[ -f "$MCP_TUNNEL_CONFIG" ]] || {
  echo "Missing MCP tunnel config: $MCP_TUNNEL_CONFIG" >&2
  exit 2
}

# Validate every server-side ID, secret, PEM, and pinned AuthSec mode before
# starting Cloudflare or SPIRE. Configuration mistakes should produce one
# useful error, not several pages of tunnel shutdown noise.
cd "$ROOT"
uv run python -m scripts.validate_share

# Older checkouts did not create the supervisor lock. Detect their listener
# before the expensive SPIRE build or either Cloudflare connector starts.
listener_pids="$(
  lsof -nP -iTCP:"$DEMO_PORT" -sTCP:LISTEN -t 2>/dev/null \
    | paste -sd, - \
    || true
)"
if [[ -n "$listener_pids" ]]; then
  if curl -fsS "http://127.0.0.1:$DEMO_PORT/healthz" 2>/dev/null \
    | grep -Fq 'authsec-github-mcp-demo'; then
    echo "AuthSec demo origin is already running on port $DEMO_PORT (PID $listener_pids)." >&2
  else
    echo "Port $DEMO_PORT is already used by PID $listener_pids." >&2
  fi
  echo "Stop the existing process before starting another share group." >&2
  exit 2
fi

if [[ "${DEMO_ENABLE_SPIRE:-false}" == "true" ]]; then
  [[ -f "$SPIRE_TUNNEL_CONFIG" ]] || {
    echo "Missing SPIRE tunnel config: $SPIRE_TUNNEL_CONFIG" >&2
    exit 2
  }
  bash "$ROOT/scripts/spire-up.sh"
  cloudflared tunnel --config "$SPIRE_TUNNEL_CONFIG" run &
  PIDS+=("$!")
fi

uv run authsec-demo-server &
PIDS+=("$!")
cloudflared tunnel --config "$MCP_TUNNEL_CONFIG" run &
PIDS+=("$!")

origin_ready=false
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$DEMO_PORT/healthz" >/dev/null 2>&1; then
    origin_ready=true
    break
  fi
  for pid in "${PIDS[@]}"; do
    kill -0 "$pid" 2>/dev/null || wait "$pid"
  done
  sleep 1
done
if [[ "$origin_ready" != "true" ]]; then
  echo "MCP origin did not become healthy within 30 seconds." >&2
  exit 1
fi

public_ready=false
for _ in $(seq 1 30); do
  if curl -fsS "https://mcp-demo.mcpauthz.com/healthz" >/dev/null 2>&1; then
    public_ready=true
    break
  fi
  sleep 1
done
if [[ "$public_ready" != "true" ]]; then
  echo "Public MCP tunnel did not become healthy within 30 seconds." >&2
  exit 1
fi

if [[ "${DEMO_ENABLE_SPIRE:-false}" == "true" ]]; then
  spire_public_ready=false
  for _ in $(seq 1 30); do
    if curl -fsS \
      "https://spire-demo.mcpauthz.com/.well-known/openid-configuration" \
      >/dev/null 2>&1; then
      spire_public_ready=true
      break
    fi
    sleep 1
  done
  if [[ "$spire_public_ready" != "true" ]]; then
    echo "Public SPIRE OIDC tunnel did not become healthy within 30 seconds." >&2
    exit 1
  fi
fi

echo "AuthSec demo is ready. Managed PIDs: ${PIDS[*]}"
echo "Stop cleanly with Ctrl-C (or pnpm share:stop); restart with: cd $ROOT && pnpm share"

# macOS ships Bash 3.2 without `wait -n`. Poll managed children so a failed
# origin or tunnel tears down the whole share group instead of leaving a
# misleading half-live demo.
while true; do
  for pid in "${PIDS[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" || exit $?
    fi
  done
  sleep 1
done
