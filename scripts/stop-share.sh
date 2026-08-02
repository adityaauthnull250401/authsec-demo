#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_DIR="$ROOT/.state/share.lock"
PID_FILE="$LOCK_DIR/pid"
SPIRE_COMPOSE="$ROOT/spire/docker-compose.spire.yml"

stop_spire() {
  # The share supervisor normally owns this in its EXIT trap.  Also do it here
  # because a terminal/parent-process death can leave only a stale lock while
  # the Compose project continues running.
  docker compose -f "$SPIRE_COMPOSE" down >/dev/null 2>&1 || true
}

if [[ ! -f "$PID_FILE" ]]; then
  echo "No lock-managed AuthSec demo share process is running."
  stop_spire
  echo "Ensured the AuthSec demo SPIRE Compose project is stopped."
  echo "If an older process owns port 8091, stop its terminal with Ctrl-C."
  exit 0
fi

pid="$(<"$PID_FILE")"
if [[ ! "$pid" =~ ^[0-9]+$ ]] || ! kill -0 "$pid" 2>/dev/null; then
  echo "Removing stale AuthSec demo share lock."
  unlink "$PID_FILE"
  rmdir "$LOCK_DIR" 2>/dev/null || true
  stop_spire
  echo "Ensured the AuthSec demo SPIRE Compose project is stopped."
  exit 0
fi

command_line="$(ps -p "$pid" -o command= 2>/dev/null || true)"
if [[ "$command_line" != *"scripts/share.sh"* ]]; then
  echo "Refusing to signal PID $pid because it is not the AuthSec share supervisor." >&2
  exit 2
fi

echo "Stopping AuthSec demo share supervisor PID $pid..."
kill -TERM "$pid"
for _ in $(seq 1 30); do
  if ! kill -0 "$pid" 2>/dev/null; then
    stop_spire
    echo "AuthSec demo stopped cleanly."
    exit 0
  fi
  sleep 0.2
done

echo "Share supervisor did not stop within six seconds; use its terminal and press Ctrl-C." >&2
exit 1
