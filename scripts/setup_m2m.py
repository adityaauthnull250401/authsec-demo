"""Generate and record local private-key-JWT material without an admin token."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from apps.mcp_server.public_keys import M2M_JWKS_PATH, M2M_JWKS_URL
from apps.shared.env import (
    SECRETS_DIR,
    STATE_DIR,
    ensure_private_directory,
    load_project_env,
    optional,
)
from scripts.keys import generate_private_key_jwks

console = Console()
PRIVATE_KEY_PATH = SECRETS_DIR / "svc-github-ci-private.pem"
BOOTSTRAP_STATE_PATH = STATE_DIR / "bootstrap.json"


def _read_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected a JSON object in {path}")
    return payload


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_private_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


def _existing_kid() -> str:
    payload = _read_object(M2M_JWKS_PATH)
    keys = payload.get("keys")
    if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
        raise RuntimeError(f"Expected exactly one public key in {M2M_JWKS_PATH}")
    kid = str(keys[0].get("kid", "")).strip()
    if not kid:
        raise RuntimeError(f"Public key in {M2M_JWKS_PATH} has no kid")
    return kid


def _ensure_key_pair() -> str:
    private_exists = PRIVATE_KEY_PATH.is_file()
    public_exists = M2M_JWKS_PATH.is_file()
    if private_exists != public_exists:
        raise RuntimeError(
            "M2M key state is incomplete: private and public key files must either both "
            "exist or both be absent. Do not regenerate until the AuthSec credential state "
            "has been checked."
        )
    if private_exists:
        return _existing_kid()

    generated = generate_private_key_jwks(PRIVATE_KEY_PATH)
    public_payload = json.loads(generated.jwks_json)
    _write_private_json(M2M_JWKS_PATH, public_payload)
    return generated.kid


def _record_state(kid: str, client_id: str) -> None:
    state = _read_object(BOOTSTRAP_STATE_PATH)
    state.update(
        {
            "m2m_private_key_path": str(PRIVATE_KEY_PATH),
            "m2m_key_id": kid,
        }
    )
    if client_id:
        state["m2m_client_id"] = client_id
    _write_private_json(BOOTSTRAP_STATE_PATH, state)


def _validate_machine_client_id(client_id: str) -> None:
    """Prevent the XAA Agent registration from being reused as an M2M caller.

    Both values are OAuth client IDs, so they look identical to an operator. They
    are nevertheless different AuthSec registrations: the confidential Agent uses
    a client secret, while svc-github-ci must be registered for private_key_jwt.
    """

    if not client_id:
        return
    load_project_env()
    agent_client_id = optional("AUTHSEC_AGENT_CLIENT_ID").strip()
    if agent_client_id and client_id == agent_client_id:
        raise RuntimeError(
            "this is AUTHSEC_AGENT_CLIENT_ID for agent-repo-assistant, not the Client ID "
            "of the svc-github-ci private-key-JWT Service Account. In AuthSec open "
            "GitHub MCP Demo → Access → Add access → Machine credential (secret/key), "
            "create svc-github-ci with Private key JWT and the printed JWKS URI, then "
            "copy its different Client ID from Service Accounts."
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate M2M private-key-JWT material and record the AuthSec client ID"
    )
    parser.add_argument(
        "--client-id",
        default="",
        help="non-secret client ID returned by the AuthSec machine-credential wizard",
    )
    args = parser.parse_args()
    try:
        _validate_machine_client_id(args.client_id.strip())
        kid = _ensure_key_pair()
        _record_state(kid, args.client_id.strip())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        console.print(f"[red]M2M setup failed:[/red] {exc}")
        sys.exit(2)

    table = Table(title="M2M private-key-JWT setup")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("Private key", f"{PRIVATE_KEY_PATH} (local, mode 0600; never upload)")
    table.add_row("Public JWKS URI", M2M_JWKS_URL)
    table.add_row("Key ID", kid)
    table.add_row("Client ID", args.client_id.strip() or "not recorded yet")
    console.print(table)
    if not args.client_id.strip():
        console.print(
            "\nNext: keep `pnpm share` running, create the Reader private-key-JWT "
            "machine credential in AuthSec using the JWKS URI above, then run:\n"
            "  uv run setup-m2m --client-id <CLIENT_ID>"
        )
    else:
        console.print(
            "\n[green]Identity recorded.[/green] Keep `pnpm share` running in another "
            "terminal before running `uv run demo-agent token ci-reporter`."
        )


if __name__ == "__main__":
    main()
