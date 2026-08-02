"""Read-only readiness checks for the platform, local tools, tunnels, and env."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich.console import Console
from rich.table import Table

from apps.mcp_server.constants import ISSUER, RESOURCE_URI
from apps.shared.env import STATE_DIR, boolean, load_project_env, optional
from apps.shared.logging import configure_logging

console = Console()


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    blocking: bool = True


async def _http_json(name: str, url: str, required_fields: set[str]) -> Check:
    try:
        async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
            response = await client.get(url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            return Check(name, "FAIL", f"HTTP {response.status_code} from {url}")
        payload = response.json()
        missing = required_fields - set(payload)
        if missing:
            return Check(name, "FAIL", "missing fields: " + ", ".join(sorted(missing)))
        return Check(name, "PASS", f"HTTP 200 from {url}")
    except Exception as exc:
        return Check(name, "FAIL", f"{type(exc).__name__}: {exc}")


async def _probe_public_mcp() -> Check:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            response = await client.get(RESOURCE_URI)
        if response.status_code == 530:
            return Check(
                "Public MCP origin",
                "WARN",
                "Cloudflare 530: DNS/route exist; run `pnpm share` to start origin+tunnel",
                blocking=False,
            )
        if response.status_code in {200, 400, 401, 405}:
            return Check("Public MCP origin", "PASS", f"reachable (HTTP {response.status_code})")
        return Check("Public MCP origin", "WARN", f"unexpected HTTP {response.status_code}", False)
    except Exception as exc:
        return Check("Public MCP origin", "WARN", f"not reachable yet: {exc}", False)


def _command_check(command: str, required: bool = True) -> Check:
    path = shutil.which(command)
    return Check(
        f"Command: {command}",
        "PASS" if path else ("FAIL" if required else "WARN"),
        path or "not installed",
        blocking=required,
    )


def _env_group(name: str, variables: list[str], required_group: bool = True) -> Check:
    missing = [item for item in variables if not os.getenv(item, "").strip()]
    if not missing:
        noun = "variable" if len(variables) == 1 else "variables"
        return Check(name, "PASS", f"{len(variables)} {noun} present")
    return Check(
        name,
        "FAIL" if required_group else "WARN",
        "missing: " + ", ".join(missing),
        blocking=required_group,
    )


def _m2m_identity() -> Check:
    """Accept either explicit env values or bootstrap's ignored local state."""

    state_path = STATE_DIR / "bootstrap.json"
    state: dict[str, str] = {}
    if state_path.is_file():
        try:
            payload = json.loads(state_path.read_text(encoding="utf-8"))
            state = {str(key): str(value) for key, value in payload.items() if value}
        except (OSError, ValueError, TypeError):
            return Check("M2M agent identity", "WARN", "bootstrap state is unreadable", False)

    requirements = {
        "AUTHSEC_M2M_CLIENT_ID": "m2m_client_id",
        "AUTHSEC_M2M_PRIVATE_KEY_PATH": "m2m_private_key_path",
        "AUTHSEC_M2M_KEY_ID": "m2m_key_id",
    }
    missing = [
        env_name
        for env_name, state_name in requirements.items()
        if not os.getenv(env_name, "").strip() and not state.get(state_name, "").strip()
    ]
    if missing:
        return Check(
            "M2M agent identity",
            "WARN",
            "missing from env/bootstrap state: " + ", ".join(missing),
            False,
        )
    return Check("M2M agent identity", "PASS", "client ID, key path, and key ID present")


def _tunnel_config() -> Check:
    raw = optional("MCP_TUNNEL_CONFIG", "~/.cloudflared/authsec-mcp-demo.yml")
    path = Path(raw).expanduser()
    if not path.is_file():
        return Check("MCP tunnel config", "FAIL", f"not found: {path}")
    text = path.read_text(encoding="utf-8")
    if "mcp-demo.mcpauthz.com" not in text or "localhost:8091" not in text:
        return Check("MCP tunnel config", "FAIL", "does not route host to localhost:8091")
    return Check("MCP tunnel config", "PASS", str(path))


async def _run(public_only: bool) -> int:
    load_project_env()
    checks: list[Check] = [
        _command_check("uv"),
        _command_check("pnpm"),
        _command_check("cloudflared"),
        _command_check("docker", required=boolean("DEMO_ENABLE_SPIRE", False)),
        _tunnel_config(),
    ]

    host = urlparse(RESOURCE_URI).hostname or ""
    try:
        socket.getaddrinfo(host, 443)
        checks.append(Check("MCP DNS", "PASS", f"{host} resolves"))
    except OSError as exc:
        checks.append(Check("MCP DNS", "FAIL", str(exc)))

    checks.extend(
        await asyncio.gather(
            _http_json(
                "Authorization Server discovery",
                f"{ISSUER}/.well-known/oauth-authorization-server",
                {"issuer", "token_endpoint", "jwks_uri", "introspection_endpoint"},
            ),
            _http_json("AuthSec JWKS", f"{ISSUER}/oauth/jwks", {"keys"}),
            _probe_public_mcp(),
        )
    )

    if not public_only:
        checks.extend(
            [
                _env_group(
                    "AuthSec runtime env",
                    [
                        "AUTHSEC_ISSUER",
                        "AUTHSEC_AUTHORIZATION_SERVER",
                        "AUTHSEC_JWKS_URL",
                        "AUTHSEC_INTROSPECTION_URL",
                        "AUTHSEC_RESOURCE_URI",
                        "AUTHSEC_RESOURCE_NAME",
                        "AUTHSEC_RESOURCE_SERVER_ID",
                        "AUTHSEC_INTROSPECTION_CLIENT_ID",
                        "AUTHSEC_INTROSPECTION_CLIENT_SECRET",
                        "AUTHSEC_POLICY_MODE",
                        "AUTHSEC_VALIDATION_MODE",
                        "AUTHSEC_PUBLISH_MANIFEST",
                    ],
                ),
                _env_group(
                    "Personal GitHub App env",
                    ["GITHUB_APP_ID", "GITHUB_INSTALLATION_ID", "GITHUB_PRIVATE_KEY"],
                ),
                _env_group(
                    "Demo workspace reference",
                    ["AUTHSEC_DEMO_WORKSPACE_ID"],
                    required_group=False,
                ),
                _env_group(
                    "Agent model env",
                    ["DEMO_LLM_MODEL", "OPENAI_API_KEY"],
                    required_group=False,
                ),
                _m2m_identity(),
                _env_group(
                    "SPIFFE agent identity",
                    ["SPIFFE_CLIENT_ID", "SPIFFE_ID"],
                    required_group=False,
                ),
                _env_group(
                    "Delegated agent identity",
                    ["AUTHSEC_AGENT_CLIENT_ID", "AUTHSEC_AGENT_CLIENT_SECRET"],
                    required_group=False,
                ),
            ]
        )

    if boolean("DEMO_ENABLE_SPIRE", False):
        oidc_url = optional("SPIRE_OIDC_DISCOVERY_URL", "https://spire-demo.mcpauthz.com")
        checks.append(
            await _http_json(
                "SPIRE OIDC discovery",
                f"{oidc_url.rstrip('/')}/.well-known/openid-configuration",
                {"issuer", "jwks_uri"},
            )
        )

    table = Table(title="AuthSec demo preflight")
    table.add_column("Status", width=7)
    table.add_column("Check")
    table.add_column("Detail")
    colors = {"PASS": "green", "WARN": "yellow", "FAIL": "red"}
    for check in checks:
        table.add_row(f"[{colors[check.status]}]{check.status}[/]", check.name, check.detail)
    console.print(table)
    failures = [check for check in checks if check.status == "FAIL" and check.blocking]
    return 1 if failures else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--public-only", action="store_true", help="check public platform/tooling without .env"
    )
    args = parser.parse_args()
    configure_logging("preflight")
    sys.exit(asyncio.run(_run(args.public_only)))


if __name__ == "__main__":
    main()
