"""Rebuild the AuthSec-side demo topology from one workspace-admin OAuth token.

The token is read from a secure prompt, stdin, or the process environment and
is never persisted. Durable one-time credentials returned by AuthSec are saved
to the private project .env immediately so an interrupted run is resumable.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import jwt
from dotenv import dotenv_values
from rich.console import Console
from rich.table import Table

from apps.mcp_server.constants import (
    APP_NAME,
    ISSUE_SCOPE,
    READ_SCOPE,
    README_SCOPE,
    RESOURCE_URI,
    TOOL_SCOPE_SUGGESTIONS,
)
from apps.mcp_server.public_keys import M2M_JWKS_PATH
from apps.shared.env import PROJECT_ROOT, SECRETS_DIR, STATE_DIR, ensure_private_directory
from apps.shared.logging import configure_logging
from scripts.authsec_api import AuthSecAdminClient, AuthSecAPIError
from scripts.keys import generate_private_key_jwks

console = Console()

ENV_PATH = PROJECT_ROOT / ".env"
ENV_TEMPLATE_PATH = PROJECT_ROOT / ".env.example"
BOOTSTRAP_STATE_PATH = STATE_DIR / "bootstrap.json"
RECOVERY_STATE_PATH = STATE_DIR / "recovery.json"
RECOVERY_LOG_PATH = STATE_DIR / "recovery-share.log"
M2M_PRIVATE_KEY_PATH = SECRETS_DIR / "svc-github-ci-private.pem"
DEFAULT_AUTHSEC_ADMIN_API_URL = "https://prod.api.authsec.ai"
DEFAULT_AUTHSEC_ISSUER_URL = "https://prod.api.authsec.ai"

READER_SCOPES = [READ_SCOPE, README_SCOPE]
TRIAGE_SCOPES = [READ_SCOPE, README_SCOPE, ISSUE_SCOPE]
SCOPE_METADATA = {
    READ_SCOPE: ("Read commits", "Read commit history from approved repositories", "low"),
    README_SCOPE: ("Read repository docs", "Read README content from approved repositories", "low"),
    ISSUE_SCOPE: ("Create sandbox issues", "Create an issue only in the demo sandbox", "high"),
}


@dataclass(frozen=True)
class AdminIdentity:
    workspace_id: str
    user_id: str


@dataclass(frozen=True)
class ApplicationAnchor:
    application_id: str
    created: bool


class PrivateEnvFile:
    """Atomic, mode-0600 updates without ever duplicating the admin token."""

    _assignment = re.compile(r"^(?P<prefix>\s*(?:export\s+)?)(?P<key>[A-Z0-9_]+)=")

    def __init__(self, path: Path = ENV_PATH, *, create: bool = True) -> None:
        self.path = path
        if not path.exists():
            if not create:
                return
            if not ENV_TEMPLATE_PATH.is_file():
                raise RuntimeError(".env and .env.example are both missing")
            path.write_text(ENV_TEMPLATE_PATH.read_text(encoding="utf-8"), encoding="utf-8")
        if create:
            path.chmod(0o600)

    def values(self) -> dict[str, str]:
        if not self.path.is_file():
            return {}
        parsed = dotenv_values(self.path)
        return {key: str(value or "") for key, value in parsed.items()}

    @staticmethod
    def _quote(value: str) -> str:
        if any(character in value for character in ("\n", "\r", "\\", "'")):
            raise RuntimeError("Refusing to write a non-portable value to .env")
        # AuthSec's generated secrets are hex/UUID strings. Single quotes also
        # make any future $, backtick, space, or double quote literal to Bash.
        return f"'{value}'"

    def update(self, values: dict[str, str]) -> None:
        if "AUTHSEC_ADMIN_TOKEN" in values:
            raise RuntimeError("AUTHSEC_ADMIN_TOKEN must never be persisted")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        pending = dict(values)
        output: list[str] = []
        for line in lines:
            match = self._assignment.match(line)
            key = match.group("key") if match else ""
            if key in pending:
                assert match is not None
                output.append(f"{match.group('prefix')}{key}={self._quote(pending.pop(key))}")
            else:
                output.append(line)
        if pending:
            output.append("")
            output.append("# Values reconciled by `uv run recover`.")
            output.extend(f"{key}={self._quote(value)}" for key, value in pending.items())

        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        temporary.write_text("\n".join(output) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(self.path)
        for key, value in values.items():
            os.environ[key] = value


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError(f"Expected a JSON object in {path}")
    return payload


def _write_private_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_private_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def _checkpoint(**values: Any) -> None:
    state = _read_json_object(RECOVERY_STATE_PATH)
    state.update(values)
    state["updated_at"] = int(time.time())
    _write_private_json(RECOVERY_STATE_PATH, state)


def _decode_admin_identity(token: str, *, now: int | None = None) -> AdminIdentity:
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
        )
    except jwt.PyJWTError as exc:
        raise RuntimeError("The supplied value is not a decodable OAuth JWT") from exc
    workspace_id = str(claims.get("workspace_id") or claims.get("tenant_id") or "").strip()
    user_id = str(claims.get("user_id") or claims.get("sub") or "").strip()
    if not workspace_id:
        raise RuntimeError("OAuth token has no workspace_id/tenant_id claim")
    try:
        UUID(workspace_id)
    except ValueError as exc:
        raise RuntimeError("OAuth token workspace claim is not a UUID") from exc
    expires_at = claims.get("exp")
    current = int(time.time()) if now is None else now
    if not isinstance(expires_at, (int, float)) or int(expires_at) <= current + 30:
        raise RuntimeError("OAuth token is expired or has less than 30 seconds remaining")
    return AdminIdentity(workspace_id=workspace_id, user_id=user_id)


def _admin_token(args: argparse.Namespace) -> str:
    if args.token_stdin:
        token = sys.stdin.readline().strip()
    else:
        token = os.getenv("AUTHSEC_ADMIN_TOKEN", "").strip()
        if not token:
            token = getpass.getpass("AuthSec workspace owner/admin OAuth token: ").strip()
    if not token:
        raise RuntimeError("An AuthSec workspace owner/admin OAuth token is required")
    return token


def _items(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in keys:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def _role_label(role: dict[str, Any]) -> str:
    return str(role.get("name", "")).rsplit(":", 1)[-1].replace("_", "-").lower()


def _has_user_role_assignment(
    assignments: list[dict[str, Any]], user_id: str, role_id: str
) -> bool:
    return any(
        item.get("identity_type") == "user"
        and str(item.get("identity_id")) == user_id
        and str(item.get("role_id")) == role_id
        for item in assignments
    )


async def _ensure_application(
    api: AuthSecAdminClient,
    env_file: PrivateEnvFile,
    identity: AdminIdentity,
) -> ApplicationAnchor:
    env = env_file.values()
    applications = _items(await api.get("/authsec/applications"), "items", "applications")
    exact = [app for app in applications if str(app.get("resource_uri", "")) == RESOURCE_URI]
    wrong_uri = [app for app in applications if app.get("name") == APP_NAME and app not in exact]
    if wrong_uri:
        raise RuntimeError(f"An Application named {APP_NAME!r} exists with the wrong Resource URI")
    if len(exact) > 1:
        raise RuntimeError("Multiple Applications own the pinned demo Resource URI")

    created = not exact
    secret = ""
    if created:
        response = await api.post(
            "/authsec/applications",
            {
                "name": APP_NAME,
                "public_base_url": RESOURCE_URI.removesuffix("/mcp"),
                "protected_base_path": "/mcp",
                "application_type": "mcp_server",
                "scopes_supported": TRIAGE_SCOPES,
                "registration_modes": ["dcr", "cimd", "prereg"],
                "default_access_enabled": False,
            },
        )
        application_id = str(response["id"])
        secret = str(response.get("introspection_secret", ""))
        if not secret:
            raise RuntimeError(
                "Application creation did not return its one-time introspection secret"
            )
        console.print("[green]created[/green] AuthSec Application and captured its secret")
    else:
        application_id = str(exact[0]["id"])
        local_anchor_matches = (
            env.get("AUTHSEC_RESOURCE_SERVER_ID") == application_id
            and env.get("AUTHSEC_INTROSPECTION_CLIENT_ID") == application_id
            and bool(env.get("AUTHSEC_INTROSPECTION_CLIENT_SECRET"))
        )
        if local_anchor_matches:
            secret = env["AUTHSEC_INTROSPECTION_CLIENT_SECRET"]
            console.print("[green]reused[/green] existing AuthSec Application anchor")
        else:
            response = await api.post(
                f"/authsec/applications/{application_id}/rotate-introspection-secret"
            )
            secret = str(response.get("introspection_secret", ""))
            if not secret:
                raise RuntimeError("Secret rotation did not return an introspection secret")
            console.print("[yellow]rotated[/yellow] the Application secret to repair local state")

    env_file.update(
        {
            "AUTHSEC_DEMO_WORKSPACE_ID": identity.workspace_id,
            "AUTHSEC_RESOURCE_SERVER_ID": application_id,
            "AUTHSEC_INTROSPECTION_CLIENT_ID": application_id,
            "AUTHSEC_INTROSPECTION_CLIENT_SECRET": secret,
        }
    )
    _checkpoint(
        phase="application",
        workspace_id=identity.workspace_id,
        resource_server_id=application_id,
    )
    return ApplicationAnchor(application_id=application_id, created=created)


async def _ensure_scopes(api: AuthSecAdminClient, application_id: str) -> dict[str, dict[str, Any]]:
    payload = await api.get(f"/authsec/applications/{application_id}/scopes")
    scopes = _items(payload, "items", "scopes")
    by_scope = {str(item.get("scope_string")): item for item in scopes}
    for scope_string in TRIAGE_SCOPES:
        if scope_string in by_scope:
            continue
        display_name, description, risk = SCOPE_METADATA[scope_string]
        created = await api.post(
            f"/authsec/applications/{application_id}/scopes",
            {
                "scope_string": scope_string,
                "display_name": display_name,
                "description": description,
                "risk_level": risk,
            },
        )
        by_scope[scope_string] = created
        console.print(f"[green]created[/green] scope {scope_string}")
    extras = sorted(set(by_scope) - set(TRIAGE_SCOPES))
    if extras:
        console.print(
            "[yellow]preserved[/yellow] non-demo scopes instead of deleting them: "
            + ", ".join(extras)
        )
    return by_scope


async def _ensure_role(
    api: AuthSecAdminClient,
    application_id: str,
    roles: list[dict[str, Any]],
    name: str,
    description: str,
    scope_ids: list[str],
) -> dict[str, Any]:
    role = next((item for item in roles if _role_label(item) == name.lower()), None)
    if role is None:
        role = await api.post(
            f"/authsec/applications/{application_id}/roles",
            {"name": name, "description": description, "scope_ids": scope_ids},
        )
        roles.append(role)
        console.print(f"[green]created[/green] {name} role")
    else:
        await api.put(
            f"/authsec/applications/{application_id}/roles/{role['id']}/scope-grants",
            {"scope_ids": scope_ids},
        )
        console.print(f"[green]reconciled[/green] {name} role")
    return role


async def _ensure_roles(
    api: AuthSecAdminClient,
    application_id: str,
    scopes: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    roles = _items(await api.get(f"/authsec/applications/{application_id}/roles"), "roles", "items")
    viewer = next((item for item in roles if _role_label(item) == "viewer"), None)
    if viewer is None:
        raise RuntimeError("AuthSec did not create the required built-in viewer role")
    await api.put(
        f"/authsec/applications/{application_id}/roles/{viewer['id']}/scope-grants",
        {"scope_ids": [str(scopes[scope]["id"]) for scope in READER_SCOPES]},
    )
    console.print("[green]reconciled[/green] built-in Viewer role with read-only scopes")
    reader = await _ensure_role(
        api,
        application_id,
        roles,
        "Reader",
        "Read commits and repository documentation",
        [str(scopes[scope]["id"]) for scope in READER_SCOPES],
    )
    triage = await _ensure_role(
        api,
        application_id,
        roles,
        "Triage",
        "Reader access plus sandbox issue creation",
        [str(scopes[scope]["id"]) for scope in TRIAGE_SCOPES],
    )
    return reader, triage


def _ensure_m2m_key_pair() -> tuple[str, str]:
    private_exists = M2M_PRIVATE_KEY_PATH.is_file()
    public_exists = M2M_JWKS_PATH.is_file()
    if private_exists != public_exists:
        raise RuntimeError(
            "M2M private/public key state is incomplete; refusing to guess or overwrite it"
        )
    if not private_exists:
        generated = generate_private_key_jwks(M2M_PRIVATE_KEY_PATH)
        _write_private_json(M2M_JWKS_PATH, json.loads(generated.jwks_json))
        kid = generated.kid
        console.print("[green]created[/green] local M2M RSA key pair")
    else:
        payload = _read_json_object(M2M_JWKS_PATH)
        keys = payload.get("keys")
        if not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict):
            raise RuntimeError("M2M JWKS must contain exactly one public key")
        forbidden = {"d", "p", "q", "dp", "dq", "qi"} & set(keys[0])
        if forbidden:
            raise RuntimeError("M2M public JWKS contains private key members")
        kid = str(keys[0].get("kid", "")).strip()
        if not kid:
            raise RuntimeError("M2M public key has no kid")
    M2M_PRIVATE_KEY_PATH.chmod(0o600)
    return kid, json.dumps(_read_json_object(M2M_JWKS_PATH), separators=(",", ":"))


async def _ensure_m2m(
    api: AuthSecAdminClient,
    env_file: PrivateEnvFile,
    application_id: str,
    workspace_id: str,
    reader_role: dict[str, Any],
) -> dict[str, str]:
    kid, public_jwks = _ensure_m2m_key_pair()
    state = _read_json_object(BOOTSTRAP_STATE_PATH)
    env = env_file.values()
    accounts = _items(
        await api.get("/authsec/uflow/admin/service-accounts"), "items", "service_accounts"
    )
    account = next(
        (
            item
            for item in accounts
            if str(item.get("id")) == str(state.get("m2m_service_account_id"))
        ),
        None,
    )
    if account is None:
        expected_client = str(state.get("m2m_client_id") or env.get("AUTHSEC_M2M_CLIENT_ID") or "")
        account = next(
            (
                item
                for item in accounts
                if item.get("name") == "svc-github-ci"
                and (not expected_client or item.get("oauth_client_id") == expected_client)
            ),
            None,
        )

    client_id = str(account.get("oauth_client_id") or "") if account else ""
    if client_id:
        assert account is not None
        expected_client = str(state.get("m2m_client_id") or env.get("AUTHSEC_M2M_CLIENT_ID") or "")
        state_matches = (
            expected_client == client_id
            and str(state.get("m2m_key_id") or kid) == kid
            and M2M_PRIVATE_KEY_PATH.is_file()
        )
        if not state_matches:
            raise RuntimeError(
                "svc-github-ci already has a different private-key credential. "
                "It cannot be adopted safely because AuthSec never returns private keys."
            )
        result = {
            "m2m_service_account_id": str(account["id"]),
            "m2m_client_id": client_id,
        }
        console.print("[green]reused[/green] existing M2M machine credential")
    else:
        body: dict[str, Any] = {"role_id": reader_role["id"], "jwks": public_jwks}
        if account:
            body["service_account_id"] = account["id"]
        else:
            body.update(
                {
                    "service_account_name": "svc-github-ci",
                    "description": "AuthSec demo CI reporter (private_key_jwt)",
                }
            )
        credential = await api.post(
            f"/authsec/applications/{application_id}/machine-access/api-credential", body
        )
        result = {
            "m2m_service_account_id": str(credential["service_account_id"]),
            "m2m_client_id": str(credential["client_id"]),
        }
        console.print("[green]created[/green] M2M machine credential")

    await _ensure_reader_assignment(
        api,
        application_id,
        result["m2m_service_account_id"],
        reader_role,
        "M2M Service Account",
    )

    env_file.update(
        {
            "AUTHSEC_M2M_CLIENT_ID": result["m2m_client_id"],
            "AUTHSEC_M2M_PRIVATE_KEY_PATH": str(M2M_PRIVATE_KEY_PATH),
            "AUTHSEC_M2M_KEY_ID": kid,
        }
    )
    state.update(
        {
            **result,
            "m2m_private_key_path": str(M2M_PRIVATE_KEY_PATH),
            "m2m_key_id": kid,
            "resource_server_id": application_id,
            "workspace_id": workspace_id,
        }
    )
    _write_private_json(BOOTSTRAP_STATE_PATH, state)
    return result


async def _ensure_spiffe(
    api: AuthSecAdminClient,
    env_file: PrivateEnvFile,
    application_id: str,
    reader_role: dict[str, Any],
    issuer_url: str,
) -> dict[str, str]:
    env = env_file.values()
    issuer = env.get("SPIRE_OIDC_DISCOVERY_URL") or "https://spire-demo.mcpauthz.com"
    trust_domain = env.get("SPIRE_TRUST_DOMAIN") or "authsec.demo"
    spiffe_id = env.get("SPIFFE_ID") or "spiffe://authsec.demo/workload/release-reporter"

    providers = _items(await api.get("/authsec/workload-identity-providers"), "items", "providers")
    matching = [
        item for item in providers if item.get("kind") == "spiffe" and item.get("issuer") == issuer
    ]
    if len(matching) > 1:
        raise RuntimeError("Multiple SPIFFE providers use the demo issuer")
    expected_audience = issuer_url.rstrip("/") + "/oauth/token"
    if matching:
        provider = matching[0]
        if provider.get("status") != "active":
            raise RuntimeError("Existing SPIFFE provider is not active")
        existing_domain = str(provider.get("trust_domain") or "")
        if existing_domain and existing_domain != trust_domain:
            raise RuntimeError("Existing SPIFFE provider has the wrong trust domain")
        if set(provider.get("allowed_audiences") or []) != {expected_audience}:
            await api.delete(f"/authsec/workload-identity-providers/{provider['id']}")
            provider = await api.post(
                "/authsec/workload-identity-providers",
                {
                    "name": "AuthSec Demo Local SPIRE",
                    "kind": "spiffe",
                    "issuer": issuer,
                    "trust_domain": trust_domain,
                    "allowed_audiences": [expected_audience],
                    "subject_claim": "sub",
                },
            )
            console.print("[green]reconciled[/green] SPIFFE provider token audience")
        else:
            console.print("[green]reused[/green] SPIFFE workload identity provider")
    else:
        provider = await api.post(
            "/authsec/workload-identity-providers",
            {
                "name": "AuthSec Demo Local SPIRE",
                "kind": "spiffe",
                "issuer": issuer,
                "trust_domain": trust_domain,
                "allowed_audiences": [expected_audience],
                "subject_claim": "sub",
            },
        )
        console.print("[green]created[/green] SPIFFE workload identity provider")

    workloads = _items(
        await api.get(f"/authsec/applications/{application_id}/workloads"), "items", "workloads"
    )
    workload = next((item for item in workloads if item.get("spiffe_id") == spiffe_id), None)
    if workload and workload.get("status") == "revoked":
        workload = await api.post(
            f"/authsec/applications/{application_id}/workloads/{workload['workload_id']}/restore"
        )
        console.print("[green]restored[/green] SPIFFE workload")
    elif workload and workload.get("status") == "active":
        console.print("[green]reused[/green] SPIFFE workload")
    elif workload:
        raise RuntimeError(f"SPIFFE workload is in unsupported state {workload.get('status')!r}")
    else:
        workload = await api.post(
            f"/authsec/applications/{application_id}/access/federated-workload",
            {
                "provider_id": provider["id"],
                "external_spiffe_id": spiffe_id,
                "role_id": reader_role["id"],
                "service_account_name": "wl-release-reporter",
                "description": "AuthSec demo release reporter (federated SPIFFE)",
            },
        )
        console.print("[green]created[/green] federated SPIFFE workload")
    client_id = str(workload.get("client_id") or "")
    service_account_id = str(workload.get("service_account_id") or "")
    if not client_id:
        raise RuntimeError("SPIFFE workload record has no OAuth Client ID")
    if not service_account_id:
        raise RuntimeError("SPIFFE workload record has no backing Service Account")
    await _ensure_reader_assignment(
        api,
        application_id,
        service_account_id,
        reader_role,
        "SPIFFE workload",
    )
    env_file.update({"DEMO_ENABLE_SPIRE": "true", "SPIFFE_CLIENT_ID": client_id})
    return {
        "provider_id": str(provider["id"]),
        "spiffe_client_id": client_id,
        "spiffe_service_account_id": service_account_id,
    }


async def _ensure_reader_assignment(
    api: AuthSecAdminClient,
    application_id: str,
    service_account_id: str,
    reader_role: dict[str, Any],
    label: str,
) -> None:
    assignments = _items(
        await api.get(f"/authsec/applications/{application_id}/access-assignments"),
        "items",
        "assignments",
    )
    relevant = [
        item
        for item in assignments
        if item.get("identity_type") == "service_account"
        and str(item.get("identity_id")) == service_account_id
    ]
    unexpected = [item for item in relevant if str(item.get("role_id")) != str(reader_role["id"])]
    if unexpected:
        raise RuntimeError(
            f"{label} has a non-Reader Application assignment; refusing to preserve "
            "unexpected machine privilege"
        )
    await api.post(
        f"/authsec/applications/{application_id}/access/workloads",
        {"service_account_id": service_account_id, "role_id": reader_role["id"]},
    )
    if relevant:
        console.print(f"[green]verified[/green] {label} has Reader only and is registered")
    else:
        console.print(f"[green]attached[/green] existing {label} to Reader")


async def _ensure_agent(
    api: AuthSecAdminClient, env_file: PrivateEnvFile, application_id: str
) -> str:
    env = env_file.values()
    client_id = env.get("AUTHSEC_AGENT_CLIENT_ID", "")
    secret = env.get("AUTHSEC_AGENT_CLIENT_SECRET", "")
    reusable = False
    if client_id and secret:
        try:
            await api.post(
                f"/authsec/applications/{application_id}/token-test/simulate-xaa",
                {"client_id": client_id},
            )
            reusable = True
        except AuthSecAPIError as exc:
            if exc.status_code != 404:
                raise
    if reusable:
        console.print("[green]reused[/green] confidential XAA Agent")
        return client_id

    response = await api.post(
        "/authsec/agents",
        {
            "name": "agent-repo-assistant",
            "redirect_uris": ["http://localhost:8126/callback"],
        },
    )
    client_id = str(response.get("client_id", ""))
    secret = str(response.get("client_secret", ""))
    if not client_id or not secret:
        raise RuntimeError("Agent creation did not return its one-time client secret")
    env_file.update({"AUTHSEC_AGENT_CLIENT_ID": client_id, "AUTHSEC_AGENT_CLIENT_SECRET": secret})
    console.print("[green]created[/green] confidential XAA Agent and captured its secret")
    return client_id


async def _ensure_presenter_assignment(
    api: AuthSecAdminClient,
    application_id: str,
    user_id: str,
    triage_role: dict[str, Any],
) -> bool:
    try:
        UUID(user_id)
    except ValueError:
        console.print(
            "[yellow]skipped[/yellow] presenter Triage assignment: token sub is not a UUID"
        )
        return False
    assignments = _items(
        await api.get(f"/authsec/applications/{application_id}/access-assignments"),
        "items",
        "assignments",
    )
    exists = _has_user_role_assignment(assignments, user_id, str(triage_role["id"]))
    if exists:
        console.print("[green]reused[/green] presenter Triage assignment")
        return True
    try:
        await api.post(
            f"/authsec/applications/{application_id}/access-assignments/users",
            {"user_id": user_id, "role_id": triage_role["id"]},
        )
    except AuthSecAPIError as exc:
        if exc.status_code == 404:
            console.print(
                "[yellow]skipped[/yellow] presenter Triage assignment: token user is not "
                "a workspace user"
            )
            return False
        raise
    console.print("[green]created[/green] presenter Triage assignment from token subject")
    return True


class ShareLifecycle:
    def __init__(self, environment: dict[str, str]) -> None:
        self.environment = environment
        self.process: subprocess.Popen[bytes] | None = None
        self._log_handle: Any = None

    def start(self) -> None:
        subprocess.run(
            ["pnpm", "share:stop"],
            cwd=PROJECT_ROOT,
            env=self.environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        ensure_private_directory(STATE_DIR)
        self._log_handle = RECOVERY_LOG_PATH.open("wb")
        RECOVERY_LOG_PATH.chmod(0o600)
        self.process = subprocess.Popen(
            ["pnpm", "share"],
            cwd=PROJECT_ROOT,
            env=self.environment,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    async def wait_ready(self, timeout_seconds: int = 240) -> None:
        deadline = time.monotonic() + timeout_seconds
        async with httpx.AsyncClient(timeout=5.0) as client:
            while time.monotonic() < deadline:
                if self.process is not None and self.process.poll() is not None:
                    raise RuntimeError(self._failure_message("pnpm share exited before readiness"))
                local_ready = False
                public_mcp_ready = False
                spire_ready = False
                try:
                    response = await client.get("http://127.0.0.1:8091/healthz")
                    local_ready = response.status_code == 200
                except httpx.HTTPError:
                    pass
                try:
                    response = await client.get("https://mcp-demo.mcpauthz.com/healthz")
                    public_mcp_ready = response.status_code == 200
                except httpx.HTTPError:
                    pass
                try:
                    response = await client.get(
                        "https://spire-demo.mcpauthz.com/.well-known/openid-configuration"
                    )
                    spire_ready = response.status_code == 200
                except httpx.HTTPError:
                    pass
                if local_ready and public_mcp_ready and spire_ready:
                    console.print("[green]ready[/green] temporary MCP and SPIRE share group")
                    return
                await asyncio.sleep(2)
        raise RuntimeError(self._failure_message("pnpm share did not become ready in time"))

    def _failure_message(self, prefix: str) -> str:
        tail = ""
        if RECOVERY_LOG_PATH.is_file():
            lines = RECOVERY_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
            tail = "\n".join(lines[-30:])
        return prefix + ("\nLast safe share log lines:\n" + tail if tail else "")

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=30)
        subprocess.run(
            ["pnpm", "share:stop"],
            cwd=PROJECT_ROOT,
            env=self.environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if self._log_handle is not None:
            self._log_handle.close()
        self._assert_stopped()

    def _assert_stopped(self) -> None:
        problems: list[str] = []
        port = subprocess.run(
            ["lsof", "-nP", "-iTCP:8091", "-sTCP:LISTEN"],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if port.stdout.strip():
            problems.append("port 8091 still has a listener")

        processes = subprocess.run(
            ["ps", "ax", "-o", "command="],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True,
        ).stdout.splitlines()
        mcp_config = self.environment.get("MCP_TUNNEL_CONFIG") or str(
            Path.home() / ".cloudflared/authsec-mcp-demo.yml"
        )
        spire_config = self.environment.get("SPIRE_TUNNEL_CONFIG") or str(
            Path.home() / ".cloudflared/authsec-spire-demo.yml"
        )
        if any(
            "authsec-demo-server" in command or ("cloudflared" in command and config in command)
            for command in processes
            for config in (mcp_config, spire_config)
        ):
            problems.append("a demo server or Cloudflare connector is still running")

        compose = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(PROJECT_ROOT / "spire/docker-compose.spire.yml"),
                "ps",
                "-q",
            ],
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if compose.stdout.strip():
            problems.append("SPIRE Compose containers are still running")
        if (STATE_DIR / "share.lock/pid").exists():
            problems.append("share supervisor lock is still present")
        if problems:
            raise RuntimeError("Recovery cleanup incomplete: " + "; ".join(problems))


async def _wait_for_manifest(
    api: AuthSecAdminClient, application_id: str, timeout_seconds: int = 90
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        status = await api.get(f"/authsec/applications/{application_id}/sdk-manifest-status")
        if not status.get("never_seen") and status.get("last_success"):
            console.print("[green]received[/green] live FastMCP manifest")
            return
        await asyncio.sleep(2)
    raise RuntimeError("AuthSec did not receive the SDK manifest within 90 seconds")


async def _map_tools(
    api: AuthSecAdminClient,
    application_id: str,
    scopes: dict[str, dict[str, Any]],
) -> None:
    matrix = await api.get(f"/authsec/applications/{application_id}/scope-matrix")
    tools = {str(item["name"]): item for item in matrix.get("tools", [])}
    missing = set(TOOL_SCOPE_SUGGESTIONS) - set(tools)
    if missing:
        raise RuntimeError("Manifest is missing tools: " + ", ".join(sorted(missing)))
    mappings: list[dict[str, Any]] = []
    for tool_name, desired_scopes in TOOL_SCOPE_SUGGESTIONS.items():
        tool = tools[tool_name]
        desired_ids = {str(scopes[scope]["id"]) for scope in desired_scopes}
        current = {
            str(item["scope_id"])
            for item in tool.get("scopes", [])
            if item.get("source") == "admin_override"
        }
        mappings.extend(
            {"tool_id": tool["id"], "scope_id": scope_id}
            for scope_id in sorted(desired_ids - current)
        )
        mappings.extend(
            {"tool_id": tool["id"], "scope_id": scope_id, "remove": True}
            for scope_id in sorted(current - desired_ids)
        )
    if mappings:
        await api.put(
            f"/authsec/applications/{application_id}/tool-scope-map", {"mappings": mappings}
        )
        console.print(f"[green]reconciled[/green] {len(mappings)} exact tool-scope changes")
    else:
        console.print("[green]verified[/green] exact tool-scope mappings")


async def _activate(api: AuthSecAdminClient, application_id: str) -> None:
    application = await api.get(f"/authsec/applications/{application_id}")
    if application.get("state") == "ready":
        console.print("[green]verified[/green] Application is active")
        return
    preview = await api.get(f"/authsec/applications/{application_id}/activation-preview")
    if not preview.get("can_activate"):
        raise RuntimeError("Activation preview is blocked: " + json.dumps(preview, sort_keys=True))
    await api.post(f"/authsec/applications/{application_id}/activate")
    console.print("[green]activated[/green] AuthSec Application after exact policy review")


def _subprocess_environment(env_file: PrivateEnvFile) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(env_file.values())
    environment.pop("AUTHSEC_ADMIN_TOKEN", None)
    return environment


def _run_verification(environment: dict[str, str]) -> None:
    commands = [
        ["pnpm", "preflight"],
        ["uv", "run", "demo-agent", "proof", "ci-reporter"],
        ["pnpm", "agent:spiffe:proof"],
    ]
    for command in commands:
        subprocess.run(command, cwd=PROJECT_ROOT, env=environment, check=True)


async def _audit(
    api: AuthSecAdminClient,
    env_file: PrivateEnvFile,
    identity: AdminIdentity,
    admin_api_url: str,
) -> int:
    env = env_file.values()
    applications = _items(await api.get("/authsec/applications"), "items", "applications")
    exact = [app for app in applications if app.get("resource_uri") == RESOURCE_URI]
    table = Table(title="AuthSec demo recovery audit")
    table.add_column("Layer")
    table.add_column("Result")
    healthy: list[bool] = []

    def add(layer: str, ready: bool, failure: str = "missing or stale") -> None:
        healthy.append(ready)
        table.add_row(layer, "[green]ready[/green]" if ready else f"[yellow]{failure}[/yellow]")

    add("OAuth token workspace", bool(identity.workspace_id))
    add("Application", len(exact) == 1, "missing or ambiguous")

    application_id = str(exact[0].get("id")) if len(exact) == 1 else ""
    local_anchor = bool(
        application_id
        and env.get("AUTHSEC_RESOURCE_SERVER_ID") == application_id
        and env.get("AUTHSEC_INTROSPECTION_CLIENT_ID") == application_id
        and env.get("AUTHSEC_INTROSPECTION_CLIENT_SECRET")
    )
    add("Local Application anchor", local_anchor)
    secret_works = False
    if local_anchor:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{admin_api_url.rstrip('/')}/authsec/resource-servers/{application_id}/sdk-policy",
                auth=(application_id, env["AUTHSEC_INTROSPECTION_CLIENT_SECRET"]),
            )
            secret_works = response.status_code == 200
    add("Introspection credential", secret_works)

    github_key = env.get("GITHUB_PRIVATE_KEY", "")
    github_key_present = "-----BEGIN" in github_key or (
        bool(github_key) and Path(github_key).expanduser().is_file()
    )
    add(
        "External GitHub assets",
        bool(env.get("GITHUB_APP_ID") and env.get("GITHUB_INSTALLATION_ID") and github_key_present),
        "incomplete",
    )
    add(
        "Cloudflare configs",
        all(
            bool(env.get(key)) and Path(env[key]).expanduser().is_file()
            for key in ("MCP_TUNNEL_CONFIG", "SPIRE_TUNNEL_CONFIG")
        ),
        "incomplete",
    )
    add(
        "Local M2M key pair",
        M2M_PRIVATE_KEY_PATH.is_file() and M2M_JWKS_PATH.is_file(),
        "incomplete",
    )

    if application_id:
        application = await api.get(f"/authsec/applications/{application_id}")
        add("Application activation", application.get("state") == "ready", "not ready")

        scopes = _items(
            await api.get(f"/authsec/applications/{application_id}/scopes"),
            "items",
            "scopes",
        )
        by_scope = {str(item.get("scope_string")): item for item in scopes}
        add("Canonical scopes", set(TRIAGE_SCOPES) <= set(by_scope))

        roles = _items(
            await api.get(f"/authsec/applications/{application_id}/roles"), "roles", "items"
        )
        by_role = {_role_label(item): item for item in roles}
        add("Reader/Triage roles", {"reader", "triage"} <= set(by_role))

        matrix = await api.get(f"/authsec/applications/{application_id}/scope-matrix")
        tools = {str(item.get("name")): item for item in matrix.get("tools", [])}
        mappings_exact = set(TOOL_SCOPE_SUGGESTIONS) <= set(tools) and set(TRIAGE_SCOPES) <= set(
            by_scope
        )
        if mappings_exact:
            for tool_name, desired in TOOL_SCOPE_SUGGESTIONS.items():
                current = {
                    str(item.get("scope_id"))
                    for item in tools[tool_name].get("scopes", [])
                    if item.get("source") == "admin_override"
                }
                wanted = {str(by_scope[scope]["id"]) for scope in desired}
                mappings_exact = mappings_exact and current == wanted
        add("Exact tool mappings", mappings_exact)

        assignments = _items(
            await api.get(f"/authsec/applications/{application_id}/access-assignments"),
            "items",
            "assignments",
        )

        accounts = _items(
            await api.get("/authsec/uflow/admin/service-accounts"),
            "items",
            "service_accounts",
        )
        m2m_client_id = env.get("AUTHSEC_M2M_CLIENT_ID", "")
        m2m_account = next(
            (
                account
                for account in accounts
                if account.get("name") == "svc-github-ci"
                and str(account.get("oauth_client_id") or "") == m2m_client_id
            ),
            None,
        )
        m2m_reader_only = bool(
            m2m_account
            and any(
                item.get("identity_type") == "service_account"
                and str(item.get("identity_id")) == str(m2m_account["id"])
                and set(item.get("effective_scopes") or []) == set(READER_SCOPES)
                for item in assignments
            )
        )
        add("M2M Service Account", bool(m2m_client_id and m2m_account and m2m_reader_only))

        providers = _items(
            await api.get("/authsec/workload-identity-providers"), "items", "providers"
        )
        issuer = env.get("SPIRE_OIDC_DISCOVERY_URL") or "https://spire-demo.mcpauthz.com"
        trust_domain = env.get("SPIRE_TRUST_DOMAIN") or "authsec.demo"
        provider_ready = any(
            provider.get("kind") == "spiffe"
            and provider.get("issuer") == issuer
            and provider.get("status") == "active"
            and str(provider.get("trust_domain") or trust_domain) == trust_domain
            for provider in providers
        )
        add("SPIFFE provider", provider_ready)

        workloads = _items(
            await api.get(f"/authsec/applications/{application_id}/workloads"),
            "items",
            "workloads",
        )
        spiffe_id = env.get("SPIFFE_ID") or "spiffe://authsec.demo/workload/release-reporter"
        spiffe_client_id = env.get("SPIFFE_CLIENT_ID", "")
        workload = next(
            (
                item
                for item in workloads
                if item.get("spiffe_id") == spiffe_id
                and item.get("status") == "active"
                and str(item.get("client_id") or "") == spiffe_client_id
            ),
            None,
        )
        workload_reader_only = bool(
            workload
            and any(
                item.get("identity_type") == "service_account"
                and str(item.get("identity_id")) == str(workload.get("service_account_id"))
                and set(item.get("effective_scopes") or []) == set(READER_SCOPES)
                for item in assignments
            )
        )
        add("SPIFFE workload", bool(spiffe_client_id and workload and workload_reader_only))

        agent_id = env.get("AUTHSEC_AGENT_CLIENT_ID", "")
        agent_ready = False
        if agent_id and env.get("AUTHSEC_AGENT_CLIENT_SECRET"):
            try:
                await api.post(
                    f"/authsec/applications/{application_id}/token-test/simulate-xaa",
                    {"client_id": agent_id},
                )
                agent_ready = True
            except AuthSecAPIError as exc:
                if exc.status_code != 404:
                    raise
        add("Confidential XAA Agent", agent_ready)

        triage = by_role.get("triage")
        presenter_ready = bool(
            triage and _has_user_role_assignment(assignments, identity.user_id, str(triage["id"]))
        )
        add("Token subject Triage", presenter_ready, "not assigned")

    console.print(table)
    return 0 if all(healthy) else 3


async def _run(args: argparse.Namespace) -> int:
    token = _admin_token(args)
    identity = _decode_admin_identity(token)
    env_file = PrivateEnvFile(create=not args.audit)
    env = env_file.values()
    issuer_url = env.get("AUTHSEC_ISSUER") or DEFAULT_AUTHSEC_ISSUER_URL
    admin_api_url = env.get("AUTHSEC_ADMIN_API_URL") or DEFAULT_AUTHSEC_ADMIN_API_URL

    async with AuthSecAdminClient(admin_api_url, token) as api:
        if args.audit:
            return await _audit(api, env_file, identity, admin_api_url)

        anchor = await _ensure_application(api, env_file, identity)
        scopes = await _ensure_scopes(api, anchor.application_id)
        reader, triage = await _ensure_roles(api, anchor.application_id, scopes)
        m2m = await _ensure_m2m(api, env_file, anchor.application_id, identity.workspace_id, reader)
        spiffe = await _ensure_spiffe(api, env_file, anchor.application_id, reader, issuer_url)
        agent_client_id = await _ensure_agent(api, env_file, anchor.application_id)
        presenter_assigned = await _ensure_presenter_assignment(
            api, anchor.application_id, identity.user_id, triage
        )
        _checkpoint(
            phase="identities",
            m2m_client_id=m2m["m2m_client_id"],
            spiffe_client_id=spiffe["spiffe_client_id"],
            spiffe_service_account_id=spiffe["spiffe_service_account_id"],
            workload_provider_id=spiffe["provider_id"],
            agent_client_id=agent_client_id,
            presenter_assigned=presenter_assigned,
        )

        environment = _subprocess_environment(env_file)
        lifecycle = ShareLifecycle(environment)
        try:
            lifecycle.start()
            await lifecycle.wait_ready()
            await _wait_for_manifest(api, anchor.application_id)
            await _map_tools(api, anchor.application_id, scopes)
            await _activate(api, anchor.application_id)
            _checkpoint(phase="activated")
            if not args.skip_proofs:
                await asyncio.to_thread(_run_verification, environment)
                _checkpoint(phase="verified")
        finally:
            lifecycle.stop()

    summary = Table(title="One-token recovery complete")
    summary.add_column("Layer")
    summary.add_column("Status")
    summary.add_row("Application / scopes / roles / mappings", "ready")
    summary.add_row("M2M private-key JWT", "ready")
    summary.add_row("SPIFFE provider / workload", "ready")
    summary.add_row("Confidential XAA Agent", "ready")
    summary.add_row(
        "Presenter Triage", "ready" if presenter_assigned else "login/assignment needed"
    )
    summary.add_row("Share process group", "stopped cleanly")
    console.print(summary)
    if not presenter_assigned:
        console.print(
            "Run `uv run demo-agent login` as the presenter, then grant that user Triage."
        )
    else:
        console.print("Run `uv run demo-agent login` once to create a fresh browser session.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rebuild the AuthSec demo from one short-lived workspace-admin OAuth token"
    )
    parser.add_argument(
        "--token-stdin",
        action="store_true",
        help="read one token line from stdin instead of using the secure prompt",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="inspect anchors without mutating AuthSec or local state",
    )
    parser.add_argument(
        "--skip-proofs",
        action="store_true",
        help="configure and activate, but skip deterministic M2M/SPIFFE proof calls",
    )
    args = parser.parse_args()
    configure_logging("recover")
    try:
        sys.exit(asyncio.run(_run(args)))
    except (
        AuthSecAPIError,
        RuntimeError,
        OSError,
        ValueError,
        subprocess.CalledProcessError,
    ) as exc:
        console.print(f"[red]Recovery failed safely:[/red] {exc}")
        console.print(
            "No admin token was persisted. One-time credentials already issued were "
            "checkpointed in the private .env; rerun the same command to resume."
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
