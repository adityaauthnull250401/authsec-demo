"""Idempotent, manifest-first AuthSec setup for the demo Application.

The Application and its one-time introspection secret remain human-created.
This command verifies that anchor, creates/updates roles, creates the M2M
service account with a locally generated private-key credential, waits for the
SDK manifest, and applies exact admin_override mappings. It never activates the
Application implicitly: the operator reviews and activates in the console,
then reruns this command for the final ready-state verification.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import jwt
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
from apps.shared.env import (
    SECRETS_DIR,
    STATE_DIR,
    ConfigurationError,
    ensure_private_directory,
    load_project_env,
    optional,
    required,
)
from apps.shared.logging import configure_logging
from scripts.authsec_api import AuthSecAdminClient
from scripts.keys import GeneratedKey, generate_private_key_jwks

console = Console()
READER_SCOPES = [READ_SCOPE, README_SCOPE]
TRIAGE_SCOPES = [READ_SCOPE, README_SCOPE, ISSUE_SCOPE]


def _role_label(role: dict[str, Any]) -> str:
    name = str(role.get("name", ""))
    return name.rsplit(":", 1)[-1].replace("_", "-").lower()


def _admin_workspace(token: str) -> str:
    claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    return str(claims.get("workspace_id") or claims.get("tenant_id") or "")


def _write_bootstrap_state(values: dict[str, str]) -> None:
    ensure_private_directory(STATE_DIR)
    path = STATE_DIR / "bootstrap.json"
    path.write_text(json.dumps(values, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)


async def _ensure_role(
    api: AuthSecAdminClient,
    rs_id: str,
    roles: list[dict[str, Any]],
    name: str,
    description: str,
    scope_ids: list[str],
) -> dict[str, Any]:
    slug = name.lower()
    role = next((item for item in roles if _role_label(item) == slug), None)
    if role is None:
        role = await api.post(
            f"/authsec/applications/{rs_id}/roles",
            {"name": name, "description": description, "scope_ids": scope_ids},
        )
        roles.append(role)
        console.print(f"[green]created[/green] {name} role")
    else:
        await api.put(
            f"/authsec/applications/{rs_id}/roles/{role['id']}/scope-grants",
            {"scope_ids": scope_ids},
        )
        console.print(f"[green]reconciled[/green] {name} role scope grants")
    return role


async def _ensure_m2m(
    api: AuthSecAdminClient,
    rs_id: str,
    reader_role: dict[str, Any],
) -> dict[str, str]:
    accounts_payload = await api.get("/authsec/uflow/admin/service-accounts")
    accounts = (
        accounts_payload
        if isinstance(accounts_payload, list)
        else accounts_payload.get("items", [])
    )
    account = next((item for item in accounts if item.get("name") == "svc-github-ci"), None)

    state_path = STATE_DIR / "bootstrap.json"
    old_state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    if account and account.get("oauth_client_id"):
        client_id = str(account["oauth_client_id"])
        stored_key_path = str(old_state.get("m2m_private_key_path", ""))
        kid = str(old_state.get("m2m_key_id", ""))
        if not stored_key_path or not Path(stored_key_path).is_file() or not kid:
            raise RuntimeError(
                "svc-github-ci already has a credential, but its local private key "
                "state is missing. AuthSec cannot reveal/recreate that private key; "
                "create a new demo service account."
            )
        console.print("[green]found[/green] existing svc-github-ci credential")
        return {
            "m2m_service_account_id": str(account["id"]),
            "m2m_client_id": client_id,
            "m2m_private_key_path": stored_key_path,
            "m2m_key_id": kid,
        }

    generated_key_path = SECRETS_DIR / "svc-github-ci-private.pem"
    generated: GeneratedKey
    if generated_key_path.exists():
        raise RuntimeError(
            f"Private key exists without a matching credential record: {generated_key_path}. "
            "Move it aside after confirming the console state, then rerun bootstrap."
        )
    generated = generate_private_key_jwks(generated_key_path)
    body: dict[str, Any] = {
        "role_id": reader_role["id"],
        "jwks": generated.jwks_json,
    }
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
        f"/authsec/applications/{rs_id}/machine-access/api-credential", body
    )
    console.print("[green]created[/green] svc-github-ci private_key_jwt credential")
    return {
        "m2m_service_account_id": str(credential["service_account_id"]),
        "m2m_client_id": str(credential["client_id"]),
        "m2m_private_key_path": str(generated.private_key_path),
        "m2m_key_id": generated.kid,
    }


async def _run() -> int:
    load_project_env()
    base_url = optional("AUTHSEC_ISSUER", "https://app.authsec.ai")
    admin_token = required("AUTHSEC_ADMIN_TOKEN")
    expected_workspace = required("AUTHSEC_DEMO_WORKSPACE_ID")
    token_workspace = _admin_workspace(admin_token)
    if token_workspace and token_workspace != expected_workspace:
        raise RuntimeError("AUTHSEC_ADMIN_TOKEN belongs to a different workspace; refusing setup")
    rs_id = required("AUTHSEC_RESOURCE_SERVER_ID")

    async with AuthSecAdminClient(base_url, admin_token) as api:
        application = await api.get(f"/authsec/applications/{rs_id}")
        if application.get("workspace_id") != expected_workspace:
            raise RuntimeError("Application is outside AUTHSEC_DEMO_WORKSPACE_ID; refusing setup")
        if application.get("name") != APP_NAME or application.get("resource_uri") != RESOURCE_URI:
            raise RuntimeError(
                "Application name/resource URI do not match the pinned demo contract"
            )

        scopes_payload = await api.get(f"/authsec/applications/{rs_id}/scopes")
        scopes = (
            scopes_payload if isinstance(scopes_payload, list) else scopes_payload.get("scopes", [])
        )
        by_scope = {str(item["scope_string"]): item for item in scopes}
        missing = set(TRIAGE_SCOPES) - set(by_scope)
        if missing:
            raise RuntimeError(
                "Create these canonical Application scopes first: " + ", ".join(sorted(missing))
            )

        roles_payload = await api.get(f"/authsec/applications/{rs_id}/roles")
        roles = list(roles_payload.get("roles", []))
        reader = await _ensure_role(
            api,
            rs_id,
            roles,
            "Reader",
            "Read commits and repository documentation",
            [by_scope[item]["id"] for item in READER_SCOPES],
        )
        await _ensure_role(
            api,
            rs_id,
            roles,
            "Triage",
            "Reader access plus sandbox issue creation",
            [by_scope[item]["id"] for item in TRIAGE_SCOPES],
        )

        state = await _ensure_m2m(api, rs_id, reader)
        state.update({"resource_server_id": rs_id, "workspace_id": expected_workspace})
        _write_bootstrap_state(state)

        manifest = await api.get(f"/authsec/applications/{rs_id}/sdk-manifest-status")
        if manifest.get("never_seen") or not manifest.get("last_success"):
            console.print(
                "[yellow]BLOCKED at manifest gate.[/yellow] Start `pnpm share`, wait for the "
                "server to publish its FastMCP inventory, then rerun `uv run bootstrap`."
            )
            return 3

        matrix = await api.get(f"/authsec/applications/{rs_id}/scope-matrix")
        tools = {str(item["name"]): item for item in matrix.get("tools", [])}
        missing_tools = set(TOOL_SCOPE_SUGGESTIONS) - set(tools)
        if missing_tools:
            raise RuntimeError("Manifest is missing tools: " + ", ".join(sorted(missing_tools)))

        mappings: list[dict[str, Any]] = []
        for tool_name, desired_scopes in TOOL_SCOPE_SUGGESTIONS.items():
            tool = tools[tool_name]
            desired_ids = {str(by_scope[item]["id"]) for item in desired_scopes}
            current_admin = {
                str(item["scope_id"])
                for item in tool.get("scopes", [])
                if item.get("source") == "admin_override"
            }
            mappings.extend(
                {"tool_id": tool["id"], "scope_id": scope_id}
                for scope_id in sorted(desired_ids - current_admin)
            )
            mappings.extend(
                {"tool_id": tool["id"], "scope_id": scope_id, "remove": True}
                for scope_id in sorted(current_admin - desired_ids)
            )
        if mappings:
            await api.put(f"/authsec/applications/{rs_id}/tool-scope-map", {"mappings": mappings})
            console.print(f"[green]reconciled[/green] {len(mappings)} admin_override changes")
        else:
            console.print("[green]verified[/green] admin_override mappings already exact")

        application = await api.get(f"/authsec/applications/{rs_id}")
        if application.get("state") != "ready":
            preview = await api.get(f"/authsec/applications/{rs_id}/activation-preview")
            console.print_json(data=preview)
            console.print(
                "[yellow]HUMAN ACTION REQUIRED:[/yellow] review and activate the Application at\n"
                f"{optional('AUTHSEC_CONSOLE_URL', 'https://app.authsec.ai')}/applications/{rs_id}\n"
                "Then rerun bootstrap. Live tools/list cannot verify before state=ready."
            )
            return 3

    table = Table(title="Bootstrap result")
    table.add_column("Value")
    table.add_column("Copy to .env")
    table.add_row("M2M client ID", f"AUTHSEC_M2M_CLIENT_ID={state['m2m_client_id']}")
    table.add_row("M2M key ID", f"AUTHSEC_M2M_KEY_ID={state['m2m_key_id']}")
    table.add_row("M2M key path", f"AUTHSEC_M2M_PRIVATE_KEY_PATH={state['m2m_private_key_path']}")
    console.print(table)
    console.print("[green]Bootstrap complete.[/green] Run `uv run smoke` after policy refresh.")
    return 0


def main() -> None:
    configure_logging("bootstrap")
    try:
        sys.exit(asyncio.run(_run()))
    except (ConfigurationError, RuntimeError) as exc:
        console.print(f"[red]Bootstrap failed:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
