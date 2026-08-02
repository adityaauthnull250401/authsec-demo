"""Idempotent rehearsal reset, hard-scoped to the pinned demo workspace/app."""

from __future__ import annotations

import argparse
import asyncio
import sys

import jwt
from authsec_sdk.identity import PendingApprovalError
from rich.console import Console

from apps.agents.config import load_agent_settings
from apps.agents.identity import XAATokenProvider
from apps.mcp_server.config import load_server_settings
from apps.mcp_server.constants import APP_NAME, RESOURCE_URI, SANDBOX_REPOSITORY
from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.tools.validation import run_id as validate_run_id
from apps.shared.env import ConfigurationError, load_project_env, optional, required
from apps.shared.logging import configure_logging
from scripts.authsec_api import AuthSecAdminClient
from scripts.run_state import load_run

console = Console()


def _workspace_from_token(token: str) -> str:
    claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    return str(claims.get("workspace_id") or claims.get("tenant_id") or "")


async def _requeue_agent() -> str:
    """A post-revoke token attempt moves AuthSec's connection back to pending."""

    provider = XAATokenProvider(load_agent_settings("repo-assistant"))
    try:
        try:
            await provider.access_token()
            return "unexpectedly approved; review the Connection manually"
        except PendingApprovalError:
            return "pending_approval"
    finally:
        await provider.aclose()


async def _run(raw_run_id: str, skip_github: bool) -> int:
    load_project_env()
    run_id = validate_run_id(raw_run_id)
    if SANDBOX_REPOSITORY != "Aditya250401/authsec-demo-sandbox":
        raise RuntimeError("sandbox repository invariant changed; refusing reset")

    admin_token = required("AUTHSEC_ADMIN_TOKEN")
    expected_workspace = required("AUTHSEC_DEMO_WORKSPACE_ID")
    token_workspace = _workspace_from_token(admin_token)
    if token_workspace and token_workspace != expected_workspace:
        raise RuntimeError("Admin token workspace does not match AUTHSEC_DEMO_WORKSPACE_ID")
    rs_id = required("AUTHSEC_RESOURCE_SERVER_ID")
    issuer = optional("AUTHSEC_ISSUER", "https://app.authsec.ai")
    run = load_run(run_id)

    async with AuthSecAdminClient(issuer, admin_token) as api:
        application = await api.get(f"/authsec/applications/{rs_id}")
        if (
            application.get("workspace_id") != expected_workspace
            or application.get("name") != APP_NAME
            or application.get("resource_uri") != RESOURCE_URI
        ):
            raise RuntimeError("Target is not the pinned demo Application; refusing reset")

        for jti in run.get("jtis", []):
            await api.delete(f"/authsec/tokens/{jti}", allow_missing=True)
            console.print(f"[green]revoked/absent[/green] token jti={jti}")

        agent_client_id = optional("AUTHSEC_AGENT_CLIENT_ID")
        if agent_client_id:
            await api.delete(
                f"/authsec/applications/{rs_id}/connections/{agent_client_id}",
                allow_missing=True,
            )
            console.print("[green]revoked/absent[/green] repo-assistant Connection")

    if not skip_github:
        github = GitHubProvider(load_server_settings())
        try:
            closed = await github.writer.close_run_issues(run_id)
        finally:
            await github.aclose()
        console.print(f"[green]closed/reconciled[/green] sandbox issues: {closed or 'none'}")

    if optional("AUTHSEC_AGENT_CLIENT_ID"):
        try:
            state = await _requeue_agent()
            console.print(f"[green]agent reset state:[/green] {state}")
        except Exception as exc:
            console.print(
                "[yellow]Agent requeue needs the pre-staged Alice session.[/yellow] "
                f"Run `uv run demo-agent token repo-assistant` before rehearsal. ({exc})"
            )
    console.print("[green]Reset complete and safe to repeat.[/green]")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id", nargs="?", default=None)
    parser.add_argument("--skip-github", action="store_true")
    args = parser.parse_args()
    configure_logging("cleanup")
    run_id = args.run_id or optional("DEMO_RUN_ID")
    if not run_id:
        parser.error("provide run_id or set DEMO_RUN_ID")
    try:
        sys.exit(asyncio.run(_run(run_id, args.skip_github)))
    except (ConfigurationError, RuntimeError) as exc:
        console.print(f"[red]Reset refused:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
