"""Operator CLI for login, token proof, and the three ReAct profiles."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from typing import Any

import jwt
from authsec_sdk.identity import (
    AuthSecIdentityError,
    CredentialInvalidError,
    PendingApprovalError,
    ResourceNotRegisteredError,
    SpiffeIdentityError,
    browser_login,
)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from apps.agents.config import ProfileName, load_agent_settings
from apps.agents.identity import build_token_provider
from apps.agents.proof import prove_read_only_access
from apps.agents.runtime import build_agent, run_interactive, run_once
from apps.agents.session import SESSION_PATH, save_subject_token
from apps.shared.env import ConfigurationError, load_project_env, optional, required
from apps.shared.logging import configure_logging, get_logger, log_token

console = Console()
log = get_logger("agent.cli")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AuthSec demo identities and agents")
    sub = parser.add_subparsers(dest="command", required=True)

    login = sub.add_parser("login", help="Pre-stage the presenter's PKCE browser session")
    login.add_argument("--port", type=int, default=None)

    for command in ("token", "run", "proof"):
        cmd = sub.add_parser(command)
        cmd.add_argument("profile", choices=["ci-reporter", "release-reporter", "repo-assistant"])
        if command == "run":
            cmd.add_argument("--prompt", default=None)
            cmd.add_argument("--interactive", action="store_true")
    return parser


async def _login(port: int | None) -> None:
    load_project_env()
    issuer = optional("AUTHSEC_ISSUER", "https://prod.api.authsec.ai")
    client_id = required("AUTHSEC_AGENT_CLIENT_ID")
    login_port = port or int(optional("AUTHSEC_AGENT_LOGIN_PORT", "8126"))
    console.print(
        Panel(
            "The presenter signs in on AuthSec's OAuth page using authorization code + "
            "PKCE. Use the named demo account whose Application access you want to "
            "demonstrate.\n\n"
            "If this email is new, the login page asks for name/password and OTP; completing "
            "that registration creates the user in this workspace. The admin console does "
            "not create the human user, and login alone grants no GitHub MCP access.\n\n"
            f"Agent client: {client_id}\nCallback: http://localhost:{login_port}/callback",
            title="XAA 1/6 — establish the human subject session",
            border_style="cyan",
        )
    )
    subject_token = await browser_login(
        issuer,
        client_id,
        resource=optional("AUTHSEC_RESOURCE_URI", "https://mcp-demo.mcpauthz.com/mcp"),
        # This demo needs only the current browser-authenticated subject token.
        # Requesting offline_access caused AuthSec to reject clients that were
        # intentionally not provisioned for refresh tokens.
        scopes=["openid", "profile", "email"],
        port=login_port,
    )
    save_subject_token(subject_token)
    log_token(log, "Human OIDC ID token stored for delegated exchange", subject_token)
    console.print(f"[green]Presenter session stored securely at {SESSION_PATH}[/green]")
    console.print(
        "[dim]For the write-capable demo, verify this person has Triage (or an equivalent "
        "Application role containing issues:write) on GitHub MCP Demo.[/dim]"
    )


def _safe_claims(token: str) -> dict[str, Any]:
    claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    allowed = {
        "iss",
        "sub",
        "aud",
        "scope",
        "exp",
        "iat",
        "jti",
        "act",
        "tf",
        "client_id",
        "workspace_id",
    }
    return {key: claims[key] for key in allowed if key in claims}


def _render_m2m_token_artifact(token: str) -> None:
    """Prove which token arrived without printing a usable bearer credential."""

    parts = token.split(".")
    if len(parts) == 3:
        safe_compact = f"{parts[0]}.{parts[1]}.[SIGNATURE REDACTED]"
    else:
        safe_compact = "[opaque bearer token; value redacted]"
    fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
    log.info(
        "M2M 4/7 actual access token received | token_type=Bearer length=%s "
        "sha256=%s compact_safe=%s",
        len(token),
        fingerprint,
        safe_compact,
    )
    console.print(
        Panel(
            json.dumps(
                {
                    "token_type": "Bearer",
                    "compact_jwt": safe_compact,
                    "length": len(token),
                    "sha256": fingerprint,
                    "signature": "REDACTED — printing it would expose the live bearer",
                },
                indent=2,
            ),
            title="M2M 4/7 — actual access token received (safe rendering)",
            border_style="green",
        )
    )


def _render_xaa_proof(claims: dict[str, Any]) -> None:
    """Explain the dual-principal token using only non-secret claims."""

    actor = claims.get("act")
    if isinstance(actor, dict):
        actor_value = actor.get("client_id") or actor.get("sub") or json.dumps(actor)
    else:
        actor_value = actor or "missing — investigate token profile"

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Evidence")
    table.add_column("Observed value")
    table.add_column("What it proves")
    table.add_row("sub", str(claims.get("sub", "missing")), "Human remains the subject")
    table.add_row("act.client_id", str(actor_value), "The Agent is a separate actor")
    table.add_row("tf", str(claims.get("tf", "missing")), "Delegated XAA token family")
    table.add_row("aud", str(claims.get("aud", "missing")), "Token is bound to this MCP server")
    table.add_row("scope", str(claims.get("scope", "missing")), "Only the approved role's scopes")
    console.print(Panel(table, title="XAA 5/6 — delegated token proof", border_style="green"))
   


def _render_m2m_proof(claims: dict[str, Any]) -> None:
    """Explain the single machine principal represented by the M2M token."""

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Evidence")
    table.add_column("Observed value")
    table.add_column("What it proves")
    table.add_row("sub", str(claims.get("sub", "missing")), "Service Account is the subject")
    table.add_row("act", str(claims.get("act", "absent")), "No human/Agent delegation")
    table.add_row("tf", str(claims.get("tf", "missing")), "M2M token family")
    table.add_row("aud", str(claims.get("aud", "missing")), "Token is bound to this MCP server")
    table.add_row("scope", str(claims.get("scope", "missing")), "Reader role limits access")
    console.print(Panel(table, title="M2M 5/7 — what the token claims mean", border_style="green"))


def _render_spiffe_proof(claims: dict[str, Any]) -> None:
    """Explain the two signed artifacts in the workload exchange."""

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Artifact / field")
    table.add_column("Observed value")
    table.add_column("What it proves")
    table.add_row("JWT-SVID sub", required("SPIFFE_ID"), "SPIRE-attested workload identity")
    table.add_row(
        "JWT-SVID aud",
        f"{optional('AUTHSEC_ISSUER', 'https://prod.api.authsec.ai').rstrip('/')}/oauth/token",
        "SVID can be redeemed only at AuthSec's token endpoint",
    )
    table.add_row(
        "Access token sub",
        str(claims.get("sub", "missing")),
        "AuthSec workload registration resolved from the SVID",
    )
    table.add_row(
        "Access token aud",
        str(claims.get("aud", "missing")),
        "Final bearer is bound to the GitHub MCP Application",
    )
    table.add_row(
        "Long-lived client secret",
        "absent",
        "Runtime identity replaced a distributed OAuth secret",
    )
    console.print(Panel(table, title="SPIFFE 5/7 — SVID exchange proof", border_style="green"))


async def _with_token(
    profile: ProfileName,
    command: str,
    prompt: str | None,
    interactive: bool,
) -> None:
    settings = load_agent_settings(profile)
    provider = build_token_provider(settings)
    try:
        token = await provider.access_token()
        safe_claims = _safe_claims(token)
        if profile == "ci-reporter":
            _render_m2m_token_artifact(token)
            log_token(log, "M2M 5/7 claims decoded from the received access token", token)
            console.print(
                Panel(
                    json.dumps(safe_claims, indent=2),
                    title="M2M 5/7 — claims decoded from the received token",
                    border_style="green",
                )
            )
            _render_m2m_proof(safe_claims)
        else:
            console.print(Panel(json.dumps(safe_claims, indent=2), title="Safe token claims"))
        if profile == "release-reporter":
            _render_spiffe_proof(safe_claims)
        elif profile == "repo-assistant":
            _render_xaa_proof(safe_claims)
        if command == "token":
            return
        if command == "proof":
            if profile == "repo-assistant":
                raise ConfigurationError(
                    "proof is for the Reader-only ci-reporter and release-reporter profiles"
                )
            if not await prove_read_only_access(settings, token):
                raise SystemExit(1)
            return
        if profile in {"ci-reporter", "release-reporter"}:
            # A normal run is a complete demo, not merely an LLM call. First
            # prove one deny and one allow with this exact bearer, then hand the
            # same bearer and AuthSec-filtered tool set to the ReAct runtime.
            if not await prove_read_only_access(settings, token):
                raise SystemExit(1)
            console.print(
                Panel(
                    "Authorization behavior is now proven with real MCP calls. The same "
                    "identity token is being handed to LangChain's ReAct agent for an "
                    "actual allowed repository action.",
                    title=(
                        "SPIFFE 7/7 — run the workload agent"
                        if profile == "release-reporter"
                        else "M2M 7/7 — run the machine agent"
                    ),
                    border_style="cyan",
                )
            )
        agent = await build_agent(settings, token)
        run_id = optional("DEMO_RUN_ID", "live-demo")
        default_prompt = {
            "ci-reporter": "Summarize the five latest commits in the sdk-authsec repository.",
            "release-reporter": (
                "Summarize the five latest commits in the github-mcp-server repository."
            ),
            "repo-assistant": (
                "Read the latest sdk-authsec commits. Then use create_issue to create an actual "
                "concise follow-up issue in the personal authsec-demo-sandbox repository with "
                f"run_id={run_id!r}. Do not merely recommend or draft the issue: perform the "
                "MCP action and include the returned GitHub issue URL in your answer."
            ),
        }[profile]
        selected_prompt = prompt or default_prompt
        if interactive:
            await run_interactive(agent, selected_prompt)
        else:
            await run_once(agent, selected_prompt)
    except PendingApprovalError as exc:
        console.print(
            Panel(
                "The human authenticated and the Agent proved its own client identity, but "
                "AuthSec did not issue an MCP access token because the human has no role on "
                "the target Application. No MCP tool has run.\n\n"
                f"request_id={exc.request_id}\n\n"
                "Open GitHub MCP Demo → Connections → Requests. Confirm the request names "
                "the signed-in person as subject and agent-repo-assistant as caller, then "
                "approve with Triage. "
                "Run the same command again to show the delegated token and filtered tools.",
                title="XAA 5/6 — access_pending (expected)",
                border_style="yellow",
            )
        )
        raise SystemExit(3) from None
    except CredentialInvalidError as exc:
        message = str(exc)
        if "does not support private_key_jwt" in message:
            message = (
                "AuthSec found this Client ID, but it belongs to a client that was not "
                "registered for private_key_jwt. Do not reuse AUTHSEC_AGENT_CLIENT_ID.\n\n"
                "Create a separate credential at GitHub MCP Demo → Access → Add access → "
                "Machine credential (secret/key), choose Private key JWT, bind Reader, and "
                "use https://mcp-demo.mcpauthz.com/.well-known/m2m-jwks.json. Then copy the "
                "new svc-github-ci Client ID from Service Accounts and run:\n\n"
                "uv run setup-m2m --client-id <NEW_SERVICE_ACCOUNT_CLIENT_ID>"
            )
        console.print(
            Panel(
                message,
                title="M2M credential rejected before MCP access",
                border_style="red",
            )
        )
        raise SystemExit(4) from None
    except ResourceNotRegisteredError:
        console.print(
            Panel(
                "The protected-resource metadata could not be loaded from "
                "https://mcp-demo.mcpauthz.com/.well-known/oauth-protected-resource/mcp.\n\n"
                "If preflight reports Cloudflare 530, start the local origin and tunnel in "
                "another terminal with:\n\n"
                "cd /Users/pc/Desktop/authsec-demo\n"
                "pnpm share\n\n"
                "Wait until the MCP and tunnel are ready, then rerun this command. If the "
                "endpoint returns something other than 530, inspect the Application Resource "
                "URI and protected-resource metadata instead.",
                title="MCP discovery unavailable — no token request was sent",
                border_style="red",
            )
        )
        raise SystemExit(5) from None
    except SpiffeIdentityError as exc:
        message = str(exc)
        if "cannot fetch workload issuer JWKS" in message:
            message = (
                "AuthSec could not read the SPIRE signing keys after four bounded "
                "attempts. This is a temporary JWKS tunnel/issuer availability failure, "
                "not a rejected SPIFFE identity. No MCP request or GitHub action ran.\n\n"
                "Keep pnpm share running and confirm that "
                "https://spire-demo.mcpauthz.com/keys returns HTTP 200. If it does not, "
                "restart the owned stack with pnpm share:stop followed by pnpm share."
            )
        console.print(
            Panel(
                f"code={exc.code}\nhttp_status={exc.http_status}\nmessage={message}",
                title="SPIFFE stopped before MCP execution",
                border_style="red",
            )
        )
        raise SystemExit(8) from None
    except AuthSecIdentityError as exc:
        if exc.code == "invalid_grant" and "expired" in str(exc).lower():
            console.print(
                Panel(
                    "The presenter's saved browser identity token has expired, so AuthSec "
                    "correctly rejected "
                    "the delegated exchange before any MCP request or GitHub action.\n\n"
                    "Refresh the human session, then rerun the Agent:\n\n"
                    "uv run demo-agent login\n"
                    "uv run demo-agent run repo-assistant --interactive",
                    title="XAA stopped before MCP — the human must sign in again",
                    border_style="yellow",
                )
            )
            raise SystemExit(6) from None
        console.print(
            Panel(
                f"code={exc.code}\nhttp_status={exc.http_status}\nmessage={exc}",
                title="AuthSec identity flow rejected before MCP execution",
                border_style="red",
            )
        )
        raise SystemExit(7) from None
    finally:
        await provider.aclose()


async def _async_main(args: argparse.Namespace) -> None:
    if args.command == "login":
        await _login(args.port)
        return
    await _with_token(
        args.profile,
        args.command,
        getattr(args, "prompt", None),
        bool(getattr(args, "interactive", False)),
    )


def main() -> None:
    configure_logging("agent")
    args = _parser().parse_args()
    try:
        asyncio.run(_async_main(args))
    except ConfigurationError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
