"""Evidence-oriented smoke runner for the five demo acts.

Safe checks run unattended. XAA approval and connection revocation remain
explicit operator actions: flags opt into issue creation or the destructive
revocation drill, and the script pauses before the console click.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from typing import Any, Literal

import httpx
import jwt
from authsec_sdk.identity import (
    ConnectionRevokedError,
    PendingApprovalError,
)
from rich.console import Console
from rich.table import Table

from apps.agents.config import load_agent_settings
from apps.agents.identity import M2MTokenProvider, SpiffeTokenProvider, XAATokenProvider
from apps.mcp_server.constants import ISSUE_SCOPE, READ_SCOPE, README_SCOPE, RESOURCE_URI
from apps.shared.env import ConfigurationError, boolean, load_project_env, optional
from apps.shared.logging import configure_logging
from scripts.mcp_rpc import call_mcp, is_authsec_denial, listed_tool_names
from scripts.run_state import record

console = Console()


@dataclass(frozen=True)
class Result:
    act: str
    assertion: str
    passed: bool
    detail: str


def _claims(token: str) -> dict[str, Any]:
    return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})


async def _public_checks(results: list[Result]) -> None:
    metadata_url = "https://mcp-demo.mcpauthz.com/.well-known/oauth-protected-resource/mcp"
    async with httpx.AsyncClient(timeout=15.0) as client:
        unauth = await client.get(RESOURCE_URI)
        challenge = unauth.headers.get("www-authenticate", "")
        results.append(
            Result(
                "0a",
                "Unauthenticated resource challenge",
                unauth.status_code == 401 and "Bearer" in challenge,
                f"HTTP {unauth.status_code}; "
                f"WWW-Authenticate={'present' if challenge else 'missing'}",
            )
        )
        metadata = await client.get(metadata_url)
        payload = metadata.json() if metadata.status_code == 200 else {}
        results.append(
            Result(
                "0b",
                "RFC 9728 metadata",
                metadata.status_code == 200
                and payload.get("resource") == RESOURCE_URI
                and "https://prod.api.authsec.ai" in payload.get("authorization_servers", []),
                f"HTTP {metadata.status_code}; resource={payload.get('resource')}",
            )
        )


async def _reader_checks(results: list[Result]) -> str:
    settings = load_agent_settings("ci-reporter")
    provider = M2MTokenProvider(settings)
    try:
        token = await provider.access_token()
    finally:
        await provider.aclose()

    claims = _claims(token)
    audience = claims.get("aud")
    scopes = set(str(claims.get("scope", "")).split())
    exp = int(claims.get("exp", 0))
    iat = int(claims.get("iat", 0))
    passed_claims = (
        (audience == RESOURCE_URI or RESOURCE_URI in (audience or []))
        and {READ_SCOPE, README_SCOPE}.issubset(scopes)
        and bool(claims.get("jti"))
        and 0 < exp - iat <= 3700
    )
    results.append(
        Result(
            "1a",
            "M2M token claims",
            passed_claims,
            json.dumps(
                {
                    "sub": claims.get("sub"),
                    "aud": audience,
                    "scope": sorted(scopes),
                    "jti": claims.get("jti"),
                    "lifetime_seconds": exp - iat,
                }
            ),
        )
    )
    if claims.get("jti"):
        record(optional("DEMO_RUN_ID", "smoke"), jti=str(claims["jti"]))

    status, listed, _ = await call_mcp(RESOURCE_URI, token, "tools/list")
    names = listed_tool_names(listed)
    results.append(
        Result(
            "0c",
            "Reader tools/list filtering",
            status == 200 and names == {"list_commits", "get_readme"},
            f"HTTP {status}; tools={sorted(names)}",
        )
    )

    status, denied, _ = await call_mcp(
        RESOURCE_URI,
        token,
        "tools/call",
        {"name": "create_issue", "arguments": {"title": "", "body": "", "run_id": "smoke"}},
        request_id=2,
    )
    results.append(
        Result(
            "0d",
            "Forced out-of-scope call fails closed",
            status == 200 and is_authsec_denial(denied),
            f"HTTP {status}; isError={bool((denied.get('result') or {}).get('isError'))}",
        )
    )

    status, commits, _ = await call_mcp(
        RESOURCE_URI,
        token,
        "tools/call",
        {"name": "list_commits", "arguments": {"repo": "github-mcp-server", "limit": 3}},
        request_id=3,
    )
    results.append(
        Result(
            "1b",
            "M2M reads real GitHub commits",
            status == 200 and not bool((commits.get("result") or {}).get("isError")),
            f"HTTP {status}",
        )
    )
    return token


async def _spiffe_check(results: list[Result]) -> None:
    if not boolean("DEMO_ENABLE_SPIRE", False):
        results.append(Result("2", "JWT-SVID workload", True, "SKIP: DEMO_ENABLE_SPIRE=false"))
        return
    settings = load_agent_settings("release-reporter")
    provider = SpiffeTokenProvider(settings)
    try:
        token = await provider.access_token()
    finally:
        await provider.aclose()
    claims = _claims(token)
    status, payload, _ = await call_mcp(
        RESOURCE_URI,
        token,
        "tools/call",
        {"name": "list_commits", "arguments": {"repo": "github-mcp-server", "limit": 2}},
    )
    results.append(
        Result(
            "2",
            "JWT-SVID workload reads commits",
            status == 200 and not bool((payload.get("result") or {}).get("isError")),
            f"sub={claims.get('sub')}; HTTP {status}",
        )
    )
    if claims.get("jti"):
        record(optional("DEMO_RUN_ID", "smoke"), jti=str(claims["jti"]))


async def _xaa_check(
    results: list[Result],
    expectation: Literal["skip", "pending", "approved"],
    allow_write: bool,
    revocation_drill: bool,
) -> None:
    if expectation == "skip":
        results.append(Result("3", "XAA delegation", True, "SKIP: --expect-xaa=skip"))
        return
    settings = load_agent_settings("repo-assistant")
    provider = XAATokenProvider(settings)
    try:
        try:
            token = await provider.access_token()
        except PendingApprovalError:
            results.append(
                Result(
                    "3a",
                    "First contact access_pending",
                    expectation == "pending",
                    "access_pending",
                )
            )
            return
        except ConnectionRevokedError:
            results.append(Result("3", "XAA delegation", False, "connection_revoked"))
            return
    finally:
        await provider.aclose()

    claims = _claims(token)
    actor = claims.get("act") or {}
    scopes = set(str(claims.get("scope", "")).split())
    approved = (
        expectation == "approved"
        and claims.get("tf") == "xaa"
        and bool(claims.get("sub"))
        and bool(actor.get("client_id"))
        and ISSUE_SCOPE in scopes
    )
    results.append(
        Result(
            "3b",
            "Approved XAA subject + actor claims",
            approved,
            json.dumps(
                {
                    "sub": claims.get("sub"),
                    "act": actor,
                    "tf": claims.get("tf"),
                    "scope": sorted(scopes),
                }
            ),
        )
    )
    run_id = optional("DEMO_RUN_ID", "smoke")
    if claims.get("jti"):
        record(run_id, jti=str(claims["jti"]))

    if allow_write:
        status, issue_payload, _ = await call_mcp(
            RESOURCE_URI,
            token,
            "tools/call",
            {
                "name": "create_issue",
                "arguments": {
                    "title": f"AuthSec demo smoke {run_id}",
                    "body": "Created by the explicit --allow-write XAA smoke check.",
                    "run_id": run_id,
                },
            },
            request_id=30,
        )
        succeeded = status == 200 and not bool((issue_payload.get("result") or {}).get("isError"))
        results.append(Result("3c", "XAA sandbox issue write", succeeded, f"HTTP {status}"))

    if revocation_drill:
        input("Revoke the repo-assistant Connection in AuthSec, then press Enter...")
        status, revoked_payload, _ = await call_mcp(
            RESOURCE_URI,
            token,
            "tools/call",
            {"name": "list_commits", "arguments": {"repo": "sdk-authsec", "limit": 1}},
            request_id=40,
        )
        results.append(
            Result(
                "4",
                "Unexpired token dies after Connection revocation",
                is_authsec_denial(revoked_payload),
                f"HTTP {status}; fail_closed={is_authsec_denial(revoked_payload)}",
            )
        )


async def _run(args: argparse.Namespace) -> int:
    load_project_env()
    results: list[Result] = []
    await _public_checks(results)
    await _reader_checks(results)
    await _spiffe_check(results)
    await _xaa_check(results, args.expect_xaa, args.allow_write, args.revocation_drill)

    table = Table(title="AuthSec demo smoke evidence")
    table.add_column("Act", width=4)
    table.add_column("Status", width=6)
    table.add_column("Assertion")
    table.add_column("Evidence")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        color = "green" if result.passed else "red"
        table.add_row(result.act, f"[{color}]{status}[/]", result.assertion, result.detail)
    console.print(table)
    return 1 if any(not result.passed for result in results) else 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect-xaa", choices=["skip", "pending", "approved"], default="skip")
    parser.add_argument(
        "--allow-write", action="store_true", help="create one labeled issue in the sandbox"
    )
    parser.add_argument(
        "--revocation-drill",
        action="store_true",
        help="pause for a human Connection revoke, then retry the same unexpired token",
    )
    args = parser.parse_args()
    configure_logging("smoke")
    if (args.allow_write or args.revocation_drill) and args.expect_xaa != "approved":
        parser.error("--allow-write/--revocation-drill require --expect-xaa=approved")
    try:
        sys.exit(asyncio.run(_run(args)))
    except (ConfigurationError, RuntimeError, httpx.HTTPError) as exc:
        console.print(f"[red]Smoke failed:[/red] {exc}")
        sys.exit(2)


if __name__ == "__main__":
    main()
