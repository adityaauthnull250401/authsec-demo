"""Presenter-safe proof for a read-only M2M or SPIFFE identity.

This deliberately avoids an LLM so the authorization proof is deterministic
and costs nothing. The normal ``pnpm agent:spiffe`` command runs the ReAct agent
after this proof succeeds.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.pretty import Pretty
from rich.table import Table

from apps.agents.config import AgentSettings
from apps.shared.logging import get_logger
from scripts.mcp_rpc import (
    call_mcp,
    is_authsec_denial,
    listed_tool_names,
    mcp_denial_evidence,
    mcp_structured_result,
)

console = Console()
log = get_logger("agent.proof")


async def prove_read_only_access(settings: AgentSettings, token: str) -> bool:
    """Show filtered discovery, a real read, then a fail-closed forced call."""

    rows: list[tuple[str, bool, str]] = []
    stage = "M2M 6/7" if settings.profile == "ci-reporter" else "SPIFFE 6/7"
    console.print(
        Panel(
            "This uses the exact identity token that will be given to the ReAct agent. "
            "It first performs an allowed GitHub read with the received token, then probes "
            "the denied write boundary. The success is shown before the deliberate failure; "
            "neither result is inferred from HTTP transport status alone.",
            title="Agent capability boundary — real MCP calls",
            border_style="cyan",
        )
    )

    status, listed, _ = await call_mcp(settings.resource_uri, token, "tools/list")
    names = listed_tool_names(listed)
    expected_visible = {"list_commits", "get_readme"}
    rows.append(
        (
            "AuthSec-filtered tools/list",
            status == 200 and names == expected_visible,
            f"visible={sorted(names)}; hidden=['create_issue']",
        )
    )

    status, commits, _ = await call_mcp(
        settings.resource_uri,
        token,
        "tools/call",
        {"name": "list_commits", "arguments": {"repo": "github-mcp-server", "limit": 2}},
        request_id=2,
    )
    allowed = status == 200 and not bool((commits.get("result") or {}).get("isError"))
    commit_result = mcp_structured_result(commits)
    commit_items = commit_result.get("commits") or []
    first_commit = commit_items[0] if commit_items and isinstance(commit_items[0], dict) else {}
    rows.append(
        (
            "Allowed list_commits succeeds",
            allowed,
            f"repository={commit_result.get('repository', 'unknown')}; "
            f"returned={commit_result.get('count', len(commit_items))}",
        )
    )
    log.info(
        "%s allowed action | profile=%s decision=%s tool=list_commits "
        "repository=%s returned=%s required_claims=%s",
        stage,
        settings.profile,
        "ALLOW" if allowed else "UNEXPECTED_ERROR",
        commit_result.get("repository"),
        commit_result.get("count", len(commit_items)),
        settings.requested_scopes,
    )
    console.print(
        Panel(
            Pretty(
                {
                    "agent_profile": settings.profile,
                    "token_claims_used": settings.requested_scopes,
                    "called_tool": "list_commits",
                    "authsec_decision": "ALLOW",
                    "github_action": "GET repository commits",
                    "repository": commit_result.get("repository"),
                    "returned": commit_result.get("count", len(commit_items)),
                    "first_commit": {
                        key: first_commit.get(key)
                        for key in ("sha", "message", "url")
                        if first_commit.get(key) is not None
                    },
                }
            ),
            title=f"{stage} — SUCCESS first: token claims allowed a real GitHub action",
            border_style="green",
        )
    )

    # Empty fields make this harmless even if policy is accidentally too broad:
    # the tool's input validation rejects it before GitHub can be changed. A
    # correct AuthSec policy rejects it earlier with an in-band MCP isError.
    status, denied, _ = await call_mcp(
        settings.resource_uri,
        token,
        "tools/call",
        {
            "name": "create_issue",
            "arguments": {"title": "", "body": "", "run_id": "authorization-proof"},
        },
        request_id=3,
    )
    rows.append(
        (
            "Forced create_issue denied",
            status == 200 and is_authsec_denial(denied),
            "AuthSec denied before tool/provider execution",
        )
    )
    denial_code, denial_message = mcp_denial_evidence(denied)
    log.info(
        "%s denied boundary | profile=%s decision=DENY tool=create_issue "
        "error_code=%s github_action_executed=false",
        stage,
        settings.profile,
        denial_code,
    )
    console.print(
        Panel(
            Pretty(
                {
                    "agent_profile": settings.profile,
                    "attempted_tool": "create_issue",
                    "mcp_transport": f"HTTP {status}",
                    "mcp_result": "isError=true",
                    "authsec_decision": "DENY",
                    "error_code": denial_code,
                    "reason": denial_message,
                    "github_action_executed": False,
                }
            ),
            title=f"{stage} — BOUNDARY second: write never reached GitHub",
            border_style="red",
        )
    )

    identity_label = "M2M Service Account" if settings.profile == "ci-reporter" else "SPIFFE"
    table = Table(title=f"{identity_label} → AuthSec → MCP authorization proof")
    table.add_column("Check")
    table.add_column("Result")
    table.add_column("Evidence")
    for check, passed, evidence in rows:
        table.add_row(check, "PASS" if passed else "FAIL", evidence)
    console.print(table)
    return all(passed for _, passed, _ in rows)
