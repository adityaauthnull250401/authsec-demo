"""Implementation of the high-risk, sandbox-only issue creation tool."""

from __future__ import annotations

from typing import Any

from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.tools.validation import bounded_text
from apps.mcp_server.tools.validation import run_id as validate_run_id


async def execute(
    provider: GitHubProvider,
    title: str,
    body: str,
    run_id: str,
) -> dict[str, Any]:
    return await provider.writer.create_issue(
        bounded_text(title, "title", 1, 120),
        bounded_text(body, "body", 1, 4_000),
        validate_run_id(run_id),
    )
