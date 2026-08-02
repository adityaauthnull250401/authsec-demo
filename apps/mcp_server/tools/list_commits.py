"""Implementation of the low-risk commit listing tool."""

from __future__ import annotations

from typing import Any

from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.tools.validation import read_repository


async def execute(provider: GitHubProvider, repo: str, limit: int = 5) -> dict[str, Any]:
    if not 1 <= limit <= 20:
        raise ValueError("limit must be between 1 and 20")
    repository = read_repository(repo)
    commits = await provider.reader.list_commits(repository, limit)
    return {"repository": repository, "count": len(commits), "commits": commits}
