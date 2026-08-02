"""Implementation of the low-risk README tool."""

from __future__ import annotations

from typing import Any

from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.tools.validation import read_repository


async def execute(provider: GitHubProvider, repo: str) -> dict[str, Any]:
    repository = read_repository(repo)
    readme = await provider.reader.get_readme(repository)
    # Bound model context even when an upstream README grows unexpectedly.
    content = str(readme["content"])
    truncated = len(content) > 20_000
    readme["content"] = content[:20_000]
    readme["truncated"] = truncated
    return {"repository": repository, **readme}
