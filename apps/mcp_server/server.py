"""FastMCP protocol server and tool registration.

This file knows the MCP tool schemas but not OAuth. `app.py` mounts this server
behind the AuthSec SDK once, so individual functions never inspect tokens,
roles, scopes, users, agents, or workloads.
"""

from __future__ import annotations

from typing import Any, Literal

from mcp.server.fastmcp import FastMCP

from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.tools import create_issue, get_readme, list_commits


def build_mcp_server(provider: GitHubProvider) -> FastMCP:
    mcp = FastMCP("GitHub MCP Demo")

    @mcp.tool(name="list_commits")
    async def list_commits_tool(
        repo: Literal["sdk-authsec", "github-mcp-server"], limit: int = 5
    ) -> dict[str, Any]:
        """List 1–20 commits from one of two approved personal demo repositories."""

        return await list_commits.execute(provider, repo, limit)

    @mcp.tool(name="get_readme")
    async def get_readme_tool(
        repo: Literal["sdk-authsec", "github-mcp-server"],
    ) -> dict[str, Any]:
        """Read the README from one of two approved personal demo repositories."""

        return await get_readme.execute(provider, repo)

    @mcp.tool(name="create_issue")
    async def create_issue_tool(title: str, body: str, run_id: str) -> dict[str, Any]:
        """Create a labeled issue in Aditya250401/authsec-demo-sandbox only."""

        return await create_issue.execute(provider, title, body, run_id)

    return mcp
