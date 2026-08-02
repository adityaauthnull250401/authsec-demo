"""Pinned public contract for the demo Application.

Keeping these names in one module prevents the tool schema, manifest
suggestions, bootstrap mappings, and smoke assertions from drifting apart.
AuthSec remains authoritative at runtime; these are the server's suggestions
and bounded upstream targets.
"""

from __future__ import annotations

from typing import Final, Literal

APP_NAME: Final = "GitHub MCP Demo"
APP_SLUG: Final = "github_mcp_demo"
RESOURCE_URI: Final = "https://mcp-demo.mcpauthz.com/mcp"
ISSUER: Final = "https://app.authsec.ai"

READ_SCOPE: Final = f"{APP_SLUG}:commits:read"
README_SCOPE: Final = f"{APP_SLUG}:repo:read"
ISSUE_SCOPE: Final = f"{APP_SLUG}:issues:write"

RepoName = Literal["sdk-authsec", "github-mcp-server"]
READ_REPOSITORIES: Final[dict[str, str]] = {
    "sdk-authsec": "Aditya250401/sdk-authsec",
    "github-mcp-server": "Aditya250401/github-mcp-server",
}
SANDBOX_REPOSITORY: Final = "Aditya250401/authsec-demo-sandbox"

TOOL_SCOPE_SUGGESTIONS: Final[dict[str, list[str]]] = {
    "list_commits": [READ_SCOPE],
    "get_readme": [README_SCOPE],
    "create_issue": [ISSUE_SCOPE],
}
