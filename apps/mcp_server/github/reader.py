"""Read-only GitHub operations using the personal demo App."""

from __future__ import annotations

import base64
from typing import Any

from apps.mcp_server.github.client import GitHubInstallationClient


class GitHubReader:
    def __init__(self, client: GitHubInstallationClient) -> None:
        self._client = client

    async def list_commits(self, repository: str, limit: int) -> list[dict[str, Any]]:
        response = await self._client.request(
            "GET", f"/repos/{repository}/commits", params={"per_page": limit}
        )
        commits: list[dict[str, Any]] = []
        for item in response.json():
            commit = item.get("commit") or {}
            author = commit.get("author") or {}
            commits.append(
                {
                    "sha": str(item.get("sha", ""))[:12],
                    "message": str(commit.get("message", "")).splitlines()[0],
                    "author": author.get("name") or "unknown",
                    "authored_at": author.get("date"),
                    "url": item.get("html_url"),
                }
            )
        return commits

    async def get_readme(self, repository: str) -> dict[str, Any]:
        response = await self._client.request("GET", f"/repos/{repository}/readme")
        payload = response.json()
        encoded = str(payload.get("content", "")).replace("\n", "")
        content = base64.b64decode(encoded).decode("utf-8", errors="replace")
        return {
            "name": payload.get("name", "README.md"),
            "path": payload.get("path", "README.md"),
            "sha": payload.get("sha"),
            "url": payload.get("html_url"),
            "content": content,
        }
