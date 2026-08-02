"""Composition root for the personal GitHub App installation."""

from __future__ import annotations

from apps.mcp_server.config import ServerSettings
from apps.mcp_server.constants import SANDBOX_REPOSITORY
from apps.mcp_server.github.client import GitHubInstallationClient
from apps.mcp_server.github.reader import GitHubReader
from apps.mcp_server.github.writer import GitHubIssueWriter


class GitHubProvider:
    def __init__(self, settings: ServerSettings) -> None:
        self._client = GitHubInstallationClient(settings.github_app)
        self.reader = GitHubReader(self._client)
        self.writer = GitHubIssueWriter(self._client, SANDBOX_REPOSITORY)

    async def aclose(self) -> None:
        await self._client.aclose()
