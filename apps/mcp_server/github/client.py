"""Shared authenticated GitHub REST transport."""

from __future__ import annotations

from typing import Any

import httpx

from apps.mcp_server.config import GitHubAppSettings
from apps.mcp_server.github.auth import (
    GITHUB_API_VERSION,
    GitHubAppAuthenticator,
    _raise_github_error,
)
from apps.shared.logging import get_logger

log = get_logger("mcp.github.rest")


class GitHubInstallationClient:
    """Minimal async REST client bound to exactly one GitHub installation."""

    def __init__(self, settings: GitHubAppSettings) -> None:
        self._http = httpx.AsyncClient(
            base_url="https://api.github.com",
            timeout=20.0,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "authsec-github-mcp-demo/0.1",
            },
        )
        self._auth = GitHubAppAuthenticator(settings, self._http)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        expected: set[int] | None = None,
    ) -> httpx.Response:
        token = await self._auth.token()
        response = await self._http.request(
            method,
            path,
            params=params,
            json=json,
            headers={"Authorization": f"Bearer {token}"},
        )
        log.info("GitHub %s %s → %s", method.upper(), path, response.status_code)
        if expected is not None and response.status_code in expected:
            return response
        if expected is not None and response.is_success:
            allowed = ", ".join(str(code) for code in sorted(expected))
            raise RuntimeError(
                f"GitHub returned unexpected HTTP {response.status_code} for "
                f"{method.upper()} {path}; expected one of: {allowed}"
            )
        _raise_github_error(response, f"{method.upper()} {path}")
        return response

    async def aclose(self) -> None:
        await self._http.aclose()
