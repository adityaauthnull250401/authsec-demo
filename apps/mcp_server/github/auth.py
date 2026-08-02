"""GitHub App JWT creation and installation-token caching."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

import httpx
import jwt

from apps.mcp_server.config import GitHubAppSettings
from apps.shared.logging import get_logger

GITHUB_API_VERSION = "2022-11-28"

log = get_logger("mcp.github.auth")


@dataclass(frozen=True)
class InstallationToken:
    value: str
    expires_at: float


class GitHubAppAuthenticator:
    """Exchange short-lived App assertions for installation access tokens.

    A lock prevents concurrent tool calls from generating multiple installation
    tokens. Tokens are renewed five minutes before GitHub's expiration time.
    Neither JWT nor installation token is ever exposed to tool results/logs.
    """

    def __init__(self, settings: GitHubAppSettings, client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._client = client
        self._cached: InstallationToken | None = None
        self._lock = asyncio.Lock()

    async def token(self) -> str:
        cached = self._cached
        if cached and cached.expires_at > time.time() + 300:
            return cached.value

        async with self._lock:
            cached = self._cached
            if cached and cached.expires_at > time.time() + 300:
                return cached.value
            self._cached = await self._exchange()
            return self._cached.value

    async def _exchange(self) -> InstallationToken:
        now = int(time.time())
        log.info(
            "GitHub App %s: minting RS256 App JWT (exp +9m) → exchanging for installation "
            "%s access token (provider hop stays server-side; never enters a tool result)",
            self._settings.app_id,
            self._settings.installation_id,
        )
        assertion = jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": self._settings.app_id},
            self._settings.private_key,
            algorithm="RS256",
        )
        response = await self._client.post(
            f"/app/installations/{self._settings.installation_id}/access_tokens",
            headers={
                "Authorization": f"Bearer {assertion}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
        )
        _raise_github_error(response, "exchange GitHub App installation token")
        log.info(
            "GitHub installation token acquired (cached ~50m), status=%s", response.status_code
        )
        payload = response.json()
        # GitHub installation tokens normally live for one hour. Parsing the
        # timestamp would add no safety here; a conservative 50-minute cache
        # guarantees renewal before expiry even if clocks differ slightly.
        return InstallationToken(value=str(payload["token"]), expires_at=time.time() + 3000)


def _raise_github_error(response: httpx.Response, operation: str) -> None:
    if response.is_success:
        return
    request_id = response.headers.get("x-github-request-id", "unknown")
    message = ""
    try:
        message = str(response.json().get("message", ""))
    except Exception:
        message = ""
    detail = f": {message}" if message else ""
    raise RuntimeError(
        f"GitHub could not {operation} (HTTP {response.status_code}, request {request_id}){detail}"
    )
