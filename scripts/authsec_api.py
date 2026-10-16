"""Small, typed-enough client for the AuthSec console API routes used here."""

from __future__ import annotations

from typing import Any

import httpx

from apps.shared.logging import get_logger

log = get_logger("authsec.api")


class AuthSecAPIError(RuntimeError):
    def __init__(self, method: str, path: str, response: httpx.Response) -> None:
        payload: Any = None
        message = ""
        try:
            payload = response.json()
            if isinstance(payload, dict):
                message = str(payload.get("error") or payload.get("message") or "")
        except Exception:
            payload = None
        suffix = f": {message}" if message else ""
        super().__init__(f"AuthSec {method} {path} failed with HTTP {response.status_code}{suffix}")
        self.status_code = response.status_code
        self.payload = payload


class AuthSecAdminClient:
    """Workspace-scoped API client authenticated by a supplied admin bearer."""

    def __init__(self, base_url: str, token: str) -> None:
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=30.0,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "authsec-github-mcp-demo/0.1",
            },
        )

    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        allowed: set[int] | None = None,
    ) -> Any:
        response = await self._http.request(method, path, json=json)
        log.info("AuthSec %s %s → %s", method.upper(), path, response.status_code)
        accepted = allowed or set(range(200, 300))
        if response.status_code not in accepted:
            raise AuthSecAPIError(method, path, response)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            content_type = response.headers.get("content-type", "unknown")
            raise RuntimeError(
                f"AuthSec {method.upper()} {path} returned HTTP {response.status_code} "
                f"with non-JSON content ({content_type}); check AUTHSEC_ADMIN_API_URL"
            ) from exc

    async def get(self, path: str) -> Any:
        return await self.request("GET", path)

    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return await self.request("POST", path, json=body or {})

    async def put(self, path: str, body: dict[str, Any]) -> Any:
        return await self.request("PUT", path, json=body)

    async def delete(self, path: str, *, allow_missing: bool = False) -> Any:
        allowed = set(range(200, 300)) | ({404} if allow_missing else set())
        return await self.request("DELETE", path, allowed=allowed)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AuthSecAdminClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.aclose()
