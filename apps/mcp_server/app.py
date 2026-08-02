"""ASGI composition root for the protected MCP facade."""

from __future__ import annotations

from typing import Any, cast

import uvicorn
from authsec_sdk.runtime import mount_mcp
from fastapi import FastAPI

from apps.mcp_server.config import (
    ServerSettings,
    load_authsec_runtime_config,
    load_server_settings,
)
from apps.mcp_server.github import GitHubProvider
from apps.mcp_server.public_keys import M2M_JWKS_ROUTE, public_m2m_jwks
from apps.mcp_server.server import build_mcp_server
from apps.shared.logging import configure_logging


def create_app() -> tuple[FastAPI, ServerSettings]:
    log = configure_logging("mcp-server")
    log.info("Starting AuthSec GitHub MCP facade — mounting AuthSec SDK at /mcp")
    settings = load_server_settings()
    authsec_config = load_authsec_runtime_config()
    github = GitHubProvider(settings)
    mcp = build_mcp_server(github)

    app = FastAPI(title="AuthSec GitHub MCP Demo", version="0.1.0")
    # FastAPI versions differ on where the legacy lifecycle helper lives.
    # Register the GitHub HTTP client's cleanup on the application when the
    # helper exists, otherwise use the underlying Starlette router hook.  This
    # keeps cleanup compatible without replacing the AuthSec SDK's MCP lifespan.
    if hasattr(app, "add_event_handler"):
        cast(Any, app).add_event_handler("shutdown", github.aclose)
    else:
        app.router.add_event_handler("shutdown", github.aclose)

    @app.get("/healthz", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "authsec-github-mcp-demo"}

    # AuthSec fetches this public key to verify svc-github-ci's RFC 7523
    # private_key_jwt assertions.  The corresponding private key is never
    # loaded by this server and never leaves the M2M caller's local state.
    app.add_api_route(
        M2M_JWKS_ROUTE,
        public_m2m_jwks,
        methods=["GET"],
        include_in_schema=False,
    )

    # This is the entire authorization integration. The SDK validates identity,
    # fetches AuthSec's canonical tool policy, filters tools/list, checks every
    # tools/call, publishes the manifest, and serves RFC 9728 metadata.
    # AuthSec SDK 4.7.2 explicitly supports FastMCP auto-detection, although
    # its handler annotation has not yet been widened from ASGI callables.
    mount_mcp(app, "/mcp", cast(Any, mcp), authsec_config)
    return app, settings


app, _settings = create_app()


def main() -> None:
    uvicorn.run(app, host=_settings.host, port=_settings.port, log_level="info")


if __name__ == "__main__":
    main()
