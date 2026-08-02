"""Validated configuration for the MCP origin and personal GitHub App."""

from __future__ import annotations

from dataclasses import dataclass

from authsec_sdk.runtime import Config, PolicyMode, ValidationMode, from_env

from apps.mcp_server.constants import APP_NAME, ISSUER, RESOURCE_URI, TOOL_SCOPE_SUGGESTIONS
from apps.shared.env import (
    ConfigurationError,
    load_project_env,
    optional,
    required,
    required_many,
    secret_text,
)
from apps.shared.logging import get_logger

log = get_logger("mcp.config")


@dataclass(frozen=True)
class GitHubAppSettings:
    """Credentials for one narrowly-scoped GitHub App installation."""

    app_id: str
    installation_id: str
    private_key: str


@dataclass(frozen=True)
class ServerSettings:
    host: str
    port: int
    github_app: GitHubAppSettings


def _github_settings() -> GitHubAppSettings:
    return GitHubAppSettings(
        app_id=required("GITHUB_APP_ID"),
        installation_id=required("GITHUB_INSTALLATION_ID"),
        private_key=secret_text("GITHUB_PRIVATE_KEY"),
    )


def load_server_settings() -> ServerSettings:
    load_project_env()
    raw_port = optional("DEMO_PORT", "8091")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ConfigurationError("DEMO_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ConfigurationError("DEMO_PORT must be between 1 and 65535")
    return ServerSettings(
        host=optional("DEMO_HOST", "0.0.0.0"),
        port=port,
        github_app=_github_settings(),
    )


def load_authsec_runtime_config() -> Config:
    """Build the official SDK config and guard the demo's pinned invariants."""

    load_project_env()
    required_many(
        [
            "AUTHSEC_ISSUER",
            "AUTHSEC_AUTHORIZATION_SERVER",
            "AUTHSEC_JWKS_URL",
            "AUTHSEC_INTROSPECTION_URL",
            "AUTHSEC_RESOURCE_URI",
            "AUTHSEC_RESOURCE_NAME",
            "AUTHSEC_RESOURCE_SERVER_ID",
            "AUTHSEC_INTROSPECTION_CLIENT_ID",
            "AUTHSEC_INTROSPECTION_CLIENT_SECRET",
            "AUTHSEC_POLICY_MODE",
            "AUTHSEC_VALIDATION_MODE",
            "AUTHSEC_PUBLISH_MANIFEST",
        ]
    )
    cfg = from_env()
    if cfg.issuer.rstrip("/") != ISSUER:
        raise ConfigurationError(f"AUTHSEC_ISSUER must exactly equal {ISSUER}")
    if cfg.resource_uri.rstrip("/") != RESOURCE_URI:
        raise ConfigurationError(f"AUTHSEC_RESOURCE_URI must exactly equal {RESOURCE_URI}")
    if cfg.resource_name != APP_NAME:
        raise ConfigurationError(f"AUTHSEC_RESOURCE_NAME must exactly equal {APP_NAME}")

    # Act 4 (live revocation) only bites if the resource introspects on EVERY
    # call. jwt_only would let an already-issued JWT survive revocation until it
    # expires, and jwt_or_introspect short-circuits on a valid JWT. Fail fast at
    # startup rather than discover it during the demo.
    vm = cfg.effective_validation_mode()
    pm = cfg.effective_policy_mode()
    if vm != ValidationMode.JWT_AND_INTROSPECT:
        raise ConfigurationError(
            "AUTHSEC_VALIDATION_MODE must be jwt_and_introspect for live "
            f"revocation; got {vm.value}"
        )
    if pm != PolicyMode.REMOTE_REQUIRED:
        raise ConfigurationError(f"AUTHSEC_POLICY_MODE must be remote_required; got {pm.value}")
    if not cfg.publish_manifest:
        raise ConfigurationError("AUTHSEC_PUBLISH_MANIFEST must be true for manifest-first setup")
    log.info(
        "MCP runtime modes | validation=%s policy=%s publish_manifest=%s resource=%s issuer=%s",
        vm.value,
        pm.value,
        getattr(cfg, "publish_manifest", "?"),
        RESOURCE_URI,
        ISSUER,
    )

    # FastMCP supplies the real inventory. These suggestions are advisory;
    # only AuthSec's admin_override mappings become runtime-effective policy.
    cfg.tool_scope_suggestions = TOOL_SCOPE_SUGGESTIONS
    return cfg
