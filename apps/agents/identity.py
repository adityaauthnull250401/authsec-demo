"""Adapters from AuthSec identity classes to one agent-side token interface."""

from __future__ import annotations

import asyncio
import re
import stat
from typing import Protocol

from authsec_sdk.identity import (
    AgentIdentity,
    PrivateKeyJwtAuth,
    SpiffeConfig,
    SpiffeTokenExchangeError,
    SpiffeWorkloadIdentity,
)

from apps.agents.config import (
    AgentSettings,
    env_or_state,
    resolve_private_key_path,
)
from apps.agents.oauth_trace import M2MHTTPTrace, SpiffeHTTPTrace, XAAHTTPTrace
from apps.agents.session import load_subject_token
from apps.shared.env import ConfigurationError, optional, required
from apps.shared.logging import get_logger, log_token

log = get_logger("agent.identity")

# The demo issuer is reached through a local Cloudflare tunnel. A connector or
# edge route can briefly return 502/503/504 even while SPIRE itself is healthy.
# Retrying only this pre-token failure is safe: no bearer was issued, no MCP
# request was sent, and no GitHub provider action could have started.
_SPIFFE_JWKS_RETRY_DELAYS_SECONDS = (1.0, 2.0, 4.0)
_TRANSIENT_JWKS_ERROR = re.compile(
    r"cannot fetch workload issuer jwks:.*http (?:502|503|504)\b",
    re.IGNORECASE | re.DOTALL,
)


def _is_transient_spiffe_jwks_error(exc: SpiffeTokenExchangeError) -> bool:
    """Return true only for an upstream JWKS gateway/service outage."""

    return bool(_TRANSIENT_JWKS_ERROR.search(str(exc)))


class TokenProvider(Protocol):
    """The only capability the ReAct runtime needs from an identity flow."""

    async def access_token(self) -> str: ...

    async def aclose(self) -> None: ...


class M2MTokenProvider:
    def __init__(self, settings: AgentSettings) -> None:
        client_id = env_or_state("AUTHSEC_M2M_CLIENT_ID", "m2m_client_id")
        agent_client_id = optional("AUTHSEC_AGENT_CLIENT_ID").strip()
        if agent_client_id and client_id == agent_client_id:
            raise ConfigurationError(
                "M2M Client ID equals AUTHSEC_AGENT_CLIENT_ID. The confidential XAA Agent "
                "does not support private_key_jwt. Create a separate svc-github-ci machine "
                "credential in GitHub MCP Demo → Access → Add access, then record its "
                "Service Account Client ID with `uv run setup-m2m --client-id <CLIENT_ID>`."
            )
        key_id = env_or_state("AUTHSEC_M2M_KEY_ID", "m2m_key_id")
        key_path = resolve_private_key_path()
        auth = PrivateKeyJwtAuth(str(key_path), kid=key_id)
        self._settings = settings
        self._trace = M2MHTTPTrace()
        self._client_id = client_id
        self._key_id = key_id
        self._key_path = key_path
        self._key_mode = format(stat.S_IMODE(key_path.stat().st_mode), "04o")
        self._identity = AgentIdentity(
            settings.issuer,
            client_id,
            auth=auth,
            preferred_mode="direct-only",
            session=self._trace.client,
        )

    async def access_token(self) -> str:
        log.info(
            "M2M 1/7 load local signing key | service_account=svc-github-ci "
            "client_id=%s private_key_path=%s file_mode=%s algorithm=RS256 kid=%s "
            "private_key_uploaded=false public_key_uri=%s",
            self._client_id,
            self._key_path,
            self._key_mode,
            self._key_id,
            "https://mcp-demo.mcpauthz.com/.well-known/m2m-jwks.json",
        )
        log.info(
            "M2M key use | SDK loads the PEM only inside ci-reporter, signs a fresh "
            "five-minute RFC 7523 client assertion, and sends the assertion—not the "
            "private key—to AuthSec | grant=client_credentials auth=private_key_jwt "
            "resource=%s scopes=%s",
            self._settings.resource_uri,
            self._settings.requested_scopes,
        )
        token = await self._identity.access_for(
            self._settings.resource_uri,
            requested_scopes=self._settings.requested_scopes,
        )
        log.info(
            "M2M 4/7 AuthSec returned a separate resource access token | "
            "client_assertion_reused_as_bearer=false bearer_signature_logged=false"
        )
        return token

    async def aclose(self) -> None:
        await self._identity.aclose()
        await self._trace.aclose()


class SpiffeTokenProvider:
    def __init__(self, settings: AgentSettings) -> None:
        spiffe_id = required("SPIFFE_ID")
        socket_path = optional("SPIRE_AGENT_SOCKET_PATH", "/run/spire/sockets/agent.sock")
        self._settings = settings
        self._spiffe_id = spiffe_id
        self._socket_path = socket_path
        self._trace = SpiffeHTTPTrace(spiffe_id)
        self._identity = SpiffeWorkloadIdentity(
            SpiffeConfig(
                mcp_server_url=settings.resource_uri,
                client_id=required("SPIFFE_CLIENT_ID"),
                spiffe_id=spiffe_id,
                scopes=" ".join(settings.requested_scopes),
                agent_socket_path=socket_path,
            ),
            session=self._trace.client,
        )

    async def access_token(self) -> str:
        log.info(
            "SPIFFE 1/7 ask local SPIRE Agent for runtime identity | socket=%s "
            "expected_spiffe_id=%s long_lived_client_secret=absent",
            self._socket_path,
            self._spiffe_id,
        )
        log.info(
            "SPIFFE proof begins | the SDK will execute `spire-agent api fetch jwt`, "
            "mint the SVID for the discovered AuthSec token endpoint audience, then place "
            "that signed SVID in a redacted client_assertion"
        )
        attempts = len(_SPIFFE_JWKS_RETRY_DELAYS_SECONDS) + 1
        for attempt in range(1, attempts + 1):
            try:
                token = await self._identity.access_for()
                log_token(
                    log,
                    "SPIFFE 5/7 AuthSec access token issued from JWT-SVID proof",
                    token,
                )
                return token
            except SpiffeTokenExchangeError as exc:
                is_last_attempt = attempt == attempts
                if not _is_transient_spiffe_jwks_error(exc) or is_last_attempt:
                    raise

                delay = _SPIFFE_JWKS_RETRY_DELAYS_SECONDS[attempt - 1]
                log.warning(
                    "SPIFFE JWKS publication was temporarily unavailable; refreshing "
                    "the SVID and retrying token exchange in %.0fs | attempt=%s/%s "
                    "mcp_request_sent=false github_action_executed=false",
                    delay,
                    attempt + 1,
                    attempts,
                )
                self._identity.clear_cache()
                await asyncio.sleep(delay)

        raise RuntimeError("unreachable SPIFFE token retry state")

    async def aclose(self) -> None:
        await self._identity.aclose()
        await self._trace.aclose()


class XAATokenProvider:
    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._subject_token = load_subject_token()
        self._trace = XAAHTTPTrace()
        self._agent_client_id = required("AUTHSEC_AGENT_CLIENT_ID")
        self._identity = AgentIdentity(
            settings.issuer,
            self._agent_client_id,
            client_secret=required("AUTHSEC_AGENT_CLIENT_SECRET"),
            idp_issuer=settings.issuer,
            preferred_mode="xaa-allowed",
            session=self._trace.client,
        )

    async def access_token(self) -> str:
        subject_claims = log_token(
            log, "XAA 1/6 signed-in human OIDC subject token", self._subject_token
        )
        log.info(
            "XAA proof begins | human_sub=%s | actor_client_id=%s | target=%s | "
            "requested_scopes=%s",
            subject_claims.get("sub", "unknown"),
            self._agent_client_id,
            self._settings.resource_uri,
            self._settings.requested_scopes,
        )
        token = await self._identity.access_for(
            self._settings.resource_uri,
            user_session={"subject_token": self._subject_token},
            requested_scopes=self._settings.requested_scopes,
        )
        log_token(log, "XAA 5/6 delegated MCP token", token)
        return token

    async def aclose(self) -> None:
        await self._identity.aclose()
        await self._trace.aclose()


def build_token_provider(settings: AgentSettings) -> TokenProvider:
    if settings.profile == "ci-reporter":
        return M2MTokenProvider(settings)
    if settings.profile == "release-reporter":
        return SpiffeTokenProvider(settings)
    return XAATokenProvider(settings)
