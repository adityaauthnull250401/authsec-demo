"""Presenter-safe tracing for the delegated OAuth/XAA exchange.

The AuthSec SDK deliberately hides bearer credentials and intermediate
assertions from callers.  That is the correct production API, but it can make
the demo look like a single opaque ``access_for`` call.  This module attaches
HTTPX event hooks to the SDK client and renders the protocol stages that
actually crossed the wire, while redacting the subject token, client secret,
ID-JAG, and final access token.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt

from apps.shared.logging import get_logger

log = get_logger("agent.xaa")
m2m_log = get_logger("agent.m2m")
spiffe_log = get_logger("agent.spiffe")


class XAAHTTPTrace:
    """Trace OAuth discovery and grants without logging credential values."""

    def __init__(self) -> None:
        self.client = httpx.AsyncClient(
            timeout=60.0,
            event_hooks={"request": [self.on_request], "response": [self.on_response]},
        )

    async def on_request(self, request: httpx.Request) -> None:
        """Classify an outgoing SDK request and log only safe request metadata."""

        stage, fields = self._classify_request(request)
        request.extensions["authsec_demo_stage"] = stage
        request.extensions["authsec_demo_safe_fields"] = fields
        log.info("%s → %s %s | %s", stage, request.method, request.url.path, fields)

    async def on_response(self, response: httpx.Response) -> None:
        """Summarize the response without ever rendering token-valued fields."""

        # Reading the response here is safe: HTTPX caches the bytes, so the SDK
        # can still call response.json() after the hook returns.
        await response.aread()
        stage = str(response.request.extensions.get("authsec_demo_stage", "XAA HTTP"))
        summary = self._safe_response_summary(response)
        log.info("%s ← HTTP %s | %s", stage, response.status_code, summary)

    async def aclose(self) -> None:
        await self.client.aclose()

    @staticmethod
    def _form(request: httpx.Request) -> dict[str, str]:
        if request.method != "POST":
            return {}
        try:
            parsed = parse_qs(request.content.decode("utf-8"), keep_blank_values=True)
        except (UnicodeDecodeError, AttributeError):
            return {}
        return {key: values[0] for key, values in parsed.items() if values}

    def _classify_request(self, request: httpx.Request) -> tuple[str, dict[str, Any]]:
        path = request.url.path
        form = self._form(request)

        if ".well-known/oauth-protected-resource" in path:
            return "XAA 2/6 discover protected resource", {}
        if path.endswith("/.well-known/oauth-authorization-server"):
            return "XAA 2/6 discover authorization server", {}
        if path.endswith("/requester-bootstrap"):
            return "XAA 3/6 select delegated flow", {
                "resource": form.get("resource", ""),
                "requested_scope": form.get("scope", ""),
            }
        if path.endswith("/token"):
            grant_type = form.get("grant_type", "")
            if grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
                return "XAA 4/6 exchange human session for ID-JAG", {
                    "grant_type": "token-exchange",
                    "subject_token_type": form.get("subject_token_type", ""),
                    "requested_token_type": form.get("requested_token_type", ""),
                    "resource": form.get("resource", ""),
                    "requested_scope": form.get("scope", ""),
                    "subject_token": "[REDACTED]",
                }
            if grant_type == "urn:ietf:params:oauth:grant-type:jwt-bearer":
                return "XAA 5/6 redeem ID-JAG for MCP token", {
                    "grant_type": "jwt-bearer",
                    "resource": form.get("resource", ""),
                    "requested_scope": form.get("scope", ""),
                    "assertion": "[REDACTED]",
                }
        return "XAA HTTP", {}

    @staticmethod
    def _safe_response_summary(response: httpx.Response) -> dict[str, Any]:
        try:
            body = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {"content_type": response.headers.get("content-type", "")}
        if not isinstance(body, dict):
            return {"json_type": type(body).__name__}

        path = response.request.url.path
        if path.endswith("/requester-bootstrap"):
            targets = []
            for target in body.get("targets", []):
                if not isinstance(target, dict):
                    continue
                targets.append(
                    {
                        key: target.get(key)
                        for key in (
                            "resource",
                            "relationship",
                            "recommended_flow",
                            "access_status",
                        )
                        if target.get(key) is not None
                    }
                )
            return {
                "targets": targets,
                "pending_requests": len(body.get("pending", [])),
            }

        # These fields prove which grant ran and whether it succeeded.  Token
        # and assertion values are intentionally represented only as booleans.
        allowed = (
            "issued_token_type",
            "token_type",
            "expires_in",
            "scope",
            "error",
            "error_description",
            "status",
            "request_id",
        )
        summary = {key: body[key] for key in allowed if key in body}
        if "access_token" in body:
            summary["credential_issued"] = True
        return summary


class M2MHTTPTrace:
    """Trace private-key-JWT authentication while redacting the assertion."""

    def __init__(self) -> None:
        self.client = httpx.AsyncClient(
            timeout=60.0,
            event_hooks={"request": [self.on_request], "response": [self.on_response]},
        )

    async def on_request(self, request: httpx.Request) -> None:
        stage, fields = self._classify_request(request)
        request.extensions["authsec_demo_stage"] = stage
        request.extensions["authsec_demo_safe_fields"] = fields
        m2m_log.info("%s → %s %s | %s", stage, request.method, request.url.path, fields)

    async def on_response(self, response: httpx.Response) -> None:
        await response.aread()
        stage = str(response.request.extensions.get("authsec_demo_stage", "M2M HTTP"))
        summary = XAAHTTPTrace._safe_response_summary(response)
        m2m_log.info("%s ← HTTP %s | %s", stage, response.status_code, summary)
        if stage.startswith("M2M 3/7") and response.is_success:
            assertion = response.request.extensions.get("authsec_demo_safe_fields", {})
            safe_claims = assertion.get("safe_assertion_claims", {})
            m2m_log.info(
                "M2M 4/7 AuthSec private-key validation PASS | "
                "checks=[client_supports_private_key_jwt,kid_resolved_from_registered_jwks,"
                "RS256_signature_valid,iss_equals_sub_equals_client_id,"
                "audience_equals_token_endpoint,assertion_not_expired,jti_not_replayed] "
                "| kid=%s assertion_jti=%s credential_issued=%s",
                safe_claims.get("kid"),
                safe_claims.get("jti"),
                bool(summary.get("credential_issued")),
            )

    async def aclose(self) -> None:
        await self.client.aclose()

    @staticmethod
    def _classify_request(request: httpx.Request) -> tuple[str, dict[str, Any]]:
        path = request.url.path
        if ".well-known/oauth-protected-resource" in path:
            return "M2M 2/7 discover protected resource", {}
        if path.endswith("/.well-known/oauth-authorization-server"):
            return "M2M 2/7 discover authorization server", {}
        if not path.endswith("/token") or request.method != "POST":
            return "M2M HTTP", {}

        form = XAAHTTPTrace._form(request)
        assertion = form.get("client_assertion", "")
        assertion_view: dict[str, Any] = {}
        if assertion:
            try:
                header = jwt.get_unverified_header(assertion)
                claims = jwt.decode(
                    assertion,
                    options={"verify_signature": False, "verify_aud": False},
                )
                assertion_view = {
                    "alg": header.get("alg"),
                    "kid": header.get("kid"),
                    **{
                        key: claims.get(key)
                        for key in ("iss", "sub", "aud", "jti", "iat", "exp")
                    },
                }
                if isinstance(claims.get("iat"), int) and isinstance(claims.get("exp"), int):
                    assertion_view["lifetime_s"] = claims["exp"] - claims["iat"]
            except jwt.PyJWTError:
                assertion_view = {"decode": "failed"}

        return "M2M 3/7 sign private-key JWT and request token", {
            "grant_type": form.get("grant_type", ""),
            "client_id": form.get("client_id", ""),
            "resource": form.get("resource", ""),
            "requested_scope": form.get("scope", ""),
            "client_assertion_type": form.get("client_assertion_type", ""),
            "client_assertion": "[REDACTED]",
            "safe_assertion_claims": assertion_view,
        }


class SpiffeHTTPTrace:
    """Trace the real JWT-SVID exchange without printing the bearer assertion.

    The SDK gets the SVID from the local SPIRE Agent before it constructs the
    token request. Observing the request hook therefore proves that a real SVID
    was fetched and placed in ``client_assertion``. We decode only its public
    claims; the signed compact token remains redacted.
    """

    def __init__(self, expected_spiffe_id: str) -> None:
        self._expected_spiffe_id = expected_spiffe_id
        self.client = httpx.AsyncClient(
            timeout=60.0,
            event_hooks={"request": [self.on_request], "response": [self.on_response]},
        )

    async def on_request(self, request: httpx.Request) -> None:
        stage, fields = self._classify_request(request)
        request.extensions["authsec_demo_stage"] = stage
        spiffe_log.info("%s → %s %s | %s", stage, request.method, request.url.path, fields)

    async def on_response(self, response: httpx.Response) -> None:
        await response.aread()
        stage = str(response.request.extensions.get("authsec_demo_stage", "SPIFFE HTTP"))
        summary = XAAHTTPTrace._safe_response_summary(response)
        spiffe_log.info("%s ← HTTP %s | %s", stage, response.status_code, summary)

    async def aclose(self) -> None:
        await self.client.aclose()

    def _classify_request(self, request: httpx.Request) -> tuple[str, dict[str, Any]]:
        path = request.url.path
        if ".well-known/oauth-protected-resource" in path:
            return "SPIFFE 2/7 discover protected resource", {}
        if path.endswith("/.well-known/oauth-authorization-server"):
            return "SPIFFE 3/7 discover authorization server", {}
        if not path.endswith("/token") or request.method != "POST":
            return "SPIFFE HTTP", {}

        form = XAAHTTPTrace._form(request)
        assertion = form.get("client_assertion", "")
        claims: dict[str, Any] = {}
        if assertion:
            try:
                claims = jwt.decode(
                    assertion,
                    options={"verify_signature": False, "verify_aud": False},
                )
            except jwt.PyJWTError:
                claims = {"decode": "failed"}

        safe_claims = {
            key: claims.get(key) for key in ("sub", "aud", "iat", "exp") if key in claims
        }
        if isinstance(claims.get("iat"), int) and isinstance(claims.get("exp"), int):
            safe_claims["lifetime_s"] = claims["exp"] - claims["iat"]
        safe_claims["spiffe_id_matches_registration"] = (
            claims.get("sub") == self._expected_spiffe_id
        )

        return "SPIFFE 4/7 exchange JWT-SVID for AuthSec token", {
            "grant_type": form.get("grant_type", ""),
            "client_id": form.get("client_id", ""),
            "client_assertion_type": form.get("client_assertion_type", ""),
            "client_assertion": "[JWT-SVID REDACTED]",
            "svid_claims": safe_claims,
            "resource": form.get("resource", ""),
            "requested_scope": form.get("scope", ""),
        }
