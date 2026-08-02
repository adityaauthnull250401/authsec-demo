"""Raw Streamable HTTP MCP calls used by smoke tests and denial proofs."""

from __future__ import annotations

import json
from typing import Any

import httpx

MCP_PROTOCOL_VERSION = "2025-06-18"


async def call_mcp(
    resource_uri: str,
    token: str,
    method: str,
    params: dict[str, Any] | None = None,
    *,
    request_id: int = 1,
) -> tuple[int, dict[str, Any], httpx.Headers]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
    }
    payload = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        payload["params"] = params
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(resource_uri, headers=headers, json=payload)
    try:
        body = response.json()
    except Exception as exc:
        raise RuntimeError(
            f"MCP {method} returned non-JSON HTTP {response.status_code}: {response.text[:200]}"
        ) from exc
    return response.status_code, body, response.headers


def listed_tool_names(payload: dict[str, Any]) -> set[str]:
    tools = (payload.get("result") or {}).get("tools") or []
    return {str(tool.get("name")) for tool in tools if isinstance(tool, dict)}


def is_authsec_denial(payload: dict[str, Any]) -> bool:
    """Recognize the SDK's in-band, fail-closed MCP tool error shape."""

    result = payload.get("result") or {}
    if result.get("isError") is not True:
        return False
    structured = result.get("structuredContent") or result.get("structured_content") or {}
    text = str(result)
    code = str(structured.get("error") or structured.get("code") or "")
    return code in {"insufficient_scope", "scope_insufficient", "invalid_token"} or any(
        marker in text for marker in ("insufficient_scope", "scope_insufficient", "invalid_token")
    )


def mcp_result_text(payload: dict[str, Any]) -> str:
    """Return presenter-safe text from an MCP CallToolResult.

    FastMCP results can arrive as ``structuredContent`` or as JSON encoded in a
    text content block. Keeping this normalization here prevents the proof and
    smoke commands from reducing a meaningful MCP decision to only HTTP 200.
    """

    result = payload.get("result") or {}
    content = result.get("content") or []
    parts = [
        str(item.get("text", ""))
        for item in content
        if isinstance(item, dict) and item.get("type") == "text" and item.get("text")
    ]
    return "\n".join(parts).strip()


def mcp_structured_result(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize structured MCP output without exposing transport internals."""

    result = payload.get("result") or {}
    structured = result.get("structuredContent") or result.get("structured_content")
    if isinstance(structured, dict):
        # FastMCP commonly wraps a function's object return under ``result``.
        nested = structured.get("result")
        return nested if isinstance(nested, dict) else structured

    text = mcp_result_text(payload)
    if not text:
        return {}
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(decoded, dict):
        return {}
    nested = decoded.get("result")
    return nested if isinstance(nested, dict) else decoded


def mcp_denial_evidence(payload: dict[str, Any]) -> tuple[str, str]:
    """Extract the AuthSec denial code and human-readable reason."""

    result = payload.get("result") or {}
    structured = result.get("structuredContent") or result.get("structured_content") or {}
    if not isinstance(structured, dict):
        structured = {}
    nested = structured.get("error")
    nested_error = nested if isinstance(nested, dict) else {}
    code = str(
        nested_error.get("code")
        or structured.get("code")
        or (nested if isinstance(nested, str) else "")
        or "authorization_denied"
    )
    message = str(
        nested_error.get("message")
        or structured.get("message")
        or mcp_result_text(payload)
        or "AuthSec rejected the MCP tool call."
    )
    if code == "authorization_denied" and "required scope" in message.lower():
        code = "insufficient_scope"
    # Keep tables and recorded presenter output readable even if an SDK embeds
    # a verbose remediation block in the MCP error text.
    return code, " ".join(message.split())[:500]
