"""Tool-contract validation: bounded inputs and server-owned targets.

This is not authorization. It constrains what an already-authorized tool can
ask GitHub to do, providing defense-in-depth below AuthSec's identity/scope
decision at the MCP transport boundary.
"""

from __future__ import annotations

import re

from apps.mcp_server.constants import READ_REPOSITORIES

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def read_repository(name: str) -> str:
    try:
        return READ_REPOSITORIES[name]
    except KeyError as exc:
        allowed = ", ".join(sorted(READ_REPOSITORIES))
        raise ValueError(f"repo must be one of: {allowed}") from exc


def bounded_text(value: str, field: str, minimum: int, maximum: int) -> str:
    cleaned = value.strip()
    if not minimum <= len(cleaned) <= maximum:
        raise ValueError(f"{field} must contain {minimum}..{maximum} characters")
    return cleaned


def run_id(value: str) -> str:
    cleaned = value.strip()
    if not RUN_ID_PATTERN.fullmatch(cleaned):
        raise ValueError("run_id must be 1..64 letters, numbers, dots, underscores, or hyphens")
    return cleaned
