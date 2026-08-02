"""Profile-specific agent settings.

The three profiles share one ReAct/MCP runtime but intentionally do not share
an identity class. That distinction is the demo: private-key service identity,
SPIFFE workload identity, and user-delegated agent identity all arrive at the
same Resource Server with different cryptographic provenance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from apps.mcp_server.constants import ISSUE_SCOPE, ISSUER, READ_SCOPE, README_SCOPE, RESOURCE_URI
from apps.shared.env import STATE_DIR, load_project_env, optional, required

ProfileName = Literal["ci-reporter", "release-reporter", "repo-assistant"]


@dataclass(frozen=True)
class AgentSettings:
    profile: ProfileName
    issuer: str
    resource_uri: str
    requested_scopes: list[str]
    model: str
    system_prompt: str


def load_agent_settings(profile: ProfileName) -> AgentSettings:
    load_project_env()
    issuer = optional("AUTHSEC_ISSUER", ISSUER).rstrip("/")
    resource_uri = optional("AUTHSEC_RESOURCE_URI", RESOURCE_URI).rstrip("/")
    model = required("DEMO_LLM_MODEL")
    scopes = [READ_SCOPE, README_SCOPE]
    task = "Read AuthSec repository information and summarize it accurately."
    if profile == "repo-assistant":
        scopes.append(ISSUE_SCOPE)
        task = (
            "Act for the authenticated user. Inspect repository information before creating "
            "an issue, explain the exact sandbox-only action, and never claim an action succeeded "
            "unless the MCP result confirms it."
        )
    return AgentSettings(
        profile=profile,
        issuer=issuer,
        resource_uri=resource_uri,
        requested_scopes=scopes,
        model=model,
        system_prompt=(
            "You are an AuthSec demo agent. Use only the MCP tools made visible to you. "
            "Treat tool errors as real authorization or provider failures; "
            "never fabricate success. " + task
        ),
    )


def bootstrap_state() -> dict[str, str]:
    """Read non-secret IDs emitted by bootstrap, if present."""

    path = STATE_DIR / "bootstrap.json"
    if not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {str(key): str(value) for key, value in payload.items() if value is not None}


def env_or_state(env_name: str, state_name: str) -> str:
    value = optional(env_name)
    if value:
        return value
    value = bootstrap_state().get(state_name, "").strip()
    if not value:
        return required(env_name)
    return value


def resolve_private_key_path() -> Path:
    raw = env_or_state("AUTHSEC_M2M_PRIVATE_KEY_PATH", "m2m_private_key_path")
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"AUTHSEC_M2M_PRIVATE_KEY_PATH does not exist: {path}")
    return path
