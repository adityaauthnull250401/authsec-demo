"""Shared LangChain v1 ReAct composition for all three identities."""

from __future__ import annotations

from typing import Any

from authsec_sdk.integrations import authsec_tool_error_handler
from langchain.agents import create_agent
from langchain_mcp_adapters.client import MultiServerMCPClient

from apps.agents.config import AgentSettings
from apps.agents.trace import render_agent_task, render_new_messages
from apps.shared.logging import get_logger

log = get_logger("agent.runtime")


async def build_agent(settings: AgentSettings, token: str) -> Any:
    client = MultiServerMCPClient(
        {
            "github": {
                "url": settings.resource_uri,
                "transport": "streamable_http",
                "headers": {"Authorization": f"Bearer {token}"},
            }
        }
    )
    if settings.profile == "ci-reporter":
        log.info(
            "M2M 7/7 call protected MCP tools/list | bearer signature=[REDACTED] resource=%s",
            settings.resource_uri,
        )
    elif settings.profile == "repo-assistant":
        log.info(
            "XAA 6/6 call protected MCP tools/list | bearer value=[REDACTED] resource=%s",
            settings.resource_uri,
        )
    elif settings.profile == "release-reporter":
        log.info(
            "SPIFFE 6/7 call protected MCP tools/list | bearer value=[REDACTED] resource=%s",
            settings.resource_uri,
        )
    tools = await client.get_tools()
    for tool in tools:
        tool.handle_tool_error = authsec_tool_error_handler
    # tools/list is already scope-filtered by AuthSec: the model only sees what
    # this identity may call. That visible set is the demo's "least visibility".
    log.info(
        "%s: MCP tools/list returned %d tool(s) visible after AuthSec policy filtering: %s",
        settings.profile,
        len(tools),
        [getattr(t, "name", "?") for t in tools],
    )
    return create_agent(settings.model, tools, system_prompt=settings.system_prompt)


async def run_once(agent: Any, prompt: str, messages: list[Any] | None = None) -> list[Any]:
    history = list(messages or [])
    history.append({"role": "user", "content": prompt})
    render_agent_task(prompt)
    result = await agent.ainvoke({"messages": history})
    output = list(result["messages"])
    render_new_messages(output, start_at=len(messages or []))
    return output


async def run_interactive(agent: Any, initial_prompt: str | None = None) -> None:
    """Keep one token/session alive across Act 3 approval and Act 4 revocation."""

    history: list[Any] = []
    if initial_prompt:
        history = await run_once(agent, initial_prompt, history)
    while True:
        prompt = input("you> ").strip()
        if prompt.lower() in {"exit", "quit"}:
            return
        if prompt:
            history = await run_once(agent, prompt, history)
