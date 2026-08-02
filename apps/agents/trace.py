"""Safe execution-trace rendering.

Only user text, model tool selections, ToolMessage results, and the final answer
are shown. Raw bearer tokens, hidden model reasoning, and credential material
are never accepted by this renderer.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.pretty import Pretty

console = Console()


def render_agent_task(prompt: str) -> None:
    """Make the exact objective given to the model visible to the audience."""

    console.print(Panel(prompt, title="ReAct agent objective", border_style="blue"))


def _tool_message_failed(message: Any) -> bool:
    status = str(getattr(message, "status", "")).lower()
    content = str(getattr(message, "content", "")).lower()
    return status == "error" or any(
        marker in content
        for marker in (
            "insufficient_scope",
            "scope_insufficient",
            "invalid_token",
            "authorization denied",
            "permission denied",
        )
    )


def render_new_messages(messages: Iterable[Any], start_at: int = 0) -> int:
    items = list(messages)
    for message in items[start_at:]:
        kind = message.__class__.__name__
        if kind == "AIMessage" and getattr(message, "tool_calls", None):
            for call in message.tool_calls:
                tool_name = str(call.get("name") or "unknown")
                console.print(
                    Panel(
                        Pretty({"tool": call.get("name"), "arguments": call.get("args", {})}),
                        title=f"ReAct decision — call MCP tool: {tool_name}",
                        border_style="cyan",
                    )
                )
        elif kind == "ToolMessage":
            tool_name = str(getattr(message, "name", None) or "MCP tool")
            failed = _tool_message_failed(message)
            console.print(
                Panel(
                    str(getattr(message, "content", "")),
                    title=(
                        f"MCP action DENIED — {tool_name}"
                        if failed
                        else f"MCP action ALLOWED — {tool_name} returned a result"
                    ),
                    border_style="red" if failed else "green",
                )
            )
        elif kind == "AIMessage" and getattr(message, "content", None):
            console.print(
                Panel(
                    str(message.content),
                    title="Agent final answer (derived from the MCP result)",
                    border_style="magenta",
                )
            )
    return len(items)
