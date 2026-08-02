"""Fail-fast validation used before `pnpm share` starts any process."""

from __future__ import annotations

import sys

from rich.console import Console

from apps.mcp_server.config import load_authsec_runtime_config, load_server_settings
from apps.shared.env import ConfigurationError, load_project_env, required_many

console = Console()


def main() -> None:
    try:
        load_project_env()
        # Report the whole operator-owned gap in one pass. The loaders below
        # then perform semantic validation and verify both PEM paths.
        required_many(
            [
                "AUTHSEC_RESOURCE_SERVER_ID",
                "AUTHSEC_INTROSPECTION_CLIENT_ID",
                "AUTHSEC_INTROSPECTION_CLIENT_SECRET",
                "GITHUB_APP_ID",
                "GITHUB_INSTALLATION_ID",
                "GITHUB_PRIVATE_KEY",
            ]
        )
        load_server_settings()
        load_authsec_runtime_config()
    except ConfigurationError as exc:
        console.print(f"[red]Cannot start the demo server:[/red] {exc}")
        console.print("Complete the missing value in .env; see setup.md.")
        sys.exit(2)
    console.print("[green]Server configuration is complete.[/green]")


if __name__ == "__main__":
    main()
