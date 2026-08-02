"""Server-side GitHub provider clients.

These credentials authenticate the facade to GitHub. They are deliberately
independent from the AuthSec bearer token authenticating the MCP caller.
"""

from .provider import GitHubProvider

__all__ = ["GitHubProvider"]
