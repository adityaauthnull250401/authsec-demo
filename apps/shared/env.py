"""Environment loading that is strict without ever printing secret values.

The demo intentionally has no magical development credentials. Public defaults
belong in code; identifiers and secrets must come from the human-created `.env`
or process environment. Every caller names the variables it requires so an Act
can fail with a useful setup instruction instead of failing deep inside OAuth.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / ".state"
SECRETS_DIR = PROJECT_ROOT / ".secrets"


class ConfigurationError(RuntimeError):
    """A required operator-provided setting is absent or malformed."""


def load_project_env() -> None:
    """Load `.env` without overwriting values already exported by the shell."""

    load_dotenv(PROJECT_ROOT / ".env", override=False)


def required(name: str) -> str:
    """Return a non-empty environment value or raise a secret-safe error."""

    value = os.getenv(name, "").strip()
    if not value:
        raise ConfigurationError(
            f"{name} is required; see .env.example and setup.md"
        )
    return value


def required_many(names: Iterable[str]) -> dict[str, str]:
    """Validate a group together so preflight can report all missing names."""

    values: dict[str, str] = {}
    missing: list[str] = []
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            values[name] = value
        else:
            missing.append(name)
    if missing:
        raise ConfigurationError("Missing required environment variables: " + ", ".join(missing))
    return values


def optional(name: str, default: str = "") -> str:
    """Return a value, treating a blank dotenv entry as unset.

    A copied template includes empty operator-owned names. Those entries must
    not erase safe defaults such as port 8091 or the known tunnel path.
    """

    value = os.getenv(name)
    if value is None or not value.strip():
        return default.strip()
    return value.strip()


def boolean(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def secret_text(name: str) -> str:
    """Read a PEM/secret from the value itself or from a referenced file path.

    GitHub downloads private keys as files, while CI systems often inject PEM
    text. Supporting both avoids unsafe shell transformations and multiline-env
    quoting. The value is never included in an exception.
    """

    raw = required(name)
    candidate = Path(raw).expanduser()
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8")
    if "-----BEGIN" in raw:
        return raw.replace("\\n", "\n")
    raise ConfigurationError(f"{name} must contain PEM text or name a readable PEM file")


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
