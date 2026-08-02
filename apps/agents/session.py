"""Private local storage for the presenter's pre-staged OIDC subject token."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from apps.shared.env import STATE_DIR, ensure_private_directory

SESSION_PATH = STATE_DIR / "alice-session.json"


def save_subject_token(token: str, path: Path = SESSION_PATH) -> None:
    if not token:
        raise ValueError("cannot save an empty subject token")
    ensure_private_directory(path.parent)
    path.write_text(
        json.dumps({"subject_token": token, "saved_at": datetime.now(UTC).isoformat()}, indent=2),
        encoding="utf-8",
    )
    path.chmod(0o600)


def load_subject_token(path: Path = SESSION_PATH) -> str:
    if not path.is_file():
        raise RuntimeError("Presenter session is missing; run `uv run demo-agent login` first")
    payload = json.loads(path.read_text(encoding="utf-8"))
    token = str(payload.get("subject_token", "")).strip()
    if not token:
        raise RuntimeError(f"Presenter session file is malformed: {path}")
    return token
