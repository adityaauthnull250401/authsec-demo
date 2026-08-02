"""Non-secret evidence needed for idempotent cleanup."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apps.shared.env import STATE_DIR, ensure_private_directory


def path_for(run_id: str) -> Path:
    return STATE_DIR / "runs" / f"{run_id}.json"


def load_run(run_id: str) -> dict[str, Any]:
    path = path_for(run_id)
    if not path.is_file():
        return {"run_id": run_id, "jtis": [], "issues": []}
    return json.loads(path.read_text(encoding="utf-8"))


def record(run_id: str, *, jti: str | None = None, issue_number: int | None = None) -> None:
    payload = load_run(run_id)
    if jti and jti not in payload["jtis"]:
        payload["jtis"].append(jti)
    if issue_number is not None and issue_number not in payload["issues"]:
        payload["issues"].append(issue_number)
    path = path_for(run_id)
    ensure_private_directory(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
