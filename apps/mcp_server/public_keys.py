"""Public-key publication for the demo's private-key-JWT Service Account.

Only the RSA public key is served.  The matching private key stays under the
ignored, mode-0700 ``.secrets`` directory and is loaded only by the M2M caller.
AuthSec fetches this JWKS URI when it verifies a freshly signed client
assertion.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from apps.shared.env import STATE_DIR

M2M_JWKS_PATH = STATE_DIR / "m2m-jwks.json"
M2M_JWKS_ROUTE = "/.well-known/m2m-jwks.json"
M2M_JWKS_URL = f"https://mcp-demo.mcpauthz.com{M2M_JWKS_ROUTE}"


def public_m2m_jwks() -> JSONResponse:
    """Return the generated public JWKS or a setup-oriented 404."""

    if not M2M_JWKS_PATH.is_file():
        raise HTTPException(
            status_code=404,
            detail="M2M public key not generated; run `pnpm m2m:setup`",
        )
    try:
        payload: Any = json.loads(M2M_JWKS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="M2M JWKS state is invalid") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        raise HTTPException(status_code=500, detail="M2M JWKS state has no keys array")
    return JSONResponse(
        content=payload,
        headers={"Cache-Control": "public, max-age=300"},
    )

