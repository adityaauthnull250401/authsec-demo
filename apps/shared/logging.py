"""Deep, traceable logging for the whole demo — without ever printing secrets.

One `configure_logging()` call per entrypoint wires:

* a Rich console handler (and an optional file via ``DEMO_LOG_FILE``),
* a correlation id (``DEMO_RUN_ID``) stamped on every record as ``trace_id``,
* demo loggers (``authsec_demo.*``) and the SDK loggers (``authsec.runtime``,
  ``authsec.manifest``, ``authsec_sdk.*``, ``spiffe``) at ``DEMO_LOG_LEVEL``,
* ``httpx`` at INFO so **every** ``POST /oauth/token`` (token-exchange →
  ID-JAG, jwt-bearer redemption, introspection) and every GitHub call appears
  as one request line — this is how the flow is traced client-side,
* ``httpcore`` wire tracing (connection + header events) only when
  ``DEMO_TRACE_HTTP=full`` — this can expose bearer headers, so it is opt-in.

``log_token()`` decodes a JWT header + claims (never the signature) and logs the
identity-relevant fields, so the M2M ``sub``, the XAA ``sub`` + ``act`` + ``tf``,
the audience, scope, ``jti`` and lifetime are visible at each hop.

The actual Hydra token exchange and ID-JAG issuance/redemption happen inside the
AuthSec backend, not here — trace those in the backend logs (see implementation.md).
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import jwt
from rich.logging import RichHandler

_DEMO_ROOT = "authsec_demo"
_SDK_LOGGERS = ("authsec.runtime", "authsec.manifest", "authsec_sdk", "spiffe")
_CONFIGURED = False


class _TraceFilter(logging.Filter):
    """Stamp every record — including third-party ones — with the run's id."""

    def __init__(self, trace_id: str) -> None:
        super().__init__()
        self._trace_id = trace_id

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "trace_id"):
            record.trace_id = self._trace_id
        return True


def _level(name: str, default: str = "INFO") -> int:
    raw = os.getenv(name, default).strip().upper() or default
    return getattr(logging, raw, logging.INFO)


def configure_logging(component: str) -> logging.Logger:
    """Idempotently install handlers/levels and return this component's logger."""

    global _CONFIGURED
    trace_id = os.getenv("DEMO_RUN_ID", "").strip() or "no-run"
    level = _level("DEMO_LOG_LEVEL")
    trace_http = os.getenv("DEMO_TRACE_HTTP", "").strip().lower()

    if not _CONFIGURED:
        trace_filter = _TraceFilter(trace_id)

        console_handler = RichHandler(
            rich_tracebacks=True, show_path=False, show_time=True, markup=False
        )
        console_handler.setFormatter(logging.Formatter("[%(trace_id)s] %(name)s — %(message)s"))
        console_handler.addFilter(trace_filter)

        handlers: list[logging.Handler] = [console_handler]

        log_file = os.getenv("DEMO_LOG_FILE", "").strip()
        if log_file:
            path = Path(log_file).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(path, encoding="utf-8")
            file_handler.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-5s [%(trace_id)s] %(name)s: %(message)s"
                )
            )
            file_handler.addFilter(trace_filter)
            handlers.append(file_handler)

        root = logging.getLogger()
        root.setLevel(level)
        for handler in handlers:
            root.addHandler(handler)

        # SDK loggers inherit the demo level (DEBUG surfaces their internals).
        for name in _SDK_LOGGERS:
            logging.getLogger(name).setLevel(level)

        # httpx request lines are the client-side trace of the token exchanges.
        logging.getLogger("httpx").setLevel(logging.INFO)
        # httpcore is verbose and can log bearer headers — opt-in only.
        logging.getLogger("httpcore").setLevel(
            logging.DEBUG if trace_http == "full" else logging.WARNING
        )
        logging.getLogger(_DEMO_ROOT).setLevel(level)
        _CONFIGURED = True

    logger = logging.getLogger(f"{_DEMO_ROOT}.{component}")
    logger.info(
        "logging ready | level=%s trace_http=%s raw_tokens=%s",
        logging.getLevelName(level),
        trace_http or "off",
        os.getenv("DEMO_LOG_RAW_TOKENS", "false"),
    )
    return logger


def get_logger(component: str) -> logging.Logger:
    """Module-level logger; safe to call before configure_logging()."""

    return logging.getLogger(f"{_DEMO_ROOT}.{component}")


_TOKEN_CLAIMS = (
    "iss",
    "sub",
    "aud",
    "scope",
    "tf",
    "act",
    "azp",
    "client_id",
    "workspace_id",
    "jti",
    "iat",
    "exp",
)


def log_token(logger: logging.Logger, label: str, token: str) -> dict[str, Any]:
    """Log a JWT's identity-relevant claims (never the signature) and return them.

    Set ``DEMO_LOG_RAW_TOKENS=true`` to additionally emit the compact token at
    DEBUG — for deep local debugging only; it is a bearer credential.
    """

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        header = {}
    try:
        claims: dict[str, Any] = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False}
        )
    except Exception:
        logger.warning("%s: token present but could not be decoded", label)
        return {}

    view = {key: claims[key] for key in _TOKEN_CLAIMS if key in claims}
    if "iat" in claims and "exp" in claims:
        with contextlib.suppress(TypeError, ValueError):
            view["lifetime_s"] = int(claims["exp"]) - int(claims["iat"])
    logger.info(
        "%s | alg=%s kid=%s | %s",
        label,
        header.get("alg"),
        header.get("kid"),
        json.dumps(view, default=str, sort_keys=True),
    )
    if os.getenv("DEMO_LOG_RAW_TOKENS", "").strip().lower() in {"1", "true", "yes", "on"}:
        logger.debug("%s RAW=%s", label, token)
    return claims
