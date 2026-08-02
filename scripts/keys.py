"""Generate the service account's private-key-JWT material locally."""

from __future__ import annotations

import base64
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from apps.shared.env import ensure_private_directory


@dataclass(frozen=True)
class GeneratedKey:
    private_key_path: Path
    kid: str
    jwks_json: str


def _b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_private_key_jwks(path: Path) -> GeneratedKey:
    """Write a mode-0600 RSA key and return only its public JWKS representation."""

    if path.exists():
        raise RuntimeError(f"Refusing to overwrite existing private key: {path}")
    ensure_private_directory(path.parent)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(pem)

    public = key.public_key().public_numbers()
    kid = f"demo-{uuid.uuid4().hex[:12]}"
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(public.n),
        "e": _b64url(public.e),
    }
    return GeneratedKey(path, kid, json.dumps({"keys": [jwk]}, separators=(",", ":")))
