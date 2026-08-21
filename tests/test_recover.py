from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from dotenv import dotenv_values

from scripts.recover import (
    AdminIdentity,
    PrivateEnvFile,
    _decode_admin_identity,
    _ensure_application,
    _ensure_reader_assignment,
    _has_user_role_assignment,
    _items,
)


def _token(**claims: object) -> str:
    return jwt.encode(claims, "test-only-signing-key-that-is-long-enough", algorithm="HS256")


def test_decode_admin_identity_accepts_workspace_and_subject() -> None:
    workspace_id = str(uuid4())
    user_id = str(uuid4())

    identity = _decode_admin_identity(
        _token(workspace_id=workspace_id, sub=user_id, exp=int(time.time()) + 300)
    )

    assert identity.workspace_id == workspace_id
    assert identity.user_id == user_id


def test_decode_admin_identity_rejects_expired_token() -> None:
    token = _token(workspace_id=str(uuid4()), sub=str(uuid4()), exp=100)

    with pytest.raises(RuntimeError, match="expired"):
        _decode_admin_identity(token, now=100)


def test_private_env_update_is_atomic_parseable_and_preserves_comments(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    path = tmp_path / ".env"
    path.write_text("# keep me\nAUTHSEC_RESOURCE_SERVER_ID=old\n", encoding="utf-8")
    env_file = PrivateEnvFile(path)

    env_file.update(
        {
            "AUTHSEC_RESOURCE_SERVER_ID": "new-id",
            "AUTHSEC_INTROSPECTION_CLIENT_SECRET": 'special$`"value',
        }
    )

    values = dotenv_values(path)
    assert values["AUTHSEC_RESOURCE_SERVER_ID"] == "new-id"
    assert values["AUTHSEC_INTROSPECTION_CLIENT_SECRET"] == 'special$`"value'
    assert "# keep me" in path.read_text(encoding="utf-8")
    assert path.stat().st_mode & 0o777 == 0o600
    assert tmp_path.stat().st_mode & 0o777 == 0o755
    assert not list(tmp_path.glob(".*.tmp"))


def test_private_env_refuses_admin_token_persistence(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_text("DEMO_PORT=8091\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="must never be persisted"):
        PrivateEnvFile(path).update({"AUTHSEC_ADMIN_TOKEN": "secret"})

    assert "secret" not in path.read_text(encoding="utf-8")


def test_private_env_audit_mode_does_not_create_file(tmp_path: Path) -> None:
    path = tmp_path / ".env"

    env_file = PrivateEnvFile(path, create=False)

    assert env_file.values() == {}
    assert not path.exists()


def test_items_normalizes_supported_api_envelopes() -> None:
    assert _items([{"id": "a"}], "items") == [{"id": "a"}]
    assert _items({"items": [{"id": "b"}]}, "items") == [{"id": "b"}]
    assert _items({"items": None}, "items") == []


def test_user_assignment_uses_access_assignment_identity_shape() -> None:
    assignments = [
        {
            "identity_type": "user",
            "identity_id": "presenter",
            "role_id": "triage",
        },
        {
            "identity_type": "service_account",
            "identity_id": "presenter",
            "role_id": "triage",
        },
    ]

    assert _has_user_role_assignment(assignments, "presenter", "triage")
    assert not _has_user_role_assignment(assignments, "somebody-else", "triage")


@pytest.mark.asyncio
async def test_application_creation_checkpoints_one_time_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    application_id = str(uuid4())
    workspace_id = str(uuid4())
    path = tmp_path / ".env"
    path.write_text("AUTHSEC_RESOURCE_SERVER_ID=\n", encoding="utf-8")

    class FakeAPI:
        async def get(self, path: str) -> object:
            assert path == "/authsec/applications"
            return []

        async def post(self, path: str, body: dict[str, object] | None = None) -> object:
            assert path == "/authsec/applications"
            assert body is not None
            assert body["protected_base_path"] == "/mcp"
            return {
                "id": application_id,
                "introspection_secret": "sec_one_time_value",
            }

    checkpoints: list[dict[str, object]] = []
    monkeypatch.setattr("scripts.recover._checkpoint", lambda **values: checkpoints.append(values))

    anchor = await _ensure_application(
        FakeAPI(),  # type: ignore[arg-type]
        PrivateEnvFile(path),
        AdminIdentity(workspace_id=workspace_id, user_id=str(uuid4())),
    )

    values = dotenv_values(path)
    assert anchor.application_id == application_id
    assert anchor.created
    assert values["AUTHSEC_INTROSPECTION_CLIENT_SECRET"] == "sec_one_time_value"
    assert values["AUTHSEC_RESOURCE_SERVER_ID"] == application_id
    assert checkpoints == [
        {
            "phase": "application",
            "workspace_id": workspace_id,
            "resource_server_id": application_id,
        }
    ]
    assert "AUTHSEC_ADMIN_TOKEN" not in values


@pytest.mark.asyncio
async def test_reader_assignment_reuses_registration_without_extra_privilege() -> None:
    posts: list[tuple[str, dict[str, object]]] = []

    class FakeAPI:
        async def get(self, path: str) -> object:
            assert path.endswith("/access-assignments")
            return {
                "items": [
                    {
                        "identity_type": "service_account",
                        "identity_id": "machine",
                        "role_id": "reader",
                    }
                ]
            }

        async def post(self, path: str, body: dict[str, object] | None = None) -> object:
            assert body is not None
            posts.append((path, body))
            return {}

    await _ensure_reader_assignment(
        FakeAPI(),  # type: ignore[arg-type]
        "application",
        "machine",
        {"id": "reader"},
        "machine",
    )

    assert posts == [
        (
            "/authsec/applications/application/access/workloads",
            {"service_account_id": "machine", "role_id": "reader"},
        )
    ]


@pytest.mark.asyncio
async def test_reader_assignment_fails_closed_on_extra_machine_role() -> None:
    class FakeAPI:
        async def get(self, _path: str) -> object:
            return {
                "items": [
                    {
                        "identity_type": "service_account",
                        "identity_id": "machine",
                        "role_id": "triage",
                    }
                ]
            }

        async def post(self, _path: str, _body: dict[str, object] | None = None) -> object:
            raise AssertionError("must not mutate an unexpectedly privileged identity")

    with pytest.raises(RuntimeError, match="non-Reader"):
        await _ensure_reader_assignment(
            FakeAPI(),  # type: ignore[arg-type]
            "application",
            "machine",
            {"id": "reader"},
            "machine",
        )
