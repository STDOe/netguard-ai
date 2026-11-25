import hashlib
import shutil
import socket
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from unittest.mock import patch
from uuid import UUID, uuid4, uuid5

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from test_integration import (
    API,
    WORKSPACE,
    design,
    headers,
    provision,
    request_body,
    validate_message,
)
from test_workflows import brownfield, greenfield, requirements

from app.config import Scope, Settings
from app.dashboard.audit import Audits
from app.main import create_app
from app.network.driver import PutStaticRoute
from app.network.policy import Profile


def service(
    settings: Settings, token: str, *scopes: Scope, **options: object
) -> TestClient:
    config = provision(settings, token, integration_scopes=frozenset(scopes), **options)
    return TestClient(
        create_app(config), client=("127.0.0.1", 40000), headers=headers(token)
    )


@pytest.mark.parametrize("kind", ["audit", "greenfield", "brownfield"])
def test_replay_after_read_revocation(
    settings: Settings,
    migration_config: Config,
    network_profile: Profile,
    route_change: PutStaticRoute,
    kind: str,
) -> None:
    command.upgrade(migration_config, "head")
    token = "ngw." + token_urlsafe(32)
    operations: dict[str, dict[str, Any]] = {
        "audit": {
            "kind": "audit",
            "idempotency_key": "rotation-test",
            "network_id": str(network_profile.network.id),
        },
        "brownfield": brownfield(network_profile, route_change),
        "greenfield": design(),
    }
    data = request_body(operations[kind])
    with service(settings, token, *Scope) as initial:
        created = initial.post(API + "/tasks", json=data)
        assert created.status_code == 201
        original = created.json()
        assert original["status"] == (
            "awaiting_approval" if kind == "brownfield" else "succeeded"
        )
        assert original[
            {"audit": "audit", "brownfield": "plan", "greenfield": "artifacts"}[kind]
        ]
    rotated = "ngw." + token_urlsafe(32)
    with service(
        settings, rotated, Scope.CREATE, Scope.ARTIFACTS, Scope.APPROVAL
    ) as restricted:
        assert (
            restricted.get(
                API + "/tasks/" + original["task_id"], params=WORKSPACE
            ).status_code
            == 403
        )
        with ThreadPoolExecutor(2) as pool:
            replies = list(
                pool.map(lambda _: restricted.post(API + "/tasks", json=data), range(2))
            )
        for replay in replies:
            assert replay.status_code == 201
            validate_message("TaskReceipt", replay.json())
            assert replay.json() == {
                "task_id": original["task_id"],
                "correlation_id": original["correlation_id"],
                "request_id": replay.headers["X-Request-ID"],
                "schema_version": "1.0",
            }
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT count(*) FROM tasks").fetchone() == (1,)
        if kind == "audit":
            assert db.execute(
                "SELECT count(*) FROM security_audit_runs"
            ).fetchone() == (1,)


def test_input_cancel_write_receipts(
    settings: Settings, migration_config: Config
) -> None:
    command.upgrade(migration_config, "head")
    token = "ngw." + token_urlsafe(32)
    with service(settings, token, Scope.CREATE, Scope.CANCEL, Scope.ARTIFACTS) as api:
        for operation in ("input", "cancel"):
            created = api.post(
                API + "/tasks",
                json=request_body(greenfield("interview-" + operation, {})),
            )
            assert created.status_code == 201
            original = created.json()
            validate_message("TaskReceipt", original)
            url = API + "/tasks/" + original["task_id"] + "/" + operation
            reply = api.post(
                url,
                params=WORKSPACE,
                json=requirements() if operation == "input" else None,
            )
            assert reply.status_code == 200
            assert reply.json() == {
                **original,
                "request_id": reply.headers["X-Request-ID"],
            }
    with service(settings, token, Scope.TASK) as api:
        assert (
            api.get(API + "/tasks/" + original["task_id"], params=WORKSPACE).json()[
                "status"
            ]
            == "cancelled"
        )


def test_audit_resume_when_profile_returns(
    settings: Settings,
    migration_config: Config,
    network_profile: Profile,
    tmp_path: Path,
) -> None:
    command.upgrade(migration_config, "head")
    token = "ngw." + token_urlsafe(32)
    body = request_body(
        {
            "kind": "audit",
            "idempotency_key": "resume-audit",
            "network_id": str(network_profile.network.id),
        }
    )
    with (
        service(settings, token, *Scope) as api,
        patch.object(
            Audits, "persist", side_effect=RuntimeError("simulated interruption")
        ),
    ):
        assert api.post(API + "/tasks", json=body).status_code == 500
    with sqlite3.connect(settings.database_path) as db:
        task_id, status = db.execute("SELECT id, status FROM tasks").fetchone()
        assert status == "queued"
    url = API + "/tasks/" + task_id
    with service(settings, token, *Scope, profile_path=tmp_path / "absent") as api:
        retry = api.post(API + "/tasks", json=body)
        assert retry.status_code == 201 and retry.json()["task_id"] == task_id
        waiting = api.get(url, params=WORKSPACE).json()
        assert (
            waiting["task_id"],
            waiting["status"],
            waiting["code"],
            waiting["audit"],
        ) == (task_id, "queued", "audit_profile_unavailable", None)
        events = api.get(url + "/events", params=WORKSPACE).json()["events"]
        assert [e["event"] for e in events] == ["task.created"]
        new_body = request_body({**body["task"], "idempotency_key": "different-key"})
        assert api.post(API + "/tasks", json=new_body).status_code == 404
    with service(settings, token, *Scope) as api:
        with ThreadPoolExecutor(2) as pool:
            results = list(
                pool.map(lambda _: api.get(url, params=WORKSPACE).json(), range(2))
            )
        assert all(
            r["status"] == "succeeded" and r["audit"]["id"] == task_id for r in results
        )
        assert [
            e["event"]
            for e in api.get(url + "/events", params=WORKSPACE).json()["events"]
        ] == ["task.created", "task.succeeded"]
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT count(*) FROM security_audit_runs").fetchone() == (1,)

    restored_dir = tmp_path / "restored-audit"
    shutil.copytree(settings.database_path.parent, restored_dir)
    restored = settings.model_copy(
        update={"database_path": restored_dir / settings.database_path.name}
    )
    with service(restored, token, Scope.TASK) as api:
        recovered = api.get(url, params=WORKSPACE).json()
        assert recovered["status"] == "succeeded"
        assert recovered["audit"] == results[0]["audit"]


def test_artifact_only_after_restore(
    settings: Settings, migration_config: Config, tmp_path: Path
) -> None:
    command.upgrade(migration_config, "head")
    token = "ngw." + token_urlsafe(32)
    with service(settings, token, Scope.CREATE) as api:
        receipt = api.post(API + "/tasks", json=request_body(design())).json()
        validate_message("TaskReceipt", receipt)
    task_id = UUID(receipt["task_id"])
    url = API + "/artifacts/" + str(uuid5(task_id, "bom.json"))
    backup = tmp_path / "restore"
    shutil.copytree(settings.database_path.parent, backup)
    restored = settings.model_copy(
        update={"database_path": backup / settings.database_path.name}
    )
    rotated = "ngw." + token_urlsafe(32)
    for database in (settings, restored):
        with service(database, rotated, Scope.ARTIFACTS) as api:
            artifact = api.get(url, params=WORKSPACE)
            assert artifact.status_code == 200
            item = artifact.json()
            assert item["task_id"] == str(task_id)
            assert (
                hashlib.sha256(item["content"].encode()).hexdigest() == item["sha256"]
            )
    for changes in (
        {"integration_workspace": "other"},
        {"integration_caller": "other"},
    ):
        with service(restored, rotated, Scope.ARTIFACTS, **changes) as foreign:
            params = {"workspace_id": changes.get("integration_workspace", "lab")}
            for path in (url, API + "/artifacts/" + str(uuid4())):
                denied = foreign.get(path, params=params)
                assert (denied.status_code, denied.json()["error"]["code"]) == (
                    404,
                    "artifact_not_found",
                )


def test_legacy_artifact_index_backfill(
    settings: Settings, migration_config: Config
) -> None:
    command.upgrade(migration_config, "head")
    token = "ngw." + token_urlsafe(32)
    with service(settings, token, *Scope) as api:
        links = api.post(API + "/tasks", json=request_body(design())).json()[
            "artifacts"
        ]
    command.downgrade(migration_config, "0007_integration_workspace")
    with sqlite3.connect(settings.database_path) as db:
        db.execute(
            "DELETE FROM integration_artifacts WHERE id != ?",
            (links[0]["artifact_id"],),
        )
    command.upgrade(migration_config, "head")
    with service(settings, token, Scope.ARTIFACTS) as api:
        for link in links:
            item = api.get(link["href"], params=WORKSPACE).json()
            assert item["sha256"] == link["sha256"]


def test_admission_before_json(settings: Settings, client: TestClient) -> None:
    path = API + "/tasks"
    malformed = {"Content-Type": "application/json"}
    disabled = client.post(path, headers=malformed, content="{")
    assert (disabled.status_code, disabled.json()["error"]["code"]) == (
        404,
        "integration_disabled",
    )
    token = "ngw." + token_urlsafe(32)
    with service(settings, token, Scope.CREATE) as api:
        for _ in range(120):
            rejected = api.post(path, headers=malformed, content="{")
            assert (rejected.status_code, rejected.json()["error"]["code"]) == (
                422,
                "invalid_request",
            )
        limited = api.post(path, headers=malformed, content="{")
        assert (limited.status_code, limited.json()["error"]["code"]) == (
            429,
            "integration_rate_limited",
        )
        assert limited.headers["retry-after"] == "60"


def test_optimized_client_requires_server() -> None:
    script = Path(__file__).resolve().parents[1] / "deploy/workforce/client.py"
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        result = subprocess.run(
            [
                sys.executable,
                "-O",
                str(script),
                "--base",
                f"http://127.0.0.1:{port}",
                "--disabled",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode != 0 and "Unable to reach NetGuard" in result.stderr
    assert "Integration is disabled" not in result.stdout
