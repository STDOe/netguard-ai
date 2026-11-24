import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Event
from typing import Any
from unittest.mock import patch

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from langgraph.checkpoint.sqlite import SqliteSaver
from pydantic import ValidationError
from sqlalchemy.orm import Session
from test_api import bearer
from test_workflows import brownfield, decision, greenfield, requirements

from app.config import Settings
from app.main import create_app
from app.network.driver import PutStaticRoute
from app.network.policy import Profile
from app.security import ROLE_PERMISSIONS, Permission, Role
from app.storage import sqlite_engine
from app.workflows.greenfield import OfflineSources
from app.workflows.models import Requirements
from app.workflows.store import WorkflowRecord, WorkflowStore


def sidecar(settings: Settings) -> Path:
    return Path(f"{settings.database_path}.checkpoints")


@pytest.mark.parametrize("damage", [False, True])
@pytest.mark.parametrize("with_writes", [False, True])
def test_first_input_checkpoint(
    client: TestClient, settings: Settings, damage: bool, with_writes: bool
) -> None:
    original = SqliteSaver.put

    def stop(
        saver: SqliteSaver, config: Any, checkpoint: Any, metadata: Any, versions: Any
    ) -> Any:
        assert metadata["source"] == "input"
        if damage:
            checkpoint["channel_values"]["__start__"]["actor"] = "wrong-owner"
        original(saver, config, checkpoint, metadata, versions)
        raise RuntimeError("stop immediately after first durable checkpoint")

    owner = bearer(settings.viewer_token)
    payload = greenfield("bootstrap-journal", {})
    original_writes = SqliteSaver.put_writes
    with (
        patch.object(SqliteSaver, "put", stop),
        patch.object(
            SqliteSaver,
            "put_writes",
            original_writes if with_writes else lambda *a, **kw: None,
        ),
    ):
        assert (
            client.post("/api/v1/tasks", headers=owner, json=payload).status_code == 500
        )
    engine = sqlite_engine(settings.database_path)
    with Session(engine) as session:
        row = session.query(WorkflowRecord).one()
        thread_id, task_id = row.thread_id, row.task_id
    engine.dispose()
    with TestClient(create_app(settings)) as restarted:
        task = restarted.get(f"/api/v1/tasks/{task_id}", headers=owner).json()
        assert task["thread_id"] == thread_id
        assert task["status"] == ("recovery_required" if damage else "awaiting_input")


@pytest.mark.parametrize("failure", ["missing", "stale", "corrupt", "receipt"])
def test_completed_checkpoint_disagreement(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
    failure: str,
) -> None:
    owner = bearer(settings.admin_token)
    task = client.post(
        "/api/v1/tasks", headers=owner, json=brownfield(network_profile, route_change)
    ).json()
    with closing(sqlite3.connect(sidecar(settings))) as db:
        anchor = db.execute("SELECT max(checkpoint_id) FROM checkpoints").fetchone()[0]
    endpoint, body = decision(task)
    completed = client.post(endpoint, headers=owner, json=body).json()
    assert completed["status"] == "succeeded"
    if failure == "receipt":
        with closing(sqlite3.connect(settings.database_path)) as db, db:
            db.execute(
                "UPDATE network_revisions SET execution_key=NULL WHERE revision=2"
            )
    else:
        with closing(sqlite3.connect(sidecar(settings))) as db, db:
            if failure == "missing":
                db.execute("DELETE FROM checkpoints")
                db.execute("DELETE FROM writes")
            elif failure == "stale":
                db.execute("DELETE FROM checkpoints WHERE checkpoint_id > ?", (anchor,))
                db.execute("DELETE FROM writes WHERE checkpoint_id >= ?", (anchor,))
            else:
                db.execute("UPDATE checkpoints SET checkpoint=x'c1'")
    with TestClient(create_app(settings)) as restarted:
        for _ in range(2):
            result = restarted.get(f"/api/v1/tasks/{task['id']}", headers=owner).json()
            assert result["status"] == "recovery_required"
            assert result["approval"] == completed["approval"]
            assert result["result"] == completed["result"]
            assert result["plan"] is None
        topology = restarted.get(
            f"/api/v1/networks/{network_profile.network.id}/topology", headers=owner
        )
        assert topology.json()["revision"] == 2


@pytest.mark.parametrize("model", ["ollama/mock", "ollama_chat/mock", "openai/mock"])
@pytest.mark.parametrize(
    "base,allowed",
    [
        ("http://model.example.org", False),
        ("http://192.0.2.1", False),
        ("http://127.0.0.1:4100", True),
        ("http://[::1]:4100", True),
        ("https://model.example.org", True),
    ],
)
def test_provider_transport(
    settings: Settings, model: str, base: str, allowed: bool
) -> None:
    values = {
        **settings.model_dump(),
        "llm_model": model,
        "llm_api_base": base,
        "llm_api_key": "synthetic",
    }
    if allowed:
        assert Settings.model_validate(values).llm_api_base == base
    else:
        with pytest.raises(ValidationError):
            Settings.model_validate(values)


def test_cancel_pending_approval_and_recheck_write_permission(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    owner = bearer(settings.admin_token)
    task = client.post(
        "/api/v1/tasks", headers=owner, json=brownfield(network_profile, route_change)
    ).json()
    endpoint, body = decision(task)
    persist = WorkflowStore.signal

    def stop(*args: Any, **kwargs: Any) -> None:
        persist(*args, **kwargs)
        raise RuntimeError("decision persisted")

    with patch.object(WorkflowStore, "signal", stop):
        assert client.post(endpoint, headers=owner, json=body).status_code == 500
    root = f"/api/v1/tasks/{task['id']}"
    with TestClient(create_app(settings)) as restarted:
        assert restarted.post(root + "/cancel", headers=owner).status_code == 409
        topology = f"/api/v1/networks/{network_profile.network.id}/topology"
        assert restarted.get(topology, headers=owner).json()["revision"] == 1
        with patch.dict(
            ROLE_PERMISSIONS,
            {Role.ADMIN: ROLE_PERMISSIONS[Role.ADMIN] - {Permission.CHANGE_NETWORK}},
        ):
            assert restarted.get(root, headers=owner).json()["status"] == "blocked"
        assert restarted.get(topology, headers=owner).json()["revision"] == 1


def test_interview_redelivery(client: TestClient, settings: Settings) -> None:
    owner = bearer(settings.viewer_token)
    task = client.post(
        "/api/v1/tasks", headers=owner, json=greenfield("repeat-answer", {})
    ).json()
    url = f"/api/v1/tasks/{task['id']}/input"
    for _ in range(6):
        assert (
            client.post(url, headers=owner, json={"sites": 2}).json()["status"]
            == "awaiting_input"
        )
    assert (
        client.post(url, headers=owner, json=requirements()).json()["status"]
        == "succeeded"
    )


def test_blocked_source_isolated(
    client: TestClient, settings: Settings, tmp_path: Path
) -> None:
    fifo = tmp_path / "catalog"
    os.mkfifo(fifo)
    assert OfflineSources(fifo).candidates(Requirements()) == ()
    entered, release = Event(), Event()
    owner = bearer(settings.viewer_token)

    def pause(_source: OfflineSources, _req: Requirements) -> tuple[()]:
        entered.set()
        assert release.wait(10)
        return ()

    with (
        patch.object(OfflineSources, "candidates", pause),
        ThreadPoolExecutor() as pool,
    ):
        slow = pool.submit(
            client.post,
            "/api/v1/tasks",
            headers=owner,
            json=greenfield("slow-catalog", requirements()),
        )
        try:
            assert entered.wait(3)
            task = client.post(
                "/api/v1/tasks", headers=owner, json=greenfield("other-task", {})
            ).json()
            assert (
                client.post(f"/api/v1/tasks/{task['id']}/cancel", headers=owner).json()[
                    "status"
                ]
                == "cancelled"
            )
        finally:
            release.set()
        assert slow.result().json()["status"] == "succeeded"


@pytest.mark.parametrize("availability", ["single", "redundant"])
def test_ha_exports(client: TestClient, settings: Settings, availability: str) -> None:
    task = client.post(
        "/api/v1/tasks",
        headers=bearer(settings.viewer_token),
        json=greenfield("ha-design", {**requirements(), "availability": availability}),
    ).json()
    assert task["status"] == "succeeded"
    for artifact in task["artifacts"]:
        assert ("HA not modeled" in artifact["content"]) == (
            availability == "redundant"
        ), artifact["name"]


def test_checkpoint_readiness(client: TestClient, settings: Settings) -> None:
    path = sidecar(settings)
    path.write_bytes(b"unreadable checkpoint sqlite file")
    assert client.get("/api/v1/health/ready").status_code == 503
    assert client.get("/api/v1/health/live").status_code == 200
    path.unlink()
    assert client.get("/api/v1/health/ready").status_code == 200
    with closing(sqlite3.connect(path)) as db:
        assert db.execute("SELECT count(*) FROM checkpoints").fetchone() == (0,)


def test_legacy_interview_checkpoint_after_migration(
    client: TestClient, settings: Settings, migration_config: Config
) -> None:
    owner = bearer(settings.viewer_token)
    task = client.post(
        "/api/v1/tasks", headers=owner, json=greenfield("legacy-input", {})
    ).json()
    root = f"/api/v1/tasks/{task['id']}"
    with closing(sqlite3.connect(sidecar(settings))) as db:
        original = db.execute("SELECT max(checkpoint_id) FROM checkpoints").fetchone()[
            0
        ]
    assert (
        client.post(root + "/input", headers=owner, json={"sites": 2}).json()["status"]
        == "awaiting_input"
    )
    command.downgrade(migration_config, "0003_agent_workflows")
    command.upgrade(migration_config, "head")
    with TestClient(create_app(settings)) as upgraded:
        intact = upgraded.get(root, headers=owner).json()
        assert intact["status"] == "awaiting_input" and "sites" not in intact["missing"]

    # Both projections say awaiting_input. Only the persisted signal distinguishes them.
    command.downgrade(migration_config, "0003_agent_workflows")
    command.upgrade(migration_config, "head")
    with closing(sqlite3.connect(sidecar(settings))) as db, db:
        db.execute("DELETE FROM checkpoints WHERE checkpoint_id > ?", (original,))
        db.execute("DELETE FROM writes WHERE checkpoint_id >= ?", (original,))
    with TestClient(create_app(settings)) as restarted:
        assert (
            restarted.get(root, headers=owner).json()["status"] == "recovery_required"
        )
