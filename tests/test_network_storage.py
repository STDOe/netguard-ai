from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from typing import cast
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session
from test_api import assert_error, bearer

from app.config import Settings
from app.main import create_app
from app.network.driver import (
    Change,
    MockNetworkDriver,
    PutFirewallRule,
    PutStaticRoute,
)
from app.network.errors import PolicyBlocked, RevisionConflict, UnsupportedOperation
from app.network.models import StaticRoute
from app.network.policy import Profile
from app.network.repository import NetworkRepository
from app.storage import AuditEvent, Task, sqlite_engine


@pytest.fixture
def network_engine(settings: Settings, migration_config: Config) -> Iterator[Engine]:
    command.upgrade(migration_config, "head")
    engine = sqlite_engine(settings.database_path)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def driver(network_engine: Engine, network_profile: Profile) -> MockNetworkDriver:
    instance = MockNetworkDriver(NetworkRepository(network_engine), network_profile)
    instance.initialize()
    return instance


def test_driver_state_survives_restart_and_restoration(
    driver: MockNetworkDriver,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    network_id = network_profile.network.id
    device_id = route_change.device_id
    assert driver.get_device_facts(network_id, device_id).name == "Infra spoke"
    assert len(driver.get_interfaces(network_id, device_id)) == 1
    assert driver.get_capabilities(network_id, device_id).routing_protocols == (
        "static",
    )
    assert driver.get_routes(network_id, device_id) == ()
    first = driver.get_snapshot(network_id)
    updated = driver.apply(network_id, 1, route_change, str(uuid4()), "admin")
    assert updated.revision == 2 and updated.sha256 != first.sha256

    second_engine = sqlite_engine(settings.database_path)
    try:
        restarted = MockNetworkDriver(NetworkRepository(second_engine), network_profile)
        restarted.initialize()
        assert restarted.get_routes(network_id, device_id) == (route_change.route,)
        assert restarted.get_snapshot(network_id) == updated
        restored = restarted.restore(network_id, 2, 1, str(uuid4()), "admin")
        assert restored.revision == 3 and restored.network == first.network
        assert restored.sha256 != first.sha256
        assert restarted.get_snapshot(network_id, 2) == updated
        assert restarted.get_firewall_rules(network_id) == ()
        assert restarted.get_routes(network_id, device_id) == ()
        assert [
            item.revision for item in restarted.repository.history(network_id, 25, None)
        ] == [3, 2, 1]
    finally:
        second_engine.dispose()


def test_driver_rejects_unmodelled_route_and_unsupported_input(
    driver: MockNetworkDriver,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    network_id = network_profile.network.id
    route = StaticRoute.model_validate(
        {
            **route_change.route.model_dump(mode="json"),
            "destination": "198.51.100.0/24",
        }
    )
    with pytest.raises(PolicyBlocked) as block:
        driver.apply(
            network_id,
            1,
            route_change.model_copy(update={"route": route}),
            str(uuid4()),
            "admin",
        )
    assert any(
        result.decision == "unknown" and result.rule_id == "routing.destination"
        for result in block.value.findings
    )
    with pytest.raises(UnsupportedOperation):
        driver.apply(network_id, 1, cast(Change, object()), str(uuid4()), "admin")
    assert driver.get_snapshot(network_id).revision == 1


def test_concurrent_compare_and_swap(
    driver: MockNetworkDriver,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
) -> None:
    repository = driver.repository
    network_id = network_profile.network.id
    candidate = network_profile.network.model_copy(
        update={"firewall_rules": (firewall_change.rule,)},
    )
    barrier = Barrier(2, timeout=5)

    def commit() -> int | None:
        barrier.wait()
        try:
            return repository.commit(
                candidate,
                1,
                "change",
                network_profile.policy.version,
                str(uuid4()),
                "admin",
            ).revision
        except RevisionConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        first, second = pool.submit(commit), pool.submit(commit)
        results = [first.result(timeout=10), second.result(timeout=10)]
    assert results.count(2) == 1 and results.count(None) == 1
    assert [item.revision for item in repository.history(network_id, 25, None)] == [
        2,
        1,
    ]


def test_failed_audit_insert_rolls_back_revision(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
) -> None:
    engine = sqlite_engine(settings.database_path)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TRIGGER reject_change_audit BEFORE INSERT ON audit_events "
                    "WHEN NEW.event_type = 'network.change' "
                    "BEGIN SELECT RAISE(ABORT, 'test failure'); END"
                )
            )
        network_id = network_profile.network.id
        admin = bearer(settings.admin_token)
        base = f"/api/v1/networks/{network_id}"
        response = client.post(
            f"{base}/changes",
            headers=admin,
            json={
                "expected_revision": 1,
                "change": firewall_change.model_dump(mode="json"),
            },
        )
        assert_error(response, 503, "unavailable")
        assert client.get(f"{base}/topology", headers=admin).json()["revision"] == 1
        assert [
            r["revision"] for r in client.get(f"{base}/revisions", headers=admin).json()
        ] == [1]
        with Session(engine) as session:
            assert (
                session.scalar(
                    select(AuditEvent).where(AuditEvent.event_type == "network.change")
                )
                is None
            )
    finally:
        engine.dispose()


def test_corrupt_snapshot_cannot_be_restored(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
) -> None:
    network_id = network_profile.network.id
    admin = bearer(settings.admin_token)
    base = f"/api/v1/networks/{network_id}"
    assert (
        client.post(
            f"{base}/changes",
            headers=admin,
            json={
                "expected_revision": 1,
                "change": firewall_change.model_dump(mode="json"),
            },
        ).status_code
        == 200
    )
    engine = sqlite_engine(settings.database_path)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "UPDATE network_revisions SET payload='{}' "
                    "WHERE network_id=:id AND revision=1"
                ),
                {"id": str(network_id)},
            )
        response = client.post(
            f"{base}/restore",
            headers=admin,
            json={
                "expected_revision": 2,
                "snapshot_revision": 1,
            },
        )
        assert_error(response, 409, "corrupt_snapshot")
        assert client.get(f"{base}/topology", headers=admin).json()["revision"] == 2
    finally:
        engine.dispose()


def test_existing_foundation_database_upgrade(
    settings: Settings,
    migration_config: Config,
    network_profile: Profile,
) -> None:
    command.upgrade(migration_config, "0001_foundation")
    engine = sqlite_engine(settings.database_path)
    task, audit = str(uuid4()), str(uuid4())
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO tasks (id, kind, status) "
                    "VALUES (:id, 'audit', 'queued')"
                ),
                {"id": task},
            )
            connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(id, occurred_at_us, request_id, outcome) "
                    "VALUES (:id, 0, :id, 401)"
                ),
                {"id": audit},
            )
        command.upgrade(migration_config, "head")
        with TestClient(create_app(settings)) as upgraded:
            assert upgraded.get("/api/v1/health/ready").status_code == 200
            networks = upgraded.get(
                "/api/v1/networks", headers=bearer(settings.viewer_token)
            )
            assert networks.json()[0]["id"] == str(network_profile.network.id)
        with Session(engine) as session:
            old = session.get(AuditEvent, audit)
            assert old is not None and old.outcome == 401 and old.event_type is None
            assert session.get(Task, task) is not None

        command.downgrade(migration_config, "0001_foundation")
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT count(*) FROM tasks")) == 1
            assert (
                connection.scalar(
                    text("SELECT count(*) FROM audit_events WHERE id=:id"),
                    {
                        "id": audit,
                    },
                )
                == 1
            )
    finally:
        engine.dispose()
