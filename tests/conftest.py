from collections.abc import Iterator
from pathlib import Path
from secrets import token_urlsafe
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.network.driver import PutFirewallRule, PutStaticRoute
from app.network.models import FirewallRule, StaticRoute
from app.network.policy import Profile, load_profile

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "backend" / "alembic.ini"


@pytest.fixture
def settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv(
        "NETGUARD_DATABASE_PATH", str(tmp_path / "db" / "netguard.sqlite3")
    )
    monkeypatch.setenv("NETGUARD_VIEWER_TOKEN", token_urlsafe(32))
    monkeypatch.setenv("NETGUARD_ADMIN_TOKEN", token_urlsafe(32))
    monkeypatch.setenv("NETGUARD_DEMO_MODE", "true")
    return Settings.model_validate({})


@pytest.fixture
def migration_config(settings: Settings) -> Config:
    return Config(str(ALEMBIC_INI))


@pytest.fixture
def client(settings: Settings, migration_config: Config) -> Iterator[TestClient]:
    command.upgrade(migration_config, "head")
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def network_profile(settings: Settings) -> Profile:
    profile = load_profile(settings.profile_path)
    assert profile is not None
    return profile


@pytest.fixture
def firewall_change(network_profile: Profile) -> PutFirewallRule:
    flow = network_profile.policy.allowed_flows[0]
    rule = FirewallRule.model_validate(
        {**flow.model_dump(), "id": uuid4(), "action": "allow"}
    )
    return PutFirewallRule(kind="put_firewall_rule", rule=rule)


@pytest.fixture
def route_change(network_profile: Profile) -> PutStaticRoute:
    network = network_profile.network
    device = next(device for device in network.devices if device.name == "Infra spoke")
    subnet = next(
        subnet for subnet in network.subnets if subnet.name == "Cash / Payment"
    )
    route = StaticRoute.model_validate(
        {
            "id": uuid4(),
            "interface_id": device.interfaces[0].id,
            "destination": subnet.prefix,
            "next_hop": "10.10.0.1",
        }
    )
    return PutStaticRoute(kind="put_static_route", device_id=device.id, route=route)
