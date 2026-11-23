from collections.abc import Iterator
from pathlib import Path
from secrets import token_urlsafe

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

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
