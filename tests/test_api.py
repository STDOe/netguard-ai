from uuid import UUID

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from httpx2 import Response
from pydantic import SecretStr, ValidationError
from sqlalchemy import text

from app.config import Settings
from app.main import create_app
from app.storage import sqlite_engine


def bearer(token: SecretStr) -> dict[str, str]:
    return {"Authorization": f"Bearer {token.get_secret_value()}"}


def assert_error(response: Response, status: int, code: str) -> None:
    assert response.status_code == status
    request_id = response.headers["X-Request-ID"]
    UUID(request_id)
    error = response.json()["error"]
    assert set(error) == {"code", "message", "request_id"}
    assert error["code"] == code
    assert error["request_id"] == request_id
    assert error["message"]


@pytest.mark.parametrize(
    ("variable", "value"), [("VIEWER_TOKEN", ""), ("DEMO_MODE", "false")]
)
def test_invalid_settings(
    settings: Settings, monkeypatch: pytest.MonkeyPatch, variable: str, value: str
) -> None:
    monkeypatch.setenv(f"NETGUARD_{variable}", value)
    with pytest.raises(ValidationError):
        Settings.model_validate({})


def test_duplicate_tokens(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    viewer_token = settings.viewer_token.get_secret_value()
    monkeypatch.setenv("NETGUARD_ADMIN_TOKEN", viewer_token)
    with pytest.raises(ValidationError) as error:
        Settings.model_validate({})
    assert viewer_token not in str(error.value)


def test_public_health(client: TestClient) -> None:
    for endpoint in ("live", "ready"):
        response = client.get(f"/api/v1/health/{endpoint}")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
        UUID(response.headers["X-Request-ID"])


def test_readiness_requires_migrations(
    settings: Settings, migration_config: Config
) -> None:
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/health/live").status_code == 200
        assert_error(client.get("/api/v1/health/ready"), 503, "unavailable")
        command.upgrade(migration_config, "head")
        assert client.get("/api/v1/health/ready").status_code == 200

        engine = sqlite_engine(settings.database_path)
        try:
            with engine.begin() as connection:
                connection.execute(text("DROP TABLE tasks"))
        finally:
            engine.dispose()
        assert_error(client.get("/api/v1/health/ready"), 503, "unavailable")


@pytest.mark.parametrize("endpoint", ["capabilities", "audit/events", "openapi.json"])
def test_protected_endpoints_require_authentication(
    client: TestClient, endpoint: str
) -> None:
    response = client.get(f"/api/v1/{endpoint}")
    assert_error(response, 401, "unauthenticated")
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_role_permissions_and_audit(client: TestClient, settings: Settings) -> None:
    viewer = bearer(settings.viewer_token)
    admin = bearer(settings.admin_token)
    capabilities = client.get("/api/v1/capabilities", headers=viewer)
    assert capabilities.status_code == 200
    assert capabilities.json() == {
        "api_version": "v1",
        "stage": "foundation",
        "demo_mode": True,
    }

    rejected = client.get(
        "/api/v1/capabilities", headers={"Authorization": "Bearer " + "x" * 43}
    )
    assert_error(rejected, 401, "unauthenticated")
    denied = client.get("/api/v1/audit/events", headers=viewer)
    assert_error(denied, 403, "forbidden")

    result = client.get("/api/v1/audit/events", headers=admin)
    assert result.status_code == 200
    events = result.json()["events"]
    assert [event["request_id"] for event in events] == [
        denied.headers["X-Request-ID"],
        rejected.headers["X-Request-ID"],
    ]
    assert [(event["actor"], event["outcome"]) for event in events] == [
        ("viewer", 403),
        (None, 401),
    ]
    assert all(event["occurred_at"].endswith("Z") for event in events)


def test_openapi_security_and_error_contract(
    client: TestClient, settings: Settings
) -> None:
    response = client.get("/api/v1/openapi.json", headers=bearer(settings.viewer_token))
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "security" not in paths["/api/v1/health/live"]["get"]
    assert paths["/api/v1/audit/events"]["get"]["security"] == [{"LocalBearer": []}]
    schema = paths["/api/v1/audit/events"]["get"]["responses"]["422"]["content"]
    assert schema["application/json"]["schema"]["$ref"].endswith("/ErrorResponse")
    assert not any(path.startswith("/api/v1/workforce") for path in paths)


def test_errors_redact_input(client: TestClient, settings: Settings) -> None:
    supplied = "private-value"
    response = client.get(
        "/api/v1/audit/events",
        params={"limit": supplied},
        headers=bearer(settings.admin_token),
    )
    assert_error(response, 422, "invalid_request")
    assert supplied not in response.text
    assert_error(client.get("/unknown"), 404, "not_found")
    method_not_allowed = client.post("/api/v1/health/live")
    assert_error(method_not_allowed, 405, "method_not_allowed")
    assert method_not_allowed.headers["Allow"] == "GET"


def test_unhandled_error_uses_public_contract(settings: Settings) -> None:
    application = create_app(settings)

    @application.get("/unexpected")
    def unexpected() -> None:
        raise RuntimeError("private diagnostic")

    with TestClient(application) as client:
        response = client.get("/unexpected")
        assert_error(response, 500, "internal_error")
        assert "private diagnostic" not in response.text
