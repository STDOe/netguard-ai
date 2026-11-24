import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from pydantic import SecretStr
from test_api import bearer
from test_workflows import brownfield, greenfield, requirements

from app.config import Scope, Settings
from app.integration.api import BODY_LIMIT
from app.integration.models import (
    ApprovalView,
    ArtifactContent,
    Capabilities,
    Events,
    TaskResponse,
)
from app.main import create_app
from app.network.driver import PutStaticRoute
from app.network.policy import Profile

API = "/api/v1/integration"
WORKSPACE = {"workspace_id": "lab"}


CONTRACTS = Path(__file__).resolve().parents[1] / "docs" / "contracts"


def validate_message(name: str, body: object) -> None:
    schema = json.loads((CONTRACTS / "integration-v1.schema.json").read_text())
    schema["$ref"] = f"#/$defs/{name}"
    Draft202012Validator(schema).validate(body)


def provision(settings: Settings, token: str, **changes: object) -> Settings:
    return settings.model_copy(
        update={
            "integration_enabled": True,
            "integration_token_sha256": SecretStr(
                hashlib.sha256(token.encode()).hexdigest()
            ),
            "integration_expires_at": datetime.now(UTC) + timedelta(hours=1),
            "integration_scopes": frozenset(Scope),
            **changes,
        }
    )


def headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def request_body(task: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": "1.0", "workspace_id": "lab", "task": task}


def design() -> dict[str, Any]:
    return greenfield("integration-design", requirements())


def test_credentials_and_release_limits(settings: Settings, client: TestClient) -> None:
    token = "ngw." + token_urlsafe(32)
    assert (
        client.get(API + "/capabilities", headers=headers(token)).json()["error"][
            "code"
        ]
        == "integration_disabled"
    )
    enabled = provision(settings, token)
    cases = (
        (enabled, None, 401),
        (enabled, token, 200),
        (enabled, settings.admin_token.get_secret_value(), 401),
        (provision(settings, "ngw." + token_urlsafe(32)), token, 401),
        (
            provision(settings, token, integration_expires_at=datetime.now(UTC)),
            token,
            401,
        ),
        (
            provision(settings, token, integration_scopes=frozenset({Scope.TASK})),
            token,
            403,
        ),
    )
    for configuration, supplied, status in cases:
        with TestClient(create_app(configuration), client=("127.0.0.1", 40000)) as app:
            assert (
                app.get(
                    API + "/capabilities", headers=headers(supplied) if supplied else {}
                ).status_code
                == status
            )
    with TestClient(create_app(enabled), client=("192.0.2.1", 40000)) as app:
        path = API + "/capabilities"
        assert (
            app.get(path, headers=headers(token)).json()["error"]["code"]
            == "tls_required"
        )
        assert (
            app.get("https://testserver" + path, headers=headers(token)).status_code
            == 200
        )
        assert (
            app.get(
                path, headers={**headers(token), "X-Forwarded-Proto": "https"}
            ).status_code
            == 403
        )
    with TestClient(create_app(enabled), client=("127.0.0.1", 40000)) as app:
        app.headers.update(headers(token))
        assert app.get("/api/v1/networks").status_code == 401
        assert app.post("/session", json={"token": token}).status_code == 403
        assert (
            app.post(API + "/tasks", content=b"x" * (BODY_LIMIT + 1)).status_code == 413
        )
        bad = request_body({"kind": "raw_cli", "idempotency_key": "unsupported"})
        assert (
            app.post(API + "/tasks", json=bad).json()["error"]["code"]
            == "invalid_request"
        )
        assert (
            app.post(
                API + "/tasks", json={**request_body(design()), "workspace_id": "other"}
            ).status_code
            == 403
        )
        assert (
            app.get(API + "/tasks/" + str(uuid4()), params=WORKSPACE).status_code == 404
        )
        responses = [app.get(API + "/capabilities") for _ in range(121)]
        assert 200 in {item.status_code for item in responses}
        limited = responses[-1]
        assert limited.status_code == 429 and limited.headers["retry-after"] == "60"
    log = client.get(
        "/api/v1/audit/events",
        params={"include_network": True},
        headers=bearer(settings.admin_token),
    ).text
    assert "integration.authorization" in log and token not in log


def test_integration_contract_scope_and_restart(
    settings: Settings, client: TestClient
) -> None:
    token = "ngw." + token_urlsafe(32)
    env = provision(settings, token)
    with TestClient(create_app(env), client=("127.0.0.1", 40000)) as service:
        service.headers.update(headers(token))
        capabilities = service.get(API + "/capabilities")
        assert (
            Capabilities.model_validate_json(
                capabilities.content
            ).external_compatibility
            == "unverified"
        )
        validate_message("Capabilities", capabilities.json())
        spec = service.get(API + "/openapi.json").json()
        assert spec == json.loads(
            (CONTRACTS / "integration-v1.openapi.json").read_text()
        )
        assert spec["openapi"].startswith("3.1")
        assert spec["paths"][API + "/tasks"]["post"]["security"] == [
            {"IntegrationBearer": []}
        ]
        assert "Submission" in spec["components"]["schemas"]
        body = request_body(design())
        validate_message("Submission", body)
        created = service.post(API + "/tasks", json=body)
        assert created.status_code == 201, created.text
        validate_message("TaskResponse", created.json())
        task = TaskResponse.model_validate_json(created.content)
        assert task.status == "succeeded"
        assert service.post(API + "/tasks", json=body).json()["task_id"] == str(
            task.task_id
        )
        body["task"]["requirements"]["sites"] = 3
        assert service.post(API + "/tasks", json=body).status_code == 409
        first = task.artifacts[0]
        data = service.get(first.href, params=WORKSPACE)
        validate_message("ArtifactContent", data.json())
        artifact = ArtifactContent.model_validate_json(data.content)
        assert artifact.task_id == task.task_id
        assert hashlib.sha256(artifact.content.encode()).hexdigest() == first.sha256
        assert len(artifact.content.encode()) == first.size_bytes
        assert (
            service.get(first.href, params={"workspace_id": "other"}).status_code == 403
        )
        local_task = client.post(
            "/api/v1/tasks", headers=bearer(settings.viewer_token), json=design()
        ).json()["id"]
        assert (
            service.get(API + f"/tasks/{local_task}", params=WORKSPACE).status_code
            == 404
        )
        url = API + f"/tasks/{task.task_id}/events"
        cursor = None
        seen = []
        while True:
            response = service.get(
                url,
                params={
                    **WORKSPACE,
                    "limit": 2,
                    **({"cursor": cursor} if cursor else {}),
                },
            )
            validate_message("Events", response.json())
            page = Events.model_validate_json(response.content)
            if not page.events:
                break
            seen.extend(page.events)
            cursor = page.next_cursor
        assert seen[0].event == "task.created"
        assert [item.sequence for item in seen] == list(range(1, len(seen) + 1))
        assert len({item.event_id for item in seen}) == len(seen)
        assert all(event.correlation_id == task.correlation_id for event in seen)
        assert (
            service.get(url, params={**WORKSPACE, "cursor": f"{uuid4()}.1"}).status_code
            == 422
        )
    with TestClient(create_app(env), client=("127.0.0.1", 40000)) as restarted:
        restarted.headers.update(headers(token))
        assert restarted.get(
            first.href, params=WORKSPACE
        ).json() == artifact.model_dump(mode="json")
        assert restarted.get(url, params=WORKSPACE).json()["events"][0][
            "event_id"
        ] == str(seen[0].event_id)
    foreign = provision(settings, token, integration_workspace="other")
    with TestClient(create_app(foreign), client=("127.0.0.1", 40000)) as app:
        assert (
            app.get(
                first.href, headers=headers(token), params={"workspace_id": "other"}
            ).status_code
            == 404
        )


def test_service_proposes_and_human_decides_once(
    settings: Settings,
    client: TestClient,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    token = "ngw." + token_urlsafe(32)
    env = provision(settings, token)
    admin = bearer(settings.admin_token)
    network = f"/api/v1/networks/{network_profile.network.id}"
    with TestClient(create_app(env), client=("127.0.0.1", 40000)) as service:
        service.headers.update(headers(token))
        body = request_body(brownfield(network_profile, route_change))
        result = service.post(API + "/tasks", json=body)
        assert result.status_code == 201, result.text
        task = TaskResponse.model_validate_json(result.content)
        assert task.status == "awaiting_approval" and task.approval_id and task.plan
        url = API + f"/approvals/{task.approval_id}"
        approval = ApprovalView.model_validate_json(
            service.get(url, params=WORKSPACE).content
        )
        assert approval.status == "pending"
        decision = {"plan_hash": approval.plan_hash, "decision": "approve"}
        local = f"/api/v1/tasks/{task.task_id}/plan/{approval.plan_id}/decision"
        assert (
            service.post(url + "/decision", params=WORKSPACE, json=decision).json()[
                "error"
            ]["code"]
            == "not_supported"
        )
        assert service.post(local, json=decision).status_code == 401
        assert client.get(network + "/topology", headers=admin).json()["revision"] == 1
        assert client.get("/api/v1/approvals", headers=admin).json()[0]["id"] == str(
            task.task_id
        )
        assert (
            client.post(
                local, headers=admin, json={**decision, "plan_hash": "0" * 64}
            ).status_code
            == 409
        )
        decided = client.post(local, headers=admin, json=decision)
        assert decided.status_code == 200, decided.text
        assert decided.json()["status"] == "succeeded"
        assert decided.json()["approval"]["actor"] == "admin"
        assert client.post(local, headers=admin, json=decision).json() == decided.json()
        assert service.post(API + "/tasks", json=body).json()["task_id"] == str(
            task.task_id
        )
        assert (
            service.post(
                API + f"/tasks/{task.task_id}/cancel", params=WORKSPACE
            ).status_code
            == 409
        )
        assert client.get(network + "/topology", headers=admin).json()["revision"] == 2
        assert service.get(url, params=WORKSPACE).json()["status"] == "approve"
        forbidden = request_body(
            {
                "kind": "brownfield",
                "idempotency_key": "denied-protocol",
                "network_id": str(network_profile.network.id),
                "goal": {
                    "kind": "set_routing_protocols",
                    "device_id": str(route_change.device_id),
                    "protocols": ["ospf"],
                },
            }
        )
        assert (
            service.post(API + "/tasks", json=forbidden).json()["status"] == "blocked"
        )


def test_concurrent_audit_idempotency(
    settings: Settings,
    client: TestClient,
    network_profile: Profile,
) -> None:
    token = "ngw." + token_urlsafe(32)
    with TestClient(
        create_app(provision(settings, token)), client=("127.0.0.1", 40000)
    ) as service:
        service.headers.update(headers(token))
        data = request_body(
            {
                "kind": "audit",
                "network_id": str(network_profile.network.id),
                "idempotency_key": "audit-mvp-01",
            }
        )
        with ThreadPoolExecutor(4) as pool:
            replies = list(
                pool.map(lambda _: service.post(API + "/tasks", json=data), range(4))
            )
        assert all(r.status_code == 201 for r in replies), [r.text for r in replies]
        ids = {r.json()["task_id"] for r in replies}
        assert len(ids) == 1 and all(
            r.json()["audit"]["score"]["value"] == 95 for r in replies
        )
        report_url = f"/api/v1/networks/{network_profile.network.id}/audits"
        reports = client.get(report_url, headers=bearer(settings.admin_token)).json()
        assert len(reports) == 1 and reports[0]["id"] in ids
        data["task"]["kind"] = "greenfield"
        data["task"].pop("network_id")
        data["task"]["requirements"] = {}
        assert service.post(API + "/tasks", json=data).status_code == 409
