import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.orm import Session
from test_api import bearer
from test_workflows import brownfield, decision

from app.config import Settings
from app.dashboard.audit import Audits, Check, score
from app.dashboard.honeypot import RATE
from app.main import create_app
from app.network.driver import MockNetworkDriver, PutStaticRoute
from app.network.models import FirewallRule
from app.network.policy import Profile
from app.network.repository import NetworkRepository, RevisionRecord, serialize
from app.storage import sqlite_engine


def login(
    client: TestClient, secret: SecretStr, origin: str = "http://testserver"
) -> str:
    response = client.post(
        "/session",
        headers={"Origin": origin, "X-NetGuard-Login": "1"},
        json={"token": secret.get_secret_value()},
    )
    assert response.status_code == 204
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    page = client.get("/")
    assert page.status_code == 200
    assert secret.get_secret_value() not in page.text
    return page.text.split('name="csrf-token" content="', 1)[1].split('"', 1)[0]


def test_session_rbac_csrf_and_mock_apply(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert "Access token" in client.get("/dashboard/audit").text
    cross_origin = client.post(
        "/session",
        headers={"Origin": "https://other.example", "X-NetGuard-Login": "1"},
        json={"token": settings.admin_token.get_secret_value()},
    )
    assert cross_origin.status_code == 403
    viewer_csrf = login(client, settings.viewer_token)
    for screen in (
        "overview",
        "topology",
        "workspace",
        "greenfield",
        "approvals",
        "audit",
        "honeypot",
        "activity",
    ):
        response = client.get(f"/dashboard/{screen}")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "DEMO MODE" in response.text
        assert settings.viewer_token.get_secret_value() not in response.text
        assert settings.admin_token.get_secret_value() not in response.text
    payload = brownfield(network_profile, route_change)
    assert client.get("/api/v1/approvals").status_code == 403
    assert (
        client.get(
            "/api/v1/networks", headers={"Sec-Fetch-Site": "same-site"}
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/tasks", json=payload, headers={"X-CSRF-Token": viewer_csrf}
        ).status_code
        == 403
    )
    assert (
        client.post("/api/v1/tasks", json={**payload, "dry_run": True}).status_code
        == 403
    )
    auth = {"X-CSRF-Token": login(client, settings.admin_token)}
    created = client.post("/api/v1/tasks", headers=auth, json=payload).json()
    path, body = decision(created)
    assert created["status"] == "awaiting_approval"
    assert client.post(path, json=body).status_code == 403
    with TestClient(create_app(settings)) as viewer:
        csrf = login(viewer, settings.viewer_token)
        assert (
            viewer.post(path, json=body, headers={"X-CSRF-Token": csrf}).status_code
            == 403
        )
    result = client.post(path, json=body, headers=auth).json()
    assert result["status"] == "succeeded"
    assert result["result"]["snapshot_revision"] == 2
    assert client.delete("/session", headers=auth).status_code == 204
    assert client.get("/api/v1/tasks").status_code == 401
    logs = capsys.readouterr()
    assert settings.admin_token.get_secret_value() not in logs.err + logs.out
    assert settings.viewer_token.get_secret_value() not in logs.err + logs.out


def test_https_cookie_and_token_rotation(
    settings: Settings, client: TestClient
) -> None:
    with TestClient(create_app(settings), base_url="https://testserver") as secure:
        login(secure, settings.admin_token, "https://testserver")
        cookie = next(
            entry for entry in secure.cookies.jar if entry.name == "netguard_session"
        )
        assert cookie.secure
        with TestClient(
            create_app(
                settings.model_copy(update={"admin_token": SecretStr("r" * 43)})
            ),
            base_url="https://testserver",
            cookies=secure.cookies,
        ) as restarted:
            assert restarted.get("/api/v1/approvals").status_code == 401


def test_saved_audit_and_policy_denial(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    route_change: PutStaticRoute,
) -> None:
    admin, viewer = bearer(settings.admin_token), bearer(settings.viewer_token)
    root = f"/api/v1/networks/{network_profile.network.id}"
    assert client.get(root + "/audits").status_code == 401
    assert client.post(root + "/audits", headers=viewer).status_code == 403
    report = client.post(root + "/audits", headers=admin).json()
    checks = {item["check_id"]: item for item in report["findings"]}
    assert checks["dmz_cash"]["status"] == checks["default_deny"]["status"] == "pass"
    assert checks["dataplane"]["status"] == "unknown"
    assert report["score"]["value"] < 100
    assert report["revision"] == 1
    assert all(
        item["network_revision"] == 1 and item["scope"] == report["network_id"]
        for item in report["findings"]
    )

    flow = network_profile.policy.blocked_pairs[0]
    network = network_profile.network
    vlans = {v.id: v.zone_id for v in network.vlans}
    source, target = (
        next(
            s.prefix
            for s in network.subnets
            if s.vlan_id is not None and vlans.get(s.vlan_id) == zone
        )
        for zone in (flow.source, flow.destination)
    )
    rule = FirewallRule(
        id=uuid4(),
        action="allow",
        source_zone=flow.source,
        destination_zone=flow.destination,
        source=source,
        destination=target,
        protocol="tcp",
        destination_port=443,
    )
    change = {"kind": "put_firewall_rule", "rule": rule.model_dump(mode="json")}
    denied = client.post(
        root + "/changes",
        headers=admin,
        json={"expected_revision": 1, "change": change},
    )
    assert denied.status_code == 403

    created = client.post(
        "/api/v1/tasks", headers=admin, json=brownfield(network_profile, route_change)
    ).json()
    path, body = decision(created)
    assert client.post(path, headers=admin, json=body).json()["status"] == "succeeded"
    report_path = f"{root}/audits/{report['id']}"
    with TestClient(create_app(settings)) as fresh:
        assert fresh.get(report_path, headers=viewer).json() == {
            **report,
            "current": False,
        }
        assert len(fresh.get(root + "/audits", headers=viewer).json()) == 1

    # Evaluate a deliberately inconsistent persisted mock revision without
    # granting application writes around the existing policy gate.
    engine = sqlite_engine(settings.database_path)
    tx = serialize(
        network.model_copy(update={"firewall_rules": (rule,)}),
        2,
        "change",
        network_profile.policy.version,
    )
    with Session(engine) as db, db.begin():
        stored = db.get_one(RevisionRecord, (str(network.id), 2))
        stored.payload, stored.sha256 = tx.payload, tx.sha256
    audits = Audits(
        engine, MockNetworkDriver(NetworkRepository(engine), network_profile)
    )
    _, findings = audits.evaluate(network.id, 2)
    assert {check.check_id: check.status for check in findings}["dmz_cash"] == "fail"
    engine.dispose()


def test_score_golden_values() -> None:
    base = Check(
        check_id="golden",
        status="pass",
        severity="critical",
        reason="",
        evidence=(),
        scope=uuid4(),
        network_revision=1,
        policy_version="1",
        timestamp=datetime.now(UTC),
    )
    unknown = base.model_copy(update={"status": "unknown", "severity": "medium"})
    excluded = base.model_copy(update={"status": "not_applicable"})
    assert score([base, unknown, excluded]).model_dump() == {
        "version": "1.0",
        "value": 76,
        "coverage": 76,
    }
    assert score([unknown, excluded]).value is None
    assert score([base, base.model_copy(update={"status": "fail"})]).value == 50


def test_honeypot_signed_ingestion_persistence_and_no_apply(
    settings: Settings,
    client: TestClient,
    network_profile: Profile,
    capsys: pytest.CaptureFixture[str],
) -> None:
    webhook = "/api/v1/webhooks/honeypot"
    events = "/api/v1/honeypot/events"
    secret = "h" * 43
    env = settings.model_copy(update={"honeypot_secret": SecretStr(secret)})
    assert client.post(webhook).status_code == 503
    assert client.get(events).status_code == 401
    root = f"/api/v1/networks/{network_profile.network.id}"
    now = int(time.time())
    event = {
        "event_id": str(uuid4()),
        "occurred_at": datetime.now(UTC).isoformat(),
        "source_ip": "192.0.2.8",
        "destination_ip": "10.30.99.2",
        "destination_port": 8080,
        "service": "http",
        "sensor": "fixture",
        "demo": True,
    }

    def signed(body: bytes, stamp: int = now, key: str = secret) -> dict[str, str]:
        return {
            "X-NetGuard-Timestamp": str(stamp),
            "X-NetGuard-Signature": "sha256="
            + hmac.digest(
                key.encode(), str(stamp).encode() + b"." + body, hashlib.sha256
            ).hex(),
        }

    def send(app: TestClient, item: dict[str, object], **kwargs: str | int) -> int:
        body = json.dumps(item).encode()
        stamp = int(kwargs.get("stamp", now))
        key = str(kwargs.get("key", secret))
        return app.post(
            webhook, content=body, headers=signed(body, stamp, key)
        ).status_code

    with TestClient(create_app(env)) as sensor:
        assert send(sensor, event, key="bad") == 401
        assert send(sensor, event, stamp=now - 301) == 401
        assert send(sensor, {**event, "sensor": "<em>data</em>"}) == 422
        assert send(sensor, {**event, "destination_port": "8080"}) == 422
        assert send(sensor, {**event, "occurred_at": "2000-01-01T00:00:00Z"}) == 422
        large = b"0" * 4097
        assert (
            sensor.post(webhook, content=large, headers=signed(large)).status_code
            == 413
        )
        assert send(sensor, event) == send(sensor, event) == 200
        assert send(sensor, {**event, "source_ip": "192.0.2.22"}) == 409
        for _ in range(RATE - 1):
            assert (
                send(
                    sensor,
                    {**event, "event_id": str(uuid4()), "destination_ip": "192.0.2.91"},
                )
                == 200
            )
        assert send(sensor, {**event, "event_id": str(uuid4())}) == 429
    with TestClient(create_app(env)) as fresh:
        headers = bearer(settings.viewer_token)
        saved = fresh.get(events, headers=headers).json()
        assert len(saved) == RATE
        initial = next(item for item in saved if item["event_id"] == event["event_id"])
        assert initial["correlation"] == "inventory_match"
        assert any(item["correlation"] == "unverified" for item in saved)
        topology = fresh.get(root + "/topology", headers=headers).json()
        assert topology["revision"] == 1 and topology["network"]["firewall_rules"] == []
    logs = capsys.readouterr()
    assert secret not in logs.err + logs.out
