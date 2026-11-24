from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from test_api import bearer

from app.config import Settings
from app.dashboard.audit import AuditFinding, AuditRun, Audits
from app.network.driver import MockNetworkDriver
from app.network.policy import Profile
from app.network.repository import NetworkRepository, RevisionRecord
from app.storage import sqlite_engine


@pytest.mark.parametrize("rule", ["baseline", "traffic.model", "traffic.routing"])
def test_policy_reachability_coverage(
    client: TestClient, settings: Settings, network_profile: Profile, rule: str
) -> None:
    data = network_profile.model_dump(mode="json")
    data["network"]["id"] = str(uuid4())
    if rule == "traffic.model":
        data["network"]["traffic_model"] = "unknown"
    if rule == "traffic.routing":
        device = data["network"]["devices"][0]
        device["routing_protocols"] = ["ospf"]
        device["capabilities"]["routing_protocols"].append("ospf")
        data["policy"]["allowed_protocols"].append("ospf")
    profile = Profile.model_validate(data)
    network_id = profile.network.id
    engine = sqlite_engine(settings.database_path)
    try:
        repo = NetworkRepository(engine)
        repo.seed(profile.network, profile.policy.version)
        driver = MockNetworkDriver(repo, profile)
        report = Audits(engine, driver).run(network_id, "admin", str(uuid4()))
        findings = {f.check_id: f for f in report.findings}
        assert report.evidence_status == "valid"
        assert findings["dataplane"].status == "unknown"
        for key in (
            "integrity",
            "segmentation",
            "capabilities",
            "default_deny",
            "policy_version",
        ):
            assert findings[key].status == "pass" and findings[key].evidence
        for key in ("routing", "firewall", "dmz_cash", "honeypot"):
            if rule == "baseline":
                assert findings[key].status == "pass"
            else:
                assert findings[key].status == "unknown"
                assert any(rule in entry for entry in findings[key].evidence)
        assert (report.score.coverage, report.score.value) == (
            (95, 95) if rule == "baseline" else (47, None)
        )
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "change", ["device_name", "policy_version", "policy_content", "legacy"]
)
def test_historical_report_preserves_original_evidence(
    settings: Settings, client: TestClient, network_profile: Profile, change: str
) -> None:
    engine = sqlite_engine(settings.database_path)
    try:
        repo = NetworkRepository(engine)
        audits = Audits(engine, MockNetworkDriver(repo, network_profile))
        network_id = network_profile.network.id
        original = audits.run(network_id, "admin", str(uuid4()))
        assert original.current
        data = network_profile.model_dump(mode="json")
        if change == "device_name":
            data["network"]["devices"][0]["name"] += " updated"
        elif change == "policy_version":
            data["policy"]["version"] += ".2"
        elif change == "policy_content":
            data["policy"]["allowed_protocols"].append("ospf")
        else:
            with Session(engine) as db, db.begin():
                row = db.get_one(AuditRun, str(original.id))
                row.profile_hash = row.findings_hash = None
        active = Audits(engine, MockNetworkDriver(repo, Profile.model_validate(data)))
        historical = active.read(network_id, original.id)[0]
        assert not historical.current
        assert historical.evidence_status == "valid"
        assert (
            historical.score == original.score
            and historical.findings == original.findings
        )
        latest = active.run(network_id, "admin", str(uuid4()))
        assert latest.current and latest == active.read(network_id, latest.id)[0]
        assert len(active.read(network_id)) == 2
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "damage", ["missing", "score", "malformed", "edited_evidence", "duplicate"]
)
def test_damaged_audit_hides_score(
    client: TestClient, settings: Settings, network_profile: Profile, damage: str
) -> None:
    url = f"/api/v1/networks/{network_profile.network.id}/audits"
    auth = bearer(settings.admin_token)
    healthy = client.post(url, headers=auth).json()
    report = client.post(url, headers=auth).json()
    engine = sqlite_engine(settings.database_path)
    try:
        with Session(engine) as db, db.begin():
            item = db.get_one(AuditFinding, (report["id"], 0))
            if damage == "missing":
                db.delete(item)
            elif damage == "score":
                db.get_one(
                    AuditRun, report["id"]
                ).score = '{"version":"1.0","value":100,"coverage":100}'
            elif damage == "malformed":
                item.payload = "{"
            elif damage == "edited_evidence":
                item.payload = item.payload.replace(report["snapshot_hash"], "0" * 64)
            else:
                item.payload = db.get_one(AuditFinding, (report["id"], 1)).payload
        result = client.get(url + "/" + report["id"], headers=auth).json()
        assert result["evidence_status"] == "corrupt" and not result["current"]
        assert result["score"]["value"] is None and result["findings"] == []
        assert client.get(url, headers=auth).json() == [result, healthy]
    finally:
        engine.dispose()


def test_audit_registry_survives_corrupt_snapshot(
    client: TestClient, settings: Settings, network_profile: Profile
) -> None:
    network_id = str(network_profile.network.id)
    url = f"/api/v1/networks/{network_id}/audits"
    admin, viewer = bearer(settings.admin_token), bearer(settings.viewer_token)
    original = client.post(url, headers=admin).json()
    engine = sqlite_engine(settings.database_path)
    try:
        with Session(engine) as db, db.begin():
            db.get_one(RevisionRecord, (network_id, 1)).sha256 = "0" * 64
        registry = "/api/v1/audit/networks"
        assert client.get(registry).status_code == 401
        assert client.get(registry, headers=viewer).json() == [
            {"id": network_id, "name": None, "snapshot_integrity": "failed"}
        ]
        assert client.get("/api/v1/networks", headers=viewer).status_code == 409
        assert client.get(url, headers=viewer).json() == [
            {**original, "current": False}
        ]
        diagnosis = client.post(url, headers=admin).json()
        assert (
            diagnosis == client.get(url + "/" + diagnosis["id"], headers=viewer).json()
        )
        assert not diagnosis["current"] and diagnosis["score"]["value"] is None
        checks = {f["check_id"]: f["status"] for f in diagnosis["findings"]}
        assert checks.pop("integrity") == "fail" and set(checks.values()) == {"unknown"}
        assert client.get("/api/v1/networks", headers=viewer).status_code == 409
    finally:
        engine.dispose()
