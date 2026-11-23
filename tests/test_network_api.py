from json import dumps
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_api import assert_error, bearer

from app.config import Settings
from app.main import create_app
from app.network.driver import PutFirewallRule
from app.network.policy import Profile


def test_api_read_and_authorization(
    client: TestClient, settings: Settings, network_profile: Profile
) -> None:
    viewer = bearer(settings.viewer_token)
    network_id = network_profile.network.id
    base = f"/api/v1/networks/{network_id}"
    device_id = network_profile.network.devices[0].id
    paths = [
        "/api/v1/networks",
        f"{base}/topology",
        f"{base}/devices/{device_id}",
        f"{base}/policy",
        f"{base}/revisions",
        f"{base}/snapshots/1",
    ]
    for path in paths:
        assert_error(client.get(path), 401, "unauthenticated")
        assert client.get(path, headers=viewer).status_code == 200
    for suffix in ("changes", "restore"):
        assert_error(client.post(f"{base}/{suffix}", json={}), 401, "unauthenticated")
        assert_error(
            client.post(f"{base}/{suffix}", json={}, headers=viewer), 403, "forbidden"
        )
    assert client.get(paths[0], headers=viewer).json()[0]["id"] == str(network_id)

    schema = client.get("/api/v1/openapi.json", headers=viewer).json()
    change = schema["paths"]["/api/v1/networks/{network_id}/changes"]["post"]
    assert change["security"] == [{"LocalBearer": []}]
    assert "409" in change["responses"]
    assert (
        schema["components"]["schemas"]["ApplyRequest"]["properties"]["change"][
            "discriminator"
        ]["propertyName"]
        == "kind"
    )


def test_apply_restore_and_request_audit(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
) -> None:
    admin = bearer(settings.admin_token)
    base = f"/api/v1/networks/{network_profile.network.id}"
    change = {"expected_revision": 1, "change": firewall_change.model_dump(mode="json")}
    applied = client.post(f"{base}/changes", headers=admin, json=change)
    assert applied.status_code == 200
    assert applied.json()["revision"] == 2
    assert applied.json()["network"]["firewall_rules"][0]["id"] == str(
        firewall_change.rule.id
    )
    findings = client.get(f"{base}/policy", headers=admin).json()["findings"]
    assert [item["decision"] for item in findings] == ["allow"]
    assert findings[0]["policy_version"] == network_profile.policy.version

    stale = client.post(f"{base}/changes", headers=admin, json=change)
    assert_error(stale, 409, "revision_conflict")
    restoration = {"expected_revision": 2, "snapshot_revision": 1}
    restored = client.post(f"{base}/restore", headers=admin, json=restoration)
    assert restored.status_code == 200
    assert restored.json()["revision"] == 3
    assert restored.json()["network"]["firewall_rules"] == []
    historical = client.get(f"{base}/snapshots/2", headers=admin)
    assert historical.json() == applied.json()
    history = client.get(f"{base}/revisions?limit=1", headers=admin).json()
    assert history[0]["revision"] == 3 and history[0]["restored_from"] == 1
    previous = client.get(f"{base}/revisions?before_revision=3", headers=admin).json()
    assert [item["revision"] for item in previous] == [2, 1]

    audit = client.get(
        "/api/v1/audit/events?include_network=true", headers=admin
    ).json()["events"]
    assert [(item["event_type"], item["outcome"]) for item in audit[:4]] == [
        ("network.restore", 200),
        ("network.change", 409),
        ("network.change", 200),
        ("network.seed", 201),
    ]
    assert audit[0]["request_id"] == restored.headers["X-Request-ID"]
    assert audit[0]["revision"] == 3


@pytest.mark.parametrize(
    ("source_zone", "destination_zone", "source", "destination", "rule_id"),
    [
        (
            "DMZ / User",
            "Cash / Payment",
            "10.30.0.0/24",
            "10.20.0.0/16",
            "firewall.isolation",
        ),
        (
            "Honeypot",
            "External",
            "10.30.99.0/24",
            "198.51.100.0/24",
            "firewall.isolation",
        ),
        (
            "Cash / Payment",
            "Infra",
            "10.20.0.0/16",
            "10.10.0.54/32",
            "firewall.default",
        ),
        ("Cash / Payment", "Infra", "10.20.0.0/15", "10.10.0.53/32", "firewall.scope"),
    ],
)
def test_firewall_rejects_forbidden_direction_and_scope(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    source_zone: str,
    destination_zone: str,
    source: str,
    destination: str,
    rule_id: str,
) -> None:
    network = network_profile.network
    zone = {item.name: str(item.id) for item in network.zones}
    admin = bearer(settings.admin_token)
    base = f"/api/v1/networks/{network.id}"
    response = client.post(
        f"{base}/changes",
        headers=admin,
        json={
            "expected_revision": 1,
            "change": {
                "kind": "put_firewall_rule",
                "rule": {
                    "id": str(uuid4()),
                    "source_zone": zone[source_zone],
                    "source": source,
                    "destination_zone": zone[destination_zone],
                    "destination": destination,
                    "protocol": "udp",
                    "destination_port": 53,
                    "action": "allow",
                },
            },
        },
    )
    assert_error(response, 403, "policy_denied")
    assert any(
        item["rule_id"] == rule_id and item["decision"] == "deny"
        for item in response.json()["findings"]
    )
    assert client.get(f"{base}/topology", headers=admin).json()["revision"] == 1


@pytest.mark.parametrize("protocol", ["bgp", "ospf"])
def test_routing_protocol_blocked(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    protocol: str,
) -> None:
    network = network_profile.network
    data = {
        "expected_revision": 1,
        "change": {
            "kind": "set_routing_protocols",
            "device_id": str(network.devices[0].id),
            "protocols": ["static", protocol],
        },
    }
    response = client.post(
        f"/api/v1/networks/{network.id}/changes",
        headers=bearer(settings.admin_token),
        json=data,
    )
    assert_error(response, 403, "policy_denied")
    assert any(
        item["rule_id"] == "routing.policy" for item in response.json()["findings"]
    )


def test_rejects_extra_policy_inline_snapshot_and_alternative_cidr(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
) -> None:
    admin = bearer(settings.admin_token)
    base = f"/api/v1/networks/{network_profile.network.id}"
    change = firewall_change.model_dump(mode="json")
    change["rule"]["source"] = "::ffff:10.20.0.0/112"
    for payload, action in (
        ({"expected_revision": 1, "change": change}, "changes"),
        ({"expected_revision": 1, "change": {"kind": "put_policy"}}, "changes"),
        ({"expected_revision": 1, "snapshot_revision": 1, "snapshot": {}}, "restore"),
    ):
        response = client.post(f"{base}/{action}", headers=admin, json=payload)
        assert_error(response, 422, "invalid_request")


@pytest.mark.parametrize("write_invalid", [False, True])
def test_missing_or_invalid_profile_blocks_mutation(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
    tmp_path: Path,
    write_invalid: bool,
) -> None:
    base = f"/api/v1/networks/{network_profile.network.id}"
    admin = bearer(settings.admin_token)
    assert client.get(f"{base}/topology", headers=admin).status_code == 200
    path = tmp_path / "custom.yaml"
    if write_invalid:
        path.write_text("network: {}\npolicy: invalid\n")
    options = settings.model_copy(update={"profile_path": path})
    with TestClient(create_app(options)) as restarted:
        candidate = {
            "expected_revision": 1,
            "change": firewall_change.model_dump(mode="json"),
        }
        response = restarted.post(f"{base}/changes", headers=admin, json=candidate)
        assert_error(response, 403, "policy_unknown")
        assert response.json()["findings"][0]["policy_version"] is None
        assert restarted.get(f"{base}/topology", headers=admin).json()["revision"] == 1


def test_restore_rechecks_current_policy(
    client: TestClient,
    settings: Settings,
    network_profile: Profile,
    firewall_change: PutFirewallRule,
    tmp_path: Path,
) -> None:
    admin = bearer(settings.admin_token)
    base = f"/api/v1/networks/{network_profile.network.id}"
    candidate = {
        "expected_revision": 1,
        "change": firewall_change.model_dump(mode="json"),
    }
    assert (
        client.post(f"{base}/changes", headers=admin, json=candidate).status_code == 200
    )
    assert (
        client.post(
            f"{base}/restore",
            headers=admin,
            json={
                "expected_revision": 2,
                "snapshot_revision": 1,
            },
        ).status_code
        == 200
    )

    profile = network_profile.model_dump(mode="json")
    profile["policy"]["version"] = "stricter/2"
    profile["policy"]["allowed_flows"] = []
    path = tmp_path / "stricter.yaml"
    path.write_text(dumps(profile))
    with TestClient(
        create_app(settings.model_copy(update={"profile_path": path}))
    ) as restarted:
        response = restarted.post(
            f"{base}/restore",
            headers=admin,
            json={
                "expected_revision": 3,
                "snapshot_revision": 2,
            },
        )
        assert_error(response, 403, "policy_denied")
        assert response.json()["findings"][0]["policy_version"] == "stricter/2"
        assert restarted.get(f"{base}/topology", headers=admin).json()["revision"] == 3
