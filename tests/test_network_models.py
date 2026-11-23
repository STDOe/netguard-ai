from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import TypeAdapter, ValidationError

from app.network.driver import PutFirewallRule
from app.network.models import CIDR, DeviceCapability, IPAddress, Network, Subnet
from app.network.policy import PolicyEngine, Profile, load_profile


@pytest.mark.parametrize("address", ["10.0.0.1", "2001:db8::1"])
def test_ip_round_trip(address: str) -> None:
    adapter = TypeAdapter(IPAddress)
    assert str(adapter.validate_python(address)) == address


@pytest.mark.parametrize(
    "invalid", ["300.0.0.1", "fe80::1%eth0", "::ffff:10.20.0.1", 167772161]
)
def test_rejects_invalid_addresses(invalid: object) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(IPAddress).validate_python(invalid)


@pytest.mark.parametrize(
    "invalid",
    [
        "10.0.0.1/16",
        "10.0.0.0/33",
        "2001:db8::/129",
        "10.0.0.0",
        "10.0.0.0/255.0.0.0",
        "::ffff:10.20.0.0/112",
    ],
)
def test_rejects_ambiguous_cidrs(invalid: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(CIDR).validate_python(invalid)


def test_ipv6_prefix_and_gateway() -> None:
    subnet = Subnet.model_validate(
        {
            "id": uuid4(),
            "name": "IPv6 access",
            "vlan_id": uuid4(),
            "prefix": "2001:0db8:0:0::/64",
            "gateway": "2001:db8::1",
        }
    )
    assert str(subnet.prefix) == "2001:db8::/64"
    assert Subnet.model_validate_json(subnet.model_dump_json()) == subnet


def test_profile_roundtrip_and_separate_allocations(network_profile: Profile) -> None:
    network = network_profile.network
    assert Network.model_validate_json(network.model_dump_json()) == network
    cash = next(item for item in network.subnets if str(item.prefix) == "10.20.0.0/16")
    honeypot = next(
        item for item in network.subnets if str(item.prefix) == "10.30.99.0/24"
    )
    parent = next(item for item in network.subnets if item.id == honeypot.parent_id)
    assert str(parent.prefix) == "10.30.0.0/16"
    assert parent.vlan_id is None
    assert cash.vlan_id != honeypot.vlan_id
    assert len(network.links) == 4


@pytest.mark.parametrize(
    "conflict", ["zone", "device", "address", "link", "subnet", "gateway"]
)
def test_conflicting_network_is_rejected(
    network_profile: Profile, conflict: str
) -> None:
    data = network_profile.network.model_dump(mode="json")
    if conflict == "zone":
        data["vlans"][0]["zone_id"] = str(uuid4())
    elif conflict == "device":
        data["devices"][1]["id"] = data["devices"][0]["id"]
    elif conflict == "address":
        data["devices"][1]["interfaces"][0]["address"] = "10.10.0.1"
    elif conflict == "link":
        data["links"][0]["endpoints"][1] = str(uuid4())
    elif conflict == "subnet":
        data["subnets"][-1]["parent_id"] = None
    else:
        data["subnets"][-1]["gateway"] = "10.10.0.1"
    with pytest.raises(ValidationError):
        Network.model_validate(data)


def test_unknown_capability_and_platform(network_profile: Profile) -> None:
    with pytest.raises(ValidationError):
        DeviceCapability.model_validate(
            {"routing_protocols": ["unrecognized"], "zone_firewall": True}
        )
    data = network_profile.network.model_dump(mode="json")
    data["devices"][0]["version"] = "unverified"
    report = PolicyEngine().evaluate(Network.model_validate(data), network_profile)
    assert any(
        item.decision == "unknown" and item.rule_id == "device.platform"
        for item in report
    )


def test_yaml_duplicate_key_is_invalid(tmp_path: Path) -> None:
    profile = tmp_path / "bad.yaml"
    profile.write_text("network: {}\npolicy: {}\npolicy: {}\n")
    assert load_profile(profile) is None


def test_policy_returns_unknown_if_gateway_cannot_enforce_rules(
    network_profile: Profile, firewall_change: PutFirewallRule
) -> None:
    data = network_profile.model_dump(mode="json")
    data["network"]["devices"][0]["capabilities"]["zone_firewall"] = False
    data["network"]["firewall_rules"] = [firewall_change.rule.model_dump(mode="json")]
    profile = Profile.model_validate(data)
    findings = PolicyEngine().evaluate(profile.network, profile)
    assert any(
        item.rule_id == "traffic.path" and item.decision == "unknown"
        for item in findings
    )
