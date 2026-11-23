from pathlib import Path
from typing import Literal, Self
from uuid import UUID

import yaml
from pydantic import Field, ValidationError, model_validator
from yaml.nodes import MappingNode

from app.network.models import (
    CIDR,
    Flow,
    Interface,
    Model,
    Name,
    Network,
    NetworkDevice,
    Protocol,
    Subnet,
    is_subnet,
)

Decision = Literal["allow", "deny", "unknown"]


class Finding(Model):
    rule_id: str
    decision: Decision
    severity: Literal["info", "high"]
    reason: str
    evidence: tuple[str, ...] = ()
    policy_version: str | None


class ZonePair(Model):
    source: UUID
    destination: UUID


class Platform(Model):
    name: Name
    versions: tuple[Name, ...] = Field(min_length=1)


class Policy(Model):
    version: Name
    default_action: Literal["deny"]
    allowed_protocols: tuple[Protocol, ...]
    platforms: tuple[Platform, ...] = Field(min_length=1)
    blocked_pairs: tuple[ZonePair, ...]
    allowed_flows: tuple[Flow, ...]


def endpoint(network: Network, zone_id: UUID, prefix: CIDR) -> Subnet | None:
    vlans = {vlan.id: vlan.zone_id for vlan in network.vlans}
    for subnet in network.subnets:
        if (
            subnet.vlan_id is not None
            and vlans[subnet.vlan_id] == zone_id
            and is_subnet(prefix, subnet.prefix)
        ):
            return subnet
    return None


def covers(allowance: Flow, rule: Flow) -> bool:
    return (
        (allowance.source_zone, allowance.destination_zone, allowance.protocol)
        == (rule.source_zone, rule.destination_zone, rule.protocol)
        and is_subnet(rule.source, allowance.source)
        and is_subnet(rule.destination, allowance.destination)
        and (
            allowance.destination_port is None
            or allowance.destination_port == rule.destination_port
        )
    )


class Profile(Model):
    network: Network
    policy: Policy

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        zones = {zone.id for zone in self.network.zones}
        blocked = {
            (pair.source, pair.destination) for pair in self.policy.blocked_pairs
        }
        if len(blocked) != len(self.policy.blocked_pairs):
            raise ValueError("duplicate isolated direction")
        for pair in self.policy.blocked_pairs:
            if pair.source not in zones or pair.destination not in zones:
                raise ValueError("policy references an unknown zone")
        for flow in self.policy.allowed_flows:
            if (flow.source_zone, flow.destination_zone) in blocked:
                raise ValueError("policy allowance contradicts an isolated direction")
            if (
                endpoint(self.network, flow.source_zone, flow.source) is None
                or endpoint(self.network, flow.destination_zone, flow.destination)
                is None
            ):
                raise ValueError(
                    "policy allowance must reference attached subnets in its zones"
                )
        if len({platform.name for platform in self.policy.platforms}) != len(
            self.policy.platforms
        ):
            raise ValueError("duplicate platform policy")
        return self


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(
        self, node: MappingNode, deep: bool = False
    ) -> dict[object, object]:
        result = super().construct_mapping(node, deep=deep)
        if len(result) != len(node.value):
            raise yaml.YAMLError("duplicate mapping key")
        return result


def load_profile(path: Path) -> Profile | None:
    try:
        with path.open("rb") as source:
            raw = source.read(256_000)
            if source.read(1):
                return None
        return Profile.model_validate(yaml.load(raw, Loader=UniqueKeyLoader))
    except (OSError, ValidationError, yaml.YAMLError, ValueError, RecursionError):
        return None


class PolicyEngine:
    def evaluate(
        self, network: Network, profile: Profile | None
    ) -> tuple[Finding, ...]:
        if profile is None or profile.network.id != network.id:
            return (
                Finding(
                    rule_id="policy.available",
                    decision="unknown",
                    severity="high",
                    reason="No valid policy for this network",
                    policy_version=None,
                ),
            )

        policy = profile.policy
        results: list[Finding] = []

        def finding(
            rule_id: str, decision: Decision, reason: str, *evidence: str
        ) -> None:
            results.append(
                Finding(
                    rule_id=rule_id,
                    decision=decision,
                    severity="info" if decision == "allow" else "high",
                    reason=reason,
                    evidence=evidence,
                    policy_version=policy.version,
                )
            )

        topology = network.model_dump(exclude={"firewall_rules", "devices"})
        profile_topology = profile.network.model_dump(
            exclude={"firewall_rules", "devices"}
        )
        device_static_fields = {"routes", "routing_protocols"}
        if topology != profile_topology or [
            device.model_dump(exclude=device_static_fields)
            for device in network.devices
        ] != [
            device.model_dump(exclude=device_static_fields)
            for device in profile.network.devices
        ]:
            finding(
                "profile.topology",
                "unknown",
                "Stored topology differs from the active profile",
            )

        if network.traffic_model != "connected-no-nat":
            finding(
                "traffic.model", "unknown", "NAT or forwarding model is unspecified"
            )

        platforms = {entry.name: entry.versions for entry in policy.platforms}
        for device in network.devices:
            if device.version not in platforms.get(device.platform, ()):
                finding(
                    "device.platform",
                    "unknown",
                    "Unconfirmed mock platform",
                    str(device.id),
                )
            protocols = set(device.routing_protocols)
            if protocols.difference(policy.allowed_protocols):
                finding(
                    "routing.policy",
                    "deny",
                    "Routing protocol is forbidden",
                    str(device.id),
                )
            if protocols.difference(device.capabilities.routing_protocols) or (
                device.routes and "static" not in protocols
            ):
                finding(
                    "device.capability",
                    "deny",
                    "Device does not support configured routing",
                    str(device.id),
                )
            if protocols.difference({"static"}):
                finding(
                    "traffic.routing",
                    "unknown",
                    "Dynamic routing is outside this model",
                )

        attachments = {
            subnet.prefix: subnet
            for subnet in network.subnets
            if subnet.vlan_id is not None
        }
        port_owners = {
            port.id: (device, port)
            for device in network.devices
            for port in device.interfaces
        }
        neighbors: dict[UUID, list[tuple[NetworkDevice, Interface]]] = {}
        for link in network.links:
            left, right = link.endpoints
            neighbors.setdefault(left, []).append(port_owners[right])
            neighbors.setdefault(right, []).append(port_owners[left])

        for device in network.devices:
            for route in device.routes:
                destination = attachments.get(route.destination)
                if destination is None or not any(
                    port.address == route.next_hop
                    and any(
                        interface.subnet_id == destination.id
                        for interface in peer.interfaces
                    )
                    for peer, port in neighbors.get(route.interface_id, [])
                ):
                    finding(
                        "routing.destination",
                        "unknown",
                        "Route is not a verified one-hop path",
                        str(route.id),
                    )

        blocked = {(pair.source, pair.destination) for pair in policy.blocked_pairs}
        for rule in network.firewall_rules:
            evidence = str(rule.id)
            if (
                rule.action == "allow"
                and (rule.source_zone, rule.destination_zone) in blocked
            ):
                finding(
                    "firewall.isolation",
                    "deny",
                    "Direction is explicitly isolated",
                    evidence,
                )
                continue

            source = endpoint(network, rule.source_zone, rule.source)
            destination = endpoint(network, rule.destination_zone, rule.destination)
            if source is None or destination is None:
                finding(
                    "firewall.scope",
                    "deny",
                    "CIDR does not belong to its declared zone",
                    evidence,
                )
                continue
            if rule.action == "deny":
                finding(
                    "firewall.rule", "allow", "Explicit deny is permitted", evidence
                )
                continue
            if not any(covers(allowance, rule) for allowance in policy.allowed_flows):
                finding(
                    "firewall.default", "deny", "No matching policy allowance", evidence
                )
                continue
            if not self.known_connected_path(network, source, destination):
                finding(
                    "traffic.path",
                    "unknown",
                    "No verified shared firewall gateway",
                    evidence,
                )
                continue
            finding(
                "firewall.rule", "allow", "Scoped connected flow is permitted", evidence
            )

        if not results:
            finding(
                "network.default", "allow", "Deny-by-default configuration is valid"
            )
        return tuple(results)

    @staticmethod
    def known_connected_path(
        network: Network, source: Subnet, destination: Subnet
    ) -> bool:
        if network.traffic_model != "connected-no-nat":
            return False
        if source.gateway is None or destination.gateway is None:
            return False
        for device in network.devices:
            if not device.capabilities.zone_firewall:
                continue
            connected = {(port.subnet_id, port.address) for port in device.interfaces}
            if (source.id, source.gateway) in connected and (
                destination.id,
                destination.gateway,
            ) in connected:
                return True
        return False
