from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from itertools import combinations
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    StrictBool,
    StringConstraints,
    model_validator,
)

MAPPED_RANGE = IPv6Network("::ffff:0:0/96")


def explicit_address(value: object) -> object:
    if not isinstance(value, (str, IPv4Address, IPv6Address)):
        raise ValueError("address must be an IPv4 or IPv6 string")
    return value


def explicit_prefix(value: object) -> object:
    if isinstance(value, (IPv4Network, IPv6Network)):
        return value
    if isinstance(value, str):
        address, _, length = value.rpartition("/")
        if address and length.isascii() and length.isdecimal():
            return value
    raise ValueError("CIDR requires an explicit numeric prefix length")


def unambiguous_address(value: IPvAnyAddress) -> IPvAnyAddress:
    if isinstance(value, IPv6Address) and (value.ipv4_mapped or value.scope_id):
        raise ValueError("mapped and scoped IPv6 addresses are unsupported")
    return value


def unambiguous_network(value: IPvAnyNetwork) -> IPvAnyNetwork:
    if isinstance(value, IPv6Network) and value.subnet_of(MAPPED_RANGE):
        raise ValueError("IPv4-mapped IPv6 networks are unsupported")
    return value


IPAddress = Annotated[
    IPvAnyAddress,
    BeforeValidator(explicit_address),
    AfterValidator(unambiguous_address),
]
CIDR = Annotated[
    IPvAnyNetwork, BeforeValidator(explicit_prefix), AfterValidator(unambiguous_network)
]
Name = Annotated[
    str, StringConstraints(min_length=1, max_length=80, strip_whitespace=True)
]
MAX_REVISION = 2**53 - 1
Revision = Annotated[int, Field(strict=True, ge=1, le=MAX_REVISION)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
Protocol = Literal["static", "bgp", "ospf"]
Transport = Literal["tcp", "udp", "icmp"]
Action = Literal["allow", "deny"]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NetworkZone(Model):
    id: UUID
    name: Name


class VLAN(Model):
    id: UUID
    name: Name
    tag: Annotated[int, Field(strict=True, ge=1, le=4094)]
    zone_id: UUID


def is_subnet(prefix: CIDR, parent: CIDR) -> bool:
    return (
        prefix.version == parent.version
        and prefix.prefixlen >= parent.prefixlen
        and prefix.network_address in parent
    )


def usable(address: IPAddress, prefix: CIDR) -> bool:
    if address not in prefix or address.is_unspecified or address.is_multicast:
        return False
    if isinstance(address, IPv4Address) and prefix.prefixlen < 31:
        return address not in (prefix.network_address, prefix.broadcast_address)
    return True


class Subnet(Model):
    id: UUID
    name: Name
    prefix: CIDR
    parent_id: UUID | None = None
    vlan_id: UUID | None = None
    gateway: IPAddress | None = None

    @model_validator(mode="after")
    def validate_attachment(self) -> Self:
        if self.vlan_id is None and self.gateway is not None:
            raise ValueError("an allocation container cannot have a gateway")
        if self.gateway is not None and not usable(self.gateway, self.prefix):
            raise ValueError("gateway must be a usable host in its subnet")
        return self


class Interface(Model):
    id: UUID
    name: Name
    subnet_id: UUID
    address: IPAddress


class DeviceCapability(Model):
    routing_protocols: tuple[Protocol, ...]
    zone_firewall: StrictBool

    @model_validator(mode="after")
    def validate_protocols(self) -> Self:
        if len(set(self.routing_protocols)) != len(self.routing_protocols):
            raise ValueError("duplicate routing capability")
        return self


class DeviceFacts(Model):
    id: UUID
    name: Name
    platform: Name
    version: Name


class StaticRoute(Model):
    id: UUID
    destination: CIDR
    interface_id: UUID
    next_hop: IPAddress


class NetworkDevice(DeviceFacts):
    capabilities: DeviceCapability
    interfaces: tuple[Interface, ...]
    routing_protocols: tuple[Protocol, ...] = ("static",)
    routes: tuple[StaticRoute, ...] = ()

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        interfaces = index(self.interfaces)
        if len({port.name.casefold() for port in self.interfaces}) != len(interfaces):
            raise ValueError("duplicate interface name")
        destinations: set[CIDR] = set()
        for route in self.routes:
            if route.interface_id not in interfaces:
                raise ValueError("route egress interface must belong to its device")
            if route.destination.version != route.next_hop.version:
                raise ValueError("route and next hop must use the same address family")
            if route.destination in destinations:
                raise ValueError("duplicate route destination")
            destinations.add(route.destination)
        if len(set(self.routing_protocols)) != len(self.routing_protocols):
            raise ValueError("duplicate routing protocols")
        return self


class Flow(Model):
    source_zone: UUID
    destination_zone: UUID
    source: CIDR
    destination: CIDR
    protocol: Transport
    destination_port: Port | None = None

    @model_validator(mode="after")
    def validate_flow(self) -> Self:
        if self.source.version != self.destination.version:
            raise ValueError("flow endpoints must use the same address family")
        if self.protocol == "icmp" and self.destination_port is not None:
            raise ValueError("ICMP does not have ports")
        return self


class FirewallRule(Flow):
    id: UUID
    action: Action


class NetworkLink(Model):
    id: UUID
    endpoints: tuple[UUID, UUID]


def index[
    T: NetworkZone
    | VLAN
    | Subnet
    | Interface
    | NetworkDevice
    | NetworkLink
    | StaticRoute
    | FirewallRule
](items: tuple[T, ...]) -> dict[UUID, T]:
    result = {item.id: item for item in items}
    if len(items) != len(result):
        raise ValueError("duplicate object identifier")
    return result


def overlapping_flows(left: Flow, right: Flow) -> bool:
    return (
        (left.source_zone, left.destination_zone, left.protocol)
        == (right.source_zone, right.destination_zone, right.protocol)
        and left.source.overlaps(right.source)
        and left.destination.overlaps(right.destination)
        and (
            left.destination_port is None
            or right.destination_port is None
            or left.destination_port == right.destination_port
        )
    )


class Network(Model):
    id: UUID
    name: Name
    traffic_model: Literal["connected-no-nat", "unknown"] = "unknown"
    zones: tuple[NetworkZone, ...] = Field(min_length=1)
    vlans: tuple[VLAN, ...] = Field(min_length=1)
    subnets: tuple[Subnet, ...] = Field(min_length=1)
    devices: tuple[NetworkDevice, ...] = Field(min_length=1)
    links: tuple[NetworkLink, ...] = ()
    firewall_rules: tuple[FirewallRule, ...] = ()

    @model_validator(mode="after")
    def validate_topology(self) -> Self:
        zones, vlans, subnets = (
            index(self.zones),
            index(self.vlans),
            index(self.subnets),
        )
        devices = index(self.devices)
        if len({device.name.casefold() for device in self.devices}) != len(devices):
            raise ValueError("duplicate device name")
        index(self.links)
        index(self.firewall_rules)
        index(tuple(route for device in self.devices for route in device.routes))

        if len({zone.name.casefold() for zone in self.zones}) != len(zones):
            raise ValueError("duplicate zone name")
        if len({vlan.tag for vlan in self.vlans}) != len(vlans):
            raise ValueError("duplicate VLAN tag")
        if any(vlan.zone_id not in zones for vlan in self.vlans):
            raise ValueError("unknown VLAN zone")

        self.validate_subnets(subnets, vlans)
        self.validate_interfaces(subnets)
        for rule in self.firewall_rules:
            if rule.source_zone not in zones or rule.destination_zone not in zones:
                raise ValueError("unknown firewall zone")
        if any(
            overlapping_flows(a, b) for a, b in combinations(self.firewall_rules, 2)
        ):
            raise ValueError("overlapping firewall rules are ambiguous")
        return self

    def validate_subnets(
        self, subnets: dict[UUID, Subnet], vlans: dict[UUID, VLAN]
    ) -> None:
        for subnet in self.subnets:
            if subnet.vlan_id is not None and subnet.vlan_id not in vlans:
                raise ValueError("unknown subnet VLAN")
            if subnet.parent_id is None:
                continue
            parent = subnets.get(subnet.parent_id)
            if (
                parent is None
                or parent.vlan_id is not None
                or subnet.prefix == parent.prefix
                or not is_subnet(subnet.prefix, parent.prefix)
            ):
                raise ValueError("nested subnet requires a strict allocation container")

        for first, second in combinations(self.subnets, 2):
            if first.prefix.overlaps(second.prefix) and not (
                self.has_ancestor(first, second.id, subnets)
                or self.has_ancestor(second, first.id, subnets)
            ):
                raise ValueError(
                    "subnet overlaps outside an explicit allocation hierarchy"
                )

    @staticmethod
    def has_ancestor(subnet: Subnet, target: UUID, subnets: dict[UUID, Subnet]) -> bool:
        while subnet.parent_id is not None:
            if subnet.parent_id == target:
                return True
            subnet = subnets[subnet.parent_id]
        return False

    def validate_interfaces(self, subnets: dict[UUID, Subnet]) -> None:
        interfaces = index(
            tuple(port for device in self.devices for port in device.interfaces)
        )
        owners = {
            port.id: device.id for device in self.devices for port in device.interfaces
        }
        addresses: set[tuple[UUID, IPAddress]] = set()
        for port in interfaces.values():
            subnet = subnets.get(port.subnet_id)
            if (
                subnet is None
                or subnet.vlan_id is None
                or not usable(port.address, subnet.prefix)
            ):
                raise ValueError(
                    "interface requires a usable address on an attached subnet"
                )
            key = (port.subnet_id, port.address)
            if key in addresses:
                raise ValueError("duplicate interface address")
            addresses.add(key)
        for subnet in self.subnets:
            if (
                subnet.gateway is not None
                and (subnet.id, subnet.gateway) not in addresses
            ):
                raise ValueError("gateway must reference an existing interface address")

        neighbors: dict[UUID, set[IPAddress]] = {}
        pairs: set[frozenset[UUID]] = set()
        for link in self.links:
            left, right = link.endpoints
            if (
                left not in interfaces
                or right not in interfaces
                or owners[left] == owners[right]
            ):
                raise ValueError("link requires two interfaces on distinct devices")
            pair = frozenset((left, right))
            if (
                pair in pairs
                or interfaces[left].subnet_id != interfaces[right].subnet_id
            ):
                raise ValueError("duplicate link or incompatible link subnets")
            pairs.add(pair)
            neighbors.setdefault(left, set()).add(interfaces[right].address)
            neighbors.setdefault(right, set()).add(interfaces[left].address)

        for device in self.devices:
            for route in device.routes:
                if route.next_hop not in neighbors.get(route.interface_id, set()):
                    raise ValueError(
                        "static route next hop must be an explicitly linked peer"
                    )
                if any(
                    route.destination.overlaps(subnets[port.subnet_id].prefix)
                    for port in device.interfaces
                ):
                    raise ValueError(
                        "static route overlaps a directly connected subnet"
                    )


class NetworkSnapshot(Model):
    network: Network
    revision: Revision
    sha256: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{64}$")]
