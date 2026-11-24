import csv
import json
import os
import re
import stat
from datetime import date
from io import StringIO
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid5

import yaml
from pydantic import (
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    field_validator,
)

from app.network.models import Model, Network
from app.workflows.models import Artifact, Positive, Requirements, Slug

DESIGN_PROVENANCE = (
    "Validated operator requirements and deterministic address allocation"
)
HA_LIMIT = "HA not modeled. Standby units are budgeted. Design failover separately."
Scope = Literal["hub", "site"]


class Datasheet(Model):
    vendor: Slug
    sku: Slug
    source_url: Annotated[str, StringConstraints(max_length=512)]
    retrieved_on: date
    throughput_mbps: Positive | None = None
    packets_per_second: Positive | None = None

    @field_validator("source_url")
    @classmethod
    def validate_provenance_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.query
            or parsed.fragment
            or not re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63}", host
            )
            or host.endswith((".internal", ".localhost", ".local", ".test", ".invalid"))
        ):
            raise ValueError(
                "provenance requires an HTTPS public DNS name without credentials"
            )
        return value


class HardwareLine(Model):
    role: Scope
    quantity: Positive
    minimum_throughput_mbps: int
    minimum_packets_per_second: int
    status: Literal["verified", "unverified", "unknown"]
    candidates: tuple[Datasheet, ...]
    unit_price: None = None
    availability: Literal["unknown"] = "unknown"


class BillOfMaterials(Model):
    schema_version: Literal[1] = 1
    task_id: UUID
    provenance: str
    live_search: Literal["unavailable"] = "unavailable"
    items: tuple[HardwareLine, ...]


class Inventory(Model):
    schema_version: Literal[1] = 1
    task_id: UUID
    provenance: str = DESIGN_PROVENANCE
    network: Network


class OfflineSources:
    def __init__(self, path: Path | None) -> None:
        self.path = path

    def candidates(self, requirements: Requirements) -> tuple[Datasheet, ...]:
        if self.path is None:
            return ()
        try:
            with os.fdopen(
                os.open(self.path, os.O_RDONLY | os.O_NONBLOCK), "rb"
            ) as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return ()
                raw = handle.read(65_537)
            if len(raw) > 65_536:
                return ()
            adapter = TypeAdapter(Annotated[list[Datasheet], Field(max_length=50)])
            candidates = adapter.validate_json(raw)
        except (OSError, ValidationError):
            return ()
        allowed = {vendor.casefold() for vendor in requirements.vendors or ()}
        return tuple(
            item
            for item in candidates
            if not allowed or item.vendor.casefold() in allowed
        )


def validate_requirements(requirements: Requirements) -> tuple[str, ...]:
    missing = tuple(name for name, value in requirements if value is None)
    if missing:
        return missing
    assert requirements.registers_per_site is not None
    assert requirements.devices_per_site is not None
    assert requirements.users_per_site is not None
    assert requirements.address_pool is not None
    assert requirements.sites is not None
    problems = []
    if requirements.registers_per_site > requirements.devices_per_site:
        problems.append("registers_per_site_exceeds_devices_per_site")
    if (
        "point_of_sale" in (requirements.services or ())
        and not requirements.registers_per_site
    ):
        problems.append("point_of_sale_requires_register_count")
    if requirements.registers_per_site and "payment_isolation" not in (
        requirements.security or ()
    ):
        problems.append("registers_require_payment_isolation")
    if not requirements.users_per_site and not requirements.devices_per_site:
        problems.append("site_requires_users_or_devices")
    if not private_pool(requirements.address_pool):
        problems.append("address_pool_must_be_private_or_ula")
    if prefix_length(requirements) < requirements.address_pool.prefixlen or (
        requirements.sites * len(segments(requirements))
        > 2 ** max(0, prefix_length(requirements) - requirements.address_pool.prefixlen)
    ):
        problems.append("address_pool_too_small")
    return tuple(problems)


def private_pool(network: IPv4Network | IPv6Network) -> bool:
    if isinstance(network, IPv6Network):
        return network.subnet_of(IPv6Network("fc00::/7"))
    return any(
        network.subnet_of(IPv4Network(pool))
        for pool in (
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        )
    )


def prefix_length(req: Requirements) -> int:
    assert req.address_pool is not None
    hosts = (req.users_per_site or 0) + (req.devices_per_site or 0) + 4
    bits = (hosts - 1).bit_length()
    return 32 - bits if isinstance(req.address_pool, IPv4Network) else 64


def segments(req: Requirements) -> tuple[str, ...]:
    return (
        ("clients", "services", "payments")
        if req.registers_per_site
        else ("clients", "services")
    )


def architecture(task_id: UUID, req: Requirements) -> Inventory:
    assert req.address_pool is not None
    assert req.sites is not None
    prefix = prefix_length(req)
    pool = req.address_pool
    network_class: type[IPv4Network] | type[IPv6Network] = type(pool)
    addresses_per_prefix = 2 ** (pool.max_prefixlen - prefix)
    zones = []
    vlans = []
    subnets = []
    links = []
    hub_interfaces = []
    sites = []
    group = segments(req)
    for name in group:
        zones.append({"id": uuid5(task_id, name), "name": name})
    for site in range(1, req.sites + 1):
        site_interfaces = []
        for offset, name in enumerate(group):
            index = (site - 1) * len(group) + offset
            block = network_class(
                (int(pool.network_address) + index * addresses_per_prefix, prefix)
            )
            vlan = uuid5(task_id, f"vlan:{site}:{name}")
            subnet = uuid5(task_id, f"subnet:{site}:{name}")
            hub_port = uuid5(task_id, f"hub:{site}:{name}")
            site_port = uuid5(task_id, f"site:{site}:{name}")
            gateway, peer = block.network_address + 1, block.network_address + 2
            vlans.append(
                {
                    "id": vlan,
                    "name": f"site-{site}-{name}",
                    "tag": index + 1,
                    "zone_id": uuid5(task_id, name),
                }
            )
            subnets.append(
                {
                    "id": subnet,
                    "name": f"site-{site}-{name}",
                    "vlan_id": vlan,
                    "prefix": block,
                    "gateway": gateway,
                }
            )
            hub_interfaces.append(
                {
                    "id": hub_port,
                    "name": f"site-{site}-{name}",
                    "subnet_id": subnet,
                    "address": gateway,
                }
            )
            site_interfaces.append(
                {"id": site_port, "name": name, "subnet_id": subnet, "address": peer}
            )
            links.append(
                {
                    "id": uuid5(task_id, f"link:{site}:{name}"),
                    "endpoints": [hub_port, site_port],
                }
            )
        sites.append(device(task_id, f"Site {site}", site_interfaces))
    core = device(task_id, "Hub", hub_interfaces)
    network = Network.model_validate(
        {
            "id": uuid5(task_id, "design"),
            "name": "greenfield-design",
            "zones": zones,
            "vlans": vlans,
            "subnets": subnets,
            "links": links,
            "devices": [core, *sites],
        }
    )
    return Inventory(
        task_id=task_id,
        network=network,
        provenance=(
            f"{DESIGN_PROVENANCE}. {HA_LIMIT}"
            if req.availability == "redundant"
            else DESIGN_PROVENANCE
        ),
    )


def device(
    task_id: UUID, name: str, interfaces: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "id": uuid5(task_id, name),
        "name": name,
        "platform": "unspecified",
        "version": "unknown",
        "capabilities": {"routing_protocols": [], "zone_firewall": False},
        "routing_protocols": [],
        "interfaces": interfaces,
    }


def hardware(
    task_id: UUID, req: Requirements, sources: OfflineSources
) -> BillOfMaterials:
    assert req.sites is not None
    assert req.throughput_mbps is not None
    assert req.packets_per_second is not None
    candidates = sources.candidates(req)
    units = 2 if req.availability == "redundant" else 1
    quantities: tuple[tuple[Scope, int, int], ...] = (
        ("hub", units, req.sites),
        ("site", req.sites * units, 1),
    )
    items = tuple(
        HardwareLine(
            role=role,
            quantity=quantity,
            minimum_throughput_mbps=req.throughput_mbps * multiplier,
            minimum_packets_per_second=req.packets_per_second * multiplier,
            status="unverified",
            candidates=tuple(
                item
                for item in candidates
                if (
                    item.throughput_mbps is None
                    or item.throughput_mbps >= req.throughput_mbps * multiplier
                )
                and (
                    item.packets_per_second is None
                    or item.packets_per_second >= req.packets_per_second * multiplier
                )
            ),
        )
        for role, quantity, multiplier in quantities
    )
    return BillOfMaterials(
        task_id=task_id,
        provenance="Offline catalog if provided. Specifications unverified."
        + (f" {HA_LIMIT}" if req.availability == "redundant" else ""),
        items=items,
    )


def export(
    req: Requirements, bom: BillOfMaterials, inventory: Inventory
) -> tuple[Artifact, ...]:
    bom_document = bom.model_dump_json(indent=2)
    BillOfMaterials.model_validate_json(bom_document)
    inventory_document = yaml.safe_dump(
        inventory.model_dump(mode="json"), sort_keys=False
    )
    Inventory.model_validate(yaml.safe_load(inventory_document))
    csv_text = StringIO(newline="")
    csv_writer = csv.writer(csv_text)
    csv_writer.writerow(
        (
            "schema_version",
            "task_id",
            "provenance",
            "role",
            "quantity",
            "minimum_mbps",
            "minimum_pps",
            "status",
            "unit_price",
            "availability",
            "candidates_json",
        )
    )
    stamp = f"Schema 1 | Task {bom.task_id} | {bom.provenance}"
    markdown = [
        "# Bill of materials",
        "",
        stamp,
        "",
        "| Role | Quantity | Minimum Mbps | Minimum PPS | Status |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    for item in bom.items:
        csv_writer.writerow(
            (
                1,
                bom.task_id,
                bom.provenance,
                item.role,
                item.quantity,
                item.minimum_throughput_mbps,
                item.minimum_packets_per_second,
                item.status,
                "",
                item.availability,
                json.dumps(
                    [candidate.model_dump(mode="json") for candidate in item.candidates]
                ),
            )
        )
        markdown.append(
            f"| {item.role} | {item.quantity} | {item.minimum_throughput_mbps} | "
            f"{item.minimum_packets_per_second} | {item.status} |"
        )
    diagram = [
        f"%% Schema 1 | Task {bom.task_id} | {inventory.provenance}",
        "flowchart TD",
        "  hub[Hub]",
    ]
    assert req.sites is not None
    for site in range(1, req.sites + 1):
        diagram.append(f"  hub --- site{site}[Site {site}]")
    ha = (
        HA_LIMIT
        if req.availability == "redundant"
        else "Single hub requested. Assess its failure domain."
    )
    assumptions = [
        "# Design assumptions",
        "",
        f"Schema 1 | Task {bom.task_id} | {DESIGN_PROVENANCE}",
        "",
        f"- Organization {req.organization}. Regional procurement scope {req.region}.",
        f"- Budget {req.budget_minor} minor units ({req.currency}). Prices unknown.",
        f"- Vendor filter {', '.join(req.vendors or ()) or 'unrestricted'}.",
        f"- Service requirements {', '.join(req.services or ()) or 'none specified'}.",
        f"- Security requirements {', '.join(req.security or ()) or 'none specified'}.",
        "- Use separate VLANs for trust zones. Default deny between zones.",
        "- Hub minimum performance assumes all sites reach peak simultaneously.",
        f"- {ha}",
        "- Validate physical sizing and compatibility against the logical inventory.",
        "- Containerlab omitted because compatible images have not been verified.",
    ]
    return (
        Artifact(name="bom.json", media_type="application/json", content=bom_document),
        Artifact(name="bom.csv", media_type="text/csv", content=csv_text.getvalue()),
        Artifact(
            name="bom.md",
            media_type="text/markdown",
            content="\n".join(markdown) + "\n",
        ),
        Artifact(
            name="topology.mmd",
            media_type="text/plain",
            content="\n".join(diagram) + "\n",
        ),
        Artifact(
            name="inventory.yaml",
            media_type="application/yaml",
            content=inventory_document,
        ),
        Artifact(
            name="assumptions.md",
            media_type="text/markdown",
            content="\n".join(assumptions),
        ),
    )
