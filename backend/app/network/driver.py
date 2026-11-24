from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, ValidationError

from app.network.errors import (
    InvalidChange,
    NotFound,
    PolicyBlocked,
    RevisionConflict,
    UnsupportedOperation,
)
from app.network.models import (
    DeviceCapability,
    DeviceFacts,
    FirewallRule,
    Interface,
    Model,
    Network,
    NetworkDevice,
    NetworkSnapshot,
    Protocol,
    StaticRoute,
)
from app.network.policy import Finding, PolicyEngine, Profile
from app.network.repository import ExecutionGuard, NetworkRepository


class PutStaticRoute(Model):
    kind: Literal["put_static_route"]
    device_id: UUID
    route: StaticRoute


class PutFirewallRule(Model):
    kind: Literal["put_firewall_rule"]
    rule: FirewallRule


class SetRoutingProtocols(Model):
    kind: Literal["set_routing_protocols"]
    device_id: UUID
    protocols: tuple[Protocol, ...]


Change = Annotated[
    PutStaticRoute | PutFirewallRule | SetRoutingProtocols, Field(discriminator="kind")
]


def upsert[T: StaticRoute | FirewallRule](
    items: tuple[T, ...], replacement: T
) -> tuple[T, ...]:
    return (*tuple(item for item in items if item.id != replacement.id), replacement)


class BaseNetworkDriver(ABC):
    @abstractmethod
    def get_snapshot(
        self, network_id: UUID, revision: int | None = None
    ) -> NetworkSnapshot: ...

    def get_device(self, network_id: UUID, device_id: UUID) -> NetworkDevice:
        for device in self.get_snapshot(network_id).network.devices:
            if device.id == device_id:
                return device
        raise NotFound

    def get_device_facts(self, network_id: UUID, device_id: UUID) -> DeviceFacts:
        device = self.get_device(network_id, device_id)
        return DeviceFacts(
            id=device.id,
            name=device.name,
            platform=device.platform,
            version=device.version,
        )

    def get_interfaces(
        self, network_id: UUID, device_id: UUID
    ) -> tuple[Interface, ...]:
        return self.get_device(network_id, device_id).interfaces

    def get_routes(self, network_id: UUID, device_id: UUID) -> tuple[StaticRoute, ...]:
        return self.get_device(network_id, device_id).routes

    def get_firewall_rules(self, network_id: UUID) -> tuple[FirewallRule, ...]:
        return self.get_snapshot(network_id).network.firewall_rules

    def get_capabilities(self, network_id: UUID, device_id: UUID) -> DeviceCapability:
        return self.get_device(network_id, device_id).capabilities


class MockNetworkDriver(BaseNetworkDriver):
    def __init__(self, repository: NetworkRepository, profile: Profile | None) -> None:
        self.repository = repository
        self.profile = profile
        self.policy = PolicyEngine()

    def initialize(self) -> None:
        if self.profile is not None:
            network = self.profile.network
            version = self._check_candidate(network)
            self.repository.seed(network, version)

    def get_snapshot(
        self, network_id: UUID, revision: int | None = None
    ) -> NetworkSnapshot:
        return self.repository.snapshot(network_id, revision)

    def check(self, snapshot: NetworkSnapshot) -> tuple[Finding, ...]:
        return self.policy.evaluate(snapshot.network, self.profile)

    def preview(
        self, snapshot: NetworkSnapshot, change: Change
    ) -> tuple[Network, tuple[Finding, ...]]:
        candidate = self._propose(snapshot.network, change)
        return candidate, self.policy.evaluate(candidate, self.profile)

    def _check_candidate(self, network: Network) -> str:
        findings = self.policy.evaluate(network, self.profile)
        if self.profile is None or any(
            result.decision != "allow" for result in findings
        ):
            raise PolicyBlocked(findings)
        return self.profile.policy.version

    def apply(
        self,
        network_id: UUID,
        expected_revision: int,
        change: Change,
        request_id: str,
        actor: str,
        *,
        execution: ExecutionGuard | None = None,
    ) -> NetworkSnapshot:
        return self._mutate(
            network_id,
            expected_revision,
            request_id,
            actor,
            lambda network: self._propose(network, change),
            execution=execution,
        )

    def restore(
        self,
        network_id: UUID,
        expected_revision: int,
        restore_revision: int,
        request_id: str,
        actor: str,
    ) -> NetworkSnapshot:
        return self._mutate(
            network_id,
            expected_revision,
            request_id,
            actor,
            lambda _: self.get_snapshot(network_id, restore_revision).network,
            restored_from=restore_revision,
        )

    def _mutate(
        self,
        network_id: UUID,
        expected_revision: int,
        request_id: str,
        actor: str,
        transform: Callable[[Network], Network],
        restored_from: int | None = None,
        *,
        execution: ExecutionGuard | None = None,
    ) -> NetworkSnapshot:
        current = self.get_snapshot(network_id)
        if current.revision != expected_revision:
            raise RevisionConflict
        candidate = transform(current.network)
        version = self._check_candidate(candidate)
        return self.repository.commit(
            candidate,
            expected_revision,
            "change" if restored_from is None else "restore",
            version,
            request_id,
            actor,
            restored_from,
            execution=execution,
        )

    @staticmethod
    def _propose(network: Network, change: Change) -> Network:
        if isinstance(change, PutFirewallRule):
            candidate = network.model_copy(
                update={"firewall_rules": upsert(network.firewall_rules, change.rule)}
            )
        elif isinstance(change, (PutStaticRoute, SetRoutingProtocols)):
            devices = {device.id: device for device in network.devices}
            device = devices.get(change.device_id)
            if device is None:
                raise NotFound
            if isinstance(change, PutStaticRoute):
                device = device.model_copy(
                    update={"routes": upsert(device.routes, change.route)}
                )
            else:
                device = device.model_copy(
                    update={"routing_protocols": change.protocols}
                )
            devices[device.id] = device
            candidate = network.model_copy(update={"devices": tuple(devices.values())})

        else:
            raise UnsupportedOperation

        try:
            return Network.model_validate_json(candidate.model_dump_json())
        except ValidationError as error:
            raise InvalidChange from error
