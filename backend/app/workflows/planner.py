import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError

from app.config import Settings
from app.network.driver import MockNetworkDriver, PutFirewallRule, PutStaticRoute
from app.network.errors import InvalidChange, NotFound, PolicyBlocked
from app.network.models import NetworkSnapshot, StaticRoute
from app.workflows.llm_worker import PlannerReply
from app.workflows.models import (
    ChangeIntent,
    Diff,
    FieldDiff,
    FindStaticRoute,
    Goal,
    Plan,
    PlanBody,
    WorkflowError,
    hash_model,
)

INTENT = TypeAdapter(ChangeIntent)


class PlannerProvider(Protocol):
    def choose(self, candidates: tuple[ChangeIntent, ...]) -> ChangeIntent: ...


class OfflinePlanner:
    def choose(self, candidates: tuple[ChangeIntent, ...]) -> ChangeIntent:
        if len(candidates) != 1:
            raise WorkflowError(409, "ambiguous_route")
        return candidates[0]


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    option: int


class LiteLLMPlanner:
    def __init__(self, settings: Settings) -> None:
        self.model = settings.llm_model
        self.base = settings.llm_api_base
        self.key = settings.llm_api_key

    def choose(self, candidates: tuple[ChangeIntent, ...]) -> ChangeIntent:
        options = [
            {"option": i, "kind": intent.kind} for i, intent in enumerate(candidates)
        ]
        request = {
            "model": self.model,
            "base": self.base,
            "key": None if self.key is None else self.key.get_secret_value(),
            "options": options,
        }
        # A stalled SDK call must release the task even if it ignores its HTTP timeout.
        try:
            process = subprocess.run(
                [sys.executable, "-m", "app.workflows.llm_worker"],
                input=json.dumps(request),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=True,
            )
            reply = PlannerReply.model_validate_json(process.stdout)
        except subprocess.TimeoutExpired:
            raise WorkflowError(502, "llm_timeout") from None
        except (OSError, subprocess.CalledProcessError, ValidationError):
            raise WorkflowError(502, "llm_unavailable") from None
        if reply.error:
            raise WorkflowError(502, reply.error)
        text = reply.text
        if not isinstance(text, str) or len(text) > 128:
            raise WorkflowError(422, "invalid_llm_output")
        try:
            index = Selection.model_validate_json(text).option
        except ValidationError:
            raise WorkflowError(422, "invalid_llm_output") from None
        if not 0 <= index < len(candidates):
            raise WorkflowError(422, "llm_scope_mismatch")
        return candidates[index]


def candidates_for(
    task_id: UUID, snapshot: NetworkSnapshot, goal: Goal
) -> tuple[ChangeIntent, ...]:
    if not isinstance(goal, FindStaticRoute):
        return (goal,)
    network = snapshot.network
    device = next((item for item in network.devices if item.id == goal.device_id), None)
    if device is None:
        raise NotFound
    destination = next(
        (
            item
            for item in network.subnets
            if item.prefix == goal.destination and item.vlan_id
        ),
        None,
    )
    if destination is None:
        raise WorkflowError(422, "unsupported_route")
    ports = {port.id: port for port in device.interfaces}
    peer_ports = {
        port.id: port
        for peer in network.devices
        if peer.id != device.id
        and any(port.subnet_id == destination.id for port in peer.interfaces)
        for port in peer.interfaces
    }
    results: list[ChangeIntent] = []
    for link in network.links:
        left, right = link.endpoints
        for local_id, peer_id in ((left, right), (right, left)):
            if local_id not in ports or peer_id not in peer_ports:
                continue
            route = StaticRoute(
                id=uuid5(task_id, f"{local_id}:{peer_id}:{goal.destination}"),
                destination=goal.destination,
                interface_id=local_id,
                next_hop=peer_ports[peer_id].address,
            )
            results.append(
                PutStaticRoute(
                    kind="put_static_route", device_id=device.id, route=route
                )
            )
    if not results or len(results) > 8:
        raise WorkflowError(422, "unsupported_route")
    return tuple(results)


def choose_intent(
    provider: PlannerProvider,
    driver: MockNetworkDriver,
    task_id: UUID,
    snapshot: NetworkSnapshot,
    goal: Goal,
) -> ChangeIntent:
    candidates = candidates_for(task_id, snapshot, goal)
    if len(candidates) > 1:
        allowed = []
        rejected: list[InvalidChange | PolicyBlocked] = []
        for candidate in candidates:
            try:
                render(driver, snapshot, candidate)
            except (PolicyBlocked, InvalidChange) as error:
                rejected.append(error)
            else:
                allowed.append(candidate)
        if not allowed:
            raise rejected[0]
        candidates = tuple(allowed)
    if len(candidates) == 1:
        return candidates[0]
    chosen = provider.choose(candidates)
    if chosen not in candidates:
        raise WorkflowError(422, "llm_scope_mismatch")
    return chosen


def render(
    driver: MockNetworkDriver, snapshot: NetworkSnapshot, intent: ChangeIntent
) -> Diff:
    candidate, findings = driver.preview(snapshot, intent)
    if not findings or any(item.decision != "allow" for item in findings):
        raise PolicyBlocked(findings)
    before = snapshot.network.model_dump(mode="json")
    after = candidate.model_dump(mode="json")
    if isinstance(intent, PutFirewallRule):
        target_id = snapshot.network.id
        field = "firewall_rules"
    else:
        target_id = intent.device_id
        field = "routes" if isinstance(intent, PutStaticRoute) else "routing_protocols"
        before = next(
            item for item in before["devices"] if item["id"] == str(target_id)
        )
        after = next(item for item in after["devices"] if item["id"] == str(target_id))
    fields = (
        ()
        if before[field] == after[field]
        else (FieldDiff(path=field, before=before[field], after=after[field]),)
    )
    return Diff(
        target_id=target_id,
        original_revision=snapshot.revision,
        risk="high"
        if isinstance(intent, PutFirewallRule) and intent.rule.action == "allow"
        else "moderate",
        fields=fields,
        expected_config_sha256=hash_model(candidate),
        findings=findings,
    )


def build_plan(
    driver: MockNetworkDriver,
    task_id: UUID,
    snapshot: NetworkSnapshot,
    intent: ChangeIntent,
    diff: Diff,
    ttl_seconds: int,
) -> Plan:
    profile = driver.profile
    if profile is None:
        raise PolicyBlocked(driver.check(snapshot))
    timestamp = datetime.now(UTC)
    body = PlanBody(
        plan_id=uuid5(task_id, "plan-v1"),
        task_id=task_id,
        network_id=snapshot.network.id,
        base_revision=snapshot.revision,
        base_snapshot_sha256=snapshot.sha256,
        policy_version=profile.policy.version,
        policy_sha256=hash_model(profile.policy),
        change_intent=intent,
        diff=diff,
        risk=diff.risk,
        created_at=timestamp,
        expires_at=timestamp + timedelta(seconds=ttl_seconds),
    )
    return Plan(**body.model_dump(), plan_hash=hash_model(body))
