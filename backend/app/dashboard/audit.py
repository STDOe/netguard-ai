from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, TypeAdapter
from sqlalchemy import Engine, ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.network.driver import MockNetworkDriver
from app.network.errors import CorruptSnapshot
from app.network.models import Model
from app.network.policy import Finding
from app.storage import Base, audit_event
from app.workflows.models import hash_model

Status = Literal["pass", "fail", "unknown", "not_applicable"]
Severity = Literal["critical", "high", "medium", "low"]
WEIGHTS: dict[Severity, int] = {"critical": 10, "high": 5, "medium": 3, "low": 1}
LIMIT = (
    "Static mock configuration. No NAT, asymmetric routing or dataplane verification."
)


class Check(Model):
    check_id: str
    status: Status
    severity: Severity
    reason: str
    evidence: tuple[str, ...]
    scope: UUID
    network_revision: int
    policy_version: str | None
    timestamp: AwareDatetime
    limitations: str = LIMIT


class Score(Model):
    version: Literal["1.0"] = "1.0"
    value: int | None
    coverage: int


def score(checks: list[Check]) -> Score:
    total = sum(WEIGHTS[c.severity] for c in checks if c.status != "not_applicable")
    known = sum(WEIGHTS[c.severity] for c in checks if c.status in ("pass", "fail"))
    passed = sum(WEIGHTS[c.severity] for c in checks if c.status == "pass")
    coverage = 100 * known // total if total else 0
    return Score(
        value=100 * passed // total if coverage >= 70 else None, coverage=coverage
    )


class AuditRun(Base):
    __tablename__ = "security_audit_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    network_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("networks.id"), index=True
    )
    revision: Mapped[int] = mapped_column(Integer)
    snapshot_hash: Mapped[str | None] = mapped_column(String(64))
    policy_version: Mapped[str | None] = mapped_column(String(80))
    policy_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    score: Mapped[str] = mapped_column(Text)


class AuditFinding(Base):
    __tablename__ = "security_audit_findings"
    run_id: Mapped[str] = mapped_column(
        ForeignKey("security_audit_runs.id"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, primary_key=True)
    payload: Mapped[str] = mapped_column(Text)


class Report(Model):
    id: UUID
    network_id: UUID
    revision: int
    snapshot_hash: str | None
    policy_version: str | None
    policy_hash: str | None
    created_at: AwareDatetime
    score: Score
    findings: list[Check]
    current: bool


class Audits:
    def __init__(self, engine: Engine, driver: MockNetworkDriver) -> None:
        self.engine = engine
        self.driver = driver

    def active_policy_hash(self, network_id: UUID) -> str | None:
        profile = self.driver.profile
        return (
            hash_model(profile.policy)
            if profile and profile.network.id == network_id
            else None
        )

    def evaluate(
        self, network_id: UUID, revision: int
    ) -> tuple[str | None, list[Check]]:
        now = datetime.now(UTC)
        profile = self.driver.profile
        policy = (
            profile.policy if profile and profile.network.id == network_id else None
        )
        checks = []

        def add(
            check_id: str,
            status: Status,
            severity: Severity,
            reason: str,
            evidence: tuple[str, ...] = (),
        ) -> None:
            checks.append(
                Check(
                    check_id=check_id,
                    status=status,
                    severity=severity,
                    reason=reason,
                    evidence=evidence,
                    scope=network_id,
                    network_revision=revision,
                    timestamp=now,
                    policy_version=policy.version if policy else None,
                )
            )

        groups: tuple[tuple[str, Severity, tuple[str, ...], str], ...] = (
            (
                "segmentation",
                "high",
                ("profile.topology", "firewall.scope"),
                "Topology and zone membership",
            ),
            (
                "default_deny",
                "critical",
                ("firewall.default",),
                "Default deny and allowlist",
            ),
            (
                "routing",
                "high",
                ("routing.policy", "routing.destination"),
                "Routing policy and one-hop paths",
            ),
            (
                "firewall",
                "critical",
                (
                    "firewall.scope",
                    "firewall.isolation",
                    "firewall.default",
                    "traffic.path",
                ),
                "Firewall rule scope and modeled reachability",
            ),
            (
                "capabilities",
                "high",
                ("device.platform", "device.capability"),
                "Platform and routing capabilities",
            ),
        )
        audit_checks = (
            *groups,
            ("dmz_cash", "critical", (), "DMZ to Cash"),
            ("honeypot", "critical", (), "Honeypot isolation"),
        )
        try:
            saved = self.driver.get_snapshot(network_id, revision)
        except CorruptSnapshot:
            add(
                "integrity",
                "fail",
                "critical",
                "Stored snapshot failed integrity validation.",
            )
            for check_id, severity, _, title in audit_checks:
                add(
                    check_id,
                    "unknown",
                    severity,
                    f"{title} requires an intact snapshot.",
                )
            add("policy_version", "unknown", "high", "Snapshot integrity failed.")
            add("dataplane", "unknown", "medium", LIMIT)
            return None, checks
        network = saved.network
        add(
            "integrity",
            "pass",
            "critical",
            "Snapshot checksum and schema verified.",
            (saved.sha256,),
        )
        results = self.driver.check(saved)
        topology_unknown = any(f.rule_id == "profile.topology" for f in results)

        def status_for(items: list[Finding]) -> Status:
            if any(item.decision == "deny" for item in items):
                return "fail"
            if (
                policy is None
                or topology_unknown
                or any(item.decision == "unknown" for item in items)
            ):
                return "unknown"
            return "pass"

        for check_id, severity, rules, title in groups:
            matched = [item for item in results if item.rule_id in rules]
            evidence = tuple(
                f"{item.rule_id}: {', '.join(item.evidence)}" for item in matched[:50]
            )
            state = status_for(matched)
            add(
                check_id,
                state,
                severity,
                f"{title}. "
                + (
                    "; ".join(dict.fromkeys(item.reason for item in matched))
                    if matched
                    else "Evaluated against the stored revision and active profile."
                ),
                evidence,
            )
        dmz = {z.id for z in network.zones if "dmz" in z.name.casefold()}
        cash = {
            z.id
            for z in network.zones
            if any(word in z.name.casefold() for word in ("cash", "payment"))
        }
        decoy = {z.id for z in network.zones if "honeypot" in z.name.casefold()}
        for check_id, sources, targets in (
            ("dmz_cash", dmz, cash),
            ("honeypot", decoy, {z.id for z in network.zones} - decoy),
        ):
            allows = tuple(
                str(rule.id)
                for rule in network.firewall_rules
                if rule.action == "allow"
                and rule.source_zone in sources
                and rule.destination_zone in targets
            )
            exceptions = policy is not None and any(
                flow.source_zone in sources and flow.destination_zone in targets
                for flow in policy.allowed_flows
            )
            if not sources or not targets:
                add(
                    check_id,
                    "not_applicable",
                    "critical",
                    "The named trust zones are absent.",
                )
            elif allows or exceptions:
                add(
                    check_id,
                    "fail",
                    "critical",
                    "A rule or policy allowance opens an isolated direction.",
                    allows,
                )
            else:
                add(
                    check_id,
                    status_for([]),
                    "critical",
                    "No modeled allow crosses the isolated direction.",
                    tuple(str(zone) for zone in sorted(sources | targets)),
                )
        saved_version = self.driver.repository.revision_info(
            network_id, revision
        ).policy_version
        version_status: Status = (
            "unknown"
            if policy is None
            else "pass"
            if saved_version == policy.version
            else "fail"
        )
        add(
            "policy_version",
            version_status,
            "high",
            "Recorded policy version compared with the active profile.",
            (saved_version,),
        )
        add("dataplane", "unknown", "medium", LIMIT)
        return saved.sha256, checks

    def run(self, network_id: UUID, actor: str, request_id: str) -> Report:
        revision = self.driver.repository.current_revision(network_id)
        snapshot_hash, checks = self.evaluate(network_id, revision)
        report = Report(
            id=uuid4(),
            network_id=network_id,
            revision=revision,
            snapshot_hash=snapshot_hash,
            findings=checks,
            policy_version=checks[0].policy_version,
            created_at=checks[0].timestamp,
            policy_hash=self.active_policy_hash(network_id),
            score=score(checks),
            current=self.driver.repository.current_revision(network_id) == revision,
        )
        with Session(self.engine) as session, session.begin():
            session.add(
                AuditRun(
                    id=str(report.id),
                    network_id=str(network_id),
                    revision=revision,
                    snapshot_hash=snapshot_hash,
                    policy_version=report.policy_version,
                    policy_hash=report.policy_hash,
                    created_at=report.created_at.isoformat(),
                    score=report.score.model_dump_json(),
                )
            )
            session.flush()
            session.add_all(
                AuditFinding(
                    run_id=str(report.id), position=i, payload=item.model_dump_json()
                )
                for i, item in enumerate(checks)
            )
            session.add(
                audit_event(
                    request_id,
                    actor,
                    201,
                    event_type="security.audit",
                    network_id=network_id,
                    revision=revision,
                    policy_version=report.policy_version,
                )
            )
        return report

    def read(self, network_id: UUID, report_id: UUID | None = None) -> list[Report]:
        try:
            snapshot = self.driver.get_snapshot(network_id)
        except CorruptSnapshot:
            snapshot = None
        policy = self.active_policy_hash(network_id)
        with Session(self.engine) as session:
            query = select(AuditRun).where(AuditRun.network_id == str(network_id))
            if report_id is not None:
                query = query.where(AuditRun.id == str(report_id))
            runs = session.scalars(
                query.order_by(AuditRun.created_at.desc(), AuditRun.id.desc()).limit(10)
            )
            timestamps = TypeAdapter(AwareDatetime)
            return [
                Report(
                    id=UUID(run.id),
                    network_id=network_id,
                    revision=run.revision,
                    snapshot_hash=run.snapshot_hash,
                    policy_version=run.policy_version,
                    policy_hash=run.policy_hash,
                    created_at=timestamps.validate_python(run.created_at),
                    score=Score.model_validate_json(run.score),
                    current=(
                        snapshot is not None
                        and snapshot.revision == run.revision
                        and snapshot.sha256 == run.snapshot_hash
                        and policy == run.policy_hash
                    ),
                    findings=[
                        Check.model_validate_json(item)
                        for item in session.scalars(
                            select(AuditFinding.payload)
                            .where(AuditFinding.run_id == run.id)
                            .order_by(AuditFinding.position)
                        )
                    ],
                )
                for run in runs
            ]
