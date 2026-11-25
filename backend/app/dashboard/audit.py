from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, TypeAdapter, ValidationError
from sqlalchemy import Engine, ForeignKey, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.network.driver import MockNetworkDriver
from app.network.errors import CorruptSnapshot, NotFound
from app.network.models import Model, NetworkSnapshot
from app.network.policy import Finding
from app.storage import Base, audit_event
from app.workflows.models import hash_model

Status = Literal["pass", "fail", "unknown", "not_applicable"]
Severity = Literal["critical", "high", "medium", "low"]
WEIGHTS: dict[Severity, int] = {"critical": 10, "high": 5, "medium": 3, "low": 1}
LIMIT = (
    "Static mock configuration. No NAT, asymmetric routing or dataplane verification."
)


REACHABILITY_RULES = ("traffic.model", "traffic.routing")
GROUPS: tuple[tuple[str, Severity, tuple[str, ...], str], ...] = (
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
        ("routing.policy", "routing.destination", *REACHABILITY_RULES),
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
            *REACHABILITY_RULES,
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
AUDIT_CHECKS = (
    *GROUPS,
    ("dmz_cash", "critical", REACHABILITY_RULES, "DMZ to Cash"),
    ("honeypot", "critical", REACHABILITY_RULES, "Honeypot isolation"),
)
REQUIRED_SEVERITIES = {
    **{check_id: severity for check_id, severity, _, _ in AUDIT_CHECKS},
    "integrity": "critical",
    "policy_version": "high",
    "dataplane": "medium",
}


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


CHECKS = TypeAdapter(list[Check])


def findings_hash(checks: list[Check]) -> str:
    return sha256(CHECKS.dump_json(checks)).hexdigest()


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
    profile_hash: Mapped[str | None] = mapped_column(String(64))
    findings_hash: Mapped[str | None] = mapped_column(String(64))
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
    evidence_status: Literal["valid", "corrupt"] = "valid"
    profile_hash: str | None = None
    current: bool


class Audits:
    def __init__(self, engine: Engine, driver: MockNetworkDriver) -> None:
        self.engine = engine
        self.driver = driver

    def current_snapshot(self, network_id: UUID) -> NetworkSnapshot | None:
        try:
            return self.driver.get_snapshot(network_id)
        except CorruptSnapshot:
            return None
        except NotFound:
            # An absent revision of a registered network is an integrity failure.
            self.driver.repository.current_revision(network_id)
            return None

    def profile_hash(self, network_id: UUID) -> str | None:
        profile = self.driver.profile
        return (
            hash_model(profile)
            if profile and profile.network.id == network_id
            else None
        )

    @staticmethod
    def is_current(
        snapshot: NetworkSnapshot | None,
        revision: int,
        snapshot_hash: str | None,
        saved_profile: str | None,
        active_profile: str | None,
    ) -> bool:
        return (
            snapshot is not None
            and snapshot.revision == revision
            and snapshot.sha256 == snapshot_hash
            and saved_profile is not None
            and saved_profile == active_profile
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

        try:
            saved = self.driver.get_snapshot(network_id, revision)
        except (CorruptSnapshot, NotFound):
            add(
                "integrity",
                "fail",
                "critical",
                "Stored snapshot failed integrity validation.",
            )
            for check_id, severity, _, title in AUDIT_CHECKS:
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

        for check_id, severity, rules, title in GROUPS:
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
                evidence or (saved.sha256,),
            )
        dmz = {z.id for z in network.zones if "dmz" in z.name.casefold()}
        cash = {
            z.id
            for z in network.zones
            if any(word in z.name.casefold() for word in ("cash", "payment"))
        }
        decoy = {z.id for z in network.zones if "honeypot" in z.name.casefold()}
        reachability = [item for item in results if item.rule_id in REACHABILITY_RULES]
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
                    status_for(reachability),
                    "critical",
                    " ".join(dict.fromkeys(f.reason for f in reachability))
                    or "No modeled allow crosses the isolated direction.",
                    tuple(str(zone) for zone in sorted(sources | targets))
                    + tuple(dict.fromkeys(f.rule_id for f in reachability)),
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
        report_id = uuid4()
        with Session(self.engine) as session, session.begin():
            self.persist(session, network_id, actor, request_id, report_id)
        return self.read(network_id, report_id)[0]

    def persist(
        self,
        session: Session,
        network_id: UUID,
        actor: str,
        request_id: str,
        report_id: UUID,
    ) -> None:
        revision = self.driver.repository.current_revision(network_id)
        snapshot_hash, checks = self.evaluate(network_id, revision)
        profile = self.driver.profile
        profile_hash = self.profile_hash(network_id)
        policy_version = checks[0].policy_version
        session.add(
            AuditRun(
                id=str(report_id),
                network_id=str(network_id),
                revision=revision,
                snapshot_hash=snapshot_hash,
                policy_version=policy_version,
                policy_hash=hash_model(profile.policy)
                if profile_hash and profile
                else None,
                profile_hash=profile_hash,
                findings_hash=findings_hash(checks),
                created_at=checks[0].timestamp.isoformat(),
                score=score(checks).model_dump_json(),
            )
        )
        session.flush()
        session.add_all(
            AuditFinding(
                run_id=str(report_id), position=i, payload=item.model_dump_json()
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
                policy_version=policy_version,
            )
        )

    def read(self, network_id: UUID, report_id: UUID | None = None) -> list[Report]:
        snapshot = self.current_snapshot(network_id)
        profile_hash = self.profile_hash(network_id)
        with Session(self.engine) as session:
            query = select(AuditRun).where(AuditRun.network_id == str(network_id))
            if report_id is not None:
                query = query.where(AuditRun.id == str(report_id))
            runs = session.scalars(
                query.order_by(AuditRun.created_at.desc(), AuditRun.id.desc()).limit(10)
            )
            return [
                self.saved_report(session, run, snapshot, profile_hash) for run in runs
            ]

    def saved_report(
        self,
        session: Session,
        run: AuditRun,
        snapshot: NetworkSnapshot | None,
        active_profile: str | None,
    ) -> Report:
        network_id = UUID(run.network_id)
        created_at = TypeAdapter(AwareDatetime).validate_python(run.created_at)
        payloads = session.scalars(
            select(AuditFinding.payload)
            .where(AuditFinding.run_id == run.id)
            .order_by(AuditFinding.position)
        )
        try:
            findings = [Check.model_validate_json(payload) for payload in payloads]
            computed = score(findings)
            valid = (
                len(findings) == len(REQUIRED_SEVERITIES)
                and {f.check_id: f.severity for f in findings} == REQUIRED_SEVERITIES
                and all(
                    f.scope == network_id
                    and f.network_revision == run.revision
                    and f.policy_version == run.policy_version
                    and f.timestamp == created_at
                    for f in findings
                )
                and computed == Score.model_validate_json(run.score, strict=True)
                and (
                    findings_hash(findings) == run.findings_hash
                    or run.findings_hash is None
                    and run.profile_hash is None
                )
            )
        except ValidationError:
            valid = False
        return Report(
            id=UUID(run.id),
            network_id=network_id,
            revision=run.revision,
            snapshot_hash=run.snapshot_hash,
            policy_version=run.policy_version,
            policy_hash=run.policy_hash,
            profile_hash=run.profile_hash,
            created_at=created_at,
            findings=findings if valid else [],
            evidence_status="valid" if valid else "corrupt",
            score=computed if valid else Score(value=None, coverage=0),
            current=valid
            and self.is_current(
                snapshot,
                run.revision,
                run.snapshot_hash,
                run.profile_hash,
                active_profile,
            ),
        )
