import asyncio
import hashlib
import hmac
import re
import time
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import HTTPException, Request
from pydantic import AwareDatetime, Field, StrictBool, ValidationError, field_validator
from sqlalchemy import Engine, Integer, String, Text, false, func, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column
from starlette.concurrency import run_in_threadpool

from app.network.driver import MockNetworkDriver
from app.network.errors import CorruptSnapshot, NotFound
from app.network.models import IPAddress, Model
from app.storage import Base, audit_event
from app.workflows.models import hash_model

MAX_BODY = 4096
WINDOW = 300
RATE = 30


class CanaryPayload(Model):
    event_id: UUID
    occurred_at: AwareDatetime
    source_ip: IPAddress
    destination_ip: IPAddress
    destination_port: Annotated[int, Field(strict=True, ge=1, le=65535)]
    service: Literal["http", "ssh", "ftp"]
    sensor: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,40}$")]
    demo: StrictBool

    @field_validator("occurred_at", mode="before")
    @classmethod
    def explicit_timestamp(cls, value: object) -> object:
        if isinstance(value, datetime) or (
            isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}T", value)
        ):
            return value
        raise ValueError("Expected an ISO 8601 timestamp with timezone")


class CanaryView(CanaryPayload):
    received_at: AwareDatetime
    inventory_device: UUID | None = None
    inventory_revision: int | None = None
    correlation: Literal["inventory_match", "unverified"] = "unverified"


class CanaryEvent(Base):
    __tablename__ = "honeypot_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    received: Mapped[int] = mapped_column(Integer, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)


class Honeypot:
    def __init__(
        self, engine: Engine, driver: MockNetworkDriver, secret: str | None
    ) -> None:
        self.engine = engine
        self.driver = driver
        self.secret = secret

    def events(self) -> list[CanaryView]:
        with Session(self.engine) as session:
            return [
                CanaryView.model_validate_json(row)
                for row in session.scalars(
                    select(CanaryEvent.payload)
                    .order_by(CanaryEvent.received.desc(), CanaryEvent.id)
                    .limit(50)
                )
            ]

    async def ingest(self, request: Request) -> CanaryView:
        if self.secret is None:
            raise HTTPException(503)
        stamp = request.headers.get("X-NetGuard-Timestamp", "")
        signature = request.headers.get("X-NetGuard-Signature", "")
        if not re.fullmatch(r"[0-9]{10}", stamp) or not re.fullmatch(
            r"sha256=[0-9a-f]{64}", signature
        ):
            raise HTTPException(401)
        now = int(time.time())
        if abs(now - int(stamp)) > WINDOW:
            raise HTTPException(401)
        body = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > MAX_BODY:
                        raise HTTPException(413)
                    body.extend(chunk)
        except TimeoutError:
            raise HTTPException(408) from None
        expected = hmac.digest(
            self.secret.encode(), stamp.encode() + b"." + body, hashlib.sha256
        ).hex()
        if not hmac.compare_digest(signature[7:], expected):
            raise HTTPException(401)
        try:
            event = CanaryPayload.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422) from None
        if abs(now - event.occurred_at.timestamp()) > WINDOW:
            raise HTTPException(422)
        return await run_in_threadpool(
            self.persist, event, now, request.state.request_id
        )

    def persist(self, event: CanaryPayload, now: int, request_id: str) -> CanaryView:
        with Session(self.engine) as session, session.begin():
            # Take the SQLite write lock before checking the replay and rate windows.
            session.execute(update(CanaryEvent).where(false()).values(received=now))
            duplicate = session.get(CanaryEvent, str(event.event_id))
            fingerprint = hash_model(event)
            if duplicate:
                if duplicate.fingerprint != fingerprint:
                    raise HTTPException(409)
                return CanaryView.model_validate_json(duplicate.payload)
            count = session.scalar(
                select(func.count())
                .select_from(CanaryEvent)
                .where(CanaryEvent.received > now - 60)
            )
            if count is not None and count >= RATE:
                raise HTTPException(429, headers={"Retry-After": "60"})
            matches: list[tuple[UUID, int]] = []
            profile = self.driver.profile
            try:
                snapshot = (
                    self.driver.get_snapshot(profile.network.id) if profile else None
                )
            except (CorruptSnapshot, NotFound):
                snapshot = None
            if snapshot is not None:
                network = snapshot.network
                zones = {
                    zone.id
                    for zone in network.zones
                    if "honeypot" in zone.name.casefold()
                }
                vlans = {vlan.id for vlan in network.vlans if vlan.zone_id in zones}
                subnets = {
                    subnet.id for subnet in network.subnets if subnet.vlan_id in vlans
                }
                matches = [
                    (device.id, snapshot.revision)
                    for device in network.devices
                    for port in device.interfaces
                    if port.address == event.destination_ip
                    and port.subnet_id in subnets
                ]
            view = CanaryView(
                **event.model_dump(),
                received_at=datetime.fromtimestamp(now, UTC),
                correlation="inventory_match" if len(matches) == 1 else "unverified",
                inventory_device=matches[0][0] if len(matches) == 1 else None,
                inventory_revision=matches[0][1] if len(matches) == 1 else None,
            )
            session.add(
                CanaryEvent(
                    id=str(view.event_id),
                    received=now,
                    payload=view.model_dump_json(),
                    fingerprint=fingerprint,
                )
            )
            session.add(
                audit_event(request_id, "honeypot", 200, event_type="honeypot.received")
            )
        return view
