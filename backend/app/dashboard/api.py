from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request

from app.config import Settings
from app.dashboard.audit import Audits, Report
from app.dashboard.honeypot import CanaryView, Honeypot
from app.network.repository import AuditTarget
from app.security import Permission, authorizer


def security_router(
    settings: Settings, audits: Audits, honeypot: Honeypot
) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["security"])
    view = Depends(authorizer(settings, Permission.VIEW_SECURITY))
    run = Depends(authorizer(settings, Permission.RUN_SECURITY))

    @router.get("/audit/networks", dependencies=[view])
    def audit_targets() -> list[AuditTarget]:
        return audits.driver.repository.audit_targets()

    @router.post("/networks/{network_id}/audits", dependencies=[run], status_code=201)
    def create_audit(network_id: UUID, request: Request) -> Report:
        return audits.run(network_id, request.state.actor, request.state.request_id)

    @router.get("/networks/{network_id}/audits", dependencies=[view])
    def list_audits(network_id: UUID) -> list[Report]:
        return audits.read(network_id)

    @router.get("/networks/{network_id}/audits/{report_id}", dependencies=[view])
    def get_audit(network_id: UUID, report_id: UUID) -> Report:
        reports = audits.read(network_id, report_id)
        if not reports:
            raise HTTPException(404)
        return reports[0]

    @router.post("/webhooks/honeypot")
    async def webhook(request: Request) -> CanaryView:
        return await honeypot.ingest(request)

    @router.get("/honeypot/events", dependencies=[view])
    def canary_events() -> list[CanaryView]:
        return honeypot.events()

    return router
