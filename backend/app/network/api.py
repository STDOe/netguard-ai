from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request

from app.config import Settings
from app.contracts import ErrorResponse
from app.network.driver import Change, MockNetworkDriver
from app.network.errors import (
    CorruptSnapshot,
    InvalidChange,
    NetworkError,
    NotFound,
    PolicyBlocked,
    RevisionConflict,
    UnsupportedOperation,
)
from app.network.models import (
    MAX_REVISION,
    Model,
    NetworkDevice,
    NetworkSnapshot,
    Revision,
)
from app.network.policy import Finding
from app.network.repository import NetworkSummary, RevisionInfo
from app.security import Permission, authorizer

FAILURES: dict[type[NetworkError], tuple[int, str]] = {
    NotFound: (404, "Network object or revision not found"),
    RevisionConflict: (409, "The current revision differs from the expected revision"),
    CorruptSnapshot: (409, "Snapshot integrity verification failed"),
    InvalidChange: (422, "Change violates network model constraints"),
    UnsupportedOperation: (422, "Operation is unsupported by the mock driver"),
    PolicyBlocked: (403, "The active policy did not allow the change"),
}


class NetworkErrorResponse(ErrorResponse):
    findings: tuple[Finding, ...] | None = None


class ApplyRequest(Model):
    expected_revision: Revision
    change: Change


class RestoreRequest(Model):
    expected_revision: Revision
    snapshot_revision: Revision


class PolicyReport(Model):
    revision: Revision
    findings: tuple[Finding, ...]


def network_router(settings: Settings, driver: MockNetworkDriver) -> APIRouter:
    errors: dict[int | str, dict[str, object]] = {
        status: {"model": NetworkErrorResponse}
        for status in (401, 403, 404, 409, 422, 500, 503)
    }
    router = APIRouter(prefix="/api/v1/networks", tags=["networks"], responses=errors)
    read = Depends(authorizer(settings, Permission.READ_NETWORK))
    change = Depends(authorizer(settings, Permission.CHANGE_NETWORK))

    @router.get("", dependencies=[read])
    def networks() -> list[NetworkSummary]:
        return driver.repository.summaries()

    @router.get("/{network_id}/topology", dependencies=[read])
    def topology(network_id: UUID) -> NetworkSnapshot:
        return driver.get_snapshot(network_id)

    @router.get("/{network_id}/devices/{device_id}", dependencies=[read])
    def device(network_id: UUID, device_id: UUID) -> NetworkDevice:
        return driver.get_device(network_id, device_id)

    @router.get("/{network_id}/policy", dependencies=[read])
    def policy(network_id: UUID) -> PolicyReport:
        snapshot = driver.get_snapshot(network_id)
        return PolicyReport(
            revision=snapshot.revision,
            findings=driver.check(snapshot),
        )

    @router.get("/{network_id}/revisions", dependencies=[read])
    def revisions(
        network_id: UUID,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        before_revision: Annotated[int, Query(ge=1, le=MAX_REVISION)] | None = None,
    ) -> list[RevisionInfo]:
        return driver.repository.history(network_id, limit, before_revision)

    @router.get("/{network_id}/snapshots/{revision}", dependencies=[read])
    def snapshot(
        network_id: UUID, revision: Annotated[int, Path(ge=1, le=MAX_REVISION)]
    ) -> NetworkSnapshot:
        return driver.get_snapshot(network_id, revision)

    @router.post("/{network_id}/changes", dependencies=[change])
    def apply(
        network_id: UUID, body: ApplyRequest, request: Request
    ) -> NetworkSnapshot:
        request.state.network_attempt = (
            "network.change",
            network_id,
            body.expected_revision,
        )
        return driver.apply(
            network_id,
            body.expected_revision,
            body.change,
            request.state.request_id,
            request.state.actor,
        )

    @router.post("/{network_id}/restore", dependencies=[change])
    def restore(
        network_id: UUID, body: RestoreRequest, request: Request
    ) -> NetworkSnapshot:
        request.state.network_attempt = (
            "network.restore",
            network_id,
            body.expected_revision,
        )
        return driver.restore(
            network_id,
            body.expected_revision,
            body.snapshot_revision,
            request.state.request_id,
            request.state.actor,
        )

    return router


def failure(error: NetworkError) -> tuple[int, str, tuple[Finding, ...] | None]:
    status, message = FAILURES.get(type(error), (500, "Internal server error"))
    return status, message, error.findings if isinstance(error, PolicyBlocked) else None
