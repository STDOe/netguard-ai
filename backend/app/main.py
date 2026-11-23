import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from uuid import uuid4

from alembic.script import ScriptDirectory
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import contracts
from app.config import Settings
from app.network.api import NetworkErrorResponse, failure, network_router
from app.network.driver import MockNetworkDriver
from app.network.errors import NetworkError, PolicyBlocked
from app.network.policy import load_profile
from app.network.repository import NetworkRepository
from app.security import Permission, authorizer
from app.storage import Storage, audit_event, sqlite_engine

logger = logging.getLogger("netguard.request")
if not logger.handlers:
    logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)
logger.propagate = False

ERRORS = {
    401: ("unauthenticated", "Authentication required"),
    403: ("forbidden", "Permission denied"),
    404: ("not_found", "Resource not found"),
    405: ("method_not_allowed", "Method not allowed"),
    422: ("invalid_request", "Request validation failed"),
    500: ("internal_error", "Internal server error"),
    503: ("unavailable", "Service unavailable"),
}


def error_response(
    request: Request, status: int, headers: Mapping[str, str] | None = None
) -> JSONResponse:
    code, message = ERRORS.get(status, ("request_failed", "Request failed"))
    body = contracts.ErrorResponse(
        error=contracts.ErrorDetail(
            code=code, message=message, request_id=request.state.request_id
        )
    )
    return JSONResponse(body.model_dump(), status_code=status, headers=headers)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings if settings is not None else Settings.model_validate({})
    storage = Storage(sqlite_engine(settings.database_path))
    networks = NetworkRepository(storage.engine)
    driver = MockNetworkDriver(networks, load_profile(settings.profile_path))
    versions = ScriptDirectory(str(Path(__file__).resolve().parents[1] / "migrations"))
    expected_heads = set(versions.get_heads())

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        try:
            try:
                if settings.database_path.is_file() and storage.check_ready(
                    expected_heads
                ):
                    networks.check_ready()
                    driver.initialize()
            except (SQLAlchemyError, PolicyBlocked):
                logger.warning(
                    json.dumps({"event": "network_initialization_unavailable"})
                )
            yield
        finally:
            await run_in_threadpool(storage.engine.dispose)

    app = FastAPI(
        title="NetGuard AI",
        version="0.1.0",
        lifespan=lifespan,
        openapi_url=None,
        docs_url=None,
        redoc_url=None,
    )

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = str(uuid4())
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            response = error_response(request, 500)

        audit_write_failed = getattr(request.state, "audit_write_failed", False)
        if response.status_code in (401, 403) and not getattr(
            request.state, "network_attempt", None
        ):
            try:
                await run_in_threadpool(
                    storage.record_denial,
                    request_id,
                    getattr(request.state, "actor", None),
                    response.status_code,
                )
            except SQLAlchemyError:
                audit_write_failed = True

        route = request.scope.get("route")
        logger.info(
            json.dumps(
                {
                    "event": "request_completed",
                    "request_id": request_id,
                    "route": getattr(route, "path", None),
                    "status": response.status_code,
                    "audit_write_failed": audit_write_failed,
                }
            )
        )
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(
        request: Request, error: StarletteHTTPException
    ) -> JSONResponse:
        return error_response(request, error.status_code, error.headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, _: RequestValidationError
    ) -> JSONResponse:
        return error_response(request, 422)

    @app.exception_handler(NetworkError)
    async def handle_network_error(
        request: Request, error: NetworkError
    ) -> JSONResponse:
        status, message, findings = failure(error)
        request_id = request.state.request_id
        attempt = getattr(request.state, "network_attempt", None)
        if attempt is not None:
            event_type, network_id, revision = attempt
            try:
                await run_in_threadpool(
                    storage.record_event,
                    audit_event(
                        request_id,
                        request.state.actor,
                        status,
                        event_type=event_type,
                        network_id=network_id,
                        revision=revision,
                        policy_version=None
                        if not findings
                        else findings[0].policy_version,
                    ),
                )
            except SQLAlchemyError:
                request.state.audit_write_failed = True
        body = NetworkErrorResponse(
            error=contracts.ErrorDetail(
                code=error.code, message=message, request_id=request_id
            ),
            findings=findings,
        )
        return JSONResponse(
            body.model_dump(
                mode="json", exclude={"findings"} if findings is None else None
            ),
            status_code=status,
        )

    @app.exception_handler(SQLAlchemyError)
    async def handle_storage_error(
        request: Request, _: SQLAlchemyError
    ) -> JSONResponse:
        if getattr(request.state, "network_attempt", None):
            request.state.audit_write_failed = True
        return error_response(request, 503)

    error_schema: dict[str, object] = {"model": contracts.ErrorResponse}
    api = APIRouter(prefix="/api/v1", responses={500: error_schema})
    read_capabilities = Depends(authorizer(settings, Permission.READ_CAPABILITIES))
    read_audit = Depends(authorizer(settings, Permission.READ_AUDIT))
    protected_errors: dict[int | str, dict[str, object]] = {
        401: error_schema,
        403: error_schema,
    }

    @api.get("/health/live")
    def live() -> contracts.Health:
        return contracts.Health()

    @api.get("/health/ready", responses={503: error_schema})
    def ready() -> contracts.Health:
        try:
            if settings.database_path.is_file() and storage.check_ready(expected_heads):
                networks.check_ready()
                return contracts.Health()
        except SQLAlchemyError as error:
            raise HTTPException(503) from error
        raise HTTPException(503)

    @api.get(
        "/capabilities", dependencies=[read_capabilities], responses=protected_errors
    )
    def capabilities() -> contracts.Capabilities:
        return contracts.Capabilities()

    @api.get(
        "/audit/events",
        dependencies=[read_audit],
        responses={**protected_errors, 422: error_schema, 503: error_schema},
    )
    def audit_events(
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
        include_network: bool = False,
    ) -> contracts.AuditResponse:
        try:
            events = storage.recent_events(limit, denials_only=not include_network)
        except SQLAlchemyError as error:
            raise HTTPException(503) from error
        return contracts.AuditResponse(
            events=[contracts.AuditEntry.model_validate(event) for event in events]
        )

    @api.get("/openapi.json", dependencies=[read_capabilities], include_in_schema=False)
    def openapi() -> JSONResponse:
        return JSONResponse(app.openapi())

    app.include_router(api)
    app.include_router(network_router(settings, driver))
    return app
