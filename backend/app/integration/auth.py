from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from ipaddress import ip_address
from re import fullmatch
from secrets import compare_digest
from threading import Lock
from time import monotonic
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import Scope, Settings
from app.storage import Storage, audit_event
from app.workflows.models import WorkflowError

bearer = HTTPBearer(auto_error=False, scheme_name="IntegrationBearer")
Credential = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


class IntegrationAuth:
    def __init__(self, settings: Settings, storage: Storage) -> None:
        self.settings = settings
        self.storage = storage
        self.owner = f"service:{settings.integration_caller}"
        self.workspace = settings.integration_workspace
        self.lock = Lock()
        self.attempts: deque[float] = deque()

    def admit(self) -> None:
        if not self.settings.integration_enabled:
            raise WorkflowError(404, "integration_disabled")
        with self.lock:
            now = monotonic()
            while self.attempts and self.attempts[0] <= now - 60:
                self.attempts.popleft()
            if len(self.attempts) >= 120:
                raise WorkflowError(429, "integration_rate_limited")
            self.attempts.append(now)

    def verify(self, request: Request, supplied: Credential, scope: Scope) -> None:
        settings = self.settings
        request.state.integration_auth = True
        loopback = False
        if request.client is not None:
            try:
                loopback = ip_address(request.client.host).is_loopback
            except ValueError:
                pass
        if request.url.scheme != "https" and (
            not loopback
            or any(
                header in request.headers
                for header in ("forwarded", "x-forwarded-for", "x-forwarded-proto")
            )
        ):
            self.record(request, None, 403)
            raise WorkflowError(403, "tls_required")
        token = supplied.credentials if supplied else ""
        digest = settings.integration_token_sha256
        expiry = settings.integration_expires_at
        if (
            not fullmatch(r"ngw\.[A-Za-z0-9_-]{43}", token)
            or digest is None
            or expiry is None
            or expiry <= datetime.now(UTC)
            or not compare_digest(
                digest.get_secret_value(), sha256(token.encode()).hexdigest()
            )
        ):
            self.record(request, None, 401)
            raise WorkflowError(401, "integration_unauthenticated")
        request.state.actor = self.owner
        allowed = scope in settings.integration_scopes
        self.record(request, self.owner, 200 if allowed else 403)
        if not allowed:
            raise WorkflowError(403, "integration_scope_denied")

    def record(self, request: Request, owner: str | None, status: int) -> None:
        self.storage.record_event(
            audit_event(
                request.state.request_id,
                owner,
                status,
                event_type="integration.authorization",
            )
        )

    def require(self, scope: Scope) -> Callable[..., None]:
        def check(request: Request, credential: Credential) -> None:
            self.verify(request, credential, scope)

        return check

    def check_workspace(self, request: Request, workspace: str) -> None:
        if workspace != self.workspace:
            self.record(request, self.owner, 403)
            raise WorkflowError(403, "integration_workspace_denied")
