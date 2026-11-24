from collections.abc import Callable
from enum import StrEnum
from secrets import compare_digest
from time import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import TOKEN_PATTERN, Settings
from app.dashboard.sessions import COOKIE, WebSession, binding, csrf, digest


class Role(StrEnum):
    VIEWER = "viewer"
    ADMIN = "admin"


class Permission(StrEnum):
    READ_CAPABILITIES = "capabilities:read"
    READ_AUDIT = "audit:read"
    READ_NETWORK = "network:read"
    CHANGE_NETWORK = "network:change"
    USE_WORKFLOWS = "workflow:use"
    VIEW_SECURITY = "security:read"
    RUN_SECURITY = "security:run"
    APPROVE_WORKFLOW = "workflow:approve"


ROLE_PERMISSIONS = {
    Role.VIEWER: frozenset(
        {
            Permission.READ_CAPABILITIES,
            Permission.READ_NETWORK,
            Permission.USE_WORKFLOWS,
            Permission.VIEW_SECURITY,
        }
    ),
    Role.ADMIN: frozenset(
        {
            Permission.READ_CAPABILITIES,
            Permission.READ_AUDIT,
            Permission.READ_NETWORK,
            Permission.CHANGE_NETWORK,
            Permission.USE_WORKFLOWS,
            Permission.VIEW_SECURITY,
            Permission.APPROVE_WORKFLOW,
            Permission.RUN_SECURITY,
        }
    ),
}
bearer = HTTPBearer(auto_error=False, scheme_name="LocalBearer")
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def identify(settings: Settings, token: str) -> Role | None:
    if not TOKEN_PATTERN.fullmatch(token):
        return None
    viewer = compare_digest(token, settings.viewer_token.get_secret_value())
    admin = compare_digest(token, settings.admin_token.get_secret_value())
    return Role.ADMIN if admin else Role.VIEWER if viewer else None


def session_role(settings: Settings, request: Request) -> Role | None:
    if request.headers.get("Sec-Fetch-Site", "none") not in ("none", "same-origin"):
        return None
    token = request.cookies.get(COOKIE, "")
    if not TOKEN_PATTERN.fullmatch(token):
        return None
    with Session(request.app.state.engine) as session:
        entry = session.get(WebSession, digest(token))
        if entry is None or entry.expires <= int(time()):
            return None
        role = Role(entry.role)
        secret = settings.admin_token if role == Role.ADMIN else settings.viewer_token
        if not compare_digest(entry.binding, binding(secret.get_secret_value(), token)):
            return None
    if request.method not in ("GET", "HEAD", "OPTIONS") and not compare_digest(
        request.headers.get("X-CSRF-Token", "").encode(), csrf(token).encode()
    ):
        raise HTTPException(403)
    return role


def authorizer(settings: Settings, permission: Permission) -> Callable[..., None]:
    def require(request: Request, credentials: Credentials) -> None:
        role = (
            identify(settings, credentials.credentials)
            if credentials is not None
            else session_role(settings, request)
            if "authorization" not in request.headers
            else None
        )
        if role is None:
            raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})
        request.state.actor = role.value
        if permission not in ROLE_PERMISSIONS[role]:
            raise HTTPException(403)

    return require
