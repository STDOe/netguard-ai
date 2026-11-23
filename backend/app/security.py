from collections.abc import Callable
from enum import StrEnum
from secrets import compare_digest
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import TOKEN_PATTERN, Settings


class Role(StrEnum):
    VIEWER = "viewer"
    ADMIN = "admin"


class Permission(StrEnum):
    READ_CAPABILITIES = "capabilities:read"
    READ_AUDIT = "audit:read"
    READ_NETWORK = "network:read"
    CHANGE_NETWORK = "network:change"


ROLE_PERMISSIONS = {
    Role.VIEWER: frozenset({Permission.READ_CAPABILITIES, Permission.READ_NETWORK}),
    Role.ADMIN: frozenset(
        {
            Permission.READ_CAPABILITIES,
            Permission.READ_AUDIT,
            Permission.READ_NETWORK,
            Permission.CHANGE_NETWORK,
        }
    ),
}
bearer = HTTPBearer(auto_error=False, scheme_name="LocalBearer")
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def authorizer(settings: Settings, permission: Permission) -> Callable[..., None]:
    viewer = settings.viewer_token.get_secret_value()
    admin = settings.admin_token.get_secret_value()

    def require(request: Request, credentials: Credentials) -> None:
        if credentials is None or not TOKEN_PATTERN.fullmatch(credentials.credentials):
            raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})

        viewer_match = compare_digest(credentials.credentials, viewer)
        admin_match = compare_digest(credentials.credentials, admin)
        if not viewer_match and not admin_match:
            raise HTTPException(401, headers={"WWW-Authenticate": "Bearer"})

        role = Role.ADMIN if admin_match else Role.VIEWER
        request.state.actor = role.value
        if permission not in ROLE_PERMISSIONS[role]:
            raise HTTPException(403)

    return require
