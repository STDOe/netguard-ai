import hashlib
import hmac
import time
from secrets import token_urlsafe

from sqlalchemy import Integer, String, delete
from sqlalchemy.orm import Mapped, Session, mapped_column

from app.storage import Base, audit_event

COOKIE = "netguard_session"
LIFETIME = 8 * 60 * 60


class WebSession(Base):
    __tablename__ = "web_sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    role: Mapped[str] = mapped_column(String(16))
    expires: Mapped[int] = mapped_column(Integer, index=True)
    binding: Mapped[str] = mapped_column(String(64))


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def binding(secret: str, token: str) -> str:
    return hmac.digest(
        secret.encode(), f"netguard-session:{token}".encode(), "sha256"
    ).hex()


def csrf(token: str) -> str:
    return digest(f"netguard-csrf:{token}")


def issue(session: Session, role: str, secret: str, request_id: str) -> str:
    now = int(time.time())
    token = token_urlsafe(32)
    session.execute(delete(WebSession).where(WebSession.expires <= now))
    session.add(
        WebSession(
            id=digest(token),
            role=role,
            expires=now + LIFETIME,
            binding=binding(secret, token),
        )
    )
    session.add(audit_event(request_id, role, 204, event_type="web.login"))
    return token
