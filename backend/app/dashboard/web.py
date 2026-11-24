import asyncio
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import Engine, delete
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.dashboard.sessions import COOKIE, LIFETIME, WebSession, csrf, digest, issue
from app.network.models import Model
from app.security import ROLE_PERMISSIONS, Permission, identify, session_role
from app.storage import Storage, audit_event

ROOT = Path(__file__).parent
NAV = {
    "overview": ("Overview", "▦"),
    "topology": ("Network Topology", "◇"),
    "workspace": ("AI Workspace", "✧"),
    "greenfield": ("Greenfield Designer", "⊞"),
    "approvals": ("Change Plans & Approvals", "✓"),
    "audit": ("Security Audit", "◎"),
    "honeypot": ("Honeypot Events", "⬡"),
    "activity": ("Activity / History", "≡"),
}


class Login(Model):
    token: str


def web_router(settings: Settings, engine: Engine, storage: Storage) -> APIRouter:
    router = APIRouter(include_in_schema=False)
    templates = Jinja2Templates(directory=ROOT / "templates")

    def render(request: Request, name: str, **context: object) -> Response:
        return templates.TemplateResponse(request=request, name=name, context=context)

    @router.get("/", response_class=HTMLResponse)
    @router.get("/dashboard", response_class=HTMLResponse)
    @router.get("/dashboard/{page}", response_class=HTMLResponse)
    def dashboard(request: Request, page: str = "overview") -> Response:
        if page not in NAV:
            raise HTTPException(404)
        role = session_role(settings, request)
        if role is None:
            return render(request, "login.html", title="Sign in")
        return render(
            request,
            "dashboard.html",
            page=page,
            title=NAV[page][0],
            nav=NAV,
            role=role,
            csrf=csrf(request.cookies[COOKIE]),
            can_approve=Permission.APPROVE_WORKFLOW in ROLE_PERMISSIONS[role],
            can_change=Permission.CHANGE_NETWORK in ROLE_PERMISSIONS[role],
            can_audit=Permission.RUN_SECURITY in ROLE_PERMISSIONS[role],
        )

    @router.get("/dashboard-fragments/activity", response_class=HTMLResponse)
    def activity(request: Request) -> Response:
        role = session_role(settings, request)
        if role is None:
            raise HTTPException(401)
        # Foundation audit history is Admin-only. Viewer history uses role-scoped tasks.
        entries = (
            storage.recent_events(15)
            if Permission.READ_AUDIT in ROLE_PERMISSIONS[role]
            else []
        )
        return render(request, "activity.html", entries=entries)

    @router.post("/session", status_code=204)
    async def login(request: Request) -> Response:
        # A custom header forces cross-origin requests to preflight. Reject browser
        # requests from other origins and require JSON for the credential exchange.
        if (
            request.headers.get("X-NetGuard-Login") != "1"
            or request.headers.get("Sec-Fetch-Site", "same-origin")
            not in ("same-origin", "none")
            or request.headers.get("content-type", "").split(";")[0]
            != "application/json"
            or request.headers.get("origin")
            != f"{request.url.scheme}://{request.url.netloc}"
        ):
            raise HTTPException(403)
        body = bytearray()
        try:
            async with asyncio.timeout(5):
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 512:
                        raise HTTPException(413)
                    body.extend(chunk)
            credentials = Login.model_validate_json(body)
        except TimeoutError:
            raise HTTPException(408) from None
        except ValidationError:
            raise HTTPException(422) from None
        role = identify(settings, credentials.token)
        if role is None:
            raise HTTPException(401)

        def persist() -> str:
            with Session(engine) as session, session.begin():
                previous = request.cookies.get(COOKIE)
                if previous:
                    session.execute(
                        delete(WebSession).where(WebSession.id == digest(previous))
                    )
                return issue(session, role, credentials.token, request.state.request_id)

        token = await run_in_threadpool(persist)
        request.state.actor = role
        response = Response(status_code=204)
        response.set_cookie(
            COOKIE,
            token,
            max_age=LIFETIME,
            httponly=True,
            secure=settings.web_secure_cookies or request.url.scheme == "https",
            samesite="strict",
        )
        return response

    @router.delete("/session", status_code=204)
    def logout(request: Request) -> Response:
        role = session_role(settings, request)
        if role is None:
            raise HTTPException(401)
        request.state.actor = role
        with Session(engine) as session, session.begin():
            session.execute(
                delete(WebSession).where(
                    WebSession.id == digest(request.cookies[COOKIE])
                )
            )
            session.add(
                audit_event(
                    request.state.request_id, role, 204, event_type="web.logout"
                )
            )
        response = Response(status_code=204)
        response.delete_cookie(
            COOKIE,
            secure=settings.web_secure_cookies or request.url.scheme == "https",
            httponly=True,
            samesite="strict",
        )
        return response

    return router
