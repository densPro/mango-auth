import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from mango_auth.config import Settings
from mango_auth.db import get_session
from mango_auth.errors import Forbidden, Unauthorized
from mango_auth.models import Application, User
from mango_auth.security.interfaces import AuditSink, PasswordHasher, TokenSigner
from mango_auth.services import RequestContext
from mango_auth.services.auth import AuthService
from mango_auth.services.rbac import RbacService

ADMIN_APP = "mango-auth"


@dataclass
class Container:
    """Concrete implementations wired once at startup (swappable in tests)."""

    settings: Settings
    hasher: PasswordHasher
    signer: TokenSigner
    audit: AuditSink


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_ctx(request: Request) -> RequestContext:
    return RequestContext(
        ip=request.client.host if request.client else None,
        request_id=request.headers.get("x-request-id") or uuid.uuid4().hex,
    )


def get_auth_service(
    session: AsyncSession = Depends(get_session), c: Container = Depends(get_container)
) -> AuthService:
    return AuthService(session, c.hasher, c.signer, c.audit, c.settings)


def get_rbac(session: AsyncSession = Depends(get_session)) -> RbacService:
    return RbacService(session)


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthorized("Missing bearer token")
    return token


@dataclass
class Principal:
    user: User
    app: Application
    claims: dict[str, Any]
    roles: list[str]
    permissions: list[str]


async def current_principal(
    token: str = Depends(bearer_token),
    auth: AuthService = Depends(get_auth_service),
) -> Principal:
    user, app, claims = await auth.authenticate(token)
    roles, perms = await auth.rbac.effective_permissions(user, app)
    return Principal(user, app, claims, roles, perms)


def require_admin(permission: str) -> Callable[..., Any]:
    """Guard for the management API. It uses the same RBAC as every other app."""

    async def dependency(
        principal: Principal = Depends(current_principal),
        c: Container = Depends(get_container),
        ctx: RequestContext = Depends(get_ctx),
    ) -> Principal:
        if principal.app.name != ADMIN_APP or permission not in principal.permissions:
            await c.audit.record(
                "admin_denied",
                "denied",
                actor_id=principal.user.id,
                app=principal.app.name,
                ip=ctx.ip,
                request_id=ctx.request_id,
                detail={"required": permission},
            )
            raise Forbidden(f"Requires '{permission}' on '{ADMIN_APP}'")
        return principal

    return dependency
