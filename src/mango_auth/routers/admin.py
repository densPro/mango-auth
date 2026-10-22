from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mango_auth.db import get_session
from mango_auth.deps import (
    Container,
    Principal,
    get_auth_service,
    get_container,
    get_ctx,
    get_rbac,
    require_admin,
)
from mango_auth.errors import NotFound
from mango_auth.models import AuditLog, User
from mango_auth.schemas import (
    AppCreate,
    AppOut,
    AuditOut,
    PermissionOut,
    PermissionsIn,
    RoleIn,
    RoleOut,
    UserCreate,
    UserOut,
    UserRolesIn,
    UserUpdate,
)
from mango_auth.services import RequestContext
from mango_auth.services.auth import AuthService
from mango_auth.services.rbac import RbacService

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


def _role_out(role) -> RoleOut:
    return RoleOut(
        name=role.name,
        description=role.description,
        permissions=sorted(p.code for p in role.permissions),
    )


async def _log(c: Container, p: Principal, ctx: RequestContext, action: str, **detail) -> None:
    await c.audit.record(
        action,
        "success",
        actor_id=p.user.id,
        app=p.app.name,
        ip=ctx.ip,
        request_id=ctx.request_id,
        detail=detail,
    )


# --- users -----------------------------------------------------------
@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    p: Principal = Depends(require_admin("user:manage")),
    auth: AuthService = Depends(get_auth_service),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    if body.is_superadmin and not p.user.is_superadmin:
        from mango_auth.errors import Forbidden

        raise Forbidden("Only a super admin can create another super admin")
    user = await auth.create_user(body.email, body.password, body.full_name, body.is_superadmin)
    await _log(c, p, ctx, "user_created", user_id=user.id, email=user.email)
    return user


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: Principal = Depends(require_admin("user:manage")), s: AsyncSession = Depends(get_session)
):
    return list((await s.execute(select(User).order_by(User.email))).scalars())


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: str,
    body: UserUpdate,
    p: Principal = Depends(require_admin("user:manage")),
    s: AsyncSession = Depends(get_session),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    user = await s.get(User, user_id)
    if user is None:
        raise NotFound("User not found")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.is_active is not None and body.is_active != user.is_active:
        user.is_active = body.is_active
        user.perm_version += 1
    await s.commit()
    await _log(c, p, ctx, "user_updated", user_id=user.id, **body.model_dump(exclude_none=True))
    return user


@router.put("/users/{user_id}/apps/{app_name}/roles", response_model=list[str])
async def set_user_roles(
    user_id: str,
    app_name: str,
    body: UserRolesIn,
    p: Principal = Depends(require_admin("role:manage")),
    rbac: RbacService = Depends(get_rbac),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    user = await rbac.set_user_roles(user_id, app_name, body.roles)
    await _log(c, p, ctx, "user_roles_changed", user_id=user.id, app=app_name, roles=body.roles)
    return body.roles


# --- applications ------------------------------------------------------
@router.post("/apps", response_model=AppOut, status_code=201)
async def create_app(
    body: AppCreate,
    p: Principal = Depends(require_admin("app:manage")),
    rbac: RbacService = Depends(get_rbac),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    app = await rbac.create_app(body.name, body.display_name)
    await _log(c, p, ctx, "app_created", name=app.name)
    return app


@router.get("/apps", response_model=list[AppOut])
async def list_apps(
    _: Principal = Depends(require_admin("app:manage")), rbac: RbacService = Depends(get_rbac)
):
    return await rbac.list_apps()


# --- permissions and roles --------------------------------------------
@router.get("/apps/{app_name}/permissions", response_model=list[PermissionOut])
async def list_permissions(
    app_name: str,
    _: Principal = Depends(require_admin("role:manage")),
    rbac: RbacService = Depends(get_rbac),
):
    return await rbac.list_permissions(app_name)


@router.post("/apps/{app_name}/permissions", response_model=list[PermissionOut])
async def register_permissions(
    app_name: str,
    body: PermissionsIn,
    p: Principal = Depends(require_admin("app:manage")),
    rbac: RbacService = Depends(get_rbac),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    perms = await rbac.register_permissions(app_name, body.codes)
    await _log(c, p, ctx, "permissions_registered", app=app_name, codes=body.codes)
    return perms


@router.get("/apps/{app_name}/roles", response_model=list[RoleOut])
async def list_roles(
    app_name: str,
    _: Principal = Depends(require_admin("role:manage")),
    rbac: RbacService = Depends(get_rbac),
):
    return [_role_out(r) for r in await rbac.list_roles(app_name)]


@router.put("/apps/{app_name}/roles", response_model=RoleOut)
async def upsert_role(
    app_name: str,
    body: RoleIn,
    p: Principal = Depends(require_admin("role:manage")),
    rbac: RbacService = Depends(get_rbac),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    role = await rbac.upsert_role(app_name, body.name, body.permissions, body.description)
    await _log(c, p, ctx, "role_changed", app=app_name, role=body.name, permissions=body.permissions)
    return _role_out(role)


# --- keys and audit ----------------------------------------------------
@router.post("/keys/rotate")
async def rotate_key(
    p: Principal = Depends(require_admin("app:manage")),
    c: Container = Depends(get_container),
    ctx: RequestContext = Depends(get_ctx),
):
    kid = await c.signer.rotate()  # type: ignore[attr-defined]
    await _log(c, p, ctx, "key_rotated", kid=kid)
    return {"kid": kid}


@router.get("/audit", response_model=list[AuditOut])
async def audit(
    action: str | None = None,
    actor_id: str | None = None,
    result: str | None = None,
    limit: int = Query(100, le=500),
    _: Principal = Depends(require_admin("audit:view")),
    s: AsyncSession = Depends(get_session),
):
    q = select(AuditLog).order_by(AuditLog.ts.desc()).limit(limit)
    if action:
        q = q.where(AuditLog.action == action)
    if actor_id:
        q = q.where(AuditLog.actor_id == actor_id)
    if result:
        q = q.where(AuditLog.result == result)
    return list((await s.execute(q)).scalars())
