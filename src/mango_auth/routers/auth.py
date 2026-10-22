from fastapi import APIRouter, Depends, Response

from mango_auth.deps import Principal, current_principal, get_auth_service, get_ctx
from mango_auth.schemas import LoginIn, MeOut, PermissionsOut, RefreshIn, TokenOut
from mango_auth.services import RequestContext
from mango_auth.services.auth import AuthService

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
async def login(
    body: LoginIn, auth: AuthService = Depends(get_auth_service), ctx: RequestContext = Depends(get_ctx)
):
    return await auth.login(body.email, body.password, body.app, ctx)


@router.post("/refresh", response_model=TokenOut)
async def refresh(
    body: RefreshIn, auth: AuthService = Depends(get_auth_service), ctx: RequestContext = Depends(get_ctx)
):
    return await auth.refresh(body.refresh_token, ctx)


@router.post("/logout", status_code=204)
async def logout(
    body: RefreshIn, auth: AuthService = Depends(get_auth_service), ctx: RequestContext = Depends(get_ctx)
):
    await auth.logout(body.refresh_token, ctx)
    return Response(status_code=204)


@router.get("/me", response_model=MeOut)
async def me(p: Principal = Depends(current_principal)):
    return MeOut(
        id=p.user.id,
        email=p.user.email,
        full_name=p.user.full_name,
        app=p.app.name,
        roles=p.roles,
        permissions=p.permissions,
        perm_version=p.user.perm_version,
    )


@router.get("/permissions", response_model=PermissionsOut)
async def permissions(p: Principal = Depends(current_principal)):
    """Called by the client library. Always reflects the latest roles and permissions."""
    return PermissionsOut(
        sub=p.user.id,
        app=p.app.name,
        perm_version=p.user.perm_version,
        roles=p.roles,
        permissions=p.permissions,
    )
