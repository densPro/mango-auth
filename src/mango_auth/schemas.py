from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    email: str
    password: str
    app: str = Field(description="Application name the token is for (the `aud` claim)")


class RefreshIn(BaseModel):
    refresh_token: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class MeOut(BaseModel):
    id: str
    email: str
    full_name: str
    app: str
    roles: list[str]
    permissions: list[str]
    perm_version: int


class PermissionsOut(BaseModel):
    sub: str
    app: str
    perm_version: int
    roles: list[str]
    permissions: list[str]


class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=8)
    full_name: str = ""
    is_superadmin: bool = False


class UserUpdate(BaseModel):
    is_active: bool | None = None
    full_name: str | None = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    full_name: str
    is_active: bool
    is_superadmin: bool


class AppCreate(BaseModel):
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    display_name: str = ""


class AppOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    display_name: str
    is_active: bool


class PermissionsIn(BaseModel):
    codes: list[str]


class PermissionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    code: str
    description: str


class RoleIn(BaseModel):
    name: str
    permissions: list[str]
    description: str = ""


class RoleOut(BaseModel):
    name: str
    description: str
    permissions: list[str]


class UserRolesIn(BaseModel):
    roles: list[str]


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    ts: datetime
    actor_id: str | None
    app: str | None
    action: str
    result: str
    ip: str | None
    request_id: str | None
    detail: dict
