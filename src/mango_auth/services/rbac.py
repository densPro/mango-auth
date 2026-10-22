from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from mango_auth.errors import Conflict, NotFound
from mango_auth.models import (
    Application,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)


class RbacService:
    """Apps, roles and permissions are plain data: new apps need no code changes."""

    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    # --- applications -------------------------------------------------
    async def get_app(self, name: str) -> Application:
        app = (await self.s.execute(select(Application).where(Application.name == name))).scalar_one_or_none()
        if app is None:
            raise NotFound(f"Unknown application '{name}'")
        return app

    async def list_apps(self) -> list[Application]:
        return list((await self.s.execute(select(Application).order_by(Application.name))).scalars())

    async def create_app(self, name: str, display_name: str = "") -> Application:
        existing = (
            await self.s.execute(select(Application).where(Application.name == name))
        ).scalar_one_or_none()
        if existing:
            raise Conflict(f"Application '{name}' already exists")
        app = Application(name=name, display_name=display_name or name)
        self.s.add(app)
        try:
            await self.s.commit()
        except IntegrityError:  # lost a race with a concurrent create
            await self.s.rollback()
            raise Conflict(f"Application '{name}' already exists") from None
        return app

    # --- permissions --------------------------------------------------
    async def list_permissions(self, app_name: str) -> list[Permission]:
        app = await self.get_app(app_name)
        rows = await self.s.execute(
            select(Permission).where(Permission.app_id == app.id).order_by(Permission.code)
        )
        return list(rows.scalars())

    async def register_permissions(self, app_name: str, codes: list[str]) -> list[Permission]:
        """Idempotent: existing codes are kept, new ones are added."""
        app = await self.get_app(app_name)
        have = {p.code for p in await self.list_permissions(app_name)}
        for code in dict.fromkeys(codes):
            if code not in have:
                self.s.add(Permission(app_id=app.id, code=code))
        await self.s.commit()
        return await self.list_permissions(app_name)

    # --- roles --------------------------------------------------------
    async def list_roles(self, app_name: str) -> list[Role]:
        app = await self.get_app(app_name)
        rows = await self.s.execute(select(Role).where(Role.app_id == app.id).order_by(Role.name))
        return list(rows.scalars())

    async def _get_role(self, app_id: str, name: str) -> Role | None:
        return (
            await self.s.execute(select(Role).where(Role.app_id == app_id, Role.name == name))
        ).scalar_one_or_none()

    async def upsert_role(
        self, app_name: str, name: str, permission_codes: list[str], description: str = ""
    ) -> Role:
        app = await self.get_app(app_name)
        perms = {p.code: p for p in await self.list_permissions(app_name)}
        missing = [c for c in permission_codes if c not in perms]
        if missing:
            raise NotFound(f"Unknown permissions for '{app_name}': {', '.join(missing)}")
        role = await self._get_role(app.id, name)
        if role is None:
            role = Role(app_id=app.id, name=name, description=description)
            self.s.add(role)
            await self.s.flush()
        elif description:
            role.description = description
        await self.s.execute(delete(RolePermission).where(RolePermission.role_id == role.id))
        for code in dict.fromkeys(permission_codes):
            self.s.add(RolePermission(role_id=role.id, permission_id=perms[code].id))
        # everyone holding this role now has different permissions
        holders = select(UserRole.user_id).where(UserRole.role_id == role.id)
        await self.s.execute(
            update(User).where(User.id.in_(holders)).values(perm_version=User.perm_version + 1)
        )
        await self.s.commit()
        await self.s.refresh(role)
        return role

    # --- user <-> role ------------------------------------------------
    async def set_user_roles(self, user_id: str, app_name: str, role_names: list[str]) -> User:
        app = await self.get_app(app_name)
        user = await self.s.get(User, user_id)
        if user is None:
            raise NotFound("User not found")
        roles = []
        for name in dict.fromkeys(role_names):
            role = await self._get_role(app.id, name)
            if role is None:
                raise NotFound(f"Unknown role '{name}' in '{app_name}'")
            roles.append(role)
        app_roles = select(Role.id).where(Role.app_id == app.id)
        await self.s.execute(
            delete(UserRole).where(UserRole.user_id == user.id, UserRole.role_id.in_(app_roles))
        )
        for role in roles:
            self.s.add(UserRole(user_id=user.id, role_id=role.id))
        user.perm_version += 1
        await self.s.commit()
        return user

    async def user_roles(self, user: User, app: Application) -> list[Role]:
        rows = await self.s.execute(
            select(Role)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user.id, Role.app_id == app.id)
            .order_by(Role.name)
        )
        return list(rows.scalars())

    async def effective_permissions(self, user: User, app: Application) -> tuple[list[str], list[str]]:
        """Return (role names, permission codes). Super admins get every permission."""
        roles = await self.user_roles(user, app)
        if user.is_superadmin:
            codes = {p.code for p in await self.list_permissions(app.name)}
        else:
            codes = {p.code for r in roles for p in r.permissions}
        return [r.name for r in roles], sorted(codes)

    async def has_access(self, user: User, app: Application) -> bool:
        if user.is_superadmin:
            return True
        return bool(await self.user_roles(user, app))
