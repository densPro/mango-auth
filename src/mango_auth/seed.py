"""Idempotent default data: the auth admin app and the ERP app with starter roles."""

import asyncio
import logging
import sys

from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from mango_auth.config import get_settings
from mango_auth.db import make_engine, make_sessionmaker
from mango_auth.errors import AuthError
from mango_auth.models import Base, User
from mango_auth.security.passwords import Argon2Hasher
from mango_auth.services.rbac import RbacService

ADMIN_APP = "mango-auth"
ADMIN_PERMISSIONS = ["user:manage", "app:manage", "role:manage", "audit:view"]

ERP_APP = "erp"
_ERP_ACTIONS = {
    "invoice": ["view", "create", "edit", "void"],
    "payment": ["view", "create"],
    "journal": ["view", "post"],
    "report": ["view", "export"],
    "customer": ["view", "create", "edit"],
    "order": ["view", "create", "edit", "cancel"],
    "product": ["view", "create", "edit"],
    "stock": ["view", "adjust", "transfer"],
    "purchase": ["view", "create", "approve"],
    "employee": ["view", "create", "edit"],
    "payroll": ["view", "run"],
    "settings": ["view", "edit"],
}
ERP_PERMISSIONS = [f"{r}:{a}" for r, acts in _ERP_ACTIONS.items() for a in acts]


def _all(*resources: str) -> list[str]:
    return [f"{r}:{a}" for r in resources for a in _ERP_ACTIONS[r]]


ERP_ROLES: dict[str, list[str]] = {
    "Super Admin": ERP_PERMISSIONS,
    "Admin": ERP_PERMISSIONS,
    "Manager": _all("order", "purchase", "report")
    + ["invoice:view", "stock:view", "customer:view", "product:view", "employee:view"],
    "Accountant": _all("invoice", "payment", "journal", "report") + ["customer:view", "payroll:view"],
    "Sales": _all("customer")
    + [
        "order:view",
        "order:create",
        "order:edit",
        "invoice:view",
        "invoice:create",
        "product:view",
        "stock:view",
        "report:view",
    ],
    "Warehouse": _all("stock") + ["product:view", "purchase:view", "order:view"],
    "HR": _all("employee", "payroll") + ["report:view"],
    "Viewer": [p for p in ERP_PERMISSIONS if p.endswith(":view")],
}


async def seed_defaults(session: AsyncSession) -> None:
    rbac = RbacService(session)
    have = {a.name for a in await rbac.list_apps()}
    if ADMIN_APP not in have:
        await rbac.create_app(ADMIN_APP, "Auth administration")
    await rbac.register_permissions(ADMIN_APP, ADMIN_PERMISSIONS)
    await rbac.upsert_role(ADMIN_APP, "Auth Admin", ADMIN_PERMISSIONS)

    if ERP_APP not in have:
        await rbac.create_app(ERP_APP, "ERP")
    await rbac.register_permissions(ERP_APP, ERP_PERMISSIONS)
    existing = {r.name for r in await rbac.list_roles(ERP_APP)}
    for name, perms in ERP_ROLES.items():
        if name not in existing:  # never overwrite roles you have customised
            await rbac.upsert_role(ERP_APP, name, perms)


async def ensure_superadmin(session: AsyncSession, email: str, password: str) -> User:
    email = email.strip().lower()
    existing = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return existing
    user = User(
        email=email,
        password_hash=Argon2Hasher().hash(password),
        full_name="Super Admin",
        is_superadmin=True,
    )
    session.add(user)
    await session.commit()
    return user


async def user_count(session: AsyncSession) -> int:
    return (await session.execute(select(func.count()).select_from(User))).scalar_one()


async def _cli(argv: list[str]) -> int:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        sessionmaker = make_sessionmaker(engine)
        async with sessionmaker() as session:
            await seed_defaults(session)
            if len(argv) == 3 and argv[0] == "create-superadmin":
                user = await ensure_superadmin(session, argv[1], argv[2])
                print(f"Super admin ready: {user.email}")
            else:
                print("Defaults seeded. To add an admin: create-superadmin EMAIL PASSWORD")
    except AuthError as e:
        print(f"error: {e.message}", file=sys.stderr)
        return 1
    except SQLAlchemyError as e:
        logging.getLogger("mango_auth.seed").exception("database error while seeding")
        print(f"error: database unavailable or rejected the request ({type(e).__name__})", file=sys.stderr)
        return 1
    finally:
        await engine.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_cli(sys.argv[1:])))
