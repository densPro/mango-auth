import hashlib
import secrets
from datetime import timedelta
from typing import Any

import jwt
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from mango_auth.config import Settings
from mango_auth.errors import Conflict, Forbidden, Locked, NotFound, Unauthorized
from mango_auth.models import Application, RefreshToken, User, aware, new_id, utcnow
from mango_auth.security.interfaces import AuditSink, PasswordHasher, TokenSigner
from mango_auth.services import RequestContext
from mango_auth.services.rbac import RbacService

_DUMMY_PASSWORD = "not-a-real-password"
_dummy_hashes: dict[int, str] = {}  # one decoy hash per hasher, computed once


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class AuthService:
    def __init__(
        self,
        session: AsyncSession,
        hasher: PasswordHasher,
        signer: TokenSigner,
        audit: AuditSink,
        settings: Settings,
    ) -> None:
        self.s = session
        self.hasher = hasher
        self.signer = signer
        self.audit = audit
        self.settings = settings
        self.rbac = RbacService(session)
        if id(hasher) not in _dummy_hashes:
            _dummy_hashes[id(hasher)] = hasher.hash(_DUMMY_PASSWORD)
        self._dummy_hash = _dummy_hashes[id(hasher)]

    # --- users --------------------------------------------------------
    async def create_user(
        self, email: str, password: str, full_name: str = "", is_superadmin: bool = False
    ) -> User:
        email = email.strip().lower()
        if (await self.s.execute(select(User).where(User.email == email))).scalar_one_or_none():
            raise Conflict("A user with that email already exists")
        user = User(
            email=email,
            password_hash=self.hasher.hash(password),
            full_name=full_name,
            is_superadmin=is_superadmin,
        )
        self.s.add(user)
        try:
            await self.s.commit()
        except IntegrityError:  # lost a race with a concurrent signup for the same email
            await self.s.rollback()
            raise Conflict("A user with that email already exists") from None
        return user

    # --- login / refresh / logout ------------------------------------
    async def login(self, email: str, password: str, app_name: str, ctx: RequestContext) -> dict:
        email = email.strip().lower()
        user = (await self.s.execute(select(User).where(User.email == email))).scalar_one_or_none()
        meta = {"ip": ctx.ip, "request_id": ctx.request_id}

        if user is None:
            self.hasher.verify(self._dummy_hash, password)  # keep timing similar
            await self.audit.record("login", "failure", app=app_name, detail={"email": email}, **meta)
            raise Unauthorized("Invalid email or password")

        now = utcnow()
        locked_until = aware(user.locked_until)
        if locked_until and locked_until > now:
            await self.audit.record(
                "login", "denied", actor_id=user.id, app=app_name, detail={"reason": "locked"}, **meta
            )
            raise Locked()

        if not user.is_active or not self.hasher.verify(user.password_hash, password):
            if user.is_active:
                user.failed_attempts += 1
                if user.failed_attempts >= self.settings.lockout_threshold:
                    user.locked_until = now + timedelta(minutes=self.settings.lockout_minutes)
                    user.failed_attempts = 0
                await self.s.commit()
            await self.audit.record("login", "failure", actor_id=user.id, app=app_name, **meta)
            raise Unauthorized("Invalid email or password")

        app = await self._active_app(app_name)
        if not await self.rbac.has_access(user, app):
            await self.audit.record(
                "login",
                "denied",
                actor_id=user.id,
                app=app_name,
                detail={"reason": "no access to app"},
                **meta,
            )
            raise Forbidden(f"You do not have access to '{app_name}'")

        user.failed_attempts = 0
        user.locked_until = None
        tokens = await self._issue(user, app, family_id=new_id())
        await self.audit.record("login", "success", actor_id=user.id, app=app_name, **meta)
        return tokens

    async def refresh(self, refresh_token: str, ctx: RequestContext) -> dict:
        meta = {"ip": ctx.ip, "request_id": ctx.request_id}
        row = (
            await self.s.execute(
                select(RefreshToken).where(RefreshToken.token_hash == _digest(refresh_token))
            )
        ).scalar_one_or_none()
        if row is None:
            await self.audit.record("token_refresh", "failure", detail={"reason": "unknown"}, **meta)
            raise Unauthorized()

        if row.revoked_at is not None:
            # A rotated token was presented again: treat the whole family as stolen.
            await self._revoke_family(row.family_id)
            await self.audit.record(
                "token_reuse_detected",
                "denied",
                actor_id=row.user_id,
                detail={"family_id": row.family_id},
                **meta,
            )
            raise Unauthorized()

        if aware(row.expires_at) <= utcnow():
            await self.audit.record(
                "token_refresh", "failure", actor_id=row.user_id, detail={"reason": "expired"}, **meta
            )
            raise Unauthorized()

        user = await self.s.get(User, row.user_id)
        app = await self.s.get(Application, row.app_id)
        if user is None or not user.is_active or app is None or not app.is_active:
            await self._revoke_family(row.family_id)
            raise Unauthorized()
        if not await self.rbac.has_access(user, app):
            await self._revoke_family(row.family_id)
            raise Forbidden(f"You no longer have access to '{app.name}'")

        row.revoked_at = utcnow()
        tokens = await self._issue(user, app, family_id=row.family_id)
        await self.audit.record("token_refresh", "success", actor_id=user.id, app=app.name, **meta)
        return tokens

    async def logout(self, refresh_token: str, ctx: RequestContext) -> None:
        row = (
            await self.s.execute(
                select(RefreshToken).where(RefreshToken.token_hash == _digest(refresh_token))
            )
        ).scalar_one_or_none()
        if row is not None:
            await self._revoke_family(row.family_id)
            await self.audit.record(
                "logout", "success", actor_id=row.user_id, ip=ctx.ip, request_id=ctx.request_id
            )

    # --- verifying access tokens ------------------------------------
    async def authenticate(self, access_token: str) -> tuple[User, Application, dict[str, Any]]:
        try:
            audience = jwt.decode(access_token, options={"verify_signature": False})["aud"]
            claims = await self.signer.verify(access_token, audience)
        except (jwt.PyJWTError, KeyError, TypeError):
            raise Unauthorized() from None
        user = await self.s.get(User, claims["sub"])
        if user is None or not user.is_active:
            raise Unauthorized()
        try:
            app = await self._active_app(audience)
        except NotFound:
            raise Unauthorized() from None
        return user, app, claims

    # --- helpers ------------------------------------------------------
    async def _active_app(self, name: str) -> Application:
        app = await self.rbac.get_app(name)
        if not app.is_active:
            raise NotFound(f"Unknown application '{name}'")
        return app

    async def _issue(self, user: User, app: Application, family_id: str) -> dict:
        s = self.settings
        now = utcnow()
        expires = now + timedelta(minutes=s.access_token_minutes)
        access = await self.signer.sign(
            {
                "sub": user.id,
                "aud": app.name,
                "exp": expires,
                "jti": new_id(),
                "pv": user.perm_version,
            }
        )
        refresh = secrets.token_urlsafe(48)
        self.s.add(
            RefreshToken(
                user_id=user.id,
                app_id=app.id,
                family_id=family_id,
                token_hash=_digest(refresh),
                expires_at=now + timedelta(days=s.refresh_token_days),
            )
        )
        await self.s.commit()
        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "expires_in": s.access_token_minutes * 60,
        }

    async def _revoke_family(self, family_id: str) -> None:
        await self.s.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=utcnow())
        )
        await self.s.commit()
