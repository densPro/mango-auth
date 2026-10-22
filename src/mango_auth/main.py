import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError

from mango_auth.audit import DbAuditSink
from mango_auth.config import Settings, get_settings
from mango_auth.db import make_engine, make_sessionmaker
from mango_auth.deps import Container
from mango_auth.errors import AuthError
from mango_auth.models import Base
from mango_auth.routers import admin, auth, jwks
from mango_auth.security.passwords import Argon2Hasher
from mango_auth.security.tokens import RsaTokenSigner
from mango_auth.seed import ensure_superadmin, seed_defaults, user_count

logger = logging.getLogger("mango_auth")


def _request_id(request: Request) -> str:
    return request.headers.get("x-request-id") or "-"


def create_app(settings: Settings | None = None, create_tables: bool = False) -> FastAPI:
    settings = settings or get_settings()
    engine = make_engine(settings.database_url)
    sessionmaker = make_sessionmaker(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if create_tables:  # dev/test convenience; production uses Alembic migrations
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        async with sessionmaker() as session:
            await seed_defaults(session)
            if (
                settings.bootstrap_admin_email
                and settings.bootstrap_admin_password
                and await user_count(session) == 0
            ):
                await ensure_superadmin(
                    session, settings.bootstrap_admin_email, settings.bootstrap_admin_password
                )
        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(title="mango-auth", version="0.1.0", lifespan=lifespan)
    app.state.sessionmaker = sessionmaker
    app.state.container = Container(
        settings=settings,
        hasher=Argon2Hasher(),
        signer=RsaTokenSigner(sessionmaker, settings.issuer),
        audit=DbAuditSink(sessionmaker),
    )

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError):
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        if exc.status >= 500:
            logger.error("%s request_id=%s: %s", exc.code, _request_id(request), exc.message)
        return JSONResponse(
            {"detail": exc.message, "code": exc.code}, status_code=exc.status, headers=headers
        )

    @app.exception_handler(IntegrityError)
    async def integrity_error_handler(request: Request, exc: IntegrityError):
        # Unique/foreign-key violations that slipped past the service-level checks (races).
        logger.warning("integrity error request_id=%s: %s", _request_id(request), exc.orig)
        return JSONResponse(
            {"detail": "The request conflicts with existing data", "code": "conflict"},
            status_code=409,
        )

    @app.exception_handler(SQLAlchemyError)
    async def db_error_handler(request: Request, exc: SQLAlchemyError):
        # Details stay in the log; clients get a generic message.
        logger.exception("database error request_id=%s", _request_id(request), exc_info=exc)
        retryable = isinstance(exc, OperationalError)
        return JSONResponse(
            {
                "detail": "Service temporarily unavailable" if retryable else "Internal server error",
                "code": "service_unavailable" if retryable else "internal_error",
            },
            status_code=503 if retryable else 500,
        )

    @app.get("/health", tags=["meta"])
    async def health():
        return {"status": "ok"}

    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(jwks.router)
    return app


logging.basicConfig(level=logging.INFO, format="%(message)s")


def app_factory() -> FastAPI:
    return create_app()
