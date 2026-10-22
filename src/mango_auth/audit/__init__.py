import json
import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from mango_auth.models import AuditLog

logger = logging.getLogger("mango_auth.audit")


class DbAuditSink:
    """Writes each event to the audit_log table and to structured JSON logs.

    Uses its own session so failure events are kept even when the request is rejected.
    A failed database write is logged (the JSON log line is still emitted) but never raised:
    an audit outage must not turn a clean 401/403 into a 500 or block a legitimate request.
    """

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession]) -> None:
        self._sessionmaker = sessionmaker

    async def record(
        self,
        action: str,
        result: str,
        *,
        actor_id: str | None = None,
        app: str | None = None,
        ip: str | None = None,
        request_id: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        entry = AuditLog(
            action=action,
            result=result,
            actor_id=actor_id,
            app=app,
            ip=ip,
            request_id=request_id,
            detail=detail or {},
        )
        try:
            async with self._sessionmaker() as s:
                s.add(entry)
                await s.commit()
        except SQLAlchemyError:
            logger.exception(
                "audit write failed: action=%s result=%s request_id=%s", action, result, request_id
            )
        logger.info(
            json.dumps(
                {
                    "event": action,
                    "result": result,
                    "actor_id": actor_id,
                    "app": app,
                    "ip": ip,
                    "request_id": request_id,
                    "detail": detail or {},
                }
            )
        )
