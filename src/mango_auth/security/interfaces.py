"""Small interfaces the services depend on (dependency inversion)."""

from typing import Any, Protocol


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...
    def verify(self, password_hash: str, password: str) -> bool: ...


class TokenSigner(Protocol):
    async def sign(self, claims: dict[str, Any]) -> str: ...
    async def verify(self, token: str, audience: str) -> dict[str, Any]: ...
    async def jwks(self) -> dict[str, Any]: ...


class AuditSink(Protocol):
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
    ) -> None: ...
