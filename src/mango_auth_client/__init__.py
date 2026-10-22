"""Drop-in client for services that use mango-auth.

auth = MangoAuthClient("https://auth.example.com", app="erp")

@app.get("/invoices")
async def invoices(user=Depends(auth.require_permission("invoice:view"))):
    ...
"""

import time
from dataclasses import dataclass, field
from typing import Any

import httpx
import jwt
from fastapi import Depends, HTTPException, Request
from jwt.algorithms import RSAAlgorithm


@dataclass
class Principal:
    sub: str
    app: str
    roles: list[str]
    permissions: list[str]
    claims: dict[str, Any] = field(default_factory=dict)

    def has(self, permission: str) -> bool:
        return permission in self.permissions


class MangoAuthClient:
    """Verifies tokens offline using the JWKS, and checks permissions with a short cache.

    `permission_ttl` is the longest a permission change can take to reach this service.
    Set it to 0 to ask the auth service on every request.
    """

    def __init__(
        self,
        auth_url: str,
        app: str,
        permission_ttl: float = 10.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.auth_url = auth_url.rstrip("/")
        self.app = app
        self.permission_ttl = permission_ttl
        self._http = http or httpx.AsyncClient(timeout=5)
        self._keys: dict[str, Any] = {}
        self._perm_cache: dict[tuple[str, str], tuple[float, dict]] = {}

    # --- token verification (no call to the auth service on the hot path) ---
    async def _load_keys(self) -> None:
        r = await self._http.get(f"{self.auth_url}/.well-known/jwks.json")
        r.raise_for_status()
        self._keys = {k["kid"]: RSAAlgorithm.from_jwk(k) for k in r.json()["keys"]}

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
            if kid not in self._keys:
                await self._load_keys()  # new key after rotation
            if kid not in self._keys:
                raise jwt.InvalidTokenError("unknown key")
            return jwt.decode(
                token,
                self._keys[kid],
                algorithms=["RS256"],
                audience=self.app,
                options={"require": ["exp", "sub", "aud"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError) as exc:
            raise HTTPException(
                401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"}
            ) from exc

    # --- permissions ----------------------------------------------------
    async def _permissions(self, token: str, claims: dict[str, Any]) -> dict:
        key = (claims["sub"], self.app)
        hit = self._perm_cache.get(key)
        now = time.monotonic()
        if hit and now - hit[0] < self.permission_ttl:
            return hit[1]
        r = await self._http.get(
            f"{self.auth_url}/api/v1/auth/permissions",
            headers={"Authorization": f"Bearer {token}"},
        )
        if r.status_code in (401, 403):
            self._perm_cache.pop(key, None)
            raise HTTPException(401, "Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
        r.raise_for_status()
        data = r.json()
        self._perm_cache[key] = (now, data)
        return data

    def invalidate(self, sub: str | None = None) -> None:
        """Drop cached permissions (all, or one user)."""
        if sub is None:
            self._perm_cache.clear()
        else:
            self._perm_cache.pop((sub, self.app), None)

    # --- FastAPI dependencies --------------------------------------------
    async def current_user(self, request: Request) -> Principal:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "Missing bearer token", headers={"WWW-Authenticate": "Bearer"})
        claims = await self.verify(token)
        data = await self._permissions(token, claims)
        return Principal(claims["sub"], self.app, data["roles"], data["permissions"], claims)

    def require_auth(self):
        return Depends(self.current_user)

    def require_permission(self, *permissions: str):
        """Dependency that needs every listed permission."""

        async def dependency(user: Principal = Depends(self.current_user)) -> Principal:
            missing = [p for p in permissions if not user.has(p)]
            if missing:
                raise HTTPException(403, f"Missing permission: {', '.join(missing)}")
            return user

        return Depends(dependency)
