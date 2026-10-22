import json
from datetime import timedelta
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from mango_auth.models import SigningKey, new_id, utcnow


def generate_key() -> SigningKey:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return SigningKey(kid=new_id(), private_pem=private_pem, public_pem=public_pem)


class RsaTokenSigner:
    """RS256 signer whose keys live in the database so they survive restarts and rotate."""

    def __init__(self, sessionmaker: async_sessionmaker[AsyncSession], issuer: str) -> None:
        self._sessionmaker = sessionmaker
        self._issuer = issuer

    async def _active_key(self) -> SigningKey:
        async with self._sessionmaker() as s:
            key = (
                (
                    await s.execute(
                        select(SigningKey).where(SigningKey.is_active).order_by(SigningKey.created_at.desc())
                    )
                )
                .scalars()
                .first()
            )
            if key is None:
                key = generate_key()
                s.add(key)
                await s.commit()
            return key

    async def rotate(self) -> str:
        """Create a new signing key. Old keys stay published so live tokens still verify."""
        async with self._sessionmaker() as s:
            await s.execute(update(SigningKey).values(is_active=False))
            key = generate_key()
            s.add(key)
            await s.commit()
            return key.kid

    async def sign(self, claims: dict[str, Any]) -> str:
        key = await self._active_key()
        return jwt.encode(
            {"iss": self._issuer, "iat": utcnow(), **claims},
            key.private_pem,
            algorithm="RS256",
            headers={"kid": key.kid},
        )

    async def jwks(self) -> dict[str, Any]:
        await self._active_key()  # make sure at least one key exists
        async with self._sessionmaker() as s:
            keys = (await s.execute(select(SigningKey))).scalars().all()
        out = []
        for k in keys:
            jwk = json.loads(RSAAlgorithm.to_jwk(serialization.load_pem_public_key(k.public_pem.encode())))
            jwk.update({"kid": k.kid, "use": "sig", "alg": "RS256"})
            out.append(jwk)
        return {"keys": out}

    async def verify(self, token: str, audience: str) -> dict[str, Any]:
        kid = jwt.get_unverified_header(token).get("kid")
        key = None
        if kid:
            async with self._sessionmaker() as s:
                key = await s.get(SigningKey, kid)
        if key is None:
            raise jwt.InvalidTokenError("unknown key id")
        return jwt.decode(
            token,
            key.public_pem,
            algorithms=["RS256"],
            audience=audience,
            issuer=self._issuer,
            options={"require": ["exp", "sub", "aud"]},
        )


def access_expiry(minutes: int):
    return utcnow() + timedelta(minutes=minutes)
