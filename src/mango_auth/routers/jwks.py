from fastapi import APIRouter, Depends

from mango_auth.deps import Container, get_container

router = APIRouter(tags=["keys"])


@router.get("/.well-known/jwks.json")
async def jwks(c: Container = Depends(get_container)):
    return await c.signer.jwks()
