import fastapi
import httpx
import pytest_asyncio

from conftest import login
from mango_auth_client import MangoAuthClient, Principal


@pytest_asyncio.fixture
async def consumer(app):
    """A separate service that protects its routes with the client library."""
    auth_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://auth")
    guard = MangoAuthClient("http://auth", app="erp", permission_ttl=0, http=auth_http)
    svc = fastapi.FastAPI()

    @svc.get("/invoices")
    async def invoices(user: Principal = guard.require_permission("invoice:view")):
        return {"user": user.sub}

    @svc.post("/stock/adjust")
    async def adjust(user: Principal = guard.require_permission("stock:adjust")):
        return {"ok": True}

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=svc), base_url="http://erp") as c:
        yield c, guard
    await auth_http.aclose()


async def test_permission_enforced_via_client(client, consumer, make_user):
    c, _ = consumer
    email, pw, _ = await make_user("acc@x.com", ["Accountant"])
    h = {"Authorization": f"Bearer {(await login(client, email, pw, 'erp')).json()['access_token']}"}
    assert (await c.get("/invoices", headers=h)).status_code == 200
    assert (await c.post("/stock/adjust", headers=h)).status_code == 403
    assert (await c.get("/invoices")).status_code == 401


async def test_wrong_audience_rejected_by_consumer(client, consumer, admin_headers):
    c, _ = consumer  # admin_headers are a token for "mango-auth", not "erp"
    assert (await c.get("/invoices", headers=admin_headers)).status_code == 401


async def test_permission_change_applies_on_next_request(client, consumer, admin_headers, make_user):
    c, _ = consumer
    email, pw, uid = await make_user("fast@x.com", ["Viewer"])
    h = {"Authorization": f"Bearer {(await login(client, email, pw, 'erp')).json()['access_token']}"}
    assert (await c.post("/stock/adjust", headers=h)).status_code == 403
    await client.put(
        f"/api/v1/admin/users/{uid}/apps/erp/roles", json={"roles": ["Warehouse"]}, headers=admin_headers
    )
    assert (await c.post("/stock/adjust", headers=h)).status_code == 200  # same old token


async def test_cache_ttl_delays_then_invalidate_forces(client, app, admin_headers, make_user):
    auth_http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://auth")
    guard = MangoAuthClient("http://auth", app="erp", permission_ttl=60, http=auth_http)
    svc = fastapi.FastAPI()

    @svc.post("/stock/adjust")
    async def adjust(user: Principal = guard.require_permission("stock:adjust")):
        return {"ok": True}

    email, pw, uid = await make_user("cache@x.com", ["Viewer"])
    token = (await login(client, email, pw, "erp")).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=svc), base_url="http://erp") as c:
        assert (await c.post("/stock/adjust", headers=h)).status_code == 403
        await client.put(
            f"/api/v1/admin/users/{uid}/apps/erp/roles", json={"roles": ["Warehouse"]}, headers=admin_headers
        )
        assert (await c.post("/stock/adjust", headers=h)).status_code == 403  # still cached
        guard.invalidate(uid)
        assert (await c.post("/stock/adjust", headers=h)).status_code == 200
    await auth_http.aclose()
