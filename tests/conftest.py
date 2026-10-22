import httpx
import pytest_asyncio

from mango_auth.config import Settings
from mango_auth.main import create_app

ADMIN = ("admin@example.com", "admin-password-1")


@pytest_asyncio.fixture
async def app():
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        bootstrap_admin_email=ADMIN[0],
        bootstrap_admin_password=ADMIN[1],
        lockout_threshold=3,
    )
    app = create_app(settings, create_tables=True)
    async with app.router.lifespan_context(app):
        yield app


@pytest_asyncio.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://auth") as c:
        yield c


async def login(client, email, password, app_name):
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": password, "app": app_name})
    return r


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture
async def admin_headers(client):
    r = await login(client, *ADMIN, "mango-auth")
    assert r.status_code == 200, r.text
    return bearer(r.json()["access_token"])


@pytest_asyncio.fixture
async def make_user(client, admin_headers):
    """Create a user with roles in an app. Returns (email, password, user_id)."""

    async def _make(email, roles, app_name="erp", password="user-password-1"):
        r = await client.post(
            "/api/v1/admin/users",
            json={"email": email, "password": password},
            headers=admin_headers,
        )
        assert r.status_code == 201, r.text
        uid = r.json()["id"]
        if roles:
            r = await client.put(
                f"/api/v1/admin/users/{uid}/apps/{app_name}/roles",
                json={"roles": roles},
                headers=admin_headers,
            )
            assert r.status_code == 200, r.text
        return email, password, uid

    return _make
