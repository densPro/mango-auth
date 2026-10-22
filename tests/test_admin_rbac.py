from conftest import bearer, login


async def test_new_app_needs_no_code_change(client, admin_headers, make_user):
    h = admin_headers
    assert (await client.post("/api/v1/admin/apps", json={"name": "inventory"}, headers=h)).status_code == 201
    r = await client.post(
        "/api/v1/admin/apps/inventory/permissions", json={"codes": ["item:view", "item:edit"]}, headers=h
    )
    assert r.status_code == 200
    r = await client.put(
        "/api/v1/admin/apps/inventory/roles", json={"name": "Clerk", "permissions": ["item:view"]}, headers=h
    )
    assert r.status_code == 200
    email, pw, _ = await make_user("clerk@x.com", ["Clerk"], app_name="inventory")
    me = await client.get(
        "/api/v1/auth/me",
        headers=bearer((await login(client, email, pw, "inventory")).json()["access_token"]),
    )
    assert me.json()["permissions"] == ["item:view"]


async def test_role_cannot_use_unregistered_permission(client, admin_headers):
    r = await client.put(
        "/api/v1/admin/apps/erp/roles", json={"name": "X", "permissions": ["made:up"]}, headers=admin_headers
    )
    assert r.status_code == 404


async def test_non_admin_cannot_use_admin_api_and_is_audited(client, make_user, admin_headers):
    email, pw, uid = await make_user("sales@x.com", ["Sales"])
    token = (await login(client, email, pw, "erp")).json()["access_token"]
    # an ERP token must not open the admin API
    assert (await client.get("/api/v1/admin/users", headers=bearer(token))).status_code == 403
    rows = (await client.get("/api/v1/admin/audit?action=admin_denied", headers=admin_headers)).json()
    assert any(r["actor_id"] == uid for r in rows)


async def test_role_change_bumps_perm_version(client, admin_headers, make_user):
    email, pw, uid = await make_user("pv@x.com", ["Viewer"])
    t = (await login(client, email, pw, "erp")).json()["access_token"]
    before = (await client.get("/api/v1/auth/me", headers=bearer(t))).json()
    await client.put(
        f"/api/v1/admin/users/{uid}/apps/erp/roles", json={"roles": ["Warehouse"]}, headers=admin_headers
    )
    after = (await client.get("/api/v1/auth/me", headers=bearer(t))).json()  # same, old token
    assert after["perm_version"] == before["perm_version"] + 1
    assert "stock:adjust" in after["permissions"]


async def test_editing_a_role_updates_everyone_holding_it(client, admin_headers, make_user):
    email, pw, _ = await make_user("hold@x.com", ["Viewer"])
    t = (await login(client, email, pw, "erp")).json()["access_token"]
    assert (
        "invoice:void" not in (await client.get("/api/v1/auth/me", headers=bearer(t))).json()["permissions"]
    )
    await client.put(
        "/api/v1/admin/apps/erp/roles",
        json={"name": "Viewer", "permissions": ["invoice:view", "invoice:void"]},
        headers=admin_headers,
    )
    assert "invoice:void" in (await client.get("/api/v1/auth/me", headers=bearer(t))).json()["permissions"]


async def test_deactivated_user_loses_access_immediately(client, admin_headers, make_user):
    email, pw, uid = await make_user("off@x.com", ["Viewer"])
    t = (await login(client, email, pw, "erp")).json()
    await client.patch(f"/api/v1/admin/users/{uid}", json={"is_active": False}, headers=admin_headers)
    assert (await client.get("/api/v1/auth/me", headers=bearer(t["access_token"]))).status_code == 401
    assert (
        await client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    ).status_code == 401


async def test_audit_records_login_events(client, admin_headers, make_user):
    email, pw, uid = await make_user("aud@x.com", ["Viewer"])
    await login(client, email, "bad-bad-bad", "erp")
    await login(client, email, pw, "erp")
    rows = (await client.get(f"/api/v1/admin/audit?actor_id={uid}", headers=admin_headers)).json()
    assert {(r["action"], r["result"]) for r in rows} >= {("login", "failure"), ("login", "success")}
