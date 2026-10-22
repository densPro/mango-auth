import jwt

from conftest import bearer, login


async def test_login_me_and_permissions(client, make_user):
    email, pw, _ = await make_user("sam@x.com", ["Sales"])
    r = await login(client, email, pw, "erp")
    assert r.status_code == 200
    tokens = r.json()
    me = await client.get("/api/v1/auth/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["roles"] == ["Sales"]
    assert "customer:create" in body["permissions"]
    assert "payroll:run" not in body["permissions"]


async def test_wrong_password_and_unknown_user_look_the_same(client, make_user):
    email, _, _ = await make_user("a@x.com", ["Viewer"])
    bad = await login(client, email, "nope-nope-nope", "erp")
    unknown = await login(client, "ghost@x.com", "whatever-123", "erp")
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()


async def test_lockout_after_repeated_failures(client, make_user):
    email, pw, _ = await make_user("lock@x.com", ["Viewer"])
    for _ in range(3):
        assert (await login(client, email, "wrong-wrong", "erp")).status_code == 401
    assert (await login(client, email, pw, "erp")).status_code == 423


async def test_user_without_role_cannot_get_token_for_app(client, make_user):
    email, pw, _ = await make_user("norole@x.com", [])
    assert (await login(client, email, pw, "erp")).status_code == 403
    assert (await login(client, email, pw, "no-such-app")).status_code == 404


async def test_refresh_rotates_and_reuse_revokes_family(client, make_user):
    email, pw, _ = await make_user("r@x.com", ["Viewer"])
    first = (await login(client, email, pw, "erp")).json()
    second = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert second.status_code == 200
    new = second.json()
    assert new["refresh_token"] != first["refresh_token"]

    # replaying the old token is theft: it fails AND kills the new token too
    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": new["refresh_token"]})
    assert after.status_code == 401


async def test_logout_revokes_refresh_token(client, make_user):
    email, pw, _ = await make_user("out@x.com", ["Viewer"])
    t = (await login(client, email, pw, "erp")).json()
    assert (
        await client.post("/api/v1/auth/logout", json={"refresh_token": t["refresh_token"]})
    ).status_code == 204
    r = await client.post("/api/v1/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r.status_code == 401


async def test_expired_access_token_is_rejected(client, app, make_user):
    email, pw, uid = await make_user("exp@x.com", ["Viewer"])
    signer = app.state.container.signer
    from datetime import timedelta

    from mango_auth.models import utcnow

    token = await signer.sign({"sub": uid, "aud": "erp", "exp": utcnow() - timedelta(minutes=1)})
    assert (await client.get("/api/v1/auth/me", headers=bearer(token))).status_code == 401


async def test_forged_token_is_rejected(client, make_user):
    _, _, uid = await make_user("forge@x.com", ["Viewer"])
    forged = jwt.encode({"sub": uid, "aud": "erp", "exp": 9999999999}, "secret", algorithm="HS256")
    assert (await client.get("/api/v1/auth/me", headers=bearer(forged))).status_code == 401


async def test_jwks_published_and_key_rotation_keeps_old_tokens_valid(client, admin_headers):
    keys = (await client.get("/.well-known/jwks.json")).json()["keys"]
    assert len(keys) == 1 and keys[0]["alg"] == "RS256"
    assert (await client.post("/api/v1/admin/keys/rotate", headers=admin_headers)).status_code == 200
    assert len((await client.get("/.well-known/jwks.json")).json()["keys"]) == 2
    # the admin token signed with the old key still works
    assert (await client.get("/api/v1/auth/me", headers=admin_headers)).status_code == 200
