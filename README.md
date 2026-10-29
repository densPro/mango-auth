# mango-auth

One reusable auth service for all your apps (ERP first, then inventory, sales, marketing, ...).
Apps never write login, refresh or permission code: they use the small client library.

Design: [docs/superpowers/specs/2026-10-14-mango-auth-design.md](docs/superpowers/specs/2026-10-14-mango-auth-design.md)

## Run it

```bash
cp .env.example .env        # set BOOTSTRAP_ADMIN_* to create the first super admin
docker compose up --build   # applies migrations, seeds the admin app + ERP roles
```

Docs: http://localhost:8000/docs

Without Docker (SQLite, for development):

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/python -m mango_auth.seed create-superadmin you@example.com 'a-long-password'
.venv/bin/uvicorn mango_auth.main:app_factory --factory --reload
.venv/bin/pytest
```

## How it works

| Piece | Behaviour |
|---|---|
| Login | `POST /api/v1/auth/login {email, password, app}` returns a 15 min access token (RS256, `aud` = app) and a rotating refresh token |
| Refresh | `POST /api/v1/auth/refresh`; each refresh token works once. Replaying an old one revokes the whole session family |
| Verify | Any service verifies tokens offline with `/.well-known/jwks.json` (supports key rotation) |
| Permissions | `resource:action` codes per app, grouped into roles. Stored only here |
| Apps | `erp` and `mango-auth` (the admin API itself) are seeded. New apps are API calls, no code changes |
| Audit | Every login, refresh, reuse, denial and admin change goes to the `audit_log` table and to JSON logs |

### Permission freshness
The token carries only `sub`, `aud` and `pv` (permission version), never the permission list.
The client library asks `/api/v1/auth/permissions` and caches the answer for `permission_ttl`
seconds (default 10; `0` = check on every request). Deactivating a user or changing a role takes
effect within that window, and immediately if the service calls `client.invalidate(user_id)`.

### Add a new app (no code)

```bash
H="Authorization: Bearer $ADMIN_TOKEN"   # token from login with "app": "mango-auth"
curl -XPOST :8000/api/v1/admin/apps -H "$H" -H 'content-type: application/json' -d '{"name":"inventory"}'
curl -XPOST :8000/api/v1/admin/apps/inventory/permissions -H "$H" -H 'content-type: application/json' \
  -d '{"codes":["item:view","item:edit"]}'
curl -XPUT :8000/api/v1/admin/apps/inventory/roles -H "$H" -H 'content-type: application/json' \
  -d '{"name":"Clerk","permissions":["item:view"]}'
curl -XPUT :8000/api/v1/admin/users/$USER_ID/apps/inventory/roles -H "$H" -H 'content-type: application/json' \
  -d '{"roles":["Clerk"]}'
```

### Protect a FastAPI service

```python
from mango_auth_client import MangoAuthClient, Principal

auth = MangoAuthClient("http://auth:8000", app="erp")

@app.post("/stock/adjust")
async def adjust(user: Principal = auth.require_permission("stock:adjust")):
    ...
```

## Try it in Postman or Insomnia

Import both files from `postman/`: `mango-auth.postman_collection.json` and
`mango-auth.postman_environment.json`, then pick the "mango-auth local" environment. Check
`adminEmail` and `adminPassword` match your `BOOTSTRAP_ADMIN_*` values, then run the whole collection
in order (Postman Collection Runner, or `newman run` from the CLI). The folders are:

| Folder | What it does |
|---|---|
| 0. Meta | health and JWKS |
| 1. Setup | logs in as the super admin, creates one user per seeded ERP role and assigns the role |
| 2. Auth flow | login, me, permissions, refresh rotation, replay detection, logout and the error cases |
| 3. Role matrix | each role logs in to `erp` and `/me` must return exactly the permissions in `seed.py` |
| 4. Admin API | every admin endpoint, a new app created through the API, deactivation and key rotation |

Each run uses a fresh `runId` so emails and app names never collide, and tokens are stored in the
environment by the test scripts. Access tokens last 15 minutes, so run it in one go. Lockout is not
tested. Insomnia needs a version with script support (v11+) for the saved variables and assertions.

## Starter ERP roles
Super Admin, Admin, Manager, Accountant, Sales, Warehouse, HR, Viewer (edit freely; seeding never
overwrites a role that already exists).

## Not built yet
Password reset by email, TOTP MFA, per-IP rate limiting, social login, multi-company support.
