# Design and plan: mango-auth (reusable auth service, FastAPI)

## Context and intent
Every new app means re-solving login, token expiry/refresh, and permissions, and each app ends up doing it differently. mango-auth is one standalone service that owns identity and permissions for all your apps, **ERP first**, then inventory, sales, marketing, social media and others. Apps plug in through a small client library instead of writing auth code.

The workspace `/home/dens/working-space/mango-auth` is empty, so this is a greenfield build.

## Goals
- One account and one login across all apps (SSO-style). *(my guess, you didn't answer directly)*
- Token expiry and refresh handled in one place; apps never write refresh logic.
- Permissions live only in the auth service, so apps stay consistent. **Permission changes apply fast** (see "Permission freshness").
- ERP-ready out of the box: pre-loaded common roles and `resource:action` permissions.
- A built-in logger for security and audit events.
- **SOLID**: adding a new app needs no change to the auth code (apps, roles and permissions are data, not code).

## Non-goals
- No business logic for any one app, and no per-app UI.
- No multi-company/tenancy in v1 *(my guess: one company; the design leaves room to add it later)*.
- No public self-signup by default (can be enabled per app later, e.g. social media).

## Anti-goals (a failure even if it technically works)
- Adding a new app requires editing auth code.
- A permission change takes minutes to take effect.
- Each app implements its own token refresh or permission rules.

## Decisions by you
- Python + FastAPI.
- ERP is the main focus; keep common roles, users and permissions for it.
- Follow SOLID and keep changes to the auth code minimal when adding apps.
- Permissions must apply fast.
- Built-in logger.
- You approved my tech defaults below and asked about migrations.

## My calls (not yet checked by you)
| Area | Choice |
|---|---|
| Stack | Python 3.12, FastAPI, SQLAlchemy 2 (async), Pydantic v2, `uv` |
| DB and migrations | PostgreSQL + **Alembic** (run automatically on container start) |
| Passwords | Argon2id |
| Tokens | Short-lived JWT access token (15 min, RS256, public key at `/.well-known/jwks.json`) + rotating opaque refresh token (hashed in DB, reuse detection) |
| Packaging | Docker + docker-compose (api + postgres) |
| Starter ERP roles | Super Admin, Admin, Manager, Accountant, Sales, Warehouse, HR, Viewer (editable) |
| Permission format | `resource:action`, e.g. `invoice:create`, `stock:adjust`, `report:view` |
| Accounts | Created by admins; no public signup by default |

## Permission freshness (the token-versus-request question)
The token holds only **identity, app (`aud`) and a `perm_version` number**, not the full permission list. The client library asks the auth service for the user's permissions and caches them briefly, keyed by `perm_version`. When an admin changes roles, `perm_version` for affected users bumps, and the next request sees the new version and refetches. Result: changes apply on the next request, and most requests need no network call. *(my call; if you'd rather have simpler "always ask the auth service", it's a one-line swap behind the same interface.)*

## Logger
- Structured JSON logs to stdout (for any log collector) **plus** an `audit_log` table.
- Records: logins and failures, token refresh and reuse, role/permission changes, denied requests, admin actions. Each entry has actor, app, action, result, IP and request id.
- Queryable via an admin-only endpoint.

## SOLID structure
- **Single responsibility:** routers (HTTP) → services (rules) → repositories (DB) → models.
- **Open/closed:** apps, roles and permissions are rows registered via API or seed files, so there is no code edit per app.
- **Liskov and interface segregation:** small `Protocol` interfaces for `PasswordHasher`, `TokenSigner`, `Mailer`, `AuditSink`, `PermissionStore`.
- **Dependency inversion:** services depend on those interfaces and FastAPI `Depends` wires the concrete ones, so each is swappable and testable.

## Build phases
1. **Foundation:** `pyproject.toml`, app factory, env settings, async DB, Alembic, Docker, pytest.
2. **Identity:** create user (admin), login, JWT issue, refresh rotation and reuse detection, logout/revoke, `/me`.
3. **Apps and RBAC:** application registry, per-app roles/permissions CRUD, user-role assignment, `perm_version`, ERP seed data.
4. **Client library `mango_auth_client`:** JWKS token verification, cached permission lookup, FastAPI deps `require_auth` and `require_permission("stock:adjust")`.
5. **Logger and hardening:** audit log and endpoint, rate limiting, lockout, password reset (pluggable mailer), optional TOTP MFA.
6. **Delivery:** OpenAPI docs, README integration guide, example consumer app, CI (ruff, mypy, pytest).

## Left to the builder
Exact table/column names, endpoint paths, cache TTL (start at about 30 s), key-rotation schedule, lockout thresholds, and choice of rate-limit library.

## Critical files (to be created)
`src/mango_auth/{main,config,db}.py`; `models/`, `schemas/`, `routers/`, `services/`, `repositories/`, `security/`, `audit/`; `src/mango_auth_client/`; `alembic/`; `tests/`; `Dockerfile`; `docker-compose.yml`.

## Verification
- `docker compose up` applies migrations. Log in, refresh and revoke via `/docs`.
- `pytest`: hashing, expiry, refresh-reuse detection, permission checks, `perm_version` invalidation (a role change is visible on the next request).
- The example consumer app verifies a token offline via JWKS, and rejects the wrong `aud` or a missing permission.
- Registering a brand-new app and its permissions requires **zero code changes**.
- Audit entries appear for each of the logged events; `ruff` and `mypy` clean.

## Process note
Builder check done by me (no subagent). I found no questions that only you can answer. Nothing is built until you approve this.
