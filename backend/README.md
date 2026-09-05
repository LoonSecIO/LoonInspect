# 🦅 LoonInspect Backend

The backend engine for LoonInspect is a Python application built with **FastAPI** and **SQLAlchemy**.

It orchestrates the hybrid sync architecture (webhook ingestion plus scheduled *collections*), content-hashes installed-app identity so lookups are `O(1)` against the tenant's app catalog instead of recomputed per device, and streams the resulting change events to your SIEM. Vulnerability enrichment rides the same wire but is not populated yet — every event ships `assessment: off` until the community corpus lands ([../docs/vulnerabilities.md](../docs/vulnerabilities.md)).

## 🛠 Tech Stack

* **Framework:** [FastAPI](https://fastapi.tiangolo.com/) (Async web framework)
* **Dependency Management:** [uv](https://github.com/astral-sh/uv) (Blazing fast Rust-based package manager)
* **Database ORM:** [SQLAlchemy](https://www.sqlalchemy.org/) 2.0 (with async support)
* **Task Scheduling:** [APScheduler](https://apscheduler.readthedocs.io/) (the minute tick that runs due *collections*, the outbox worker, and cleanup jobs)
* **Auth:** Email + password + server-side sessions (`app/core/auth.py`), passwords hashed with Argon2 (`app/core/security.py`). Passwordless sign-in and directory provisioning are not implemented — see [../docs/auth-design.md](../docs/auth-design.md) for what's shipped versus deferred.

---

## 🏗 Architecture

The backend is structured to separate HTTP routing logic from Jamf sync logic. `app/mdm/`
is Jamf-only by design (#79) — `factory.py` builds a `JamfClient` directly rather than
dispatching through an abstraction. A `provider` column and a credential-schema registry
(`app/mdm/credentials.py`) are the seam a second MDM would plug into as a sibling
vertical in this repo, not a class dropped into this package; see "MDM support" below.

```text
backend/
├── pyproject.toml         # Managed by uv - contains dependencies
└── app/
    ├── main.py            # FastAPI initialization and scheduler
    ├── api/                # HTTP Routers (UI endpoints, Webhook receivers)
    ├── core/               # DB setup, environment config, content hashing, and SIEM streaming
    ├── models/             # SQLAlchemy Database schemas (MdmConnection, Device, InstalledApp)
    ├── schemas/            # Pydantic validation schemas (JSON payload validation)
    └── mdm/                # Jamf sync and diff logic
        ├── factory.py      # Builds a JamfClient from a connection's stored credentials
        ├── service.py      # Orchestrates one connection's sync: diffs inventory, then hands off to core's hashing and streaming
        ├── jamf/           # Jamf API client and payload normalizers
        └── patch/          # Jamf Patch title matching
```

## 🚀 Local Development Setup

We use `uv` instead of `pip`. `uv` automatically manages the virtual environment (`.venv`), the Python version, and dependency locking.

### 1. Install `uv`

If you don't have it installed globally, grab it via Homebrew or curl:

#### macOS

```bash
brew install uv
```

#### Linux / Windows WSL

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Install dependencies

Navigate to the `backend/` directory and run a sync. `uv` will automatically read `pyproject.toml`, create a virtual environment, and install all packages in milliseconds.

```bash
uv sync
```

### 3. Set an encryption key

MDM connection secrets (Jamf client secret, LoonSecIO license key, etc.) are encrypted at rest, read from `backend/.env` — a separate file from the `.env` the root [README](../README.md) has you create at the repo root for Docker Compose; this local setup runs the backend directly against a Postgres of your own instead. Generate a key:

```bash
uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then, from the **repo root** (`cd ..` first if you're still inside `backend/`):

```bash
cp backend/.env.example backend/.env
# paste the generated key as ENCRYPTION_KEY=...
```

### 4. Start a Postgres

`app/main.py` will not boot without one: `database_url` defaults to
`postgresql+asyncpg://looninspect_app@localhost:5432/looninspect`
(`app/core/config.py`), and Alembic migrations run against it at startup. The
bundled `db` service the root README uses is **not** an option here unmodified —
compose deliberately publishes no port for it ("the database is reachable only
over the compose network," `docker-compose.yml`) — so point this at a Postgres of
your own instead. The role has to be a non-superuser, the same reason the bundled
one is: a superuser bypasses row-level security silently, and this backend's
tenant isolation depends on RLS actually being enforced. Fastest path, mirroring
`ops/postgres/initdb/10-app-role.sh`:

```bash
docker run -d --name looninspect-dev-db -p 5432:5432 \
  -e POSTGRES_DB=looninspect -e POSTGRES_USER=looninspect -e POSTGRES_PASSWORD=devpassword \
  postgres:17-alpine

docker exec -i looninspect-dev-db psql -U looninspect -d looninspect <<'SQL'
CREATE ROLE looninspect_app LOGIN PASSWORD 'devpassword'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER SCHEMA public OWNER TO looninspect_app;
SQL
```

Then set `DATABASE_URL=postgresql+asyncpg://looninspect_app:devpassword@localhost:5432/looninspect` in `backend/.env`.

### 5. Run the development server

FastAPI standardized its CLI. Instead of calling `uvicorn` directly, use the modern `fastapi dev` command wrapped via `uv run`. Back inside `backend/` (`cd backend` if an earlier step left you at the repo root):

```bash
uv run fastapi dev app/main.py --port 8001
```

This starts the server at <http://127.0.0.1:8001> with hot-reloading enabled (`fastapi dev` defaults to 8000; the compose file, `app/serve.py` and the Vite proxy all expect 8001). On startup it automatically applies any pending Alembic migrations (`app/core/database.py::init_db()`) against the Postgres from step 4 — there's no separate manual migration step for local dev.

MDM connections are configured through the API/UI (`/api/mdm/connections`) and stored in the database, not via environment variables. Jamf Pro is the only provider today — see "MDM support" below.

### 6. View API documentation

FastAPI automatically generates interactive Swagger documentation. While the server is running, visit:

👉 <http://127.0.0.1:8001/docs>

## 🔄 Adding New Dependencies

Do not use `pip install`. If you need to add a new Python package (e.g., `boto3`), use `uv add`. This updates both the `pyproject.toml` and the deterministic `uv.lock` file.

```bash
uv add boto3
```

## 🔒 MDM support

LoonInspect is Jamf Pro only at launch, by ruling (#79, [PR #80](https://github.com/LoonSecIO/LoonInspect/pull/80)). Earlier revisions of this backend dispatched through an `MdmClient` abstract base class toward `simplemdm`/`addigy`/`nano` providers that raised `NotImplementedError` — never-shipped surface pretending to be optionality. PR #80 removed it: `app/mdm/factory.py::get_mdm_client` returns a `JamfClient` directly, and the `provider` column is a one-member enum.

What's kept is the seam, not a plugin API: the `provider` column and the credential-schema registry pattern in `app/mdm/credentials.py`. A real second MDM integration is a **sibling vertical** — its own module built when a specific vendor partnership warrants it — not a class dropped into this package against a shared interface. There is no "adding a new MDM" how-to today because there is no abstraction to extend.