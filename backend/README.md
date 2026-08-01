# 🦅 LoonInspect Backend

The backend engine for LoonInspect is a high-performance Python application built with **FastAPI** and **SQLAlchemy**.

It orchestrates the hybrid sync architecture, including webhook ingestion and cron sweeps, deduplicates raw Mac application data into `O(1)` hashes, and securely streams vulnerability data.

## 🛠 Tech Stack

* **Framework:** [FastAPI](https://fastapi.tiangolo.com/) (Async web framework)
* **Dependency Management:** [uv](https://github.com/astral-sh/uv) (Blazing fast Rust-based package manager)
* **Database ORM:** [SQLAlchemy](https://www.sqlalchemy.org/) 2.0 (with async support)
* **Task Scheduling:** [APScheduler](https://apscheduler.readthedocs.io/) (for the 1:00 AM CST full sync sweep)
* **Security:** `webauthn` for FIDO2/TouchID and `scim2-models` for Okta integration

---

## 🏗 Domain-Driven Architecture

The backend is structured to separate HTTP routing logic from business/MDM sync logic. This keeps endpoints microscopic and prevents vendor lock-in.

```text
backend/
├── pyproject.toml         # Managed by uv - contains dependencies
└── app/
    ├── main.py            # FastAPI initialization and cron scheduler
    ├── api/               # HTTP Routers (UI endpoints, Webhook receivers)
    ├── core/              # DB setup and environment config (Pydantic Settings)
    ├── models/            # SQLAlchemy Database schemas (MdmConnection, Device, InstalledApp)
    ├── schemas/           # Pydantic validation schemas (JSON payload validation)
    └── mdm/               # Business Logic & Diff Engine
        ├── base.py        # Abstract Base Class for MDMs
        ├── service.py     # The core hashing & SIEM streaming engine
        └── jamf/          # Jamf-specific API clients and payload normalizers
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

MDM connection secrets (Jamf client secret, LoonSecIO license key, etc.) are encrypted at rest. Generate a key and put it in `.env`:

```bash
uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

```bash
cp .env.example .env
# then paste the generated key as ENCRYPTION_KEY=...
```

### 4. Run the development server

FastAPI standardized its CLI. Instead of calling `uvicorn` directly, use the modern `fastapi dev` command wrapped via `uv run`:

```bash
uv run fastapi dev app/main.py
```

This starts the server at <http://127.0.0.1:8000> with hot-reloading enabled. On startup it automatically applies any pending Alembic migrations (`app/core/database.py::init_db()`) — there's no separate manual migration step for local dev.

MDM connections (Jamf, SimpleMDM, etc.) are configured through the API/UI (`/api/mdm/connections`) and stored in the database, not via environment variables.

### 5. View API documentation

FastAPI automatically generates interactive Swagger documentation. While the server is running, visit:

👉 <http://127.0.0.1:8000/docs>

## 🔄 Adding New Dependencies

Do not use `pip install`. If you need to add a new Python package (e.g., `boto3`), use `uv add`. This updates both the `pyproject.toml` and the deterministic `uv.lock` file.

```bash
uv add boto3
```

## 🔒 Adding a New MDM Provider

LoonInspect uses an Abstract Base Class design. To add a new MDM (e.g., SimpleMDM, Addigy, Fleet, Nano, etc):

1. Create a new folder, for example: `app/mdm/simplemdm/`.
2. Create your API client and webhook parsers inside it.
3. Ensure your parser outputs the standard `NormalizedDevice` and `NormalizedApp` objects.
4. Pass those objects to `app.mdm.service.process_sync()` so the core engine can handle diffing and SIEM streaming.