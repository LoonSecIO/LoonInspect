# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Frontend build
# ---------------------------------------------------------------------------
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend

# Manifest and lockfile first so the dependency layer is cached independently of
# source edits. `npm ci` installs exactly what the lockfile pins and fails if the
# two have drifted, which `npm install` would silently reconcile instead.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Backend runtime
# ---------------------------------------------------------------------------
# Pinned to 3.12 to match backend/.python-version. pyproject's requires-python
# (>=3.11) is the floor the code supports; this is the version actually shipped.
FROM python:3.12-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app

# Pinned rather than :latest so a rebuild resolves the same toolchain.
COPY --from=ghcr.io/astral-sh/uv:0.9.30 /uv /uvx /bin/

# Dependencies before application source, for the same caching reason as above.
# --frozen fails if uv.lock is stale rather than silently re-resolving; --no-dev
# keeps ruff and other tooling out of the runtime image.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY backend/ ./
RUN uv sync --frozen --no-dev

COPY --from=frontend-build /app/frontend/dist ./app/static

# Run as a non-root account. /app/data is created here so a fresh named volume
# inherits this ownership when Docker initialises it from the image.
RUN groupadd --gid 10001 looninspect \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/looninspect \
               --shell /usr/sbin/nologin looninspect \
    && mkdir -p /app/data \
    && chown -R looninspect:looninspect /app
USER looninspect

EXPOSE 8000

# TLS_MODE decides the scheme the server binds with, so the probe follows it.
# A self-signed certificate is expected here, hence the unverified context.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["uv", "run", "--frozen", "--no-dev", "python", "-c", \
         "import os,ssl,urllib.request;\
m=os.environ.get('TLS_MODE','off');\
s='https' if m!='off' else 'http';\
p=os.environ.get('PORT','8000');\
c=ssl._create_unverified_context() if s=='https' else None;\
urllib.request.urlopen(f'{s}://127.0.0.1:{p}/api/health',timeout=4,context=c).read()"]

# app.serve rather than `fastapi run`: it decides TLS mode before binding and gets
# logging configured before uvicorn's first line. See backend/app/serve.py.
CMD ["uv", "run", "--frozen", "--no-dev", "python", "-m", "app.serve"]
