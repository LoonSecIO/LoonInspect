FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS backend
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY backend/ ./
RUN uv sync
COPY --from=frontend-build /app/frontend/dist ./app/static

EXPOSE 8000
# app.serve rather than `fastapi run`: it decides TLS mode before binding and gets
# logging configured before uvicorn's first line. See backend/app/serve.py.
CMD ["uv", "run", "python", "-m", "app.serve"]
