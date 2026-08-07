# Public self-hosted image (hounddogai/hounddog-self-hosted) bundling the React UI, the REST API,
# and the SAQ background worker. Build from the private monorepo root:
#   docker build -f public/self-hosted/Dockerfile -t hounddogai/hounddog-self-hosted .

FROM node:24-alpine AS frontend-build
ENV PNPM_HOME=/root/.local/share/pnpm
ENV PATH="${PNPM_HOME}:${PATH}"
WORKDIR /app
RUN npm install -g pnpm@11.6.0
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY frontend/ .
ARG HOUNDDOG_VERSION=dev
ENV VITE_HOUNDDOG_VERSION=$HOUNDDOG_VERSION
RUN pnpm run build --mode self-hosted

FROM python:3.14-slim-bookworm
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY --from=caddy:2 /usr/bin/caddy /usr/local/bin/caddy
ARG HOUNDDOG_VERSION=dev
ENV HOUNDDOG_ENV=self-hosted \
    HOUNDDOG_VERSION=$HOUNDDOG_VERSION \
    HOUNDDOG_DATA_DIR=/data \
    DJANGO_SETTINGS_MODULE=hounddog.settings \
    DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8 \
    UV_PROJECT_ENVIRONMENT=/app/venv \
    VIRTUAL_ENV=/app/venv \
    PATH=/app/venv/bin:$PATH

WORKDIR /app

# Create the non-root user, install system dependencies, and create the virtualenv. Caddy serves the UI.
RUN groupadd -r hounddog && \
    useradd -m -r -g hounddog -s /bin/bash hounddog && \
    apt-get update && \
    apt-get install --no-install-recommends -y build-essential libpq-dev curl git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    uv venv /app/venv

COPY backend/pyproject.toml ./pyproject.toml
COPY backend/uv.lock ./uv.lock
RUN uv sync --no-dev --no-install-project

COPY backend/manage.py ./manage.py
COPY backend/hounddog ./hounddog
COPY rules /rules
COPY prompts /prompts
COPY --from=frontend-build /app/build/client /srv/frontend
COPY public/self-hosted/entrypoint.sh ./entrypoint.sh
COPY public/self-hosted/Caddyfile ./Caddyfile

RUN mkdir -p /data && \
    chown -R hounddog:hounddog /app /data /srv/frontend && \
    chmod +x /app/entrypoint.sh

EXPOSE 3300 8800

# Health checks are defined per service in public/self-hosted/compose.yaml because the image runs
# in different roles (api, worker, caddy).

USER hounddog

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["api"]
