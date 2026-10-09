# Build from the private monorepo root with -f public/self-hosted/Dockerfile.
FROM rust:1.99-slim-bookworm AS backend-build
ARG TARGETARCH
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS
WORKDIR /build/backend
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/crates ./crates
COPY prompts /build/prompts
RUN --mount=type=cache,id=backend-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=backend-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=backend-cargo-target-${TARGETARCH},target=/build/backend/target \
    cargo install --locked --path crates/app --root /out --target-dir /build/backend/target --bins

FROM node:24-alpine AS frontend-build
WORKDIR /frontend
RUN npm install -g pnpm@11.6.0
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build --mode self-hosted

FROM caddy:2 AS caddy

FROM debian:bookworm-slim AS runtime
ARG HOUNDDOG_VERSION=dev
ENV HOUNDDOG_ENV=self-hosted \
    HOUNDDOG_VERSION=$HOUNDDOG_VERSION \
    HOUNDDOG_LISTEN=0.0.0.0:8800 \
    HOUNDDOG_DATA_DIR=/data \
    HOUNDDOG_RULES_DIR=/rules \
    HOUNDDOG_PROMPTS_DIR=/prompts \
    RUST_LOG=info
WORKDIR /app
RUN groupadd -r hounddog && useradd -m -r -g hounddog -s /bin/bash hounddog \
    && apt-get update && apt-get install --no-install-recommends -y ca-certificates curl git libssl3 openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /data && chown hounddog:hounddog /data
COPY --from=backend-build /out/bin/ /usr/local/bin/
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY --from=frontend-build /frontend/build/client /srv/frontend
COPY public/self-hosted/Caddyfile ./Caddyfile
COPY backend/migrations ./migrations
COPY rules /rules
COPY prompts /prompts
COPY public/self-hosted/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER hounddog
EXPOSE 3300 8800
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["api"]
