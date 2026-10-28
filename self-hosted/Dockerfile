# Build from the private monorepo root with -f public/self-hosted/Dockerfile.
# cargo-chef compiles the backend dependencies in their own layer, as in docker/backend/Dockerfile.
FROM rust:1.99-slim-bookworm AS backend-chef
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS
WORKDIR /build
RUN apt-get update && apt-get install --no-install-recommends -y build-essential cmake libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-chef --locked --version 0.1.78

FROM backend-chef AS backend-planner
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo chef prepare --recipe-path recipe.json

FROM backend-chef AS backend-build
COPY --from=backend-planner /build/recipe.json ./
RUN cargo chef cook --release --locked --package hounddog-app --bins --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY prompts ./prompts
RUN cargo install --locked --path crates/app --root /out --target-dir target --bins

FROM node:26-alpine AS frontend-build
WORKDIR /frontend
RUN npm install -g pnpm@11.6.0
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml frontend/.pnpmfile.mjs ./
RUN --mount=type=cache,id=pnpm,target=/pnpm/store pnpm install --frozen-lockfile
COPY frontend/ ./
# `_headers` holds Cloudflare Pages' headers for the cloud frontend; Caddy sets the self-hosted ones itself.
RUN pnpm run build --mode self-hosted && rm build/client/_headers

# Stock Caddy cannot rate limit, so xcaddy adds the caddy-ratelimit module. The module's only tag (v0.1.0, 2024)
# predates its Caddyfile validation and ipv6_prefix, so it is pinned to a commit on its main branch.
FROM caddy:2.11.7-builder AS caddy
RUN xcaddy build --output /usr/bin/caddy \
    --with github.com/mholt/caddy-ratelimit@v0.1.1-0.20260612195517-5625512f24f6

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
COPY crates/models/migrations ./migrations
COPY rules /rules
COPY prompts /prompts
COPY public/self-hosted/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
USER hounddog
EXPOSE 3300 8800
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["api"]
