FROM rust:1-bookworm AS rust-builder
WORKDIR /build
#ENV RUSTFLAGS="-Clink-arg=-Wl,--allow-multiple-definition"
COPY . .
RUN cargo build --release

FROM python:3.12-bookworm

ARG HOUNDDOG_VERSION=dev
ARG HOUNDDOG_ENV=dev
ARG HOUNDDOG_DOCKER_TAG
ARG HOUNDDOG_SENTRY_DSN

# Set environment variables.
ENV HOUNDDOG_VERSION=${HOUNDDOG_VERSION}
ENV HOUNDDOG_ENV=${HOUNDDOG_ENV}
ENV HOUNDDOG_DOCKER_TAG=${HOUNDDOG_DOCKER_TAG}
ENV HOUNDDOG_SENTRY_DSN=${HOUNDDOG_SENTRY_DSN}
ENV HOUNDDOG_IS_USING_DOCKER=1

# Copy the Typescript scanner.
COPY --from=rust-builder /build/target/release/TSScanner /opt/scanner/rust/
ENV HOUNDDOG_TS_SCANNER_PATH=/opt/scanner/rust/TSScanner
