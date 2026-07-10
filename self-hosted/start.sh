#!/usr/bin/env bash
#
# Starts the HoundDog.ai self-hosted stack. Extra arguments are passed to `docker compose up`,
# e.g. ./start.sh --scale api=3 --scale worker=2

set -euo pipefail

cd "$(dirname "$0")"

if [ ! -f .env ]; then
    printf 'ERROR: No .env file found in %s.\n' "$(pwd)" >&2
    printf 'Run ./setup.sh first, or copy .env.example to .env and fill in the values.\n' >&2
    exit 1
fi

docker compose up -d --wait "$@"

# Read the effective URLs from the running stack instead of re-deriving the defaults here.
app_base_url="$(docker compose exec -T caddy sh -c 'echo "$HOUNDDOG_APP_BASE_URL"')"
api_base_url="$(docker compose exec -T caddy sh -c 'echo "$HOUNDDOG_API_BASE_URL"')"

printf '\nHoundDog.ai is running:\n'
printf '  Web UI:   %s\n' "$app_base_url"
printf '  REST API: %s\n' "$api_base_url"
printf '\nFirst run? Open the web UI now to create your organization and admin account.\n'
