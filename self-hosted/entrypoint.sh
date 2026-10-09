#!/bin/bash

set -e

# The first argument selects the API, pgqueue worker, Caddy, or an administrative binary.
role="${1:-api}"

case "$role" in
api)
    wait-for-db
    echo "Applying database migrations ..."
    migrate
    echo "Updating scan rules ..."
    update-rules
    echo "Starting API (port 8800) ..."
    exec api
    ;;
worker)
    wait-for-db
    echo "Starting pgqueue worker ..."
    exec worker
    ;;
caddy)
    echo "Starting Caddy (app and /api proxy on port 3300) ..."
    exec caddy run --config /app/Caddyfile --adapter caddyfile
    ;;
*)
    exec "$@"
    ;;
esac
