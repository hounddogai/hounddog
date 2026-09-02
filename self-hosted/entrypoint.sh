#!/bin/bash

set -e

# The container role is the first argument: "api" (REST API, the image default), "worker" (SAQ
# background worker), "caddy" (React UI and API reverse proxy), or any other command to exec as-is
# (e.g. manage.py shell).
role="${1:-api}"

case "$role" in
api)
    python manage.py wait_for_db
    echo "Applying database migrations ..."
    PGOPTIONS="${PGOPTIONS:--c lock_timeout=5s}" python manage.py migrate --noinput
    echo "Updating scan rules ..."
    python manage.py update_rules
    echo "Starting API (port 8800) ..."
    exec uvicorn hounddog.asgi:application --host 0.0.0.0 --port 8800 --no-access-log --lifespan off
    ;;
worker)
    python manage.py wait_for_db
    echo "Starting SAQ worker ..."
    exec python manage.py start_saq_worker
    ;;
caddy)
    echo "Starting Caddy (app and /api proxy on port 3300) ..."
    exec caddy run --config /app/Caddyfile --adapter caddyfile
    ;;
*)
    exec "$@"
    ;;
esac
