# HoundDog.ai Self-Hosted

Run the [HoundDog.ai](https://hounddog.ai) Cloud Platform on your own infrastructure with Docker Compose. All services
run from the public `hounddogai/hounddog-self-hosted` image plus Postgres; no external dependencies.

## Requirements

- Docker with Compose v2
- 4 GB RAM and 80 GB disk recommended

## Quick start

```shell
./setup.sh    # interactive wizard: generates .env (secret key + database settings)
./start.sh    # starts the stack
```

Then open http://localhost:3300 and create your organization and admin account.

> **Do this right away.** Until the first account exists, the setup page is open to anyone who
> can reach the instance. Do not expose the configured UI and API ports (`3300` and `8800` by
> default) to an untrusted network before completing setup.

## Services

| Service    | Role                                                                                                 |
|------------|------------------------------------------------------------------------------------------------------|
| `caddy`    | Web UI and REST API reverse proxy on the configured ports (the only service with published ports)    |
| `api`      | REST API (uvicorn), horizontally scalable                                                            |
| `worker`   | Background task worker (SAQ), horizontally scalable                                                  |
| `init`     | One-shot database migrations and scanner rules bootstrap                                             |
| `postgres` | Bundled database, enabled by the `postgres` compose profile                                          |

## Scaling

```shell
./start.sh --scale api=3 --scale worker=2
```

## Using your own Postgres

Set `HOUNDDOG_POSTGRES_URL` in `.env` and remove the `COMPOSE_PROFILES=postgres` line so the
bundled database does not start (the setup wizard can do this for you):

```shell
HOUNDDOG_POSTGRES_URL=postgres://user:password@host:5432/hounddog
```

## Configuration

See `.env.example` for the full commented reference. Required: `HOUNDDOG_SECRET_KEY` — a stable
random string of 50+ characters that encrypts sensitive data at rest. Keep a copy somewhere
safe; encrypted settings are unrecoverable without it, and it must never change once set.

Set `HOUNDDOG_APP_PORT` and `HOUNDDOG_API_PORT` to change the ports published by the starter Compose stack. For
deployments not accessed via localhost, set `HOUNDDOG_APP_BASE_URL` and `HOUNDDOG_API_BASE_URL` to the URLs your
users' browsers reach. When the base URLs are omitted, they are derived from the configured ports.

## Production checklist

- Put a TLS-terminating reverse proxy (or your load balancer) in front of the configured UI and API ports, and set
  the base URLs above to the HTTPS origins. Credentials transit in cleartext otherwise.
- Keep `.env` private (it contains the secret key); it is created with owner-only permissions
  and ignored by git.
- Back up the `postgres_data` and `hounddog_data` volumes, and store the secret key separately
  from database backups.

## CLI scanner

Point the [HoundDog.ai CLI scanner](https://docs.hounddog.ai) at your deployment:

```shell
HOUNDDOG_ENV=self-hosted \
HOUNDDOG_API_URL=http://localhost:8800 \
HOUNDDOG_APP_URL=http://localhost:3300 \
HOUNDDOG_API_KEY=<api key> \
hounddog scan <path>
```

Use the externally reachable API and app URLs when the deployment uses custom ports or hostnames. `HOUNDDOG_API_URL`
controls scanner API requests; `HOUNDDOG_APP_URL` controls links emitted in scanner output.

## Upgrading

```shell
docker compose pull
./start.sh
```
