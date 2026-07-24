# HoundDog.ai Self-Hosted

## Requirements

- Docker with Compose v2
- At least 8 GB RAM and 80 GB disk

## Setup

```shell
git clone https://github.com/hounddogai/hounddog.git
cd hounddog/self-hosted
./setup.sh
docker compose up -d --wait
```

`setup.sh` creates a private `.env` file at `hounddog/self-hosted/.env` by default, relative to the directory where you
ran `git clone`. It also lets you choose the bundled database or your own Postgres server.

When setup completes, the console displays the one-time setup key. It is also stored as `HOUNDDOG_SETUP_KEY` in
`hounddog/self-hosted/.env`. Open http://localhost:3300 and enter this key when prompted.

## Configuration

See [`.env.example`](.env.example) for all settings.

The example uses `hounddog` as the bundled Postgres user, password, and database so local testing
works with minimal setup. Change all three values before the first start of any non-local deployment,
or use an external Postgres server. Existing Postgres volumes keep the credentials they were initialized with.
Because these values are interpolated into the database URL, use only ASCII letters, numbers, hyphens, periods,
underscores, and tildes. Other special characters such as `/`, `?`, and `%` are not supported in these fields.

To use another local port, add this to `.env`:

```dotenv
HOUNDDOG_PORT=4300
```

The public URL will default to `http://localhost:4300`. When you use a domain or reverse proxy, set the public URL too:

```dotenv
HOUNDDOG_URL=https://hounddog.example.com
```

The web app is served at `HOUNDDOG_URL`. The API is served at `HOUNDDOG_URL/api`.
The OpenAPI schema is available without authentication at `HOUNDDOG_URL/api/openapi.json`.

HoundDog.ai-managed AI is not available in self-hosted deployments. Add your own provider under **Settings > AI**.

## External Postgres

Choose external Postgres when you run `./setup.sh`. To configure it by hand, set the URL in `.env` and remove
`COMPOSE_PROFILES` and `POSTGRES_PASSWORD`:

```dotenv
HOUNDDOG_POSTGRES_URL=postgres://user:password@host:5432/hounddog
```

Percent-encode special characters in the username and password. URL options such as `?sslmode=require` are kept.
Separate host, port, database, user, and password settings are not supported.

## Operations

```shell
docker compose ps
docker compose logs -f
docker compose down
```

`docker compose down` stops the stack without deleting data. Scale the API and worker services when needed:

```shell
docker compose up -d --wait --scale api=3 --scale worker=2
```

The bundled Postgres and Caddy containers use stable `hounddog-self-hosted-*` names. Only one self-hosted stack can run
on a Docker host. API and worker containers use numbered names and can be scaled.

## Production

- Put a TLS reverse proxy or load balancer in front of HoundDog.ai. Without TLS, passwords and API keys are not
  encrypted in transit.
- Set `HOUNDDOG_URL` to the public HTTPS URL.
- Keep `.env` private. It contains secrets and is ignored by git.
- Back up `hounddog_data`. If you use bundled Postgres, also back up `postgres_data`.
- Store `HOUNDDOG_SECRET_KEY` separately from the database backup. Encrypted settings cannot be recovered without it.

## CLI Scanner

The self-hosted deployment does not include the CLI scanner. [Install the CLI scanner][scanner-install] on each machine
where you want to run scans.

Create an API key in HoundDog.ai, then export the self-hosted environment variables with the same public URL:

```shell
export HOUNDDOG_ENV=self-hosted
export HOUNDDOG_URL=http://localhost:3300
export HOUNDDOG_API_KEY=YOUR_API_KEY

hounddog scan <path>
```

[scanner-install]: https://github.com/hounddogai/hounddog#installation

## Upgrade

```shell
git pull
docker compose pull
docker compose up -d --wait
```
