# HoundDog.ai Self-Hosted

Run HoundDog.ai in your own environment.

## Requirements

- Docker with Compose v2
- At least 4 GB of RAM and 40 GB of disk space

## Installation

```shell
git clone https://github.com/hounddogai/hounddog.git
cd hounddog/self-hosted
./install.sh
```

The installer will ask you to choose the installation type:

1. **Trial:** The quickest way to try HoundDog.ai. Postgres is set up locally for you.
2. **Production:** Connects HoundDog.ai to your own Postgres database. This option requires more setup and maintenance.

When the installation finishes:

1. Open the HoundDog.ai URL printed by the installer, such as `http://localhost:3300`.
2. Enter the one-time setup key printed by the installer.
3. Create your organization and owner account.

The installer publishes port 3300 on all host interfaces by default so the app is reachable from another machine.
Set `HOUNDDOG_BIND_ADDRESS=127.0.0.1` in `.env` and recreate the containers to restrict access to the Docker host.

In Trial mode, the installer automatically sets up a CLI API key so you can scan a repository right away:

```shell
hounddog scan /path/to/repository
```

## Upgrade

Upgrading keeps your configuration and data. Take a database backup first. The installer pulls the new image, stops
the web/API/worker containers, runs migrations once with the new image, and starts the new stack only after migration
succeeds:

```shell
git pull && ./install.sh
```

The application is unavailable during this maintenance window. If a migration fails, the installer deliberately
leaves application containers stopped. Fix forward with the new release, or restore the pre-upgrade database backup
before restarting an older release; do not run an older release against a partially migrated database.

The installer preserves API and worker replica counts set with `docker compose up --scale` when it restarts an
existing installation, including a worker scale of zero. The public web application requires an API, so an upgrade
restores a missing API service at scale one.

### Recovering RoPA migrations 0126 and 0127

Migration 0126 applies the normalized RoPA schema atomically. If it fails, correct the reported lock or schema problem
and rerun `./install.sh`; PostgreSQL rolled its schema transaction back. Do not start an older API or worker against a
database where either migration has completed.

The installer checks legacy reports before stopping writers, after stopping the API, and after stopping workers. If an
import raced the first check, the old worker remains running so it can finish before you retry. Migration 0127 copies
each report's current table into normalized storage in its own transaction. If it fails after all writers stop, keep
`caddy`, `api`, and `worker` stopped, correct the reported report, and rerun the installer:

```shell
./install.sh
```

If the API-closed preflight instead names an active review that raced the first check, migrations have not started. Run
`docker compose start api caddy`, resolve or delete that review in the previous application, and rerun `./install.sh`.
Do not restart the previous application after migration 0127 has started.

The normal migration retry skips completed reports and rolls back the report that failed. The installer restores the
API and worker replica counts it observed before the upgrade after migration succeeds. Migration 0127 is irreversible;
do not fake either migration or invoke its Python helper manually. Take another database backup after recovery succeeds.

## Reset

Reset deletes your local configuration and data, then starts a fresh installation. It does not delete external Postgres.

```shell
./reset.sh
```

## Uninstall

Uninstall removes HoundDog.ai and its local data. It keeps the CLI, configuration backups, repository files, and any
external Postgres database.

```shell
./uninstall.sh
```
