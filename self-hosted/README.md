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

Upgrading keeps your configuration and data. Database migrations run automatically during startup:

```shell
git pull && ./install.sh
```

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
