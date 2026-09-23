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

By default, HoundDog.ai is reachable from other machines on your network. To allow access only from this machine, set
`HOUNDDOG_BIND_ADDRESS=127.0.0.1` in `.env` and run `docker compose up -d`.

In Trial mode, the installer automatically sets up a CLI API key so you can scan a repository right away:

```shell
hounddog scan /path/to/repository
```

## Upgrade

Upgrading keeps your configuration and data, and also upgrades the CLI. Back up your database first, because
HoundDog.ai is briefly unavailable while the upgrade runs.

```shell
git pull && ./upgrade.sh
```

If the upgrade fails, HoundDog.ai stays stopped. Fix the reported error and run `./upgrade.sh` again, or restore your
database backup before going back to the previous version.

## Reset

Reset deletes your local configuration and data, then starts a fresh installation. It does not delete data in your own
Postgres database.

```shell
./reset.sh
```

## Uninstall

Uninstall removes HoundDog.ai and its local data. It keeps the CLI, configuration backups, this directory, and your own
Postgres database.

```shell
./uninstall.sh
```
