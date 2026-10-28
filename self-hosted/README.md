# HoundDog.ai Self-Hosted

Run HoundDog.ai in your own environment.

## Requirements

- Docker with Compose v2
- PostgreSQL 18 or newer for an external database; Trial mode includes PostgreSQL 18
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
2. Enter the one-time setup key printed by the installer, which starts with `hd_setup_`.
3. Name your organization and create your owner account.
4. Connect an AI provider, such as Anthropic or OpenAI, with your own API key. HoundDog.ai has no built-in AI model
   when self-hosted, so this is what lets AI review the dataflows each scan finds, updating their severity and ignoring
   false positives. You can skip it and connect a provider later in Settings > AI.

By default, HoundDog.ai is reachable from other machines on your network. To allow access only from this machine, set
`HOUNDDOG_BIND_ADDRESS=127.0.0.1` in `.env` and run `docker compose up -d`.

HoundDog.ai reads the list of AI models it offers from `https://hounddog.ai/model-catalog-v1.json` at most once an hour,
so new models appear without an upgrade. To offer only the models of the installed version instead, for example on a
server without internet access, set `HOUNDDOG_MODEL_CATALOG_URL=off` in `.env` and run `docker compose up -d`.

The installer saves your configuration in `.env`. Keep a private copy of its `HOUNDDOG_SECRET_KEY`: it encrypts the
credentials that HoundDog.ai stores in its database, which cannot be decrypted without it.

In Trial mode, the installer automatically sets up a CLI API key so you can scan a repository right away:

```shell
hounddog scan /path/to/repository
```

The installer's key is an organization API key named "HoundDog CLI": it can scan and upload results, but cannot read
or change anything else, so it is also the right kind of key for CI. It expires one year after setup. Before then,
create a new organization API key under API Keys and put it in `HOUNDDOG_API_KEY` in `~/.config/hounddog/.env`.

## Accounts and Sign-In

Owners and admins add users in Settings > Users, which gives each new user a temporary password to change at their
first sign-in. Owners and admins also reset passwords there, except that only owners reset the passwords of admins and
other owners.

After 10 failed sign-ins in a row to the same email address from one IP address, that address cannot sign in to it for
15 minutes. Sign-ins from other addresses still work, and resetting the password lifts the lock. Settings > Users shows
which users are locked, and the Audit Log records sign-ins, failed sign-ins, locks, sign-outs, and password changes.

If nobody can reset a password in the web app, for example because the only owner forgot it, issue a temporary
password from this directory:

```shell
docker compose exec api reset-password owner@example.com
```

It signs the account out everywhere, lifts its locks, and prints a temporary password, which must be changed at the
next sign-in.

## Reverse Proxy

HoundDog.ai allows each client IP address 10 sign-in, first-run setup, and password change attempts per minute
(`HOUNDDOG_AUTH_RATE_LIMIT_EVENTS` and `HOUNDDOG_AUTH_RATE_LIMIT_WINDOW` in `.env`). Clients whose address it cannot see
share one limit and one sign-in lock per account, so one of them can block sign-in for all of them:

- **Proxy or load balancer on another host:** set `HOUNDDOG_TRUSTED_PROXIES` in `.env` to its IP address or CIDR range.
- **Proxy on this host:** it connects through the Docker network's gateway, not from `127.0.0.1`. Set
  `HOUNDDOG_BIND_ADDRESS=127.0.0.1`, so that only this host can connect, and `HOUNDDOG_TRUSTED_PROXIES=private_ranges`.
- **No proxy:** Docker hides the address of IPv6 clients, and of all clients on Docker Desktop or rootless Docker. Put a
  reverse proxy in front of HoundDog.ai to give these clients separate limits.

The proxy must send the client address in the `X-Forwarded-For` header. Run `docker compose up -d` after changing
`.env`.

## Upgrade

Upgrading keeps your configuration and data, and also upgrades the CLI. Back up your database first, because
HoundDog.ai is briefly unavailable while the upgrade runs.

```shell
git pull && ./upgrade.sh
```

HoundDog.ai does not start when `HOUNDDOG_SETUP_KEY` in `.env` is set but does not start with `hd_setup_`, which is
the case for installations made before setup keys had that prefix. Setup no longer needs the key once it is complete,
so remove that line from `.env` before upgrading. If setup is not complete yet, replace the value with `hd_setup_`
followed by a random value instead.

If a prerequisite check fails, existing containers keep running. If migration or startup fails after the drain,
HoundDog.ai stays stopped. Fix the reported error and run `./upgrade.sh` again, or restore your
database backup before going back to the previous version.

## Reset

Reset deletes your local data, backs up and deletes your configuration, then starts a fresh installation. It does not
delete data in your own Postgres database, so install into a new or empty database.

```shell
./reset.sh
```

## Uninstall

Uninstall removes HoundDog.ai and its local data, and backs up and deletes your configuration. It keeps the CLI, the
configuration backups, this directory, and your own Postgres database.

```shell
./uninstall.sh
```

Reset and uninstall back up `.env` to `.env.backup.<timestamp>.<random>` in this directory, and the CLI configuration
in `~/.config/hounddog/` the same way. To use your own Postgres database again, copy the backup to `.env` and run
`docker compose up -d`, because only its `HOUNDDOG_SECRET_KEY` can decrypt the credentials stored in that database.
