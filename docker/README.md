# Docker container of `doh-auth-proxy`

We have several docker-specific environment variables, which doesn't relates the behavior of `doh-auth-proxy`.

- `HOST_USER` (default: `user`): User name executing `rpxy` inside the container.
- `HOST_UID` (default: `900`): `UID` of `HOST_USER`.
- `HOST_GID` (default: `900`): `GID` of `HOST_USER`
- `LOG_LEVEL=debug|info|warn|error` (default: `info`): Log level
- `LOG_TO_FILE=true|false` (default: `false`): Enable logging to the log file `/modoh/log/doh-auth-proxy.log` using `logrotate`. You should mount `/modoh/log` via docker volume option if enabled. The log dir and file will be owned by the `HOST_USER` with `HOST_UID:HOST_GID` on the host machine. Hence, `HOST_USER`, `HOST_UID` and `HOST_GID` should be the same as ones of the user who executes the `doh-auth-proxy` docker container on the host.

See [`docker/docker-compose.yml`](./docker/docker-compose.yml) for the detailed configuration of the above env vars.

Other than them, we have the following environment variables as `doh-auth-proxy` specific parameters. In `docker-compose.yml`, they are configured through `.env` file. (See `.env.example`.)

```:.env
## All values are optional

## Common to DoH and ODoH
# TARGET_URLS=https://dns.google/dns-query
TARGET_URLS=https://odoh.cloudflare-dns.com/dns-query
TARGET_RANDOMIZATION=true
BOOTSTRAP_DNS_ADDR=1.1.1.1
BOOTSTRAP_DNS_PORT=53

## ODoH
## If specified, ODoH is enabled.
ODOH_RELAY_URLS=https://odoh1.surfdomeinen.nl/proxy
ODOH_RELAY_RANDOMIZATION=true

## Mutualized ODoH
## If specified, ODoH queries are transferred over multiple hops,
## where the first hop (nexthop) is always ODOH_RELAY_URL as a trusted relay.
## ODOH_RELAY_URL must be specified.
# MODOH_MID_RELAY_URLS=https://relay1.example.com/proxy,https://relay2.example.com/proxy
# MODOH_MAX_MID_RELAYS=2

## Authentication at the nexthop
## If specified, authentication is enabled at
## - DoH: Target DoH server, i.e., TARGET_URL.
## - ODoH/Mutualized ODoH: Nexthop relay url, i.e., ODOH_RELAY_URL.
# TOKEN_API=https://xxx.token.com/v1.0 # i.e., token issuer
# USERNAME=user
# PASSWORD=password
# CLIENT_ID=xxxxxxx # i.e., app_id

## Plugins
# PLUGINS_DIR="./plugins"
## Place below files in ${PLUGINS_DIR} directory
# DOMAINS_BLOCKED_FILE="blocklist.txt"
# DOMAINS_OVERRIDDEN_FILE="override.txt"
```

and execute `docker-compose` as

```shell
% docker-compose up -d
```

By this example, it listens at the port `50553` by default and outputs a log file to `./log` directory. You should configure params in `docker-compose.yml` as you like in addition to `.env`.
