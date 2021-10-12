# doh-auth-proxy

DoH and Oblivious DoH local proxy supporting authenticated connection, written in Rust

## Build

```:bash
# debug mode
$ cargo build

# release mode
$ cargo build --release
```

Now you have a compiled executable binary `doh-auth-proxy` in `./target/debug/` or `./target/release/`.

## Basic example

### Connecting to Google public DoH server

```:bash
$ ./path/to/doh-auth-proxy \
    --listen-address=127.0.0.1:50053 \
    --listen-address="[::1]:50053" \
    --target-url=https://dns.google/dns-query \
    --bootstrap-dns=1.1.1.1:53
```

Now you can query through `127.0.0.1:50053` as

```:bash
% dig github.com @localhost -p 50053
~~~~~~~
;; ANSWER SECTION:
github.com.             60      IN      A       52.69.186.44
~~~~~~~
```

The parameter `bootstrap-dns` is used to resolve the IP address of the host of `target-url` (i.e., target DoH server).

### Connecting to Cloudflare ODoH server via `surfdomeinen.nl` ODoH relay

```:bash
$ ./path/to/doh-auth-proxy \
    --listen-address=127.0.0.1:50053 \
    --listen-address="[::1]:50053" \
    --target-url=https://odoh.cloudflare-dns.com/dns-query \
    --relay-url=https://odoh1.surfdomeinen.nl/proxy \
    --bootstrap-dns=1.1.1.1:53
```

This example issues ODoH encrypted queries by an URL `https://odoh1.surfdomeinen.nl/proxy?targethost=odoh.cloudflare-dns.com&targetpath=/dns-query`.

Now you can query through `127.0.0.1:50053` as

```:bash
% dig github.com @localhost -p 50053
~~~~~~~
;; ANSWER SECTION:
github.com.             11      IN      A       140.82.121.4
~~~~~~~
```

where this takes more round-trip time than the above ordinary DoH example due to the intermediate relay (especially when it is far from your location).

## All options

```:bash
USAGE:
    doh-auth-proxy [FLAGS] [OPTIONS]

FLAGS:
    -g, --use-get-method    Use Get method to query
    -h, --help              Prints help information
    -V, --version           Prints version information

OPTIONS:
    -b, --bootstrap-dns <bootstrap_dns>
            DNS (Do53) resolver address for bootstrap
            [default: 1.1.1.1:53]

    -t, --target-url <doh_target_url>
            URL of (O)DoH target server like "https://dns.google/dns-query"
            [default: https://dns.google/dns-query]

    -l, --listen-address <listen_addresses>...
            Address to listen to. To specify multiple
            addresses, set args like
            "--listen-address=127.0.0.1:50053 --listen-address='[::1]:50053'"

    -p, --reboot-period <rebootstrap_period_min>
            Minutes to re-fetch the IP addr of the target
            url host via the bootstrap DNS

---
OPTION FOR OBLIVIOUS DNS OVER HTTPS:
    -r, --relay-url <odoh_relay_url>
            URL of ODoH relay server like "https://relay.example.com/relay".
            If specified, ODoH is enabled.

---
OPTIONS FOR AUTHORIZED ACCESS TO THE NEXT HOP:
    -c, --credential-file-path <credential_file_path>
            Credential env file path for login endpoint like
            "./credential.env"

    -a, --token-api <token_api>
            API url to retrieve and refresh tokens and
            validation keys (jwks) like "https://example.com/v1.0",
            where /tokens and /refresh are used for login and refresh,
            respectively. Also /jwks is used for jwks retrieval.
```

## Docker container

You can run this proxy as a docker container, where the docker image is hosted at [Docker Hub](https://hub.docker.com/r/jqtype/doh-auth-proxy). You can run the docker container by appropriately configure `.env` file as

```:.env
## Common to DoH and ODoH
### Required
# TARGET_URL=https://dns.google/dns-query
TARGET_URL=https://odoh.cloudflare-dns.com/dns-query
LOG_DIR=./log

### Optional
BOOTSTRAP_DNS_ADDR=1.1.1.1
BOOTSTRAP_DNS_PORT=53
DEBUG=true # If set, it outputs debug log
LOG_NUM=3
LOG_SIZE=10M

## ODoH
## If specified, ODoH is enabled.
ODOH_RELAY_URL=https://odoh1.surfdomeinen.nl/proxy
```

and execute `docker-compose` as

```:bash
$ docker-compose up -d
```

which listens at the port `50553` as default and outputs a log file to `./log` directory. You should configure params in `docker-compose.yml` as you like in addition to `.env`.

**NOTE**: Authorized access to the next hop node is not supported in docker container at this point.

## Authentication at the next hop node (DoH target or ODoH relay)

This proxy provides **authenticated connection** to a DoH target resolver (in DoH) or to an ODoH relay (in ODoH).
This function allows the nexthop node (DoH target/ODoH relay) to be private to users, and avoids unauthorized access.
To leverage the function, an authentication server issueing Authorization Bearer tokens and an authentication-enabled DoH target/ODoH relay, given in the following.

- [`doh-server` (`jwt-auth` branch)](https://github.com/junkurihara/doh-server/tree/jwt-auth): A fork of [`DNSCrypt/doh-server`](https://github.com/DNSCrypt/doh-server) enabling the ODoH relay function, and authenticated connection with Authorization Bearer token.

- [`rust-token-server`](https://github.com/junkurihara/rust-token-server): An implementation of authentication server issueing `id_token` in the context of OIDC.

## TODO

- Better handling DNS query/response
  - Cache of DNS response messages
  - EDNS0 padding options
    https://datatracker.ietf.org/doc/html/rfc7830
    https://datatracker.ietf.org/doc/html/rfc8467
- Ping to the target DNS resolver when DoH client instance is created and refreshed.
- `crates.io`
