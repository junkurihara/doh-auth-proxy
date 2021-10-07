# doh-auth-proxy

DoH and Oblivious DoH local proxy supporting authenticated connection, written in Rust

## Build

```:bash
# debug mode
$ cargo build

# release mode
$ cargo build --release
```

## Usage

```bash
USAGE:
    doh-auth-proxy [FLAGS] [OPTIONS]

FLAGS:
    -g, --use-get-method    Use Get method to query
    -h, --help              Prints help information
    -V, --version           Prints version information

OPTIONS:
    -b, --bootstrap-dns <bootstrap_dns>                  DNS (Do53) resolver address for bootstrap [default: 1.1.1.1:53]
    -c, --credential-file-path <credential_file_path>
            Credential env file path for login endpoint like "./credential.env"

    -t, --target-url <doh_target_url>
            URL of (O)DoH target server like "https://dns.google/dns-query" [default: https://dns.google/dns-query]

    -l, --listen-address <listen_addresses>...
            Address to listen to. To specify multiple addresses, set args like "--listen-address=127.0.0.1:50053
            --listen-address='[::1]:50053'"
    -r, --relay-url <odoh_relay_url>                     URL of ODoH relay server like "https://relay.example.com/relay"
    -p, --reboot-period <rebootstrap_period_min>
            Minutes to re-fetch the IP addr of the target url host via the bootstrap DNS

    -a, --token-api <token_api>
            API url to retrieve and refresh tokens and validation keys (jwks) like "https://example.com/v1.0", where
            /tokens and /refresh are used for login and refresh, respectively. Also /jwks is used for jwks retrieval.
```

## Authentication at the next hop node (DoH target or ODoH relay)

This proxy provides **authenticated connection** to a DoH target resolver (in DoH) or to an ODoH relay (in ODoH).
This function avoids the nexthop node to be private to users.
To leverage the function, an authentication server issueing Authorization Bearer tokens and an authentication-enabled DoH target/ODoH relay, given in the following.

- [`doh-server` (`jwt-auth` branch)](https://github.com/junkurihara/doh-server/tree/jwt-auth): A fork of [`DNSCrypt/doh-server`](https://github.com/DNSCrypt/doh-server) enabling the ODoH relay function, and authenticated connection with Authorization Bearer token.

- [`rust-token-server`](https://github.com/junkurihara/rust-token-server): An implementation of authentication server issueing `id_token` in the context of OIDC.
