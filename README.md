# doh-auth-proxy
DoH local proxy with http authorization header, written in Rust

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
    -d, --debug-mode        Use debug mode to issue authorized query even in odoh. just for development.
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
