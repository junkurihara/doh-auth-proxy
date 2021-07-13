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
    doh-auth-proxy [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -t, --target-url <doh_target_url>          URL of target DoH server like "https://dns.google/dns-query" [default:
                                               https://dns.google/dns-query]
    -l, --listen-address <listen_address>      Address to listen to [default: 127.0.0.1:50053]
    -s, --token-file-path <token_file_path>    JWT file path like "./token.example"
```
