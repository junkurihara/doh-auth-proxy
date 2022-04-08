# ToDo

- Better handling DNS query/response
  - Cache of DNS response messages
  - EDNS0 padding options
    <https://datatracker.ietf.org/doc/html/rfc7830>
    <https://datatracker.ietf.org/doc/html/rfc8467>
- `crates.io`
- Sophistication of mu-ODNS based on ODoH, such as loop detection
- Docker container packaged with token server (server-side)
- Override with command line options over TOML configuration
- **Domain-based filtering** much like `dnscrypt-proxy` (server-side filtering is alreadly implemented in my fork of `doh-server`)
