# ToDo

- Better handling DNS query/response
  - Cache of DNS response messages (Almost done)
   -> More sophisticated handling of TTL.
  - EDNS0 padding options
    <https://datatracker.ietf.org/doc/html/rfc7830>
    <https://datatracker.ietf.org/doc/html/rfc8467>
- `crates.io`
- Docker container packaged with token server (server-side)
- Override with command line options over TOML configuration
- Tweaks for anonymization
  - Override user-agent for DoH/ODoH/MODoH by specifying one in `config.toml`
- Refactor
