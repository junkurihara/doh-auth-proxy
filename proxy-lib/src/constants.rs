////////////////////////////////
// Constant Values for Config //
////////////////////////////////
// Cannot override by config.toml

/// UDP buffer size TODO: めちゃ適当
pub const UDP_BUFFER_SIZE: usize = 2048;
/// UDP channel Capacity TODO: めちゃ適当
pub const UDP_CHANNEL_CAPACITY: usize = 1024; // TODO: channelキャパシティめちゃ適当
/// UDP timeout in secs
pub const UDP_TIMEOUT_SEC: u64 = 10;
/// TCP listen backlog
pub const TCP_LISTEN_BACKLOG: u32 = 1024;

/// Max connections via UPD and TCP (total) TODO: めちゃ適当
pub const MAX_CONNECTIONS: usize = 128;
/// Time out secs for HTTP requests
pub const HTTP_TIMEOUT_SEC: u64 = 10;
/// TTL for overridden records (plugin) in synthetic response
pub const MIN_TTL: u32 = 10;

////////////////////////////////
// Default Values for Config  //
////////////////////////////////
// Can override by specifying values in config.toml

/// Default listen address
pub const LISTEN_ADDRESSES: &[&str] = &["127.0.0.1:50053", "[::1]:50053"];

/// Bootstrap DNS address
pub const BOOTSTRAP_DNS_IPS: &[&str] = &["1.1.1.1"];
/// Bootstrap DNS port
pub const BOOTSTRAP_DNS_PORT: u16 = 53;

/// Endpoint resolution period in minutes
pub const ENDPOINT_RESOLUTION_PERIOD_MIN: u64 = 60;

/// Health check: Check for health of paths and purge cache for every 600 secs
pub const HEALTHCHECK_PERIOD_MIN: u64 = 10;

/// Default DoH target server
pub const DOH_TARGET_URL: &[&str] = &["https://dns.google/dns-query"];

/// Max cache size of DNS response messages
pub const MAX_CACHE_SIZE: usize = 16384;

///////////////////////////////
// Constant Values for Proxy //
///////////////////////////////
// Cannot override below by config.toml

/// HTTP User-Agent
pub const HTTP_USER_AGENT: &str = "doh-auth-proxy";

// ODoH

/// ODoH config path
pub const ODOH_CONFIG_PATH: &str = ".well-known/odohconfigs";
/// ODoH config is retrieved every 3600 secs
pub const ODOH_CONFIG_WATCH_DELAY: i64 = 3600;

// Authentication

/// refresh at least two minutes before expiration
pub const TOKEN_REFRESH_MARGIN: i64 = 120;
/// wait for 60 secs before watching token expiration
/// every 60 secs, token is checked. then if the refresh condition is satisfied, refresh.
/// this is to rapidly recover from the hibernation of PC on which this is working. (at most 60 secs is needed for recovery)
pub const TOKEN_REFRESH_WATCH_DELAY: i64 = 60;
/// wait for 10 secs before relogin
pub const TOKEN_RELOGIN_WAITING_SEC: u64 = 10;
/// relogin at most 5 times
pub const MAX_RELOGIN_ATTEMPTS: usize = 5;

// Health check

/// Health check target FQDN
pub const HEALTHCHECK_TARGET_FQDN: &str = "dns.google.";
/// Health check target IP address for assertion
pub const HEALTHCHECK_TARGET_ADDR: &str = "8.8.8.8";
