////////////////////////////////
// Constant Values for Config //
////////////////////////////////
// Cannot override by config.toml
pub const UDP_BUFFER_SIZE: usize = 2048; // TODO: バッファサイズめちゃ適当
pub const UDP_CHANNEL_CAPACITY: usize = 1024; // TODO: channelキャパシティめちゃ適当
pub const MAX_CONNECTIONS: usize = 128; // TODO: 最大接続数(UDP+TCP)めちゃ適当
pub const TIMEOUT_SEC: u64 = 10;

pub const MIN_TTL: u32 = 10; // TTL for overridden records (plugin)

////////////////////////////////
// Default Values for Config  //
////////////////////////////////
// Can override by specifying values in config.toml
pub const LISTEN_ADDRESSES: &[&str] = &["127.0.0.1:50053", "[::1]:50053"];

pub const BOOTSTRAP_DNS_IPS: &[&str] = &["1.1.1.1"];
pub const BOOTSTRAP_DNS_PORT: u16 = 53;
pub const REBOOTSTRAP_PERIOD_MIN: u64 = 60;
pub const DOH_TARGET_URL: &[&str] = &["https://dns.google/dns-query"];

pub const MAX_CACHE_SIZE: usize = 16384;

///////////////////////////////
// Constant Values for Proxy //
///////////////////////////////
// Cannot override below by config.toml
pub const ODOH_CONFIG_PATH: &str = ".well-known/odohconfigs"; // client

// Authentication

/// refresh at least two minutes before expiration
pub const TOKEN_REFRESH_MARGIN: i64 = 120;
/// wait for 60 secs before watching token expiration
pub const TOKEN_REFRESH_WATCH_DELAY: i64 = 60;

// pub const CREDENTIAL_REFRESH_MARGIN: i64 = 10; // at least 10 secs must be left to refresh // client::credential
// pub const CREDENTIAL_CHECK_PERIOD_SECS: u64 = 60; // proxy
//                                                   // every 60 secs, token is checked. then if the refresh condition is satisfied, refresh.
//                                                   // this is to rapidly recover from the hibernation of PC on which this is working. (at most 60 secs is needed for recovery)
// pub const ENDPOINT_RELOGIN_WAITING_SEC: u64 = 10; // proxy
// pub const MAX_LOGIN_ATTEMPTS: usize = 5; // proxy

pub const HEALTHCHECK_TARGET_FQDN: &str = "dns.google."; // client
pub const HEALTHCHECK_TARGET_ADDR: &str = "8.8.8.8"; // client
