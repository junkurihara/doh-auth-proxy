pub const UDP_BUFFER_SIZE: usize = 2048; // TODO: バッファサイズめちゃ適当
pub const UDP_CHANNEL_CAPACITY: usize = 1024; // TODO: channelキャパシティめちゃ適当
pub const UDP_TIMEOUT_SEC: u64 = 10;

pub const LISTEN_ADDRESS: &str = "127.0.0.1:50053";

pub const DOH_TIMEOUT_SEC: u64 = 10;
pub const DOH_TARGET_URL: &str = "https://dns.google/dns-query";
