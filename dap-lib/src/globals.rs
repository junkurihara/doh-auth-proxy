use crate::{client::DoHMethod, constants::*};
// use futures::future;
// use rand::Rng;
use std::net::SocketAddr;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub struct Globals {
  // pub cache: Arc<Cache>,
  // pub counter: ConnCounter,
  // pub doh_clients: Arc<RwLock<Option<Vec<DoHClient>>>>,
  pub proxy_config: ProxyConfig,
  pub runtime_handle: tokio::runtime::Handle,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ProxyConfig {
  pub listen_addresses: Vec<SocketAddr>,
  pub max_connections: usize,
  pub max_cache_size: usize,

  /// bootstrap DNS
  pub bootstrap_dns: Vec<SocketAddr>,
  pub rebootstrap_period_sec: Duration,

  // udp proxy setting
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub timeout_sec: Duration,

  // doh, odoh, modoh target settings
  pub target_config: TargetConfig,

  // odoh and modoh nexthop
  pub nexthop_relay_config: Option<NextHopRelayConfig>,

  // modoh
  pub subseq_relay_config: Option<SubseqRelayConfig>,
  // pub query_plugins: Option<QueryPluginsApplied>,
  // pub min_ttl: u32, // TTL of overridden response
  // pub credential: Arc<RwLock<Option<Credential>>>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// doh, odoh, modoh target settings
pub struct TargetConfig {
  pub doh_method: DoHMethod,
  pub doh_target_urls: Vec<String>,
  pub target_randomization: bool,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// odoh and modoh nexthop
pub struct NextHopRelayConfig {
  pub odoh_relay_urls: Vec<String>,
  pub odoh_relay_randomization: bool,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// modoh
pub struct SubseqRelayConfig {
  pub mid_relay_urls: Vec<String>,
  pub max_mid_relays: usize,
}

impl Default for TargetConfig {
  fn default() -> Self {
    Self {
      doh_method: DoHMethod::Post,
      doh_target_urls: DOH_TARGET_URL.iter().map(|v| v.parse().unwrap()).collect(),
      target_randomization: true,
    }
  }
}

impl Default for ProxyConfig {
  fn default() -> Self {
    Self {
      listen_addresses: LISTEN_ADDRESSES.iter().map(|v| v.parse().unwrap()).collect(),
      max_connections: MAX_CONNECTIONS,
      max_cache_size: MAX_CACHE_SIZE,

      bootstrap_dns: BOOTSTRAP_DNS.iter().map(|v| v.parse().unwrap()).collect(),
      rebootstrap_period_sec: Duration::from_secs(REBOOTSTRAP_PERIOD_MIN * 60),

      udp_buffer_size: UDP_BUFFER_SIZE,
      udp_channel_capacity: UDP_CHANNEL_CAPACITY,
      timeout_sec: Duration::from_secs(TIMEOUT_SEC),

      target_config: TargetConfig::default(),
      nexthop_relay_config: None,
      subseq_relay_config: None,
    }
  }
}
