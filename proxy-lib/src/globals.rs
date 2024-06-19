use crate::{bootstrap::BootstrapDnsInner, constants::*, QueryLoggingBase};
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::Notify, time::Duration};
use url::Url;

#[derive(Debug)]
/// Global objects containing shared resources
pub struct Globals {
  /// proxy configuration
  pub proxy_config: ProxyConfig,

  /// tokio runtime handler
  pub runtime_handle: tokio::runtime::Handle,

  /// notifier for termination at spawned tokio tasks
  pub term_notify: Option<Arc<Notify>>,

  /// query logger sender
  pub query_log_tx: crossbeam_channel::Sender<QueryLoggingBase>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct ProxyConfig {
  /// listen addresses
  pub listen_addresses: Vec<SocketAddr>,
  /// maximum number of connections
  pub max_connections: usize,
  /// maximum cache size
  pub max_cache_size: usize,

  /// bootstrap DNS
  pub bootstrap_dns: BootstrapDns,
  /// endpoint resolution period
  pub endpoint_resolution_period_sec: Duration,
  /// health check period
  pub healthcheck_period_sec: Duration,

  // udp and tcp proxy setting
  /// UDP buffer size
  pub udp_buffer_size: usize,
  /// UDP channel capacity
  pub udp_channel_capacity: usize,
  /// UDP timeout
  pub udp_timeout_sec: Duration,
  /// TCP listen backlog
  pub tcp_listen_backlog: u32,

  /// timeout for HTTP requests (DoH, ODoH, and authentication requests)
  pub http_timeout_sec: Duration,

  /// http user agent
  pub http_user_agent: String,

  /// doh, odoh, modoh target settings
  pub target_config: TargetConfig,

  /// odoh and modoh nexthop settings
  pub nexthop_relay_config: Option<NextHopRelayConfig>,

  /// modoh relay settings
  pub subseq_relay_config: Option<SubseqRelayConfig>,

  /// authentication settings
  pub token_config: Option<TokenConfig>,

  /// query manipulation settings
  pub query_manipulation_config: Option<Arc<QueryManipulationConfig>>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// doh, odoh, modoh target settings
pub struct TargetConfig {
  pub use_get: bool,
  pub doh_target_urls: Vec<Url>,
  pub target_randomization: bool,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// odoh and modoh nexthop
pub struct NextHopRelayConfig {
  pub odoh_relay_urls: Vec<Url>,
  pub odoh_relay_randomization: bool,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// modoh
pub struct SubseqRelayConfig {
  pub mid_relay_urls: Vec<Url>,
  pub max_mid_relays: usize,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct TokenConfig {
  /// authentication client configuration inner
  pub authentication_config: auth_client::AuthenticationConfig,
  #[cfg(feature = "anonymous-token")]
  /// use anonymous token instead of ID token for the connection to the next hop node
  /// only if the authentication is configured. if not, no token is set in the http authorization header.
  pub use_anonymous_token: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Manipulation rules. For reloading from source, this struct is based on raw strings.
/// After reading from source, they are converted to actual manipulator objects.
pub struct QueryManipulationConfig {
  /// query override plugin
  pub domain_override: Option<Vec<String>>,
  /// query block plugin
  pub domain_block: Option<Vec<String>>,
  /// minimum TTL for synthetic response
  pub min_ttl: u32,
}

impl Default for TargetConfig {
  fn default() -> Self {
    Self {
      use_get: false,
      doh_target_urls: DOH_TARGET_URL.iter().map(|v| v.parse().unwrap()).collect(),
      target_randomization: true,
    }
  }
}

impl Default for QueryManipulationConfig {
  fn default() -> Self {
    QueryManipulationConfig {
      domain_override: None,
      domain_block: None,
      min_ttl: MIN_TTL,
    }
  }
}

/* ---------------------------------------- */
#[derive(PartialEq, Eq, Debug, Clone)]
/// Bootstrap DNS Addresses
pub struct BootstrapDns {
  inner: Vec<BootstrapDnsInner>,
}

impl BootstrapDns {
  /// Get bootstrap DNS addresses
  pub(crate) fn inner(&self) -> &[BootstrapDnsInner] {
    &self.inner
  }
}

impl Default for BootstrapDns {
  fn default() -> Self {
    Self {
      inner: BOOTSTRAP_DNS_ADDRS
        .iter()
        .map(|v| BootstrapDnsInner::try_new(BOOTSTRAP_DNS_PROTO, v).unwrap())
        .collect(),
    }
  }
}

impl std::fmt::Display for BootstrapDns {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut first = true;
    for v in &self.inner {
      if !first {
        write!(f, ", ")?;
      }
      write!(f, "{v}")?;
      first = false;
    }
    Ok(())
  }
}

impl TryFrom<Vec<(String, SocketAddr)>> for BootstrapDns {
  type Error = anyhow::Error;

  fn try_from(value: Vec<(String, SocketAddr)>) -> anyhow::Result<Self, Self::Error> {
    let inner = value
      .into_iter()
      .map(|(proto, addr)| BootstrapDnsInner::try_new(&proto, &addr.to_string()).unwrap())
      .collect();
    Ok(Self { inner })
  }
}

impl Default for ProxyConfig {
  fn default() -> Self {
    Self {
      listen_addresses: LISTEN_ADDRESSES.iter().map(|v| v.parse().unwrap()).collect(),
      max_connections: MAX_CONNECTIONS,
      max_cache_size: MAX_CACHE_SIZE,

      bootstrap_dns: BootstrapDns::default(),
      endpoint_resolution_period_sec: Duration::from_secs(ENDPOINT_RESOLUTION_PERIOD_MIN * 60),
      healthcheck_period_sec: Duration::from_secs(HEALTHCHECK_PERIOD_MIN * 60),

      udp_buffer_size: UDP_BUFFER_SIZE,
      udp_channel_capacity: UDP_CHANNEL_CAPACITY,
      udp_timeout_sec: Duration::from_secs(UDP_TIMEOUT_SEC),
      tcp_listen_backlog: TCP_LISTEN_BACKLOG,

      http_timeout_sec: Duration::from_secs(HTTP_TIMEOUT_SEC),
      http_user_agent: format!("{}/{}", HTTP_USER_AGENT, env!("CARGO_PKG_VERSION")),

      target_config: TargetConfig::default(),
      nexthop_relay_config: None,
      subseq_relay_config: None,

      token_config: None,

      query_manipulation_config: None,
    }
  }
}
