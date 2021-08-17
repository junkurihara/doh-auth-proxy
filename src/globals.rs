use crate::client::{DoHClient, DoHMethod};
use crate::credential::Credential;
use std::net::SocketAddr;
use std::time::Duration;
use tokio;

#[derive(Debug, Clone)]
pub struct Globals {
  pub listen_addresses: Vec<SocketAddr>,
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub timeout_sec: Duration,

  pub doh_target_url: String,
  pub doh_method: Option<DoHMethod>,
  // pub odoh_relay_url: Option<String>,
  pub bootstrap_dns: SocketAddr,
  pub rebootstrap_period_sec: Duration,

  pub runtime_handle: tokio::runtime::Handle,
}

#[derive(Debug, Clone)]
pub struct GlobalsCache {
  pub doh_client: Option<DoHClient>,
  pub doh_target_addrs: Option<Vec<SocketAddr>>,
  // pub odoh_relay_addrs: Option<Vec<SocketAddr>>,
  pub credential: Option<Credential>,
}
