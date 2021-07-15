use crate::client::{DoHClient, DoHMethod};
use std::net::SocketAddr;
// use std::sync::Arc;
use std::time::Duration;
use tokio;

#[derive(Debug, Clone)]
pub struct Globals {
  pub listen_address: SocketAddr,
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub udp_timeout: Duration,

  pub doh_target_url: String,
  pub doh_timeout_sec: u64,
  pub doh_method: Option<DoHMethod>,
  pub bootstrap_dns: SocketAddr,
  pub rebootstrap_period_sec: Duration,

  pub auth_token: Option<String>,

  pub runtime_handle: tokio::runtime::Handle,
  // pub client: DoHClient,
}

#[derive(Debug, Clone)]
pub struct GlobalsCache {
  pub doh_client: DoHClient,
  pub doh_target_addrs: Vec<SocketAddr>,
}
