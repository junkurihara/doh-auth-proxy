use crate::client::DoHClient;
use std::net::SocketAddr;
use std::time::Duration;
use tokio;

#[derive(Debug)]
pub struct Globals {
  pub listen_address: SocketAddr,
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub udp_timeout: Duration,

  pub doh_target_url: String,
  pub doh_timeout_sec: u64,
  pub bootstrap_dns: SocketAddr,

  pub auth_token: Option<String>,

  pub runtime_handle: tokio::runtime::Handle,
  pub client: DoHClient,
}
