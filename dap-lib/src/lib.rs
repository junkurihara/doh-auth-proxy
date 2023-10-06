mod client;
mod constants;
mod error;
mod globals;
mod log;

use crate::{error::*, globals::Globals, log::info};
use std::sync::Arc;

pub use client::DoHMethod;
pub use globals::{AuthenticationConfig, NextHopRelayConfig, ProxyConfig, SubseqRelayConfig, TargetConfig};

pub async fn entrypoint(
  proxy_config: &ProxyConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  info!("Hello, world!");

  // build global
  let globals = Arc::new(Globals {
    proxy_config: proxy_config.clone(),
    runtime_handle: runtime_handle.clone(),
  });

  Ok(())
}
