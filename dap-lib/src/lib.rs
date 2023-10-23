mod auth;
mod bootstrap;
mod client;
mod constants;
mod error;
mod globals;
mod http;
mod log;
mod proxy;

use crate::{error::*, globals::Globals, http::HttpClient, log::info};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

pub use client::DoHMethod;
pub use globals::{AuthenticationConfig, NextHopRelayConfig, ProxyConfig, SubseqRelayConfig, TargetConfig};

#[async_trait]
pub trait ResolveIps {
  async fn resolve_ips(&self, target_url: &Url) -> Result<ResolveIpResponse>;
}
pub struct ResolveIpResponse {
  pub hostname: String,
  pub addresses: Vec<SocketAddr>,
}

pub async fn entrypoint(
  proxy_config: &ProxyConfig,
  runtime_handle: &tokio::runtime::Handle,
  term_notify: Option<Arc<tokio::sync::Notify>>,
) -> Result<()> {
  info!("Start DoH w/ Auth Proxy");

  // build bootstrap DNS resolver
  let bootstrap_dns_resolver =
    bootstrap::BootstrapDnsResolver::try_new(&proxy_config.bootstrap_dns, runtime_handle.clone()).await?;

  // build http client that is used commonly by DoH client and authentication client
  let mut endpoint_candidates = vec![];
  if let Some(nexthop_relay_config) = &proxy_config.nexthop_relay_config {
    endpoint_candidates.extend(nexthop_relay_config.odoh_relay_urls.clone());
  } else {
    endpoint_candidates.extend(proxy_config.target_config.doh_target_urls.clone());
  }
  if let Some(auth) = &proxy_config.authentication_config {
    endpoint_candidates.push(auth.token_api.clone());
  }
  let http_client = HttpClient::new(
    &endpoint_candidates,
    proxy_config.timeout_sec,
    None,
    bootstrap_dns_resolver,
  )
  .await?;

  let http_client = Arc::new(RwLock::new(http_client));

  if let Some(auth_config) = &proxy_config.authentication_config {
    let authenticator = auth::Authenticator::new(auth_config, http_client).await?;
    authenticator.login().await?;
  }

  // // build global
  // let globals = Arc::new(Globals {
  //   proxy_config: proxy_config.clone(),
  //   runtime_handle: runtime_handle.clone(),
  //   term_notify: term_notify.clone(),
  // });

  Ok(())
}
