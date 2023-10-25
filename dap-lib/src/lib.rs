mod auth;
mod bootstrap;
mod constants;
mod doh_client;
mod error;
mod globals;
mod http_client;
mod log;
mod proxy;
mod trait_resolve_ips;

use crate::{doh_client::DoHClient, error::*, globals::Globals, http_client::HttpClient, log::*, proxy::Proxy};
use futures::future::select_all;
use std::sync::Arc;

pub use auth_client::AuthenticationConfig;
pub use doh_client::DoHMethod;
pub use globals::{NextHopRelayConfig, ProxyConfig, SubseqRelayConfig, TargetConfig};

/// entrypoint of DoH w/ Auth Proxy
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
    proxy_config.http_timeout_sec,
    None,
    bootstrap_dns_resolver,
  )
  .await?;

  // spawn authentication service
  let term_notify_clone = term_notify.clone();
  let mut auth_service = None;
  if let Some(auth_config) = &proxy_config.authentication_config {
    let authenticator = auth::Authenticator::new(auth_config, http_client.inner()).await?;
    let auth_service_inner = runtime_handle.spawn(async move {
      authenticator
        .start_service(term_notify_clone)
        .await
        .with_context(|| "auth service got down")
    });
    auth_service = Some(auth_service_inner);
  }

  // TODO: services
  // - Authentication refresh/re-login service loop (Done)
  // - HTTP client update service loop, changing DNS resolver to the self when it works
  // - Health check service checking every path, flag unreachable patterns as unhealthy

  // build doh_client
  let doh_client = Arc::new(DoHClient::new(http_client.inner()));

  // TODO: doh_clientにResolveIps traitを実装、http client ip updateサービスをここでspawn

  // build global
  let globals = Arc::new(Globals {
    http_client: Arc::new(http_client),
    proxy_config: proxy_config.clone(),
    runtime_handle: runtime_handle.clone(),
    term_notify,
  });

  // Start proxy for each listen address
  let addresses = globals.proxy_config.listen_addresses.clone();
  let proxy_service = select_all(addresses.into_iter().map(|addr| {
    let proxy = Proxy::new(globals.clone(), &addr, &doh_client);
    globals.runtime_handle.spawn(async move { proxy.start().await })
  }));

  // wait for all future
  if let Some(auth_service) = auth_service {
    futures::future::select(proxy_service, auth_service).await;
    warn!("Some proxy services and auth service are down or term notified");
  } else {
    let _res = proxy_service.await;
    warn!("Some proxy services are down or term notified");
  }

  Ok(())
}
