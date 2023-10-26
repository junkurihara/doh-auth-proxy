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
use futures::{
  future::{select_all, FutureExt},
  select,
};
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

  // build global
  let globals = Arc::new(Globals {
    proxy_config: proxy_config.clone(),
    runtime_handle: runtime_handle.clone(),
    term_notify: term_notify.clone(),
  });

  // build bootstrap DNS resolver
  let bootstrap_dns_resolver =
    Arc::new(bootstrap::BootstrapDnsResolver::try_new(&proxy_config.bootstrap_dns, runtime_handle.clone()).await?);

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
    bootstrap_dns_resolver.clone(),
    proxy_config.endpoint_resolution_period_sec,
  )
  .await?;
  let http_client = Arc::new(http_client);

  // spawn authentication service
  let term_notify_clone = term_notify.clone();
  let mut authenticator = None;
  let mut auth_service = None;
  if let Some(auth_config) = &proxy_config.authentication_config {
    let auth = Arc::new(auth::Authenticator::new(auth_config, http_client.inner()).await?);
    let auth_clone = auth.clone();
    let auth_service_inner = runtime_handle.spawn(async move {
      auth_clone
        .start_service(term_notify_clone)
        .await
        .with_context(|| "auth service got down")
    });
    authenticator = Some(auth);
    auth_service = Some(auth_service_inner);
  }

  // build doh_client
  let doh_client = Arc::new(DoHClient::new(globals.clone(), http_client.inner(), authenticator)?);

  // spawn endpoint ip update service with bootstrap dns resolver and doh_client
  let doh_client_clone = doh_client.clone();
  let term_notify_clone = term_notify;
  let http_client_clone = http_client.clone();
  let ip_resolution_service = runtime_handle.spawn(async move {
    http_client_clone
      .start_endpoint_ip_update_service(doh_client_clone, bootstrap_dns_resolver, term_notify_clone)
      .await
      .with_context(|| "endpoint ip update service got down")
  });

  // Start proxy for each listen address
  let addresses = globals.proxy_config.listen_addresses.clone();
  let proxy_service = select_all(addresses.into_iter().map(|addr| {
    let proxy = Proxy::new(globals.clone(), &addr, &doh_client);
    globals.runtime_handle.spawn(async move { proxy.start().await })
  }));

  // wait for all future
  if let Some(auth_service) = auth_service {
    select! {
      _ = proxy_service.fuse() => {
        warn!("Proxy services are down, or term notified");
      },
      _ = auth_service.fuse() => {
        warn!("Auth services are down, or term notified");
      }
      _ = ip_resolution_service.fuse() => {
        warn!("Ip resolution service are down, or term notified");
      }
    }
  } else {
    select! {
      _ = proxy_service.fuse() => {
        warn!("Proxy services are down, or term notified");
      },
      _ = ip_resolution_service.fuse() => {
        warn!("Ip resolution service are down, or term notified");
      }
    }
  }

  // TODO: services
  // - Authentication refresh/re-login service loop (Done)
  // - HTTP client update service loop, changing DNS resolver to the self when it works (Done)
  // - Health check service checking every path, flag unreachable patterns as unhealthy (as individual service inside doh_client?),
  //   which also needs ODoH config refresh.

  Ok(())
}
