use tokio::time::sleep;

use super::{HttpClient, HttpClientInner};
use crate::{
  error::*,
  log::*,
  trait_resolve_ips::{resolve_ips, ResolveIpResponse, ResolveIps},
};
use std::sync::Arc;

impl HttpClient {
  /// Periodically resolves endpoints to ip addresses, and override their ip addresses in the inner client.
  pub async fn start_endpoint_ip_update_service(
    &self,
    primary_resolver: impl ResolveIps + Clone,
    fallback_resolver: impl ResolveIps + Clone,
    term_notify: Option<Arc<tokio::sync::Notify>>,
  ) -> Result<()> {
    info!("start periodic service for resolution of endpoint ip addresses");

    match term_notify {
      Some(term) => {
        tokio::select! {
          res = self.resolve_endpoint_ip_service(primary_resolver, fallback_resolver) => {
            warn!("Endpoint ip resolution service got down");
            res
          }
          _ = term.notified() => {
            info!("Endpoint ip resolution service receives term signal");
            Ok(())
          }
        }
      }
      None => {
        let res = self.resolve_endpoint_ip_service(primary_resolver, fallback_resolver).await;
        warn!("Endpoint ip resolution service got down");
        res
      }
    }
  }

  /// periodic refresh checker
  async fn resolve_endpoint_ip_service(
    &self,
    primary_resolver: impl ResolveIps + Clone,
    fallback_resolver: impl ResolveIps + Clone,
  ) -> Result<()> {
    let mut fail_cnt = 0;
    loop {
      sleep(self.endpoint_resolution_period_sec()).await;
      let endpoints = self.endpoints();

      let primary_res = resolve_ips(endpoints, primary_resolver.clone()).await;
      if primary_res.is_ok() {
        self.update_inner(&primary_res.unwrap()).await?;
        fail_cnt = 0;
        info!("Resolved endpoint ip addresses by DoH resolver");
        continue;
      }
      warn!(
        "Failed to resolve endpoint ip addresses by doh resolver, trying fallback with bootstrap resolver: {}",
        primary_res.err().unwrap()
      );

      let fallback_res = resolve_ips(endpoints, fallback_resolver.clone()).await;
      if fallback_res.is_ok() {
        self.update_inner(&fallback_res.unwrap()).await?;
        fail_cnt = 0;
        info!("Resolved endpoint ip addresses by bootstrap resolver");
        continue;
      }
      warn!("Failed to resolve endpoint ip addresses by both DoH and bootstrap resolvers");

      fail_cnt += 1;
      if fail_cnt > 3 {
        return Err(DapError::TooManyFailsToResolveIps);
      }
    }
  }

  /// Update http client inner
  async fn update_inner(&self, resolved_ips: &[ResolveIpResponse]) -> Result<()> {
    let inner = self.inner();
    let mut inner_lock = inner.write().await;
    *inner_lock = HttpClientInner::new(self.timeout_sec(), self.user_agent(), self.default_headers(), resolved_ips).await?;
    drop(inner_lock);
    Ok(())
  }
}
