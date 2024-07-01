use super::error::HttpClientError;
use async_trait::async_trait;
use std::net::SocketAddr;
use url::Url;

#[async_trait]
/// Trait that resolves ip addresses from a given url.
/// This will be used both for bootstrap DNS resolver and MODoH resolver itself.
pub trait ResolveIps {
  type Error: std::fmt::Debug;
  async fn resolve_ips(&self, target_url: &Url) -> Result<ResolveIpResponse, Self::Error>;
}
/// Response of ResolveIps trait
pub struct ResolveIpResponse {
  /// hostname of target url
  pub hostname: String,
  /// resolved ip addresses
  pub addresses: Vec<SocketAddr>,
}

/// Resolve ip addresses for given endpoints
pub async fn resolve_ips(endpoints: &[Url], resolver_ips: impl ResolveIps) -> Result<Vec<ResolveIpResponse>, HttpClientError> {
  let resolve_ips_fut = endpoints.iter().map(|endpoint| async {
    let host_is_ipaddr = endpoint
      .host_str()
      .map_or(false, |host| host.parse::<std::net::IpAddr>().is_ok());
    if host_is_ipaddr {
      Ok(ResolveIpResponse {
        hostname: endpoint.host_str().unwrap().to_string(),
        addresses: vec![endpoint.socket_addrs(|| None).unwrap()[0]],
      })
    } else {
      resolver_ips.resolve_ips(endpoint).await
    }
  });
  let resolve_ips = futures::future::join_all(resolve_ips_fut).await;
  if resolve_ips.iter().any(|resolve_ip| resolve_ip.is_err()) {
    return Err(HttpClientError::FailedToResolveIpsForHttpClient);
  }
  let resolve_ips_vec = resolve_ips.into_iter().map(|resolve_ip| resolve_ip.unwrap()).collect();
  Ok(resolve_ips_vec)
}
