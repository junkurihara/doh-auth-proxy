use crate::error::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use url::Url;

#[async_trait]
/// Trait that resolves ip addresses from a given url.
/// This will be used both for bootstrap DNS resolver and MODoH resolver itself.
pub trait ResolveIps {
  async fn resolve_ips(&self, target_url: &Url) -> Result<ResolveIpResponse>;
}
/// Response of ResolveIps trait
pub struct ResolveIpResponse {
  /// hostname of target url
  pub hostname: String,
  /// resolved ip addresses
  pub addresses: Vec<SocketAddr>,
}
