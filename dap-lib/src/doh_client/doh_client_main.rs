use crate::{
  error::*,
  globals::Globals,
  http_client::HttpClientInner,
  trait_resolve_ips::{ResolveIpResponse, ResolveIps},
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug)]
/// DoH, ODoH, MODoH client
pub struct DoHClient {
  inner: Arc<RwLock<HttpClientInner>>,
}

impl DoHClient {
  /// Create a new DoH client
  pub fn new(inner: Arc<RwLock<HttpClientInner>>) -> Self {
    Self { inner }
  }

  /// Make DoH query
  pub async fn make_doh_query(&self, packet_buf: &[u8], globals: &Arc<Globals>) -> Result<Vec<u8>> {
    Ok(vec![])
  }
}

// TODO: implement ResolveIps for DoHClient
#[async_trait]
impl ResolveIps for Arc<DoHClient> {
  /// Resolve ip addresses of the given domain name
  async fn resolve_ips(&self, domain: &Url) -> Result<ResolveIpResponse> {
    Err(DapError::Other(anyhow!("Not implemented")))
  }
}
