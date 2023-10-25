use crate::{
  auth::Authenticator,
  error::*,
  globals::Globals,
  http_client::HttpClientInner,
  trait_resolve_ips::{ResolveIpResponse, ResolveIps},
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/// DoH, ODoH, MODoH client
pub struct DoHClient {
  http_client: Arc<RwLock<HttpClientInner>>,
  auth_client: Option<Arc<Authenticator>>,
  // odoh config
  // path candidates
}

impl DoHClient {
  /// Create a new DoH client
  pub fn new(
    globals: Arc<Globals>,
    http_client: Arc<RwLock<HttpClientInner>>,
    auth_client: Option<Arc<Authenticator>>,
  ) -> Self {
    // TODO: 1. build all path candidates from globals
    // TODO: 2. spawn odoh config service
    // TODO: 3. spawn healthcheck for every path
    Self {
      http_client,
      auth_client,
    }
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
