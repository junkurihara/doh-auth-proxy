use super::{
  odoh_config_store::ODoHConfigStore,
  path_manage::{self, DoHPathManager},
};
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
  /// http client to make doh query
  http_client: Arc<RwLock<HttpClientInner>>,
  /// auth_client to retrieve id token
  auth_client: Option<Arc<Authenticator>>,
  /// path candidates with health flags
  path_manager: Arc<DoHPathManager>,
  // odoh config store
  odoh_configs: Option<Arc<ODoHConfigStore>>,
}

impl DoHClient {
  /// Create a new DoH client
  pub async fn new(
    globals: Arc<Globals>,
    http_client: Arc<RwLock<HttpClientInner>>,
    auth_client: Option<Arc<Authenticator>>,
  ) -> Result<Self> {
    // 1. build all path candidates from globals
    let path_manager = Arc::new(DoHPathManager::new(&globals)?);

    // spawn odoh config service if odoh or modoh are enabled
    let odoh_configs = match &globals.proxy_config.nexthop_relay_config {
      Some(nexthop_relay_config) => {
        if nexthop_relay_config.odoh_relay_urls.is_empty() {
          return Err(DapError::ODoHNoRelayUrl);
        }
        let odoh_configs = Arc::new(ODoHConfigStore::new(http_client.clone(), &path_manager.targets()).await?);
        let odoh_config_clone = odoh_configs.clone();
        let term_notify = globals.term_notify.clone();
        globals
          .runtime_handle
          .spawn(async move { odoh_config_clone.start_service(term_notify).await });
        Some(odoh_configs)
      }
      None => None,
    };

    // TODO: 3. spawn healthcheck for every possible path? too many?
    Ok(Self {
      http_client,
      auth_client,
      path_manager,
      odoh_configs,
    })
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
