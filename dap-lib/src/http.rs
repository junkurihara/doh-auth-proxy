use std::sync::Arc;

use crate::{error::*, ResolveIpResponse, ResolveIps};
use futures::future::join_all;
use reqwest::{header::HeaderMap, Client, IntoUrl, RequestBuilder, Url};
use tokio::{sync::RwLock, time::Duration};

#[derive(Debug)]
/// HttpClient that is a wrapper of reqwest::Client
pub struct HttpClient {
  /// client inner
  inner: Arc<RwLock<HttpClientInner>>,

  /// domain: endpoint candidates that the client will connect to, where these ip addresses are resolved when instantiated by a given resolver implementing ResolveIps.
  /// This would be targets for DoH, nexthop relay for ODoH (path including target, not mid-relays for dynamic randomization)
  endpoints: Vec<Url>,

  /// timeout for http request
  timeout_sec: Duration,
}

impl HttpClient {
  /// Build HttpClient
  pub async fn new(
    endpoints: &[Url],
    timeout_sec: Duration,
    default_headers: Option<&HeaderMap>,
    resolver_ips: impl ResolveIps,
  ) -> Result<Self> {
    let resolved_ips = resolve_ips(endpoints, resolver_ips).await?;
    Ok(Self {
      inner: Arc::new(RwLock::new(
        HttpClientInner::new(timeout_sec, default_headers, &resolved_ips).await?,
      )),
      timeout_sec,
      endpoints: endpoints.to_vec(),
    })
  }

  /// Get inner client pointer
  pub fn inner(&self) -> Arc<RwLock<HttpClientInner>> {
    self.inner.clone()
  }
}

#[derive(Debug)]
pub struct HttpClientInner {
  /// client: reqwest::Client,
  pub client: Client,
}
impl HttpClientInner {
  /// Build HttpClientInner
  pub(super) async fn new(
    timeout_sec: Duration,
    default_headers: Option<&HeaderMap>,
    resolved_ips: &[ResolveIpResponse],
  ) -> Result<Self> {
    let mut client = Client::builder()
      .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
      .timeout(timeout_sec)
      .trust_dns(true);

    // Override pre-resolved ip addresses
    client = resolved_ips.iter().fold(client, |client, resolve_ip| {
      client.resolve_to_addrs(&resolve_ip.hostname, &resolve_ip.addresses)
    });

    // Set default headers
    if let Some(headers) = default_headers {
      client = client.default_headers(headers.clone());
    }
    Ok(Self {
      client: client.build().map_err(DapError::HttpClientError)?,
    })
  }

  /// Post wrapper
  pub async fn post(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.post(url)
  }

  /// Get wrapper
  pub async fn get(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.get(url)
  }
}

/// Resolve ip addresses for given endpoints
async fn resolve_ips(endpoints: &[Url], resolver_ips: impl ResolveIps) -> Result<Vec<ResolveIpResponse>> {
  let resolve_ips_fut = endpoints.iter().map(|endpoint| resolver_ips.resolve_ips(endpoint));
  let resolve_ips = join_all(resolve_ips_fut).await;
  if resolve_ips.iter().any(|resolve_ip| resolve_ip.is_err()) {
    return Err(DapError::HttpClientBuildError);
  }
  let resolve_ips_vec = resolve_ips.into_iter().map(|resolve_ip| resolve_ip.unwrap()).collect();
  Ok(resolve_ips_vec)
}
