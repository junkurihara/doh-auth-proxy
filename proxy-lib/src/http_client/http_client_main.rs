use crate::{
  error::*,
  trait_resolve_ips::{resolve_ips, ResolveIpResponse, ResolveIps},
};
use reqwest::{header::HeaderMap, Client, IntoUrl, RequestBuilder, Url};
use std::sync::Arc;
use tokio::{sync::RwLock, time::Duration};

#[derive(Debug)]
/// HttpClient that is a wrapper of reqwest::Client
pub struct HttpClient {
  /// client inner
  inner: Arc<RwLock<HttpClientInner>>,

  /// domain: endpoint candidates that the client will connect to, where these ip addresses are resolved when instantiated by a given resolver implementing ResolveIps.
  /// This would be targets for DoH, nexthop relay for ODoH (path including target, not mid-relays for dynamic randomization)
  endpoints: Vec<Url>,

  /// default headers
  default_headers: Option<HeaderMap>,

  /// timeout for http request
  timeout_sec: Duration,

  /// http user agent
  user_agent: String,

  /// period for endpoint ip resolution, such as next hop relay
  endpoint_resolution_period_sec: Duration,
}

impl HttpClient {
  /// Build HttpClient
  pub async fn new(
    endpoints: &[Url],
    timeout_sec: Duration,
    user_agent: &str,
    default_headers: Option<&HeaderMap>,
    resolver_ips: impl ResolveIps,
    endpoint_resolution_period_sec: Duration,
  ) -> Result<Self> {
    let resolved_ips = resolve_ips(endpoints, resolver_ips).await?;
    Ok(Self {
      inner: Arc::new(RwLock::new(
        HttpClientInner::new(timeout_sec, user_agent, default_headers, &resolved_ips).await?,
      )),
      default_headers: default_headers.cloned(),
      timeout_sec,
      user_agent: user_agent.to_string(),
      endpoints: endpoints.to_vec(),
      endpoint_resolution_period_sec,
    })
  }

  /// Get inner client pointer
  pub fn inner(&self) -> Arc<RwLock<HttpClientInner>> {
    self.inner.clone()
  }

  /// Get endpoints
  pub fn endpoints(&self) -> &[Url] {
    &self.endpoints
  }

  /// Get default headers
  pub fn default_headers(&self) -> Option<&HeaderMap> {
    self.default_headers.as_ref()
  }

  /// Get timeout
  pub fn timeout_sec(&self) -> Duration {
    self.timeout_sec
  }

  /// Get rebootstrap period
  pub fn endpoint_resolution_period_sec(&self) -> Duration {
    self.endpoint_resolution_period_sec
  }

  /// Get user agent
  pub fn user_agent(&self) -> &str {
    &self.user_agent
  }
}

#[derive(Debug)]
/// Simple wrapper of reqwest::Client
pub struct HttpClientInner {
  pub client: Client,
}
impl HttpClientInner {
  /// Build HttpClientInner
  pub(super) async fn new(
    timeout_sec: Duration,
    user_agent: &str,
    default_headers: Option<&HeaderMap>,
    resolved_ips: &[ResolveIpResponse],
  ) -> Result<Self> {
    let mut client = Client::builder()
      .user_agent(user_agent)
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
  pub fn post(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.post(url)
  }

  /// Get wrapper
  pub fn get(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.get(url)
  }
}
