use crate::{error::*, ResolveIps};
use futures::future::join_all;
use reqwest::{header::HeaderMap, Client, IntoUrl, RequestBuilder, Url};
use tokio::time::Duration;

#[derive(Debug)]
/// HttpClient that is a wrapper of reqwest::Client
pub struct HttpClient {
  /// client: reqwest::Client,
  client: Client,

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
    let resolve_ips_fut = endpoints.iter().map(|endpoint| resolver_ips.resolve_ips(endpoint));
    let resolve_ips = join_all(resolve_ips_fut).await;
    if resolve_ips.iter().any(|resolve_ip| resolve_ip.is_err()) {
      return Err(DapError::HttpClientError("Failed to resolve ip addresses".to_string()));
    }
    let resolve_ips_iter = resolve_ips.into_iter().map(|resolve_ip| resolve_ip.unwrap());

    let mut client = Client::builder()
      .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
      .timeout(timeout_sec)
      .trust_dns(true);

    // Override pre-resolved ip addresses
    client = resolve_ips_iter.fold(client, |client, resolve_ip| {
      client.resolve_to_addrs(&resolve_ip.hostname, &resolve_ip.addresses)
    });

    // Set default headers
    if let Some(headers) = default_headers {
      client = client.default_headers(headers.clone());
    }

    Ok(Self {
      client: client.build().map_err(|e| DapError::HttpClientError(e.to_string()))?,
      timeout_sec,
      endpoints: endpoints.to_vec(),
    })
  }

  pub async fn post(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.post(url)
  }

  pub async fn get(&self, url: impl IntoUrl) -> RequestBuilder {
    self.client.get(url)
  }
}
