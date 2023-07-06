use crate::{context::ProxyContext, error::*, log::*};
use reqwest::header::HeaderMap;
use std::{net::SocketAddr, sync::Arc};
use trust_dns_resolver::{config::*, TokioAsyncResolver};
use url::Url;

#[derive(Debug, Clone)]
pub struct HttpClient {
  pub client: reqwest::Client,
  pub endpoint: String, // domain: target for DoH, nexthop relay for ODoH (path including target, not mid-relays for dynamic randomization)
  pub resolve_endpoint_by_system: bool,
}

impl HttpClient {
  pub async fn new(
    globals: &Arc<ProxyContext>,
    endpoint: &str,
    default_headers: Option<&HeaderMap>,
    resolve_endpoint_by_system: bool,
  ) -> Result<Self> {
    let mut client = reqwest::Client::builder()
      .user_agent(format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")))
      .timeout(globals.timeout_sec)
      .trust_dns(true);

    client = if resolve_endpoint_by_system {
      let (target_host_str, target_addresses) =
        resolve_by_bootstrap(&globals.bootstrap_dns, endpoint, globals.runtime_handle.clone()).await?;
      let target_addr = target_addresses[0];
      debug!(
        "Via bootstrap DNS [{:?}], endpoint {:?} resolved: {:?}",
        &globals.bootstrap_dns, &endpoint, &target_addr
      );
      client.resolve(&target_host_str, target_addr)
    } else {
      client
    };

    client = match default_headers {
      Some(headers) => client.default_headers(headers.clone()),
      None => client,
    };

    Ok(HttpClient {
      client: client.build()?,
      endpoint: endpoint.to_string(),
      resolve_endpoint_by_system,
    })
  }
}

pub async fn resolve_by_bootstrap(
  bootstrap_dns: &SocketAddr,
  target_url: &str,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(String, Vec<SocketAddr>)> {
  let name_servers = NameServerConfigGroup::from_ips_clear(&[bootstrap_dns.ip()], bootstrap_dns.port(), true);
  let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

  let resolver = runtime_handle
    .spawn(async move { TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default()) })
    .await??;

  // Lookup the IP addresses associated with a name.
  // The final dot forces this to be an FQDN, otherwise the search rules as specified
  // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
  let url = Url::parse(target_url)?;
  let scheme = url.scheme(); // already checked at config.rs
  let host_str = url.host_str().unwrap();
  let port = match url.port() {
    None => {
      if scheme == "https" {
        443
      } else {
        80
      }
    }
    Some(t) => t,
  };

  let response = resolver.lookup_ip(format!("{}.", host_str)).await?;

  // There can be many addresses associated with the name,
  //  this can return IPv4 and/or IPv6 addresses
  let mut target_addresses: Vec<SocketAddr> = vec![];
  let mut response_iter = response.iter();

  for address in &mut response_iter {
    target_addresses.push(format!("{}:{}", address, port).parse().unwrap());
  }
  if target_addresses.is_empty() {
    bail!("Unable to obtain target resolver address");
  }
  debug!(
    "Updated target url Ips {:?} by using bootstrap dns [{:?}]",
    target_addresses, bootstrap_dns
  );

  Ok((host_str.to_string(), target_addresses))
}
