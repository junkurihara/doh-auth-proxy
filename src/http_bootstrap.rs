use crate::error::*;
use crate::globals::Globals;
use crate::log::*;
use reqwest::header::HeaderMap;
use std::net::SocketAddr;
use std::sync::Arc;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

pub struct HttpClient {
  pub client: reqwest::Client,
}

impl HttpClient {
  pub async fn new(
    globals: &Arc<Globals>,
    endpoint_bootstrap: Option<&str>,
    default_headers: Option<&HeaderMap>,
  ) -> Result<Self, Error> {
    let mut client = reqwest::Client::builder()
      .user_agent(format!("doh-auth/{}", env!("CARGO_PKG_VERSION")))
      .timeout(globals.timeout_sec)
      .trust_dns(true);

    client = match endpoint_bootstrap {
      Some(endpoint) => {
        let (target_host_str, target_addresses) = resolve_by_bootstrap(
          &globals.bootstrap_dns,
          endpoint,
          globals.runtime_handle.clone(),
        )
        .await?;
        let target_addr = target_addresses[0];
        debug!(
          "Via bootstrap DNS [{:?}], endpoint {:?} resolved: {:?}",
          &globals.bootstrap_dns, &endpoint, &target_addr
        );
        client.resolve(&target_host_str, target_addr)
      }
      None => client,
    };

    client = match default_headers {
      Some(headers) => client.default_headers(headers.clone()),
      None => client,
    };

    Ok(HttpClient {
      client: client.build()?,
    })
  }
}

pub async fn resolve_by_bootstrap(
  bootstrap_dns: &SocketAddr,
  target_url: &str,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(String, Vec<SocketAddr>), Error> {
  let name_servers =
    NameServerConfigGroup::from_ips_clear(&[bootstrap_dns.ip()], bootstrap_dns.port(), true);
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
