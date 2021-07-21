use crate::error::*;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

pub async fn resolve_by_bootstrap(
  bootstrap_dns: &SocketAddr,
  target_url: &str,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(String, Vec<SocketAddr>), Error> {
  let name_servers =
    NameServerConfigGroup::from_ips_clear(&[bootstrap_dns.ip()], bootstrap_dns.port(), true);
  let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

  let resolver = runtime_handle
    .clone()
    .spawn(async move { TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default()) })
    .await??;

  // Lookup the IP addresses associated with a name.
  // The final dot forces this to be an FQDN, otherwise the search rules as specified
  //  in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
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
  while let Some(address) = response_iter.next() {
    target_addresses.push(format!("{}:{}", address, port).parse().unwrap());
  }
  if target_addresses.len() == 0 {
    bail!("Unable to obtain target resolver address");
  }
  debug!(
    "Updated target url Ips {:?} by using bootstrap dns [{:?}]",
    target_addresses, bootstrap_dns
  );

  Ok((host_str.to_string(), target_addresses))
}
