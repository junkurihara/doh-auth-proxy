use crate::{
  error::*,
  globals::BootstrapDns,
  log::*,
  trait_resolve_ips::{ResolveIpResponse, ResolveIps},
};
use async_trait::async_trait;
use reqwest::Url;
use std::{net::SocketAddr, sync::Arc};
use trust_dns_resolver::{
  config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
  name_server::{GenericConnector, TokioRuntimeProvider},
  AsyncResolver, TokioAsyncResolver,
};

#[derive(Clone)]
/// stub resolver using bootstrap DNS resolver
pub struct BootstrapDnsResolver {
  /// wrapper of trust-dns-resolver
  pub inner: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl BootstrapDnsResolver {
  /// Build stub resolver using bootstrap dns resolver
  pub async fn try_new(bootstrap_dns: &BootstrapDns, runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    let ips = &bootstrap_dns.ips;
    let port = &bootstrap_dns.port;
    let name_servers = NameServerConfigGroup::from_ips_clear(ips, *port, true);
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_servers);

    let resolver = runtime_handle
      .spawn(async { TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default()) })
      .await
      .map_err(|e| DapError::Other(anyhow!(e)))?;

    Ok(Self { inner: resolver })
  }
}

#[async_trait]
impl ResolveIps for Arc<BootstrapDnsResolver> {
  /// Lookup the IP addresses associated with a name using the bootstrap resolver
  async fn resolve_ips(&self, target_url: &Url) -> Result<ResolveIpResponse> {
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    let host_str = target_url
      .host_str()
      .ok_or_else(|| DapError::Other(anyhow!("Unable to parse target host name")))?;
    let port = target_url
      .port()
      .unwrap_or_else(|| if target_url.scheme() == "https" { 443 } else { 80 });
    let response = self
      .inner
      .lookup_ip(format!("{}.", host_str))
      .await
      .map_err(DapError::BootstrapResolverError)?;

    // There can be many addresses associated with the name,
    // this can return IPv4 and/or IPv6 addresses
    let target_addrs = response
      .iter()
      .filter_map(|addr| format!("{}:{}", addr, port).parse::<SocketAddr>().ok())
      .collect::<Vec<_>>();

    if target_addrs.is_empty() {
      return Err(DapError::Other(anyhow!(
        "Invalid target url: {target_url}, cannot resolve ip address"
      )));
    }
    debug!(
      "Updated target url {} ip addresses by using bootstrap dns: {:?}",
      host_str, target_addrs
    );

    Ok(ResolveIpResponse {
      hostname: host_str.to_string(),
      addresses: target_addrs,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::IpAddr;

  #[tokio::test]
  async fn test_bootstrap_dns_resolver() {
    let bootstrap_dns = BootstrapDns {
      ips: vec![IpAddr::from([8, 8, 8, 8])],
      port: 53,
    };
    let resolver = BootstrapDnsResolver::try_new(&bootstrap_dns, tokio::runtime::Handle::current())
      .await
      .unwrap();
    let resolver = Arc::new(resolver);
    let target_url = Url::parse("https://dns.google").unwrap();
    let response = resolver.resolve_ips(&target_url).await.unwrap();

    assert_eq!(response.hostname.as_str(), "dns.google");
    assert!(response.addresses.contains(&SocketAddr::from(([8, 8, 8, 8], 443))));
    assert!(response.addresses.contains(&SocketAddr::from(([8, 8, 4, 4], 443))));
  }
}
