use crate::{
  constants::{BOOTSTRAP_DNS_ADDRS, BOOTSTRAP_DNS_PROTO, BOOTSTRAP_DNS_TIMEOUT_MSEC},
  error::*,
  log::*,
  trait_resolve_ips::{ResolveIpResponse, ResolveIps},
};
use async_trait::async_trait;
use hickory_client::{
  client::{AsyncClient, ClientHandle},
  proto::iocompat::AsyncIoTokioAsStd,
  rr::{DNSClass, Name, RecordType},
  tcp::TcpClientStream,
  udp::UdpClientStream,
};
use hickory_proto::{
  xfer::{DnsExchangeBackground, DnsRequestSender},
  Time,
};
use tokio::{
  net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket},
  sync::Notify,
};

use hickory_resolver::{
  config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
  name_server::{GenericConnector, TokioRuntimeProvider},
  AsyncResolver, TokioAsyncResolver,
};
use reqwest::Url;
use std::{
  net::{IpAddr, SocketAddr},
  str::FromStr,
  sync::Arc,
  time::Duration,
};

/* ---------------------------------------- */
#[derive(PartialEq, Eq, Debug, Clone)]
/// Bootstrap DNS Addresses
pub struct BootstrapDns {
  pub inner: Vec<BootstrapDnsInner>,
}

impl Default for BootstrapDns {
  fn default() -> Self {
    Self {
      inner: BOOTSTRAP_DNS_ADDRS
        .iter()
        .map(|v| BootstrapDnsInner {
          proto: <BootstrapDnsProto as std::str::FromStr>::from_str(BOOTSTRAP_DNS_PROTO).unwrap(),
          addr: v.parse().unwrap(),
        })
        .collect(),
    }
  }
}

impl std::fmt::Display for BootstrapDns {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let mut first = true;
    for v in &self.inner {
      if !first {
        write!(f, ", ")?;
      }
      write!(f, "{}://{}", v.proto, v.addr)?;
      first = false;
    }
    Ok(())
  }
}

impl TryFrom<Vec<(String, SocketAddr)>> for BootstrapDns {
  type Error = anyhow::Error;

  fn try_from(value: Vec<(String, SocketAddr)>) -> anyhow::Result<Self, Self::Error> {
    let inner = value
      .into_iter()
      .map(|(proto, addr)| BootstrapDnsInner {
        proto: <BootstrapDnsProto as std::str::FromStr>::from_str(&proto).unwrap(),
        addr,
      })
      .collect();
    Ok(Self { inner })
  }
}

/* ---------------------------------------- */
#[derive(PartialEq, Eq, Debug, Clone)]
/// Bootstrap DNS Protocol
pub enum BootstrapDnsProto {
  /// UDP
  Udp,
  /// TCP
  Tcp,
}
impl std::str::FromStr for BootstrapDnsProto {
  type Err = DapError;

  fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
    match s {
      "udp" => Ok(Self::Udp),
      "tcp" => Ok(Self::Tcp),
      _ => Err(DapError::Other(anyhow!("Invalid bootstrap dns protocol"))),
    }
  }
}
impl std::fmt::Display for BootstrapDnsProto {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Self::Udp => write!(f, "udp"),
      Self::Tcp => write!(f, "tcp"),
    }
  }
}

/* ---------------------------------------- */
#[derive(PartialEq, Eq, Debug, Clone)]
/// Bootstrap DNS Address with port and protocol
pub struct BootstrapDnsInner {
  /// protocol
  pub proto: BootstrapDnsProto,
  /// socket address
  pub addr: SocketAddr,
}

impl BootstrapDnsInner {
  /// Lookup the IP addresses associated with a name using the bootstrap resolver connection
  pub(crate) async fn lookup_ips(&self, target_url: &Url) -> Result<Vec<SocketAddr>> {
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    let host = target_url
      .host_str()
      .ok_or_else(|| DapError::Other(anyhow!("Unable to parse target host name")))?;
    let fqdn = format!("{host}.");
    let timeout = Duration::from_millis(BOOTSTRAP_DNS_TIMEOUT_MSEC);
    let bg_close_notify = Arc::new(Notify::new());

    let result_ips = match self.proto {
      BootstrapDnsProto::Udp => {
        let stream = UdpClientStream::<TokioUdpSocket>::with_timeout(self.addr, timeout);
        let (mut client, bg) = AsyncClient::connect(stream).await?;
        self
          .lookup_ips_inner(&fqdn, &mut client, bg, bg_close_notify.clone())
          .await
      }
      BootstrapDnsProto::Tcp => {
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_timeout(self.addr, timeout);
        let (mut client, bg) = AsyncClient::with_timeout(stream, sender, timeout, None).await?;
        self
          .lookup_ips_inner(&fqdn, &mut client, bg, bg_close_notify.clone())
          .await
      }
    };
    bg_close_notify.notify_one();
    let result_ips = result_ips?;

    let port = target_url
      .port()
      .unwrap_or_else(|| if target_url.scheme() == "https" { 443 } else { 80 });

    Ok(
      result_ips
        .iter()
        .filter_map(|addr| format!("{}:{}", addr, port).parse::<SocketAddr>().ok())
        .collect::<Vec<_>>(),
    )
  }

  /// Inner: Lookup the IP addresses associated with a name using the bootstrap resolver connection
  async fn lookup_ips_inner<S, TE>(
    &self,
    fqdn: &str,
    client: &mut AsyncClient,
    bg: DnsExchangeBackground<S, TE>,
    bg_close_notify: Arc<Notify>,
  ) -> Result<Vec<IpAddr>>
  where
    S: DnsRequestSender + 'static + Send + Unpin,
    TE: Time + Unpin + 'static + Send,
  {
    tokio::spawn(async move {
      tokio::select! {
        _ = bg_close_notify.notified() => debug!("Close bootstrap dns client background task"),
        _ = bg => debug!("Bootstrap dns client background task finished")
      }
    });
    let name = Name::from_str(fqdn).map_err(|e| DapError::InvalidFqdn(e.to_string()))?;

    // First try to lookup an A record, if failed, try AAAA.
    let response = client.query(name.clone(), DNSClass::IN, RecordType::A).await?;
    let ips = response
      .answers()
      .iter()
      .filter_map(|a| a.data().and_then(|v| v.as_a()).map(|v| IpAddr::V4(v.0)))
      .collect::<Vec<_>>();
    if !ips.is_empty() {
      return Ok(ips);
    }
    let response = client.query(name, DNSClass::IN, RecordType::AAAA).await?;
    let ipv6s = response
      .answers()
      .iter()
      .filter_map(|aaaa| aaaa.data().and_then(|v| v.as_aaaa()).map(|v| IpAddr::V6(v.0)))
      .collect::<Vec<_>>();
    if ipv6s.is_empty() {
      return Err(DapError::InvalidBootstrapDnsResponse);
    }
    Ok(ipv6s)
  }
}

/* ---------------------------------------- */
#[derive(Clone)]
/// stub resolver using bootstrap DNS resolver
pub struct BootstrapDnsResolver {
  /// wrapper of trust-dns-resolver
  pub inner: AsyncResolver<GenericConnector<TokioRuntimeProvider>>,
}

impl BootstrapDnsResolver {
  /// Build stub resolver using bootstrap dns resolver
  pub async fn try_new(bootstrap_dns: &BootstrapDns, runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    let ips = &bootstrap_dns.inner.iter().map(|x| x.addr.ip()).collect::<Vec<_>>();
    let port = &bootstrap_dns.inner.iter().map(|x| x.addr.port()).collect::<Vec<_>>()[0];
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
      inner: vec![
        BootstrapDnsInner {
          proto: BootstrapDnsProto::Udp,
          addr: SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
        },
        BootstrapDnsInner {
          proto: BootstrapDnsProto::Tcp,
          addr: SocketAddr::new(IpAddr::from([8, 8, 4, 4]), 53),
        },
      ],
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

  #[tokio::test]
  async fn test_bootstrap_dns_client_inner() {
    let inner = BootstrapDnsInner {
      proto: BootstrapDnsProto::Udp,
      addr: SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
    };
    let target_url = Url::parse("https://dns.google").unwrap();
    let ips = inner.lookup_ips(&target_url).await.unwrap();

    assert!(ips.contains(&SocketAddr::from(([8, 8, 8, 8], 443))));
    assert!(ips.contains(&SocketAddr::from(([8, 8, 4, 4], 443))));

    let inner = BootstrapDnsInner {
      proto: BootstrapDnsProto::Tcp,
      addr: SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
    };
    let target_url = Url::parse("https://dns.google").unwrap();
    let ips = inner.lookup_ips(&target_url).await.unwrap();

    assert!(ips.contains(&SocketAddr::from(([8, 8, 8, 8], 443))));
    assert!(ips.contains(&SocketAddr::from(([8, 8, 4, 4], 443))));
  }
}
