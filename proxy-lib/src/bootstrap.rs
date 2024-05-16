use crate::{
  constants::BOOTSTRAP_DNS_TIMEOUT_MSEC,
  error::*,
  globals::BootstrapDns,
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

use reqwest::Url;
use std::{
  net::{IpAddr, SocketAddr},
  str::FromStr,
  sync::Arc,
  time::Duration,
};

/* ---------------------------------------- */
#[derive(PartialEq, Eq, Debug, Clone)]
/// Bootstrap DNS Protocol
pub(crate) enum BootstrapDnsProto {
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
pub(crate) struct BootstrapDnsInner {
  /// protocol
  proto: BootstrapDnsProto,
  /// socket address
  addr: SocketAddr,
}

impl std::fmt::Display for BootstrapDnsInner {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}://{}", self.proto, self.addr)
  }
}

impl BootstrapDnsInner {
  /// Generate a new BootstrapDnsInner
  pub(crate) fn try_new(proto: &str, addr: &str) -> Result<Self> {
    Ok(Self {
      proto: <BootstrapDnsProto as std::str::FromStr>::from_str(proto)?,
      addr: addr
        .parse()
        .map_err(|e| DapError::Other(anyhow!("Invalid bootstrap dns address: {}", e)))?,
    })
  }
  /// Lookup the IP addresses associated with a name using the bootstrap resolver connection
  pub(crate) async fn lookup_ips(&self, fqdn: &str, runtime_handle: tokio::runtime::Handle) -> Result<Vec<IpAddr>> {
    let timeout = Duration::from_millis(BOOTSTRAP_DNS_TIMEOUT_MSEC);
    let bg_close_notify = Arc::new(Notify::new());

    let result_ips = match self.proto {
      BootstrapDnsProto::Udp => {
        let stream = UdpClientStream::<TokioUdpSocket>::with_timeout(self.addr, timeout);
        let (mut client, bg) = AsyncClient::connect(stream).await?;
        self
          .lookup_ips_inner(fqdn, &mut client, bg, bg_close_notify.clone(), runtime_handle)
          .await
      }
      BootstrapDnsProto::Tcp => {
        let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::with_timeout(self.addr, timeout);
        let (mut client, bg) = AsyncClient::with_timeout(stream, sender, timeout, None).await?;
        self
          .lookup_ips_inner(fqdn, &mut client, bg, bg_close_notify.clone(), runtime_handle)
          .await
      }
    };
    bg_close_notify.notify_one();
    let result_ips = result_ips?;

    Ok(result_ips)
  }

  /// Inner: Lookup the IP addresses associated with a name using the bootstrap resolver connection
  async fn lookup_ips_inner<S, TE>(
    &self,
    fqdn: &str,
    client: &mut AsyncClient,
    bg: DnsExchangeBackground<S, TE>,
    bg_close_notify: Arc<Notify>,
    runtime_handle: tokio::runtime::Handle,
  ) -> Result<Vec<IpAddr>>
  where
    S: DnsRequestSender + 'static + Send + Unpin,
    TE: Time + Unpin + 'static + Send,
  {
    runtime_handle.spawn(async move {
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
pub(crate) struct BootstrapDnsResolver {
  /// booststrap dns resolvers
  pub(crate) inner: BootstrapDns,
  /// tokio runtime handle
  pub(crate) runtime_handle: tokio::runtime::Handle,
}

impl BootstrapDnsResolver {
  /// Build DNS client using bootstrap dns resolver
  pub(crate) async fn try_new(bootstrap_dns: &BootstrapDns, runtime_handle: tokio::runtime::Handle) -> Result<Self> {
    Ok(Self {
      inner: bootstrap_dns.clone(),
      runtime_handle,
    })
  }
  pub(crate) fn inner(&self) -> &[BootstrapDnsInner] {
    self.inner.inner()
  }
}

#[async_trait]
impl ResolveIps for Arc<BootstrapDnsResolver> {
  /// Lookup the IP addresses associated with a name using the bootstrap resolver
  async fn resolve_ips(&self, target_url: &Url) -> Result<ResolveIpResponse> {
    // The final dot forces this to be an FQDN, otherwise the search rules as specified
    // in `ResolverOpts` will take effect. FQDN's are generally cheaper queries.
    let host = target_url
      .host_str()
      .ok_or_else(|| DapError::Other(anyhow!("Unable to parse target host name")))?;
    let fqdn = format!("{host}.");

    let port = target_url
      .port()
      .unwrap_or_else(|| if target_url.scheme() == "https" { 443 } else { 80 });

    // There can be many addresses associated with the name,
    // this can return IPv4 and/or IPv6 addresses
    for v in self.inner().iter() {
      let Ok(ips) = v
        .lookup_ips(&fqdn, self.runtime_handle.clone())
        .await
        .map(|p| p.iter().map(|ip| SocketAddr::new(*ip, port)).collect::<Vec<_>>())
      else {
        continue;
      };

      if !ips.is_empty() {
        debug!(
          "Updated socket addresses for `{}://{host}`: {ips:?} (@{v})",
          target_url.scheme(),
        );
        return Ok(ResolveIpResponse {
          hostname: target_url.host_str().unwrap().to_string(),
          addresses: ips,
        });
      }
    }

    Err(DapError::Other(anyhow!(
      "Invalid target url: {target_url}, cannot resolve ip address"
    )))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::IpAddr;

  #[tokio::test]
  async fn test_bootstrap_dns_resolver() {
    let inner = vec![
      ("udp".to_owned(), SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53)),
      ("tcp".to_owned(), SocketAddr::new(IpAddr::from([8, 8, 4, 4]), 53)),
    ];
    let bootstrap_dns = BootstrapDns::try_from(inner).unwrap();

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

    let runtime_handle = tokio::runtime::Handle::current();
    let ips = inner.lookup_ips("dns.google.", runtime_handle.clone()).await.unwrap();

    assert!(ips.contains(&IpAddr::from([8, 8, 8, 8])));
    assert!(ips.contains(&IpAddr::from([8, 8, 4, 4])));

    let inner = BootstrapDnsInner {
      proto: BootstrapDnsProto::Tcp,
      addr: SocketAddr::new(IpAddr::from([8, 8, 8, 8]), 53),
    };

    let ips = inner.lookup_ips("dns.google.", runtime_handle).await.unwrap();

    assert!(ips.contains(&IpAddr::from([8, 8, 8, 8])));
    assert!(ips.contains(&IpAddr::from([8, 8, 4, 4])));
  }
}
