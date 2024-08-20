mod counter;
mod proxy_main;
mod proxy_tcp;
mod proxy_udp;
mod socket;

pub use proxy_main::Proxy;

#[derive(Debug)]
/// Proxy protocol
pub(crate) enum ProxyProtocol {
  /// Tcp proxy
  Tcp,
  /// Udp proxy
  Udp,
}

impl std::fmt::Display for ProxyProtocol {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      ProxyProtocol::Tcp => write!(f, "TCP"),
      ProxyProtocol::Udp => write!(f, "UDP"),
    }
  }
}
