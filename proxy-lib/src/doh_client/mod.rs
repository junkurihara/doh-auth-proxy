mod cache;
mod dns_message;
mod doh_client_healthcheck;
mod doh_client_main;
mod error;
mod manipulation;
mod odoh;
mod odoh_config_store;
mod path_manage;

pub use doh_client_main::DoHClient;
pub use error::DohClientError;

#[derive(Debug)]
/// DoH response types
pub enum DoHResponseType {
  /// Blocked response
  Blocked,
  /// Overridden response
  Overridden,
  /// Not forwarded due to the nature of dns forwarding (like resolver.arpa)
  NotForwarded,
  /// Overridden response for the localhost and broadcast addresses
  DefaultHost,
  /// Cached response
  Cached,
  /// Standard response fetched from upstream
  Normal,
}

impl std::fmt::Display for DoHResponseType {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      DoHResponseType::Blocked => write!(f, "Blocked"),
      DoHResponseType::Overridden => write!(f, "Overridden"),
      DoHResponseType::NotForwarded => write!(f, "NotForwarded"),
      DoHResponseType::DefaultHost => write!(f, "DefaultHost"),
      DoHResponseType::Cached => write!(f, "Cached"),
      DoHResponseType::Normal => write!(f, "Normal"),
    }
  }
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// DoH method, GET or POST
pub enum DoHMethod {
  Get,
  Post,
}

#[derive(Debug, Clone)]
/// DoH type, Standard or Oblivious
pub(super) enum DoHType {
  Standard,
  Oblivious,
}

impl DoHType {
  fn as_str(&self) -> String {
    match self {
      DoHType::Standard => String::from("application/dns-message"),
      DoHType::Oblivious => String::from("application/oblivious-dns-message"),
    }
  }
}
