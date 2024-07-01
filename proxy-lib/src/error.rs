use std::net::SocketAddr;
use tokio::sync::mpsc::error::SendError;

pub use crate::auth::AuthenticatorError;
pub use crate::doh_client::DohClientError;
pub use crate::http_client::HttpClientError;

pub(crate) type Result<T> = std::result::Result<T, DapError>;

/// Describes things that can go wrong in the Rpxy
#[derive(Debug, thiserror::Error)]
pub enum DapError {
  /// Error from the authenticator
  #[error(transparent)]
  AuthenticatorError(#[from] AuthenticatorError),

  /// Error from the DoH client
  #[error(transparent)]
  DohClientError(#[from] DohClientError),

  /// Error from the HTTP client shared among services
  #[error(transparent)]
  HttpClientError(#[from] HttpClientError),

  #[error("Service down: {0}")]
  ServiceDown(String),
  #[error("Proxy service exited: {0}")]
  ProxyServiceError(String),
  #[error("Query log service exited")]
  QueryLogServiceError,

  /* -- bootstarp dns -- */
  #[error("Bootstrap dns client error: {0}")]
  BootstrapDnsClientError(#[from] hickory_client::error::ClientError),
  #[error("Bootstrap dns proto error: {0}")]
  BootstrapDnsProtoError(#[from] hickory_client::proto::error::ProtoError),
  #[error("Invalid Fqdn is given to bootstrap dns: {0}")]
  InvalidFqdn(String),
  #[error("Invalid bootstrap dns response")]
  InvalidBootstrapDnsResponse,
  #[error(transparent)]
  Other(#[from] anyhow::Error),

  /* -- proxy -- */
  #[error("Io Error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Null TCP stream")]
  NullTcpStream,
  #[error("Udp channel send timeout")]
  UdpChannelSendTimeout,
  #[error("Udp channel send error")]
  UdpChannelSendError(#[from] SendError<(Vec<u8>, SocketAddr)>),
  #[error("Invalid DNS response size")]
  InvalidDnsResponseSize,
  #[error("Too many connections")]
  TooManyConnections,
  #[error("Failed to make DoH query")]
  FailedToMakeDohQuery,
}
