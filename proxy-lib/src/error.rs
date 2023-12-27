pub use anyhow::{anyhow, bail, ensure, Context};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

pub type Result<T> = std::result::Result<T, DapError>;

/// Describes things that can go wrong in the Rpxy
#[derive(Debug, Error)]
pub enum DapError {
  #[error("Bootstrap resolver error: {0}")]
  BootstrapResolverError(#[from] hickory_resolver::error::ResolveError),

  #[error("Url error: {0}")]
  UrlError(#[from] url::ParseError),

  #[error("Failed all attempts of login and refresh")]
  FailedAllAttemptsOfLoginAndRefresh,

  #[error("Token error: {0}")]
  TokenError(String),

  #[error("HttpClient error")]
  HttpClientError(#[from] reqwest::Error),
  #[error("Failed to resolve ips for HTTP client")]
  FailedToResolveIpsForHttpClient,
  #[error("Too many fails to resolve ips for HTTP client in periodic task")]
  TooManyFailsToResolveIps,
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
  #[error("Failed to build DoH url")]
  FailedToBuildDohUrl,
  #[error("ODoH No Relay Url")]
  ODoHNoRelayUrl,
  #[error("ODoH No Client Config")]
  ODoHNoClientConfig,
  #[error("ODoH does not allow GET method")]
  ODoHGetNotAllowed,
  #[error("ODoH invalid content length")]
  ODoHInvalidContentLength,
  #[error("ODoH operation error")]
  ODoHError(#[from] odoh_rs::Error),

  #[error("Invalid DNS query")]
  InvalidDnsQuery,
  #[error("Invalid DNS response")]
  InvalidDnsResponse,

  #[error("All paths are unhealthy even after some retry")]
  AllPathsUnhealthy,

  #[error("No path available to send query")]
  NoPathAvailable,
  #[error("DoH query error")]
  DoHQueryError,

  #[error("Regex error: {0}")]
  RegexError(#[from] regex::Error),

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
