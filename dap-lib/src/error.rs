pub use anyhow::{anyhow, bail, ensure, Context};
use std::net::SocketAddr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DapError>;

/// Describes things that can go wrong in the Rpxy
#[derive(Debug, Error)]
pub enum DapError {
  #[error("Bootstrap resolver error: {0}")]
  BootstrapResolverError(#[from] trust_dns_resolver::error::ResolveError),

  #[error("Url error: {0}")]
  UrlError(#[from] url::ParseError),

  #[error("Authentication error: {0}")]
  AuthenticationError(String),

  #[error("Token error: {0}")]
  TokenError(String),

  #[error("HttpClient error")]
  HttpClientError(#[from] reqwest::Error),
  #[error("HttpClient build error")]
  HttpClientBuildError,
  #[error("Io Error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Null TCP stream")]
  NullTcpStream,
  #[error("Udp channel send error")]
  UdpChannelSendError(#[from] tokio::sync::mpsc::error::SendError<(Vec<u8>, SocketAddr)>),
  #[error("Invalid DNS response size")]
  InvalidDnsResponseSize,
  #[error("Too many connections")]
  TooManyConnections,
  #[error("Failed to make DoH query")]
  FailedToMakeDohQuery,

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
