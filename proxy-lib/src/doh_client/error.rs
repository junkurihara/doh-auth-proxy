use thiserror::Error;

pub(super) type DohClientResult<T> = std::result::Result<T, DohClientError>;

/// Describes things that can go wrong in the authentication
#[derive(Debug, Error)]
pub enum DohClientError {
  /// Error from the authenticator
  #[error(transparent)]
  AuthenticatorError(#[from] crate::auth::AuthenticatorError),

  #[error("HttpClient error for DoH client: {0}")]
  HttpClientError(#[from] reqwest::Error),

  #[error("All paths are unhealthy even after some retry")]
  AllPathsUnhealthy,

  #[error("Failed to build DoH url")]
  FailedToBuildDohUrl,
  #[error("Url error: {0}")]
  UrlError(#[from] url::ParseError),

  #[error("Dns message error: {0}")]
  DnsMessageError(anyhow::Error),

  #[error("ODoH No Client Config")]
  ODoHNoClientConfig,
  #[error("ODoH does not allow GET method")]
  ODoHGetNotAllowed,
  #[error("ODoH invalid content length")]
  ODoHInvalidContentLength,
  #[error("ODoH operation error")]
  ODoHError(#[from] odoh_rs::Error),
  #[error("ODoH No Relay Url")]
  ODoHNoRelayUrl,
  #[error("Invalid DNS query")]
  InvalidDnsQuery,
  #[error("Invalid DNS response")]
  InvalidDnsResponse,
  #[error("No path available to send query")]
  NoPathAvailable,
  #[error("DoH query error")]
  DoHQueryError,
  #[error("Failed to resolve ips via DoH for HTTP client")]
  FailedToResolveIpsForHttpClient,

  #[error("Regex error: {0}")]
  RegexError(#[from] regex::Error),

  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
