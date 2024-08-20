use thiserror::Error;

/// Describes things that can go wrong in the authentication
#[derive(Debug, Error)]
pub enum HttpClientError {
  #[error(transparent)]
  ReqwestError(#[from] reqwest::Error),
  #[error("Failed to resolve ips for HTTP client")]
  FailedToResolveIpsForHttpClient,
  #[error("Too many fails to resolve ips for HTTP client in periodic task")]
  TooManyFailsToResolveIps,
}
