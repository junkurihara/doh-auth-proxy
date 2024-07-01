use thiserror::Error;

pub(super) type AuthResult<T> = std::result::Result<T, AuthenticatorError>;

/// Describes things that can go wrong in the authentication
#[derive(Debug, Error)]
pub enum AuthenticatorError {
  #[error("Auth http client error: {0}")]
  AuthClientError(#[from] auth_client::AuthError),

  #[error("Failed all attempts of login and refresh")]
  FailedAllAttemptsOfLoginAndRefresh,

  #[cfg(feature = "anonymous-token")]
  #[error("Invalid anonyous token: {0}")]
  InvalidAnonymousToken(String),

  #[cfg(feature = "anonymous-token")]
  #[error("Failed to check blind validation key validity")]
  FailedToCheckBlindValidationKey,
}
