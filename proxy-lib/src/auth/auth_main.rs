use crate::{
  constants::TOKEN_REFRESH_MARGIN,
  error::{bail, Context, DapError},
  globals::TokenConfig,
  http_client::HttpClientInner,
  log::*,
};
use async_trait::async_trait;
use auth_client::{token::token_fields::Field, TokenClient, TokenHttpClient};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

/* ------------------------------------------------------------------ */
#[async_trait]
/// TokenHttpClient trait implementation for HttpClientInner to use it in auth_client::TokenClient
impl TokenHttpClient for HttpClientInner {
  async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> anyhow::Result<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync,
  {
    let res = self.client.post(url.to_owned()).json(json_body).send().await?;
    if !res.status().is_success() {
      let err_res = res.error_for_status_ref();
      bail!(DapError::HttpClientError(err_res.unwrap_err()));
    }
    let json_res = res.json::<R>().await?;
    Ok(json_res)
  }

  async fn get_json<R>(&self, url: &Url) -> anyhow::Result<R>
  where
    R: DeserializeOwned + Send + Sync,
  {
    let res = self.client.get(url.to_owned()).send().await?;
    if !res.status().is_success() {
      let err_res = res.error_for_status_ref();
      bail!(DapError::HttpClientError(err_res.unwrap_err()));
    }
    let json_res = res.json::<R>().await?;

    Ok(json_res)
  }

  #[cfg(feature = "anonymous-token")]
  async fn post_json_with_bearer_token<S, R>(&self, url: &Url, json_body: &S, bearer_token: &str) -> anyhow::Result<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync,
  {
    let authorization_header = format!("Bearer {}", bearer_token);
    let res = self
      .client
      .post(url.to_owned())
      .header(reqwest::header::AUTHORIZATION, authorization_header)
      .json(json_body)
      .send()
      .await?;
    if !res.status().is_success() {
      let err_res = res.error_for_status_ref();
      bail!(DapError::HttpClientError(err_res.unwrap_err()));
    }
    let json_res = res.json::<R>().await?;
    Ok(json_res)
  }
}

/* ------------------------------------------------------------------ */
/// Authentication client
pub struct Authenticator {
  inner: TokenClient<HttpClientInner>,
  #[cfg(feature = "anonymous-token")]
  use_anonymous_token: bool,
}
impl Authenticator {
  /// Build authentication client with initial login
  pub async fn new(token_config: &TokenConfig, http_client: Arc<RwLock<HttpClientInner>>) -> Result<Self, DapError> {
    let inner = TokenClient::new(&token_config.authentication_config, http_client).await?;
    inner.login().await?;
    info!("Successful login");

    #[cfg(feature = "anonymous-token")]
    if token_config.use_anonymous_token {
      // request anonymous token to the token server
      inner.request_blind_signature_with_id_token().await?;
      info!("Successful request for signing blind signature with ID token");
    }

    Ok(Self {
      inner,
      #[cfg(feature = "anonymous-token")]
      use_anonymous_token: token_config.use_anonymous_token,
    })
  }
  /// Refresh via refresh token or login if refresh failed.
  pub(super) async fn refresh_or_login(&self) -> Result<(), DapError> {
    // expiration check logic
    let expires_in = self
      .inner
      .remaining_seconds_until_expiration()
      .await
      .with_context(|| "Failed to get remaining seconds until expiration from token client")?;

    if expires_in <= TOKEN_REFRESH_MARGIN {
      info!("Id Token is about to expire. Refreshing...");
      let Err(e) = self.inner.refresh().await else {
        return Ok(());
      };
      warn!("Refresh failed. Login again... {e}");
      self.inner.login().await?;
    } else {
      info!("Token is not about to expire. No need to refresh. (remaining: {expires_in} secs)");
    }

    Ok(())
  }

  #[cfg(feature = "anonymous-token")]
  /// Request blind signature with id token and get anonymous token
  pub(super) async fn request_blind_signature_with_id_token(&self) -> Result<(), DapError> {
    self.inner.request_blind_signature_with_id_token().await?;
    Ok(())
  }

  #[cfg(feature = "anonymous-token")]
  /// Check if the blind validation key is still alive
  pub(super) async fn blind_remaining_seconds_until_expiration(&self) -> Result<i64, DapError> {
    let expires_in = self.inner.blind_remaining_seconds_until_expiration().await?;
    Ok(expires_in)
  }

  /// Get id token or anonymous token
  pub async fn bearer_token(&self) -> Result<String, DapError> {
    #[cfg(feature = "anonymous-token")]
    if self.use_anonymous_token {
      let anon_token_b64 = self.inner.anonymous_token().await?.try_into_base64url()?;
      return Ok(anon_token_b64);
    }

    let id_token = self.inner.token().await?.id.as_str().to_owned();
    Ok(id_token)
  }
}
