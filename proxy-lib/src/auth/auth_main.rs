use crate::{
  constants::TOKEN_REFRESH_MARGIN,
  error::{bail, Context, DapError},
  http_client::HttpClientInner,
  log::*,
};
use async_trait::async_trait;
use auth_client::{token::token_fields::Field, AuthenticationConfig, TokenClient, TokenHttpClient};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

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
}

/// Authentication client
pub struct Authenticator {
  inner: TokenClient<HttpClientInner>,
}
impl Authenticator {
  /// Build authentication client with initial login
  pub async fn new(
    auth_config: &AuthenticationConfig,
    http_client: Arc<RwLock<HttpClientInner>>,
  ) -> Result<Self, DapError> {
    let inner = TokenClient::new(auth_config, http_client).await?;
    inner.login().await?;
    Ok(Self { inner })
  }
  /// Login
  pub async fn login(&self) -> Result<(), DapError> {
    self.inner.login().await?;
    info!("Login success");
    Ok(())
  }
  /// Refresh via refresh token or login if refresh failed.
  pub async fn refresh_or_login(&self) -> Result<(), DapError> {
    // expiration check logic
    let expires_in = self
      .inner
      .remaining_seconds_until_expiration()
      .await
      .with_context(|| "Failed to get remaining seconds until expiration from token client")?;

    if expires_in <= TOKEN_REFRESH_MARGIN {
      info!("Id Token is about to expire. Refreshing...");
      let Err(e) = self.inner.refresh().await else {
        info!("Refresh success");
        return Ok(());
      };
      warn!("Refresh failed. Login again... {e}");
      self.login().await?;
    } else {
      info!("Token is not about to expire. No need to refresh. (remaining: {expires_in} secs)");
    }

    Ok(())
  }
  /// Get id token
  pub async fn id_token(&self) -> Result<String, DapError> {
    let token = self.inner.token().await?;
    Ok(token.id.as_str().to_owned())
  }
}
