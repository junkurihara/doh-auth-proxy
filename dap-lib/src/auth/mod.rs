mod service;

use crate::{
  error::{bail, DapError},
  http::HttpClientInner,
  log::*,
};
use async_trait::async_trait;
use auth_client::{AuthenticationConfig, TokenClient, TokenHttpClient};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

#[async_trait]
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
  pub async fn new(
    auth_config: &AuthenticationConfig,
    http_client: Arc<RwLock<HttpClientInner>>,
  ) -> Result<Self, DapError> {
    let inner = TokenClient::new(auth_config, http_client).await?;
    Ok(Self { inner })
  }
  pub async fn login(&self) -> Result<(), DapError> {
    self.inner.login().await?;
    info!("Login success");
    Ok(())
  }
  pub async fn refresh(&self) -> Result<(), DapError> {
    // TODO: expiration check logic
    self.inner.refresh().await?;
    info!("Refresh success");
    Ok(())
  }
}
