use super::Authenticator;
use crate::{constants::TOKEN_REFRESH_WATCH_DELAY, error::*, log::*};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

impl Authenticator {
  /// Check token expiration every 60 secs, and refresh if the token is about to expire.
  pub async fn start_service(&self, term_notify: Option<Arc<tokio::sync::Notify>>) -> Result<()> {
    info!("start periodic authentication service");

    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.auth_service() => {
            warn!("Auth service got down");
          }
          _ = term.notified() => {
            info!("Auth service receives term signal");
          }
        }
      }
      None => {
        self.auth_service().await?;
        warn!("Auth service got down");
      }
    }
    Ok(())
  }

  /// periodic refresh checker
  async fn auth_service(&self) -> Result<()> {
    loop {
      self
        .refresh_or_login()
        .await
        .with_context(|| "auth service failed to refresh or login")?;
      sleep(Duration::from_secs(TOKEN_REFRESH_WATCH_DELAY as u64)).await;
    }
  }
}
