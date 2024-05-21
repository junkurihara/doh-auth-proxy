use super::Authenticator;
use crate::{
  constants::{MAX_RELOGIN_ATTEMPTS, TOKEN_REFRESH_WATCH_DELAY, TOKEN_RELOGIN_WAITING_SEC},
  error::*,
  log::*,
};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

impl Authenticator {
  /// Check token expiration every 60 secs, and refresh if the token is about to expire.
  pub async fn start_service(&self, term_notify: Option<Arc<tokio::sync::Notify>>) -> Result<()> {
    info!("Start periodic authentication service");

    match term_notify {
      Some(term) => {
        tokio::select! {
          res = self.auth_service() => {
            warn!("Auth service got down. Possibly failed to refresh or login.");
            res
          }
          _ = term.notified() => {
            info!("Auth service receives term signal");
            Ok(())
          }
        }
      }
      None => {
        let res = self.auth_service().await;
        warn!("Auth service got down. Possibly failed to refresh or login.");
        res
      }
    }
  }

  /// periodic refresh checker
  async fn auth_service(&self) -> Result<()> {
    loop {
      let mut cnt = 0;
      while cnt < MAX_RELOGIN_ATTEMPTS {
        if self.refresh_or_login().await.is_ok() {
          break;
        }
        warn!("Auth service failed to refresh or login. retrying...");
        cnt += 1;
        sleep(Duration::from_secs(TOKEN_RELOGIN_WAITING_SEC)).await;
      }
      if cnt == MAX_RELOGIN_ATTEMPTS {
        error!("Failed to refresh or login. Terminating auth service.");
        return Err(DapError::FailedAllAttemptsOfLoginAndRefresh);
      }
      sleep(Duration::from_secs(TOKEN_REFRESH_WATCH_DELAY as u64)).await;
    }
  }
}
