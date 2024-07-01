use super::{
  error::{AuthResult, AuthenticatorError},
  Authenticator,
};
use crate::{
  constants::{MAX_RELOGIN_ATTEMPTS, TOKEN_REFRESH_WATCH_DELAY, TOKEN_RELOGIN_WAITING_SEC},
  log::*,
};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

impl Authenticator {
  /// Check token expiration every 60 secs, and refresh if the token is about to expire.
  pub async fn start_service(&self, term_notify: Option<Arc<tokio::sync::Notify>>) -> AuthResult<()> {
    info!("Start periodic authentication service");
    let services = async {
      #[cfg(feature = "anonymous-token")]
      tokio::select! {
        res = self.auth_service() => {
          warn!("Auth service got down. Possibly failed to refresh or login.");
          res
        }
        res = self.anonymous_token_service() => {
          warn!("Anonymous token service got down. Possibly failed to refresh or login.");
          res
        }
      }

      #[cfg(not(feature = "anonymous-token"))]
      {
        let res = self.auth_service().await;
        warn!("Auth service got down. Possibly failed to refresh or login.");
        res
      }
    };

    match term_notify {
      Some(term) => {
        tokio::select! {
          res = services => res,
          _ = term.notified() => {
            info!("Auth service receives term signal");
            Ok(())
          }
        }
      }
      None => services.await,
    }
  }

  /// periodic refresh checker for ID token
  async fn auth_service(&self) -> AuthResult<()> {
    info!("Start periodic authentication service to retrieve ID token");
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
        return Err(AuthenticatorError::FailedAllAttemptsOfLoginAndRefresh);
      }
      sleep(Duration::from_secs(TOKEN_REFRESH_WATCH_DELAY as u64)).await;
    }
  }

  /// Periodic blindjwks update checker and sign request for ID token
  #[cfg(feature = "anonymous-token")]
  async fn anonymous_token_service(&self) -> AuthResult<()> {
    use crate::constants::BLIND_JWKS_ENDPOINT_WATCH_DELAY_SEC;
    info!("Start periodic signing request service to retrieve anonymous token");

    // In `new` method, the blind validation key is already fetch and the anonymous token is already requested.
    // So we first sleep for the delay time.
    sleep(Duration::from_secs(BLIND_JWKS_ENDPOINT_WATCH_DELAY_SEC)).await;

    let mut expired_refetch_cnt = 0;
    loop {
      // Check if the blind validation key is up-to-date.
      let Ok(is_updated) = self.update_blind_validation_key_if_stale().await else {
        error!("Failed to update the blind validation key. Terminating anonymous token service.");
        return Err(AuthenticatorError::FailedToCheckBlindValidationKey);
      };

      // Check if the blind validation key is alive just in case
      let Ok(remaining) = self.blind_remaining_seconds_until_expiration().await else {
        error!("Failed to check if the blind validation key is alive. Terminating anonymous token service.");
        return Err(AuthenticatorError::FailedToCheckBlindValidationKey);
      };
      if remaining < 0 {
        error!("Blind validation key is already expired. refetch again.");
        if expired_refetch_cnt >= MAX_RELOGIN_ATTEMPTS {
          error!("Failed to refetch the blind validation key. Terminating anonymous token service.");
          return Err(AuthenticatorError::FailedAllAttemptsOfLoginAndRefresh);
        }
        expired_refetch_cnt += 1;
        sleep(Duration::from_secs(TOKEN_RELOGIN_WAITING_SEC)).await;
        continue;
      }
      expired_refetch_cnt = 0;

      // This simply (re)generates the anonymous token if the blind validation key was stale (just updated).
      if is_updated {
        // request blind signature with ID token
        debug!("Requesting blind signature with ID token.");
        let mut cnt = 0;
        while cnt < MAX_RELOGIN_ATTEMPTS {
          if self.request_blind_signature_with_id_token().await.is_ok() {
            break;
          }
          warn!("Anonymous token service failed to request blind signature with ID token. retrying...");
          cnt += 1;
          sleep(Duration::from_secs(TOKEN_RELOGIN_WAITING_SEC)).await;
        }
        if cnt == MAX_RELOGIN_ATTEMPTS {
          error!("Failed to request blind signature with ID token. Terminating anonymous token service.");
          return Err(AuthenticatorError::FailedAllAttemptsOfLoginAndRefresh);
        }
      }

      debug!(
        "Blind validation key will expire in {} secs. Waiting for the next update. Check in {} secs again.",
        remaining,
        BLIND_JWKS_ENDPOINT_WATCH_DELAY_SEC.min(remaining as u64 + 1),
      );

      sleep(Duration::from_secs(
        BLIND_JWKS_ENDPOINT_WATCH_DELAY_SEC.min(remaining as u64 + 1),
      ))
      .await;
    }
  }
}
