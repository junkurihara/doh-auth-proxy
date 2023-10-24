use super::HttpClient;
use crate::{error::*, log::*, ResolveIps};
use std::sync::Arc;

impl HttpClient {
  /// Periodically resolves endpoints to ip addresses, and override their ip addresses in the inner client.
  pub async fn start_ip_update_service(
    &self,
    primary_resolver: impl ResolveIps,
    fallback_resolver: impl ResolveIps,
    term_notify: Option<Arc<tokio::sync::Notify>>,
  ) -> Result<()> {
    info!("start periodic service updating endpoint ip addresses");

    // match term_notify {
    //   Some(term) => {
    //     tokio::select! {
    //       _ = self.auth_service() => {
    //         warn!("Auth service got down");
    //       }
    //       _ = term.notified() => {
    //         info!("Auth service receives term signal");
    //       }
    //     }
    //   }
    //   None => {
    //     self.auth_service().await?;
    //     warn!("Auth service got down");
    //   }
    // }
    Ok(())
  }

  // /// periodic refresh checker
  // async fn auth_service(&self) -> Result<()> {
  //   loop {
  //     self
  //       .refresh_or_login()
  //       .await
  //       .with_context(|| "auth service failed to refresh or login")?;
  //     sleep(Duration::from_secs(TOKEN_REFRESH_WATCH_DELAY as u64)).await;
  //   }
  // }
}
