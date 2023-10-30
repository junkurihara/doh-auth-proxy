use super::DoHClient;
use crate::{error::*, log::*};
use std::sync::Arc;
use tokio::sync::Notify;

impl DoHClient {
  /// Start health check service
  pub async fn start_healthcheck_service(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
    info!("Start periodic path health check service with cache purge");
    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.healthcheck_service() => {
            warn!("Health check service got down.");
          }
          _ = term.notified() => {
            info!("Health check service receives term signal");
          }
        }
      }
      None => {
        self.healthcheck_service().await?;
        warn!("Health check service got down.");
      }
    }
    Ok(())
  }

  /// Health check service periodically executes
  /// - health of every path;
  /// - purge expired DNS cache
  async fn healthcheck_service(&self) -> Result<()> {
    // purge expired DNS cache
    loop {
      let cache_clone = self.cache.clone();
      self.runtime_handle.spawn(async move {
        let purged = cache_clone.purge_expired_entries().await;
        debug!("Purged {} expired entries from cache", purged);
      });

      //　TODO: health check for every path
      // TODO: Health checkの時はキャッシュを無効化しないとダメなのでmake doh queryをいじる
      tokio::time::sleep(self.healthcheck_period_sec).await;
    }

    Ok(())
  }
}
