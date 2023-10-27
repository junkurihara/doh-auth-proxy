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

  /// Health check service periodically checks the health of the path and purge the cache
  async fn healthcheck_service(&self) -> Result<()> {
    //TODO:
    Ok(())
  }
}
