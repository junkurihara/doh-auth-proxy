use super::{dns_message, path_manage::DoHPath, DoHClient};
use crate::{
  constants::{HEALTHCHECK_TARGET_ADDR, HEALTHCHECK_TARGET_FQDN},
  error::*,
  log::*,
};
use futures::future::join_all;
use hickory_proto::op::response_code::ResponseCode;
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

      // health check for every path
      let futures = self
        .path_manager
        .paths
        .iter()
        .flatten()
        .flatten()
        .map(|path| async move {
          if let Err(e) = self.healthcheck(path).await {
            warn!("Healthcheck fails for {}: {e}", path.as_url()?)
          }
          Ok(()) as Result<()>
        });
      let _ = join_all(futures).await;

      if !self
        .path_manager
        .paths
        .iter()
        .flatten()
        .flatten()
        .any(|v| v.is_healthy())
      {
        error!("All possible paths are unhealthy. Should check the Internet connection");
      }
      tokio::time::sleep(self.healthcheck_period_sec).await;
    }
  }

  /// Check health for a given path, and update health status for the path.
  async fn healthcheck(&self, path: &Arc<DoHPath>) -> Result<()> {
    let q_msg = dns_message::build_query_a(HEALTHCHECK_TARGET_FQDN)?;
    let packet_buf = dns_message::encode(&q_msg)?;

    let Ok((_, res_msg)) = self.make_doh_query_inner(&packet_buf, path).await else {
      path.make_unhealthy();
      warn!(
        "Failed to query or invalid response. Path {} is unhealthy",
        path.as_url()?
      );
      return Ok(());
    };

    if res_msg.header().response_code() != ResponseCode::NoError {
      path.make_unhealthy();
      warn!("Response is not Ok. Path {} is unhealthy", path.as_url()?);
      return Ok(());
    }

    let answers = res_msg.answers();
    if answers.is_empty() {
      path.make_unhealthy();
      warn!("Response has no answer. Path {} is unhealthy", path.as_url()?);

      return Ok(());
    }

    let target_addr_contains = answers
      .iter()
      .filter_map(|answer| answer.data())
      .any(|v| v.to_string() == HEALTHCHECK_TARGET_ADDR);

    if !target_addr_contains {
      path.make_unhealthy();
      warn!(
        "Response has no or wrong rdata. Maybe suspicious and polluted target. Path {} is unhealthy.",
        path.as_url()?
      );
      return Ok(());
    }

    path.make_healthy();
    debug!("Path {} is healthy", path.as_url()?);
    Ok(())
  }
}
