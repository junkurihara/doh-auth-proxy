use super::{
  dns_message,
  error::{DohClientError, DohClientResult},
  path_manage::DoHPath,
  DoHClient,
};
use crate::{
  constants::{HEALTHCHECK_RETRY_WAITING_SEC, HEALTHCHECK_TARGET_ADDR, HEALTHCHECK_TARGET_FQDN, MAX_ALL_UNHEALTHY_RETRY},
  log::*,
};
use futures::future::join_all;
use hickory_proto::op::response_code::ResponseCode;
use std::sync::Arc;
use tokio::sync::Notify;

impl DoHClient {
  /// Start health check service
  pub async fn start_healthcheck_service(&self, term_notify: Option<Arc<Notify>>) -> DohClientResult<()> {
    info!("Start periodic path health check service with cache purge");
    match term_notify {
      Some(term) => {
        tokio::select! {
          res = self.healthcheck_service() => {
            warn!("Health check service got down.");
            res
          }
          _ = term.notified() => {
            info!("Health check service receives term signal");
            Ok(())
          }
        }
      }
      None => {
        let res = self.healthcheck_service().await;
        warn!("Health check service got down.");
        res
      }
    }
  }

  /// Health check service periodically executes
  /// - health of every path;
  /// - purge expired DNS cache
  async fn healthcheck_service(&self) -> DohClientResult<()> {
    let mut all_unhealthy_cnt = 0;
    // purge expired DNS cache
    loop {
      info!("Execute periodic health check");
      let cache_clone = self.cache.clone();
      self.runtime_handle.spawn(async move {
        let purged = cache_clone.purge_expired_entries().await;
        debug!("Purged {} expired entries from cache", purged);
      });

      // health check for every path
      let futures = self.path_manager.paths.iter().flatten().flatten().map(|path| async move {
        if let Err(e) = self.healthcheck(path).await {
          warn!("Healthcheck fails for {}: {e}", path.as_url()?)
        }
        Ok(()) as DohClientResult<()>
      });
      let _ = join_all(futures).await;

      if !self.path_manager.paths.iter().flatten().flatten().any(|v| v.is_healthy()) {
        all_unhealthy_cnt += 1;
        error!("All possible paths are unhealthy. Should check the Internet connection");
        if all_unhealthy_cnt > MAX_ALL_UNHEALTHY_RETRY {
          return Err(DohClientError::AllPathsUnhealthy);
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(HEALTHCHECK_RETRY_WAITING_SEC)).await;
        continue;
      }
      tokio::time::sleep(self.healthcheck_period_sec).await;
    }
  }

  /// Check health for a given path, and update health status for the path.
  async fn healthcheck(&self, path: &Arc<DoHPath>) -> DohClientResult<()> {
    let q_msg = dns_message::build_query_a(HEALTHCHECK_TARGET_FQDN)?;
    let packet_buf = dns_message::encode(&q_msg)?;

    let res_msg = match self.make_doh_query_inner(&packet_buf, path).await {
      Ok((_, res_msg)) => res_msg,
      Err(e) => {
        path.make_unhealthy();
        warn!(
          "Failed to query or invalid response. Path {} is unhealthy: {}",
          path.as_url()?,
          e
        );
        return Ok(());
      }
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
