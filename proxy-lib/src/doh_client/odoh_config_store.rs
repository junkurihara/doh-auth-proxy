use super::{odoh::ODoHConfig, path_manage::DoHTarget};
use crate::{
  constants::{ODOH_CONFIG_PATH, ODOH_CONFIG_WATCH_DELAY},
  error::*,
  http_client::HttpClientInner,
  log::*,
};
use rustc_hash::FxHashMap as HashMap;
use std::sync::Arc;
use tokio::{
  sync::{Notify, RwLock},
  time::{sleep, Duration},
};
use url::Url;

#[allow(clippy::complexity)]
/// ODoH config store
pub struct ODoHConfigStore {
  inner: Arc<RwLock<HashMap<Arc<DoHTarget>, Arc<Option<ODoHConfig>>>>>,
  http_client: Arc<RwLock<HttpClientInner>>,
}

impl ODoHConfigStore {
  /// Create a new ODoHConfigStore
  pub async fn new(http_client: Arc<RwLock<HttpClientInner>>, targets: &[Arc<DoHTarget>]) -> Result<Self> {
    let inner = targets
      .iter()
      .map(|target| (target.clone(), Arc::new(None as Option<ODoHConfig>)))
      .collect::<HashMap<_, _>>();
    let res = Self {
      inner: Arc::new(RwLock::new(inner)),
      http_client,
    };
    res.update_odoh_config_from_well_known().await?;
    Ok(res)
  }

  /// Get a ODoHConfig for DoHTarget
  pub async fn get(&self, target: &Arc<DoHTarget>) -> Option<Arc<Option<ODoHConfig>>> {
    let inner_lock = self.inner.read().await;
    let inner = inner_lock.get(target)?;
    Some(inner.clone())
  }

  /// Fetch ODoHConfig from target
  pub async fn update_odoh_config_from_well_known(&self) -> Result<()> {
    // TODO: Add auth token when fetching config?
    // fetch public key from odoh target (/.well-known)
    let inner_lock = self.inner.read().await;
    let inner = inner_lock.clone();
    drop(inner_lock);

    let futures = inner.keys().map(|target| async {
      let mut destination = Url::parse(&format!("{}://{}", target.scheme(), target.authority())).unwrap();
      destination.set_path(ODOH_CONFIG_PATH);
      let lock = self.http_client.read().await;
      debug!("Fetching ODoH config from {}", destination);
      lock
        .get(destination)
        .header(reqwest::header::ACCEPT, "application/binary")
        .send()
        .await
    });
    let joined = futures::future::join_all(futures);
    let update_futures = joined.await.into_iter().zip(inner).map(|(res, current)| async move {
      match res {
        Ok(response) => {
          if response.status() != reqwest::StatusCode::OK {
            error!("Failed to fetch ODoH config!: {:?}", response.status());
            return (current.0.clone(), Arc::new(None as Option<ODoHConfig>));
          }
          let Ok(body) = response.bytes().await else {
            error!("Failed to parse response body in ODoH config response");
            return (current.0.clone(), Arc::new(None as Option<ODoHConfig>));
          };
          let config = ODoHConfig::new(current.0.authority(), &body).ok();
          (current.0.clone(), Arc::new(config))
        }
        Err(e) => {
          error!("Failed to fetch ODoH config!: {:?}", e);
          (current.0.clone(), Arc::new(None as Option<ODoHConfig>))
        }
      }
    });
    let update_joined = futures::future::join_all(update_futures)
      .await
      .into_iter()
      .collect::<HashMap<_, _>>();
    let mut inner_lock = self.inner.write().await;
    *inner_lock = update_joined;
    drop(inner_lock);
    Ok(())
  }

  /// start odoh config watch service
  pub(super) async fn start_service(&self, term_notify: Option<Arc<Notify>>) -> Result<()> {
    info!("Start periodic odoh config watch service");
    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.watch_service() => {
            warn!("ODoH config watch service is down");
          }
          _ = term.notified() => {
            info!("ODoH config watch service receives term signal");
          }
        }
      }
      None => {
        self.watch_service().await?;
        warn!("ODoH config watch service is down.");
      }
    }
    Ok(())
  }

  /// watch service
  async fn watch_service(&self) -> Result<()> {
    loop {
      self.update_odoh_config_from_well_known().await?;
      sleep(Duration::from_secs(ODOH_CONFIG_WATCH_DELAY as u64)).await;
    }
  }
}
