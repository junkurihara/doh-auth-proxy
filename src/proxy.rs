use crate::client::DoHClient;
use crate::errors::DoHError;
use crate::globals::{Globals, GlobalsCache};
use crate::udpserver::UDPServer;
use log::{debug, error, info, warn};
use std::error::Error;
use std::sync::{Arc, RwLock};
use tokio::time::{sleep,};

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl Proxy {
  async fn update_resolver_addr(self) -> Result<(), Box<dyn Error>> {
    let (doh_client, doh_target_addrs) = DoHClient::new(self.globals.clone()).await?;
    let mut globals_cache = match self.globals_cache.try_write() {
      Ok(g) => g,
      Err(e) => Err(format!(
        "Failed to update global cache for resolver addresses: {:?}",
        e
      ))?,
    };
    *globals_cache = GlobalsCache {
      doh_client,
      doh_target_addrs,
    };

    Ok(())
  }

  async fn run_periodic_rebootstrap(self) {
    info!("Start periodic rebootstrap process to acquire target URL IP Addr");

    let period = self.globals.rebootstrap_period_sec;
    loop {
      sleep(period).await;
      match self.clone().update_resolver_addr().await {
        Ok(_) => info!("Successfully Refetched target resolver addresses via bootstrap DNS"),
        Err(e) => error!("{:?}", e),
      };

      // TODO: cache handling here?
    }
  }

  pub async fn entrypoint(self) -> Result<(), DoHError> {
    debug!("Proxy entrypoint");
    info!("Listen address: {:?}", &self.globals.listen_address);
    info!("Target DoH URL: {:?}", &self.globals.doh_target_url);
    info!(
      "Target DoH Address is re-fetched every {:?} min",
      &self.globals.rebootstrap_period_sec.as_secs() / 60
    );
    if let Some(_) = &self.globals.auth_token {
      info!("Enabled Authorization header in DoH query");
    }

    // spawn a process to periodically update the DoH client via globa.bootstrap_dns
    tokio::spawn(self.clone().run_periodic_rebootstrap());

    // TODO: definition of error
    // TODO: TCP serverはspawnして別スレッドで待ち受け。別にいらない気もする。

    // UDP socket here
    let udp_server = UDPServer {
      globals: self.globals.clone(),
      globals_cache: self.globals_cache.clone(),
    };
    udp_server.start().await?;

    Ok(())
  }
}
