use crate::client::DoHClient;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::tcpserver::TCPServer;
use crate::udpserver::UDPServer;
use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl Proxy {
  async fn update_resolver_addr(self) -> Result<(), Error> {
    let (doh_client, doh_target_addrs) = DoHClient::new(self.globals.clone()).await?;
    let mut globals_cache = match self.globals_cache.try_write() {
      Ok(g) => g,
      Err(e) => {
        bail!(
          "Failed to update global cache for resolver addresses: {:?}",
          e
        )
      }
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
        Ok(_) => info!("Successfully re-fetched target resolver addresses via bootstrap DNS"),
        Err(e) => error!("{:?}", e),
      };

      // TODO: cache handling here?
    }
  }

  pub async fn entrypoint(self) -> Result<(), Error> {
    debug!("Proxy entrypoint");
    info!("Target DoH URL: {:?}", &self.globals.doh_target_url);
    info!(
      "Target DoH Address is re-fetched every {:?} min",
      &self.globals.rebootstrap_period_sec.as_secs() / 60
    );
    if let Some(_) = &self.globals.auth_token {
      info!("Enabled Authorization header in DoH query");
    }

    // spawn a process to periodically update the DoH client via global.bootstrap_dns
    self
      .globals
      .runtime_handle
      .spawn(self.clone().run_periodic_rebootstrap());

    // TODO: definition of error

    // handle TCP and UDP servers on listen socket addresses
    let addresses = self.globals.listen_addresses.clone();
    let futures = addresses
      .into_iter()
      .map(|addr| {
        info!("Listen address: {:?}", addr);

        // TCP server here
        let tcp_server = TCPServer {
          globals: self.globals.clone(),
          globals_cache: self.globals_cache.clone(),
        };

        // UDP server here
        let udp_server = UDPServer {
          globals: self.globals.clone(),
          globals_cache: self.globals_cache.clone(),
        };

        // spawn as a tuple of (udp, tcp) for each socket address
        (
          self.globals.runtime_handle.spawn(async move {
            if let Err(e) = udp_server.start(addr).await {
              error!("Error in UDP acceptor {:?}", e);
            }
          }),
          self.globals.runtime_handle.spawn(async move {
            if let Err(e) = tcp_server.start(addr).await {
              error!("Error in TCP acceptor {:?}", e);
            }
          }),
        )
      })
      .collect::<Vec<_>>();
    for (u, t) in futures {
      // await for each tuple of (udp, tcp)
      let _ = u.await;
      let _ = t.await;
    }

    Ok(())
  }
}
