use crate::client::{DoHClient, DoHMethod};
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::tcpserver::TCPServer;
use crate::udpserver::UDPServer;
use futures::future::select_all;
use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl Proxy {
  // TODO: token refresh時にもリゾルバアドレスもリフレッシュしてDoHクライアントオブジェクトを作り直す
  async fn update_resolver_addr(self) -> Result<(), Error> {
    let credential = match self.globals_cache.try_read() {
      Ok(cache) => match cache.credential.clone() {
        Some(x) => x,
        None => bail!("credential is not properly configured to update resolver"),
      },
      Err(e) => {
        bail!("Failed to read cache: {}", e);
      }
    };
    let (doh_client, doh_target_addrs) =
      DoHClient::new(self.globals.clone(), &credential.id_token()).await?;
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
      doh_client: Some(doh_client),
      doh_target_addrs: Some(doh_target_addrs),
      credential: Some(credential),
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

  async fn run_periodic_token_refresh(self) {
    //
    // TODO: first read current token in globals_cache, check its expiration, and set period
    // TODO: login password should be stored in keychain access like secure storage rather than dotenv.
  }

  pub async fn entrypoint(self) -> Result<(), Error> {
    info!("Target DoH URL: {:?}", &self.globals.doh_target_url);
    info!(
      "Target DoH Address is re-fetched every {:?} min",
      &self.globals.rebootstrap_period_sec.as_secs() / 60
    );

    // prepare authorization
    match &mut self.globals_cache.try_write() {
      Ok(c) => {
        // Login and setup client first
        if let Some(credential) = &mut c.credential {
          credential.login(&self.globals).await?;
        }
        info!("Enabled Authorization header in DoH query");
        let id_token = if let Some(t) = c.credential.clone() {
          t.id_token()
        } else {
          bail!("Id token is not properly configured");
        };
        let (client, target_addrs) = DoHClient::new(self.globals.clone(), &id_token).await?;
        c.doh_client = Some(client);
        c.doh_target_addrs = Some(target_addrs);
        // spawn a thread to periodically refresh token
        self
          .globals
          .runtime_handle
          .spawn(self.clone().run_periodic_token_refresh());
      }
      Err(e) => {
        bail!("Failed to read cache: {}", e);
      }
    }
    ////
    match self.globals.doh_method {
      Some(DoHMethod::GET) => info!("Use GET method to query"),
      Some(DoHMethod::POST) => info!("Use POST method to query"),
      _ => bail!("Something wrong for DoH method"),
    }

    // spawn a process to periodically update the DoH client via global.bootstrap_dns
    self
      .globals
      .runtime_handle
      .spawn(self.clone().run_periodic_rebootstrap());

    // handle TCP and UDP servers on listen socket addresses
    let addresses = self.globals.listen_addresses.clone();
    let futures = select_all(addresses.into_iter().flat_map(|addr| {
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
      vec![
        self.globals.runtime_handle.spawn(udp_server.start(addr)),
        self.globals.runtime_handle.spawn(tcp_server.start(addr)),
      ]
    }));
    // .collect::<Vec<_>>();

    // wait for all future
    if let (Ok(_), _, _) = futures.await {
      println!("Some packet acceptors are down");
    };

    // for f in futures {
    //   // await for each future
    //   let _ = f.await;
    // }

    Ok(())
  }
}
