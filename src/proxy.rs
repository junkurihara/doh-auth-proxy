use crate::client::DoHClient;
use crate::constants::*;
use crate::credential::Credential;
use crate::error::*;
use crate::exitcodes::*;
use crate::globals::{Globals, GlobalsCache};
use crate::tcpserver::TCPServer;
use crate::udpserver::UDPServer;
use futures::future::select_all;
use log::{debug, error, info, warn};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl Proxy {
  fn get_credential_clone(&self) -> Result<Option<Credential>, Error> {
    match self.globals_cache.try_read() {
      Ok(cache) => Ok(cache.credential.clone()),
      Err(e) => {
        bail!("Failed to read cache: {}", e);
      }
    }
  }

  async fn authenticate(&self) -> Result<(), Error> {
    // Read credential first
    let mut credential = match self.get_credential_clone()? {
      None => {
        // No credential is set (no authorization server)
        return Ok(());
      }
      Some(c) => c,
    };
    credential.login(&self.globals).await?;
    {
      match self.globals_cache.try_write() {
        Ok(mut cache) => {
          cache.credential = Some(credential);
          drop(cache);
        }
        Err(e) => {
          bail!("Failed to read cache: {}", e);
        }
      };
    }
    Ok(())
  }

  async fn update_client(&self) -> Result<(), Error> {
    let credential = self.get_credential_clone()?;

    let id_token = match credential {
      Some(c) => c.id_token(),
      None => None,
    };
    let (doh_client, doh_target_addrs) = DoHClient::new(self.globals.clone(), &id_token).await?;
    {
      let mut globals_cache = match self.globals_cache.try_write() {
        Ok(g) => g,
        Err(e) => {
          bail!("Failed to write-lock global cache: {:?}", e)
        }
      };
      globals_cache.doh_client = Some(doh_client);
      globals_cache.doh_target_addrs = Some(doh_target_addrs);
      drop(globals_cache);
    }
    Ok(())
  }

  async fn update_id_token(&self) -> Result<(), Error> {
    let mut credential = match self.get_credential_clone()? {
      None => {
        // This function is called only when authorized
        bail!("No credential is configured");
      }
      Some(c) => c,
    };

    {
      // println!("before {:#?}", credential);
      credential.refresh(&self.globals).await?;
      let mut globals_cache = match self.globals_cache.try_write() {
        Ok(g) => g,
        Err(e) => {
          bail!("Failed to write-lock global cache: {:?}", e)
        }
      };
      globals_cache.credential = Some(credential);
      drop(globals_cache);
      // if let Ok(c) = self.globals_cache.try_read() {
      //   println!("after {:#?}", c.credential);
      // }
    }
    Ok(())
  }

  async fn run_periodic_rebootstrap(self) {
    debug!("Start periodic rebootstrap process to acquire target URL IP Addr");

    let period = self.globals.rebootstrap_period_sec;
    loop {
      sleep(period).await;
      match self.update_client().await {
        Ok(_) => debug!("Successfully re-fetched target resolver addresses via bootstrap DNS"),
        Err(e) => error!(
          "Failed to update DoH client with new DoH resolver addresses {:?}",
          e
        ), // TODO: should exit?
      };

      // TODO: cache handling here?
    }
  }

  async fn run_periodic_token_refresh(self) -> Result<(), Error> {
    {
      // read current token in globals_cache, check its expiration, and set period
      debug!("Start periodic refresh process of Id token");
      loop {
        {
          let credential = {
            if let Some(c) = self.get_credential_clone()? {
              c
            } else {
              // No need to refresh
              return Ok(());
            }
          };
          let period = match credential.id_token_expires_in_secs().await {
            Ok(secs) => {
              let period_secs = match secs > CREDENTIAL_REFRESH_BEFORE_EXPIRATION_IN_SECS {
                true => secs - CREDENTIAL_REFRESH_BEFORE_EXPIRATION_IN_SECS,
                false => 1,
              };
              Duration::from_secs(period_secs as u64)
            }
            Err(e) => {
              error!("Need to re-login to token endpoint {:?}", e);
              std::process::exit(EXIT_ON_LOGIN_FAILURE);
            }
          };
          info!("Sleep {:?} until next token refresh", period);
          sleep(period).await;
        }

        match self.update_id_token().await {
          Ok(_) => {
            debug!("Successfully refresh Id token");
            match self.update_client().await {
              Ok(_) => debug!("Successfully update DoH client with updated Id token"),
              Err(e) => {
                error!("Failed to update DoH client with new Id token {:?}", e);
                std::process::exit(EXIT_ON_REFRESH_FAILURE);
              }
            };
          }
          Err(e) => {
            warn!(
              "Unsuccessful token refresh. maybe refresh token expired, try to re-login: {}",
              e
            );
            if let Err(e) = self.authenticate().await {
              error!("Failed to login to token endpoint {:?}", e);
              std::process::exit(EXIT_ON_LOGIN_FAILURE);
            }
            if let Err(e) = self.update_client().await {
              error!("Failed to update DoH client with new Id token {:?}", e);
              std::process::exit(EXIT_ON_CLIENT_FAILURE);
            }
          }
        }
      }
    }
  }

  pub async fn entrypoint(self) -> Result<(), Error> {
    // 1. prepare authorization
    {
      if let Err(e) = self.authenticate().await {
        error!("Failed to login to token endpoint {:?}", e);
        std::process::exit(EXIT_ON_LOGIN_FAILURE);
      }
    }
    // 2. prepare client
    {
      if let Err(e) = self.update_client().await {
        error!("Failed to update DoH client with new Id token {:?}", e);
        std::process::exit(EXIT_ON_CLIENT_FAILURE);
      }
    }

    // spawn a thread to periodically refresh token if credential is given
    {
      self
        .globals
        .runtime_handle
        .spawn(self.clone().run_periodic_token_refresh());
    }

    // spawn a process to periodically update the DoH client via global.bootstrap_dns
    {
      self
        .globals
        .runtime_handle
        .spawn(self.clone().run_periodic_rebootstrap());
    }

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
