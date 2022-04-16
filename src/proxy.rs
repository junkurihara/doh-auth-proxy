use crate::{
  constants::*, credential::Credential, error::*, exitcodes::*, globals::Globals,
  tcpserver::TCPServer, udpserver::UDPServer,
};
use futures::future::{join_all, select_all};
use log::*;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
}

impl Proxy {
  async fn get_credential_clone(&self) -> Option<Credential> {
    let globals_rw = self.globals.rw.read().await;
    globals_rw.credential.clone()
  }

  // TODO: Should login to relay when odoh
  async fn authenticate(&self) -> Result<()> {
    // Read credential first
    let mut credential = match self.get_credential_clone().await {
      None => {
        // No credential is set (no authorization server)
        return Ok(());
      }
      Some(c) => c,
    };
    credential.login(&self.globals).await?;
    {
      let mut globals_rw = self.globals.rw.write().await;
      globals_rw.credential = Some(credential);
      drop(globals_rw);
    }
    Ok(())
  }

  async fn update_client(&self) -> Result<()> {
    let mut globals_rw = self.globals.rw.write().await;
    globals_rw.update_doh_client(&self.globals).await?;
    drop(globals_rw);
    if self.clients_health_check().await {
      info!("All pairs of client - destination are healthy");
    } else {
      error!("Some clients are unhealthy. Recommend to restart proxy");
    }
    Ok(())
  }

  async fn clients_health_check(&self) -> bool {
    match &self.globals.rw.read().await.doh_clients {
      Some(doh_clients) => {
        let polls = doh_clients
          .iter()
          .map(|client| client.health_check(&self.globals));
        join_all(polls).await.iter().all(|r| match r {
          Ok(()) => true,
          Err(e) => {
            error!("{:?}", e);
            false
          }
        })
      }
      None => false,
    }
  }

  // TODO: update id_token for odoh_relay when odoh
  async fn update_id_token(&self) -> Result<()> {
    // println!("before {:#?}", self.get_credential_clone().await.unwrap());
    let mut globals_rw = self.globals.rw.write().await;
    globals_rw.update_credential(&self.globals).await?;
    drop(globals_rw);
    // println!("after {:#?}", self.globals.rw.read().await.credential);
    Ok(())
  }

  async fn run_periodic_rebootstrap(self) {
    debug!("Start periodic rebootstrap process to acquire target URL IP Addr");

    let period = self.globals.rebootstrap_period_sec;
    loop {
      sleep(period).await;
      match self.update_client().await {
        Ok(_) => debug!("Successfully re-fetched target resolver (DoH) / relay (ODoH) addresses via bootstrap DNS"),
        Err(e) => error!(
          "Failed to update DoH client with new DoH resolver addresses {:?}",
          e
        ), // TODO: should exit?
      };

      // cache handling here to remove expired entries
      let purged = self.globals.cache.purge_expired_entries().await;
      debug!("Purged expired cached content: {} entries", purged);
    }
  }

  async fn run_periodic_token_refresh(self) {
    // read current token in globals.rw, check its expiration, and set period
    debug!("Start periodic expiration-check and refresh process of Id token");
    let mut retry_login = 0;
    loop {
      {
        if retry_login >= MAX_LOGIN_ATTEMPTS {
          error!("Done too many login attempts.");
          std::process::exit(EXIT_ON_TOO_MANY_RETRY);
        }
        if retry_login > 0 {
          warn!("Retry login after {} secs", ENDPOINT_RELOGIN_WAITING_SEC);
          sleep(Duration::from_secs(ENDPOINT_RELOGIN_WAITING_SEC)).await;
          // TODO: ここは再ログインが正しいのか、それともrefreshが正しいのか
          if let Err(e) = self.authenticate().await {
            warn!("Login failed. retry: {}", e);
            retry_login += 1;
            continue;
          }
          if let Err(e) = self.update_client().await {
            warn!("DoH client update failed. retry login: {}", e);
            retry_login += 1;
            continue;
          }
          retry_login = 0;
        }
      }
      {
        // every XX secs, check credential expiration (recovery from hibernation...)
        sleep(Duration::from_secs(CREDENTIAL_CHECK_PERIOD_SECS)).await;
        let credential = {
          if let Some(c) = self.get_credential_clone().await {
            c
          } else {
            // No need to refresh, stash thread
            return;
          }
        };
        match credential.id_token_expires_in_secs().await {
          Ok(secs) => {
            if secs > CREDENTIAL_REFRESH_BEFORE_EXPIRATION_IN_SECS {
              // No need to refresh yet
              debug!(
                "Approx. {:?} secs until next token refresh",
                secs - CREDENTIAL_REFRESH_BEFORE_EXPIRATION_IN_SECS
              );
              continue;
            };
          }
          Err(e) => {
            warn!("Id token is invalid. retry login: {}", e);
            retry_login += 1;
            continue;
          }
        };
      }

      // TODO: Refresh Tokenの更新期限も延長すべきか?
      // Finally refresh
      info!("Refreshing Id token");
      match self.update_id_token().await {
        Ok(_) => {
          debug!("Successfully refreshed Id token");
          match self.update_client().await {
            Ok(_) => debug!("Successfully update DoH client with updated Id token"),
            Err(e) => {
              warn!("DoH client update failed. retry login: {}", e);
              retry_login += 1;
              continue;
            }
          };
        }
        Err(e) => {
          warn!(
            "Failed to refresh. maybe refresh token expired. retry login: {}",
            e
          );
          retry_login += 1;
          continue;
        }
      }
    }
  }

  pub async fn entrypoint(self) -> Result<()> {
    // 1. prepare authorization
    {
      // TODO: 一番初めにログインさせるのが本当にいいのかは疑問。token持つだけの方がいい？
      if let Err(e) = self.authenticate().await {
        error!("Failed to login to token endpoint {:?}", e);
        std::process::exit(EXIT_ON_LOGIN_FAILURE);
      }
    }
    // 2. prepare client
    {
      if let Err(e) = self.update_client().await {
        error!("Failed to update (O)DoH client (with new Id token) {:?}", e);
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
      };

      // UDP server here
      let udp_server = UDPServer {
        globals: self.globals.clone(),
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
      error!("Some packet acceptors are down");
    };

    // for f in futures {
    //   // await for each future
    //   let _ = f.await;
    // }

    Ok(())
  }
}
