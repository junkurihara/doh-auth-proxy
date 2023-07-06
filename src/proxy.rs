use crate::{
  constants::*,
  context::ProxyContext,
  error::*,
  log::*,
  servers::{TCPServer, UDPServer},
};
use futures::future::{join_all, select_all};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<ProxyContext>,
}

impl Proxy {
  // TODO: Should login to relay when odoh
  async fn authenticate(&self) -> Result<()> {
    // Read credential first
    let Some(mut credential) = self.globals.credential.read().await.clone() else {
      // No credential is set (no authorization server)
      return Ok(());
    };
    credential.login(&self.globals).await?;
    {
      *self.globals.credential.write().await = Some(credential);
    }
    Ok(())
  }

  async fn update_client(&self) -> Result<()> {
    self.globals.update_doh_client().await?;
    if self.clients_health_check().await {
      info!("All pairs of client - destination are healthy");
    } else {
      error!("Some clients are unhealthy. Recommend to restart proxy");
    }
    Ok(())
  }

  async fn clients_health_check(&self) -> bool {
    match &self.globals.doh_clients.read().await.as_ref() {
      Some(doh_clients) => {
        let polls = doh_clients.iter().map(|client| client.health_check(&self.globals));
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
    self.globals.update_credential().await?;
    Ok(())
  }

  async fn client_refresh_service(&self) {
    debug!("Start periodic re-bootstrap process to acquire target URL IP Addr");

    let period = self.globals.rebootstrap_period_sec;
    loop {
      sleep(period).await;
      match self.update_client().await {
        Ok(_) => debug!("Successfully re-fetched target resolver (DoH) / relay (ODoH) addresses via bootstrap DNS"),
        Err(e) => error!("Failed to update DoH client with new DoH resolver addresses {:?}", e), // TODO: should exit?
      };

      // cache handling here to remove expired entries
      let purged = self.globals.cache.purge_expired_entries().await;
      debug!("Purged expired cached content: {} entries", purged);
    }
  }

  async fn token_refresh_service(&self) {
    // read current token in globals.rw, check its expiration, and set period
    debug!("Start periodic expiration-check and refresh process of Id token");
    let mut retry_login = 0;
    loop {
      {
        if retry_login >= MAX_LOGIN_ATTEMPTS {
          error!("Done too many login attempts.");
          std::process::exit(1);
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
        let Some(credential) = self.globals.credential.read().await.clone() else {
          // No need to refresh, stash thread
          return;
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
          warn!("Failed to refresh. maybe refresh token expired. retry login: {}", e);
          retry_login += 1;
          continue;
        }
      }
    }
  }

  pub async fn entrypoint(&self) -> Result<()> {
    // 1. prepare authorization
    {
      // TODO: 一番初めにログインさせるのが本当にいいのかは疑問。token持つだけの方がいい？
      if let Err(e) = self.authenticate().await {
        error!("Failed to login to token endpoint {:?}", e);
        std::process::exit(1);
      }
    }
    // 2. prepare client
    {
      if let Err(e) = self.update_client().await {
        error!("Failed to update (O)DoH client (with new Id token) {:?}", e);
        std::process::exit(1);
      }
    }

    // handle TCP and UDP servers on listen socket addresses
    let addresses = self.globals.listen_addresses.clone();
    let udp_tcp_services = select_all(addresses.into_iter().flat_map(|addr| {
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

    if self.globals.credential.read().await.is_none() {
      debug!("No credential found");
      tokio::select! {
        _ = udp_tcp_services => {
          error!("Some packet acceptors got down");
        }
        // Periodic rebootstrap for client refresh to get IP addr for the next hop url
        _ = self.client_refresh_service() => {
          error!("Rebootstrapping task got down");
        }
      }
    } else {
      tokio::select! {
        _ = udp_tcp_services => {
          error!("Some packet acceptors got down");
        }
        // Periodic rebootstrap for client refresh to get IP addr for the next hop url
        _ = self.client_refresh_service() => {
          error!("Rebootstrapping task got down");
        }
        // Periodic token retrieval when authentication is enabled
        _ = self.token_refresh_service() => {
          error!("Token refreshing task got down");
        }
      }
    }

    Ok(())
  }
}
