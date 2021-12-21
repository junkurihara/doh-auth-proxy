use crate::client::{DoHClient, DoHMethod};
use crate::counter::Counter;
use crate::credential::Credential;
use crate::error::*;
use futures::future;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Globals {
  pub listen_addresses: Vec<SocketAddr>,
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub timeout_sec: Duration,

  pub doh_target_urls: Vec<String>,
  pub target_randomization: bool,
  pub doh_method: DoHMethod,

  pub odoh_relay_urls: Option<Vec<String>>,
  pub odoh_relay_randomization: bool,
  pub mid_relay_urls: Option<Vec<String>>,
  pub max_mid_relays: usize,

  pub bootstrap_dns: SocketAddr,
  pub rebootstrap_period_sec: Duration,

  pub max_connections: usize,
  pub counter: Counter,
  pub runtime_handle: tokio::runtime::Handle,
}

#[derive(Debug, Clone)]
pub struct GlobalsCache {
  pub doh_clients: Option<Vec<DoHClient>>,
  pub credential: Option<Credential>,
}

impl GlobalsCache {
  // This updates doh_client in globals_cache in order to
  // - re-fetch the resolver address by the bootstrap DNS (Do53)
  // - re-fetch the ODoH configs when ODoH
  pub async fn update_doh_client(&mut self, globals: &Arc<Globals>) -> Result<(), Error> {
    let id_token = match &self.credential {
      Some(c) => c.id_token(),
      None => None,
    };
    {
      let doh_target_urls = globals.doh_target_urls.clone();

      // doh clients are configured for targets x nexthop relays.
      // if let Some(relay_urls) = &globals.odoh_relay_urls {
      //   // anonymization
      //   let polls = doh_target_urls.iter().map(|target| {
      //     let polls_inner = relay_urls
      //       .iter()
      //       .map(|relay| DoHClient::new(target, Some(relay.clone()), globals.clone(), &id_token))
      //       .collect::<Vec<_>>();
      //     future::join_all(polls_inner)
      //   });
      //   let inner = polls.map(|p| async {
      //     p.await
      //       .into_iter()
      //       .collect::<Result<Vec<DoHClient>, Error>>()
      //   });
      //   let doh_clients = future::join_all(inner)
      //     .await
      //     .into_iter()
      //     .collect::<Result<Vec<Vec<DoHClient>>, Error>>()?;
      //   self.doh_clients = Some(doh_clients);
      // } else {
      // non-anonymization
      let polls = doh_target_urls.iter().map(|target| {
        DoHClient::new(
          target,
          globals.odoh_relay_urls.clone(),
          globals.clone(),
          &id_token,
        )
      });
      let doh_clients = future::join_all(polls)
        .await
        .into_iter()
        .collect::<Result<Vec<DoHClient>, Error>>()?;
      self.doh_clients = Some(doh_clients);
      // }
    }

    Ok(())
  }

  pub fn get_random_client(&self, globals: &Arc<Globals>) -> Result<DoHClient, Error> {
    if let Some(clients) = &self.doh_clients {
      let num_targets = clients.len();
      let target_idx = if globals.target_randomization {
        let mut rng = rand::thread_rng();
        rng.gen::<usize>() % num_targets
      } else {
        0
      };
      if let Some(target) = clients.get(target_idx) {
        return Ok(target.clone());
      }
    }
    bail!("DoH client is not properly configured");
  }

  // This refreshes id_token for doh_target when doh, or for odoh_relay when odoh.
  pub async fn update_credential(&mut self, globals: &Arc<Globals>) -> Result<(), Error> {
    let mut credential = match self.credential.clone() {
      None => {
        // This function is called only when authorized
        bail!("No credential is configured");
      }
      Some(c) => c,
    };

    {
      credential.refresh(globals).await?;
      self.credential = Some(credential);
    }
    Ok(())
  }
}
