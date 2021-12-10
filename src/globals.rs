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
  pub doh_method: Option<DoHMethod>,
  pub odoh_relay_url: Option<String>,
  pub mid_relay_urls: Option<Vec<String>>,
  pub max_mid_relays: Option<u64>,
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
      // let doh_clients: Result<Vec<DoHClient>, Error> =
      let polls = doh_target_urls
        .into_iter()
        .map(|target_url| DoHClient::new(target_url, globals.clone(), &id_token));
      let doh_clients = future::join_all(polls)
        .await
        .into_iter()
        .collect::<Result<Vec<DoHClient>, Error>>()?;
      self.doh_clients = Some(doh_clients);
    }

    Ok(())
  }

  pub fn get_random_client(&self) -> Result<DoHClient, Error> {
    if let Some(clients) = &self.doh_clients {
      let num_clients = clients.len();
      let mut rng = rand::thread_rng();
      let idx = rng.gen::<usize>() % num_clients;
      if let Some(client) = clients.get(idx) {
        return Ok(client.clone());
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
