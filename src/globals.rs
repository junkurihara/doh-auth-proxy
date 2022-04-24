use crate::{
  cache::Cache,
  client::{DoHClient, DoHMethod},
  counter::Counter,
  credential::Credential,
  error::*,
};
use futures::future;
use rand::Rng;
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::RwLock, time::Duration};

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

  // pub rw: Arc<RwLock<GlobalsRW>>,
  pub doh_clients: Arc<RwLock<Option<Vec<DoHClient>>>>,
  pub credential: Arc<RwLock<Option<Credential>>>,
  pub cache: Arc<Cache>,
}

// #[derive(Debug, Clone)]
// pub struct GlobalsRW {
//   pub doh_clients: Option<Vec<DoHClient>>,
//   pub credential: Option<Credential>,
// }

impl Globals {
  // This updates doh_client in globals.rw in order to
  // - re-fetch the resolver address by the bootstrap DNS (Do53)
  // - re-fetch the ODoH configs when ODoH
  pub async fn update_doh_client(&self, globals: &Arc<Globals>) -> Result<()> {
    let id_token = match self.credential.read().await.as_ref() {
      Some(c) => c.id_token(),
      None => None,
    };
    {
      let doh_target_urls = globals.doh_target_urls.clone();
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
        .collect::<Result<Vec<DoHClient>>>()?;
      *self.doh_clients.write().await = Some(doh_clients);
    }

    Ok(())
  }

  pub async fn get_random_client(&self, globals: &Arc<Globals>) -> Result<DoHClient> {
    let doh_clients = self.doh_clients.read().await.clone();
    if let Some(clients) = &doh_clients {
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
  pub async fn update_credential(&self, globals: &Arc<Globals>) -> Result<()> {
    let mut credential = match self.credential.read().await.clone() {
      None => {
        // This function is called only when authorized
        bail!("No credential is configured");
      }
      Some(c) => c,
    };

    {
      credential.refresh(globals).await?;
      *self.credential.write().await = Some(credential);
    }
    Ok(())
  }
}
