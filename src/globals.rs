use crate::client::{DoHClient, DoHMethod};
use crate::credential::Credential;
use crate::error::*;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio;

#[derive(Debug, Clone)]
pub struct Globals {
  pub listen_addresses: Vec<SocketAddr>,
  pub udp_buffer_size: usize,
  pub udp_channel_capacity: usize,
  pub timeout_sec: Duration,

  pub doh_target_url: String,
  pub doh_method: Option<DoHMethod>,
  pub odoh_relay_url: Option<String>,
  pub bootstrap_dns: SocketAddr,
  pub rebootstrap_period_sec: Duration,

  pub runtime_handle: tokio::runtime::Handle,
}

#[derive(Debug, Clone)]
pub struct GlobalsCache {
  pub doh_client: Option<DoHClient>,
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
      let doh_client = DoHClient::new(globals.clone(), &id_token).await?;
      self.doh_client = Some(doh_client);
    }

    Ok(())
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
      credential.refresh(&globals).await?;
      self.credential = Some(credential);
    }
    Ok(())
  }
}
