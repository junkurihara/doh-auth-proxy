use super::counter::ConnCounter;
use crate::{doh_client::DoHClient, error::*, globals::Globals, log::*};
use std::{net::SocketAddr, sync::Arc};

/// Proxy object serving UDP and TCP queries
#[derive(Clone)]
pub struct Proxy {
  pub(super) globals: Arc<Globals>,
  pub(super) counter: ConnCounter,
  pub(super) doh_client: Arc<DoHClient>,
  pub(super) listening_on: SocketAddr,
}

impl Proxy {
  /// Create a new proxy object
  pub fn new(globals: Arc<Globals>, listening_on: &SocketAddr, doh_client: &Arc<DoHClient>) -> Self {
    Self {
      globals,
      counter: ConnCounter::default(),
      doh_client: doh_client.clone(),
      listening_on: *listening_on,
    }
  }
  /// Start proxy for single port
  pub async fn start(self) -> Result<()> {
    let term_notify = self.globals.term_notify.clone();
    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = self.clone().start_udp_listener() => {
            warn!("UDP listener service got down");
          }
          _ = self.start_tcp_listener() => {
            warn!("TCP listener service got down");
          }
          _ = term.notified() => {
            info!("Proxy receives term signal");
          }
        }
      }
      None => {
        tokio::select! {
          _ = self.clone().start_udp_listener() => {
            warn!("UDP listener service got down");
          }
          _ = self.start_tcp_listener() => {
            warn!("TCP listener service got down");
          }
        }
      }
    }
    Ok(())
  }
}
