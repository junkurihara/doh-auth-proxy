use super::counter::ConnCounter;
use crate::{doh_client::DoHClient, error::*, globals::Globals, log::*};
use futures::future::select;
use std::{net::SocketAddr, sync::Arc};

/// Proxy object serving UDP and TCP queries
#[derive(Clone)]
pub struct Proxy {
  pub(super) globals: Arc<Globals>,
  pub(super) counter: Arc<ConnCounter>,
  pub(super) doh_client: Arc<DoHClient>,
  pub(super) listening_on: SocketAddr,
}

impl Proxy {
  /// Create a new proxy object
  pub fn new(globals: Arc<Globals>, listening_on: &SocketAddr, doh_client: &Arc<DoHClient>) -> Self {
    Self {
      globals,
      counter: Arc::new(ConnCounter::default()),
      doh_client: doh_client.clone(),
      listening_on: *listening_on,
    }
  }
  /// Start proxy for single port
  pub async fn start(self) -> Result<()> {
    let term_notify = self.globals.term_notify.clone();
    let self_clone = self.clone();

    let udp_fut = self.globals.runtime_handle.spawn(async move {
      match term_notify {
        Some(term) => {
          tokio::select! {
            res = self_clone.start_udp_listener() => {
              warn!("UDP listener service got down");
              res
            }
            _ = term.notified() => {
              info!("UDP listener received term signal");
              Ok(())
            }
          }
        }
        None => {
          let res = self_clone.start_udp_listener().await;
          warn!("UDP listener service got down");
          res
        }
      }
    });

    let self_clone = self.clone();
    let term_notify = self.globals.term_notify.clone();
    let tcp_fut = self.globals.runtime_handle.spawn(async move {
      match term_notify {
        Some(term) => {
          tokio::select! {
            res = self_clone.start_tcp_listener() => {
              warn!("TCP listener service got down");
              res
            }
            _ = term.notified() => {
              info!("TCP listener received term signal");
              Ok(())
            }
          }
        }
        None => {
          let res = self_clone.start_tcp_listener().await;
          warn!("TCP listener service got down");
          res
        }
      }
    });

    // If something goes wrong in any of the futures, we will return the error
    let Ok(Ok(_)) = select(udp_fut, tcp_fut).await.factor_first().0 else {
      return Err(Error::ProxyServiceError("UDP or TCP listener failed".to_string()));
    };

    Ok(())
  }
}
