use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

#[derive(Clone)]
pub struct UDPServer {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl UDPServer {
  async fn serve_query(
    self,
    packet_buf: Vec<u8>,
    src_addr: std::net::SocketAddr,
    res_sender: mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
  ) -> Result<(), Error> {
    let self_clone = self.clone();
    let globals_cache = match self_clone.globals_cache.try_read() {
      Ok(g) => g,
      Err(e) => {
        bail!("try_read failed for RwLock {:?}", e);
      }
    };

    let doh_client = globals_cache.doh_client.clone();
    self.globals.runtime_handle.clone().spawn(async move {
      debug!("handle query from {:?}", src_addr);
      let res = tokio::time::timeout(
        self.globals.udp_timeout + Duration::from_secs(1),
        // serve udp dns message here
        doh_client.make_doh_query(packet_buf),
      )
      .await
      .ok();
      // debug!("response from DoH server: {:?}", res);
      // send response via channel to the dispatch socket
      if let Some(Ok(r)) = res {
        match res_sender.send((r, src_addr)).await {
          Err(e) => error!("res_sender on channel fail: {:?}", e),
          Ok(_) => (), // debug!("res_sender on channel success"),
        }
      }
    });

    Ok(())
  }

  async fn respond_to_src(
    self,
    socket_sender: Arc<tokio::net::UdpSocket>,
    mut channel_receiver: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
  ) {
    while let Some((bytes, addr)) = channel_receiver.recv().await {
      // debug!("respond_to_src");
      match &socket_sender.send_to(&bytes, &addr).await {
        Ok(len) => {
          debug!("send_to src with response of {:?} bytes", len);
        }
        Err(e) => {
          error!("send_to error: {:?}", e);
        }
      };
    }
  }

  pub async fn start(self, listen_address: SocketAddr) -> Result<(), Error> {
    // setup a channel for sending out responses
    let (channel_sender, channel_receiver) =
      mpsc::channel::<(Vec<u8>, SocketAddr)>(self.globals.udp_channel_capacity);

    let udp_socket = UdpSocket::bind(&listen_address).await?;
    // .map_err(DoHError::Io)?;
    info!(
      "Listening on UDP: {:?}",
      udp_socket.local_addr()? //.map_err(DoHError::Io)?
    );

    let socket_sender = Arc::new(udp_socket);
    let socket_receiver = socket_sender.clone();
    // create sender thread that sends out response given through channel
    self
      .globals
      .runtime_handle
      .spawn(self.clone().respond_to_src(socket_sender, channel_receiver));

    // Setup buffer
    let mut udp_buf = vec![0u8; self.globals.udp_buffer_size];

    // receive from src
    let udp_socket_service = async {
      while let Ok((buf_size, src_addr)) = socket_receiver.recv_from(&mut udp_buf).await {
        let packet_buf = udp_buf[..buf_size].to_vec();
        // too many threads?
        self.globals.runtime_handle.spawn(self.clone().serve_query(
          packet_buf,
          src_addr,
          channel_sender.clone(),
        ));
      }
      Ok(()) as Result<(), Error>
    };
    udp_socket_service.await?;

    Ok(())
  }
}
