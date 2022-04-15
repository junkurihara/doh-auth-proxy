use crate::{
  counter::CounterType,
  error::*,
  globals::{Globals, GlobalsRW},
  log::*,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
  net::UdpSocket,
  sync::{mpsc, RwLock},
  time::Duration,
};

#[derive(Clone)]
pub struct UDPServer {
  pub globals: Arc<Globals>,
  pub globals_rw: Arc<RwLock<GlobalsRW>>,
}

impl UDPServer {
  async fn serve_query(
    self,
    packet_buf: Vec<u8>,
    src_addr: std::net::SocketAddr,
    res_sender: mpsc::Sender<(Vec<u8>, std::net::SocketAddr)>,
  ) -> Result<()> {
    let self_clone = self.clone();
    let globals_rw = self_clone.globals_rw.read().await;
    let doh_client = globals_rw.get_random_client(&self.globals)?;
    let counter = self.globals.counter.clone();

    if counter.increment(CounterType::Udp) >= self.globals.max_connections {
      error!(
        "Too many connections: max = {} (udp+tcp)",
        self.globals.max_connections
      );
      counter.decrement(CounterType::Udp);
      bail!("Too many connections");
    }

    self.globals.runtime_handle.clone().spawn(async move {
      debug!("handle query from {:?}", src_addr);
      let res = tokio::time::timeout(
        self.globals.timeout_sec + Duration::from_secs(1),
        // serve udp dns message here
        doh_client.make_doh_query(&packet_buf, &self.globals, &self.globals_rw),
      )
      .await
      .ok();
      // debug!("response from DoH server: {:?}", res);
      // send response via channel to the dispatch socket
      if let Some(Ok(r)) = res {
        if let Err(e) = res_sender.send((r, src_addr)).await {
          error!("res_sender on channel fail: {:?}", e);
        }
        // else {
        //   debug!("res_sender on channel success"),
        // }
      }
      counter.decrement(CounterType::Udp);
    });

    Ok(())
  }

  async fn respond_to_src(
    self,
    socket_sender: Arc<UdpSocket>,
    mut channel_receiver: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
  ) {
    loop {
      let (bytes, addr) = match channel_receiver.recv().await {
        None => {
          error!("udp channel_receiver.recv()");
          continue;
        }
        Some(res) => res,
      };
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

  pub async fn start(self, listen_address: SocketAddr) -> Result<()> {
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
      loop {
        let (buf_size, src_addr) = match socket_receiver.recv_from(&mut udp_buf).await {
          Err(e) => {
            error!("Error in UDP acceptor: {}", e);
            continue;
          }
          Ok(res) => res,
        };
        let packet_buf = udp_buf[..buf_size].to_vec();
        // too many threads?
        let self_clone = self.clone();
        let channel_sender_clone = channel_sender.clone();
        self.globals.runtime_handle.spawn(async move {
          self_clone
            .serve_query(packet_buf, src_addr, channel_sender_clone)
            .await
        });
      }
    };
    udp_socket_service.await;

    Ok(())
  }
}
