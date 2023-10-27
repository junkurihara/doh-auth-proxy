use super::{counter::CounterType, proxy_main::Proxy, socket::bind_udp_socket};
use crate::{error::*, log::*};
use std::{
  net::{SocketAddr, UdpSocket},
  sync::Arc,
};
use tokio::{
  sync::{mpsc, Notify},
  time::Duration,
};

impl Proxy {
  /// Start UDP listener
  pub async fn start_udp_listener(&self) -> Result<()> {
    // setup a channel for sending out responses
    let (channel_sender, channel_receiver) =
      mpsc::channel::<(Vec<u8>, SocketAddr)>(self.globals.proxy_config.udp_channel_capacity);

    let udp_socket = bind_udp_socket(&self.listening_on)?;
    info!("Listening on UDP: {:?}", udp_socket.local_addr()?);

    let socket_sender = Arc::new(udp_socket);
    let socket_receiver = socket_sender.clone();

    // create sender thread that sends out response given through channel
    self.globals.runtime_handle.spawn(Self::udp_responder_service(
      socket_sender,
      channel_receiver,
      self.globals.term_notify.clone(),
    ));

    // Setup buffer
    let mut udp_buf = vec![0u8; self.globals.proxy_config.udp_buffer_size];

    // receive from src
    let udp_socket_service = async {
      loop {
        let (buf_size, src_addr) = match socket_receiver.recv_from(&mut udp_buf) {
          Err(e) => {
            error!("Error in UDP listener: {}", e);
            continue;
          }
          Ok(res) => res,
        };

        let packet_buf = udp_buf[..buf_size].to_vec();
        let self_clone = self.clone();
        let channel_sender_clone = channel_sender.clone();
        self.globals.runtime_handle.spawn(async move {
          if let Err(e) = self_clone
            .serve_udp_query(packet_buf, src_addr, channel_sender_clone)
            .await
          {
            error!("Failed to handle UDP query: {}", e);
          }
        });
      }
    };
    udp_socket_service.await;

    Ok(())
  }

  /// Send response to source client
  async fn udp_responder_service(
    socket_sender: Arc<UdpSocket>,
    mut channel_receiver: mpsc::Receiver<(Vec<u8>, std::net::SocketAddr)>,
    term_notify: Option<Arc<Notify>>,
  ) {
    let service = async {
      loop {
        let (bytes, addr) = match channel_receiver.recv().await {
          None => {
            error!("udp channel_receiver.recv()");
            continue;
          }
          Some(res) => res,
        };
        match &socket_sender.send_to(&bytes, addr) {
          Ok(len) => {
            debug!("send_to source with response of {:?} bytes", len);
          }
          Err(e) => {
            error!("send_to error: {:?}", e);
          }
        };
      }
    };

    match term_notify {
      Some(term) => {
        tokio::select! {
          _ = service => {
            warn!("Udp responder service got down");
          }
          _ = term.notified() => {
            info!("Udp responder service receives term signal");
          }
        }
      }
      None => {
        service.await;
        warn!("Udp responder service got down");
      }
    }
  }

  /// Serve UDP query from source client
  async fn serve_udp_query(
    self,
    packet_buf: Vec<u8>,
    src_addr: SocketAddr,
    res_sender: mpsc::Sender<(Vec<u8>, SocketAddr)>,
  ) -> Result<()> {
    debug!("handle udp query from {:?}", src_addr);
    let counter = self.counter.clone();
    if counter.increment(CounterType::Udp) >= self.globals.proxy_config.max_connections {
      error!(
        "Too many connections: max = {} (udp+tcp)",
        self.globals.proxy_config.max_connections
      );
      counter.decrement(CounterType::Udp);
      return Err(DapError::TooManyConnections);
    }

    // self.globals.runtime_handle.clone().spawn(async move {
    let res = tokio::time::timeout(
      self.globals.proxy_config.http_timeout_sec + Duration::from_secs(1),
      // serve udp dns message here
      self.doh_client.make_doh_query(&packet_buf),
    )
    .await
    .ok();
    // debug!("response from DoH server: {:?}", res);

    // send response via channel to the dispatch socket
    if let Some(Ok(r)) = res {
      if let Err(e) = res_sender.send((r, src_addr)).await {
        error!("res_sender on channel fail: {:?}", e);
        return Err(DapError::UdpChannelSendError(e));
      }
    } else {
      return Err(DapError::FailedToMakeDohQuery);
    }
    counter.decrement(CounterType::Udp);
    // });

    Ok(())
  }
}
