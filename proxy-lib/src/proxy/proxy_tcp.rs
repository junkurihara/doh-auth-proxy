use super::{counter::CounterType, proxy_main::Proxy, socket::bind_tcp_socket, ProxyProtocol};
use crate::{error::*, log::*};
use std::net::SocketAddr;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
};

impl Proxy {
  /// Start TCP listener
  pub async fn start_tcp_listener(&self) -> Result<()> {
    let tcp_socket = bind_tcp_socket(&self.listening_on)?;
    let tcp_listener = tcp_socket.listen(self.globals.proxy_config.tcp_listen_backlog)?;
    info!("Listening on TCP: {:?}", tcp_listener.local_addr()?);

    // receive from src
    let tcp_listener_service = async {
      loop {
        let (stream, src_addr) = match tcp_listener.accept().await {
          Err(e) => {
            error!("Error in TCP listener: {}", e);
            continue;
          }
          Ok(res) => res,
        };
        let self_clone = self.clone();
        self.globals.runtime_handle.spawn(async move {
          if let Err(e) = self_clone.serve_tcp_query(stream, src_addr).await {
            error!("Failed to handle TCP query: {}", e);
          }
        });
      }
    };
    tcp_listener_service.await;

    Ok(())
  }

  /// Serve TCP query
  pub async fn serve_tcp_query(self, mut stream: TcpStream, src_addr: SocketAddr) -> Result<()> {
    debug!("handle tcp query from {:?}", src_addr);
    let counter = self.counter.clone();
    if counter.increment(CounterType::Tcp) >= self.globals.proxy_config.max_connections as isize {
      error!(
        "Too many connections: max = {} (udp+tcp)",
        self.globals.proxy_config.max_connections
      );
      counter.decrement(CounterType::Tcp);
      return Err(Error::TooManyConnections);
    }
    // let doh_client = self.context.get_random_client().await?;

    // read data from stream
    // first 2bytes indicates the length of dns message following from the 3rd byte
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;
    let msg_length = u16::from_be_bytes(length_buf) as usize;
    if msg_length == 0 {
      return Err(Error::NullTcpStream);
    }
    let mut packet_buf = vec![0u8; msg_length];
    stream.read_exact(&mut packet_buf).await?;

    // make DoH query
    let res = tokio::time::timeout(
      self.globals.proxy_config.http_timeout_sec + std::time::Duration::from_secs(1),
      // serve tcp dns message here
      self.doh_client.make_doh_query(&packet_buf, ProxyProtocol::Tcp, &src_addr),
    )
    .await
    .ok();
    // debug!("response from DoH server: {:?}", res);

    // send response via stream
    counter.decrement(CounterType::Tcp); // decrement counter anyways

    if let Some(Ok(r)) = res {
      if r.len() > (u16::MAX as usize) {
        return Err(Error::InvalidDnsResponseSize);
      }
      let length_buf = u16::to_be_bytes(r.len() as u16);
      stream.write_all(&length_buf).await?;
      stream.write_all(&r).await?;
    } else {
      return Err(Error::FailedToMakeDohQuery);
    }

    Ok(())
  }
}
