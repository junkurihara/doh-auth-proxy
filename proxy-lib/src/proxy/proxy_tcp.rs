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
  pub async fn serve_tcp_query(self, stream: TcpStream, src_addr: SocketAddr) -> Result<()> {
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

    let res = self.serve_tcp_query_inner(stream, src_addr).await;

    // decrement counter anyways
    counter.decrement(CounterType::Tcp);

    res
  }

  /// Serve TCP query inner, supporting connection reuse and pipelining (RFC7766)
  pub async fn serve_tcp_query_inner(self, stream: TcpStream, src_addr: SocketAddr) -> Result<()> {
    // split stream into readable and writeable
    let (mut readable_stream, mut writeable_stream) = stream.into_split();

    /* --------------------------------- */
    // spawn a task to write DoH response to stream
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10);
    self.globals.runtime_handle.spawn(async move {
      if let Err(e) = write_response(&mut writeable_stream, &mut rx).await {
        error!("Failed to write response: {}", e);
      }
    });

    /* --------------------------------- */
    // read query from readable stream
    loop {
      let Ok(res) = tokio::time::timeout(
        self.globals.proxy_config.tcp_idle_timeout_sec,
        read_query(&mut readable_stream),
      )
      .await
      else {
        debug!("TCP idle timeout");
        let _ = tx.send(vec![]).await; // send empty vec to shutdown write task
        break;
      };

      let packet_buf = res?;
      // connection closed for EOF
      if packet_buf.is_empty() {
        let _ = tx.send(vec![]).await; // send empty vec to shutdown write task
        break;
      }

      /* ------- */
      // make doh query
      let tx_clone = tx.clone();
      let self_clone = self.clone();
      self.globals.runtime_handle.spawn(async move {
        let res = tokio::time::timeout(
          self_clone.globals.proxy_config.http_timeout_sec + std::time::Duration::from_secs(1),
          // serve tcp dns message here
          self_clone
            .doh_client
            .make_doh_query(&packet_buf, ProxyProtocol::Tcp, &src_addr),
        )
        .await
        .ok();
        if let Some(Ok(r)) = res {
          let _ = tx_clone.send(r).await;
        } else {
          error!("Failed to make DoH query, shutdown TCP connection");
          let _ = tx_clone.send(vec![]).await; // send empty vec to shutdown write task
        }
      });
      /* ------- */
    }
    /* --------------------------------- */

    Ok(())
  }
}

/// Write response to stream
async fn write_response(
  stream: &mut tokio::net::tcp::OwnedWriteHalf,
  rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
  while let Some(r) = rx.recv().await {
    // if response is empty, connection is closed
    if r.is_empty() {
      break;
    }

    // send response via stream
    if r.len() > (u16::MAX as usize) {
      error!("Response too large: {}", r.len());
      return Err(Error::InvalidDnsResponseSize);
    }
    let length_buf = u16::to_be_bytes(r.len() as u16);
    stream.write_all(&length_buf).await?;
    stream.write_all(&r).await?
  }
  debug!("Finish serving TCP writable stream");
  Ok(())
}

/// Read query from stream, if stream is closed, return empty vec
async fn read_query(stream: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Vec<u8>> {
  // check if stream is closed
  let x = stream.peek(&mut [0u8]).await?;
  if x == 0 {
    debug!("TCP connection closed");
    return Ok(vec![]);
  }

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
  Ok(packet_buf)
}
