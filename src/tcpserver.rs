use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct TCPServer {
  pub globals: Arc<Globals>,
  pub globals_cache: Arc<RwLock<GlobalsCache>>,
}

impl TCPServer {
  async fn serve_query(self, mut stream: TcpStream, src_addr: SocketAddr) -> Result<(), Error> {
    debug!("handle query from {:?}", src_addr);
    let globals_cache = self.globals_cache.read().await;
    let doh_client = match globals_cache.doh_client.clone() {
      Some(x) => x,
      None => bail!("DoH client is not properly configured"),
    };

    // read data from stream
    // first 2bytes indicates the length of dns message following from the 3rd byte
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;
    let msg_length = u16::from_be_bytes(length_buf) as usize;
    ensure!(msg_length > 0, "Null stream");

    let mut packet_buf = vec![0u8; msg_length];
    stream.read_exact(&mut packet_buf).await?;

    // make DoH query
    let res = tokio::time::timeout(
      self.globals.timeout_sec + std::time::Duration::from_secs(1),
      // serve udp dns message here
      doh_client.make_doh_query(&packet_buf, &self.globals, &self.globals_cache),
    )
    .await
    .ok();

    // debug!("response from DoH server: {:?}", res);
    // send response via stream
    if let Some(Ok(r)) = res {
      ensure!(r.len() <= (u16::MAX as usize), "Invalid response size");
      let length_buf = u16::to_be_bytes(r.len() as u16);
      stream.write_all(&length_buf).await?;
      stream.write_all(&r).await?;
    } else {
      bail!("Failed to make a DoH query");
    }
    Ok(())
  }

  pub async fn start(self, listen_address: SocketAddr) -> Result<(), Error> {
    let tcp_listener = TcpListener::bind(&listen_address).await?;
    info!("Listening on TCP: {:?}", tcp_listener.local_addr()?);

    // receive from src
    // TODO: アクティブな同時接続数の管理
    let tcp_listener_service = async {
      loop {
        let (stream, src_addr) = match tcp_listener.accept().await {
          Err(e) => {
            error!("Error in TCP acceptor: {}", e);
            continue;
          }
          Ok(res) => res,
        };
        let self_clone = self.clone();
        self.globals.runtime_handle.spawn(async move {
          if let Err(e) = self_clone.serve_query(stream, src_addr).await {
            error!("Failed to handle query: {:?}", e);
          }
        });
      }
    };
    tcp_listener_service.await;

    Ok(())
  }
}
