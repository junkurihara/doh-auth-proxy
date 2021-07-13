use crate::errors::DoHError;
use crate::globals::Globals;
use crate::udpserver::UDPServer;
use log::{debug, error, info, warn};
// use std::str;
use std::sync::Arc;
// use std::thread;

#[derive(Debug, Clone)]
pub struct Proxy {
  pub globals: Arc<Globals>,
}

impl Proxy {
  pub async fn entrypoint(self) -> Result<(), DoHError> {
    debug!("Proxy entrypoint");
    info!("Listen address: {:?}", &self.globals.listen_address);
    info!("Target DoH URL: {:?}", &self.globals.doh_target_url);
    if let Some(_) = &self.globals.auth_token {
      info!("Enabled Authorization header in DoH query");
    }

    // TODO: global.bootstrap_dnsを使ったclientの定期更新をspawnして実行する。

    // TODO: definition of error
    // TODO: TCP serverはspawnして別スレッドで待ち受け。別にいらない気もする。

    // UDP socket here
    let udp_server = UDPServer {
      globals: self.globals.clone(),
    };
    udp_server.start().await?;

    Ok(())
  }
}
