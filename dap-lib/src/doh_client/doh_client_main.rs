use crate::{error::*, globals::Globals, http_client::HttpClientInner};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug)]
/// DoH, ODoH, MODoH client
pub struct DoHClient {
  inner: Arc<RwLock<HttpClientInner>>,
}

impl DoHClient {
  /// Create a new DoH client
  pub fn new(inner: Arc<RwLock<HttpClientInner>>) -> Self {
    Self { inner }
  }

  /// Make DoH query
  pub async fn make_doh_query(&self, packet_buf: &[u8], globals: &Arc<Globals>) -> Result<Vec<u8>> {
    Ok(vec![])
  }
}
