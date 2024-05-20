pub use tracing::{debug, error, info, warn};

use crate::{
  constants::{QUERY_LOG_CHANNEL_SIZE, QUERY_LOG_EVENT_NAME},
  doh_client::DoHResponseType,
  proxy::ProxyProtocol,
};
use crossbeam_channel::{Receiver, Sender};
use hickory_proto::op::Message;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Notify;

#[derive(Debug)]
/// Logging base for query-response
pub(crate) struct QueryLoggingBase {
  /// Raw DNS message packet either query or response
  raw_packet: Vec<u8>,
  /// Proxy protocol
  proto: ProxyProtocol,
  /// Source address
  src_addr: IpAddr,
  /// Response type
  res_type: DoHResponseType,
  /// Destination url
  dst_url: Option<url::Url>,
  /// Resolving time
  elapsed: std::time::Duration,
}

impl From<(Vec<u8>, ProxyProtocol, IpAddr, DoHResponseType, Option<url::Url>, Duration)> for QueryLoggingBase {
  fn from(
    (raw_packet, proto, src_addr, res_type, dst_url, elapsed): (
      Vec<u8>,
      ProxyProtocol,
      IpAddr,
      DoHResponseType,
      Option<url::Url>,
      Duration,
    ),
  ) -> Self {
    Self {
      raw_packet,
      proto,
      src_addr,
      res_type,
      dst_url,
      elapsed,
    }
  }
}

impl QueryLoggingBase {
  /// Log the query-response through tracing
  pub fn log(&self) {
    let span = tracing::info_span!(crate::constants::QUERY_LOG_EVENT_NAME);
    let _guard = span.enter();

    let src = self.src_addr.to_string();
    let Ok(message) = Message::from_vec(&self.raw_packet) else {
      error!("Failed to parse message from raw packet");
      return;
    };
    let id = message.id();
    let (qname, qtype, qclass) = message
      .query()
      .map(|q| (q.name().to_string(), q.query_type().to_string(), q.query_class().to_string()))
      .unwrap_or_default();
    let rcode = message.response_code().to_string();
    let proto = self.proto.to_string();
    let dst = match self.res_type {
      DoHResponseType::Blocked => "blocked".to_owned(),
      DoHResponseType::Overridden => "overridden".to_owned(),
      DoHResponseType::Cached => "cached".to_owned(),
      DoHResponseType::Normal => {
        if let Some(dst_url) = &self.dst_url {
          dst_url.to_string()
        } else {
          "unknown".to_string()
        }
      }
    };
    let elapsed_micros = self.elapsed.as_micros();

    tracing::event!(
      name: QUERY_LOG_EVENT_NAME,
      tracing::Level::INFO,
      src,
      qname,
      qtype,
      qclass,
      rcode,
      proto,
      id,
      dst,
      elapsed_micros
    );
  }
}

/// Logger for query-response
pub(crate) struct QueryLogger {
  /// Receiver for message
  query_log_rx: Receiver<QueryLoggingBase>,
  /// Notify for termination for the logger service
  term_notify: Option<Arc<Notify>>,
}

impl QueryLogger {
  /// Create a new instance of QrLogger
  pub(crate) fn new(term_notify: Option<Arc<Notify>>) -> (Sender<QueryLoggingBase>, Self) {
    let (query_log_tx, query_log_rx) = crossbeam_channel::bounded(QUERY_LOG_CHANNEL_SIZE);
    (
      query_log_tx,
      Self {
        query_log_rx,
        term_notify,
      },
    )
  }

  /// Start the logger service
  pub(crate) async fn start(&mut self) {
    let Some(ref term_notify) = self.term_notify else {
      while let Ok(qr_log) = self.query_log_rx.recv() {
        qr_log.log();
      }
      return;
    };

    loop {
      tokio::select! {
        _ = term_notify.notified() => {
          info!("Query logger is terminated via term_notify");
          break;
        }
        Ok(qr_log) = async { self.query_log_rx.recv() } => {
          qr_log.log();
        }
      }
    }
  }
}
