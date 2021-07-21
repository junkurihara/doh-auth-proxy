use crate::bootstrap::resolve_by_bootstrap;
use crate::error::*;
use crate::globals::Globals;
use data_encoding::BASE64URL_NOPAD;
use log::{debug, error, info, warn};
use reqwest;
use reqwest::header;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum DoHMethod {
  GET,
  POST,
}

#[derive(Debug, Clone)]
pub struct DoHClient {
  client: reqwest::Client,
  method: DoHMethod,
  bootstrap_dns: SocketAddr,
  target_url: String,
}

fn get_default_header() -> header::HeaderMap {
  let mut headers = header::HeaderMap::new();
  headers.insert(
    "Accept",
    header::HeaderValue::from_static("application/dns-message"),
  );
  headers.insert(
    "Content-Type",
    header::HeaderValue::from_static("application/dns-message"),
  );
  headers
}

impl DoHClient {
  pub async fn new(globals: Arc<Globals>) -> Result<(Self, Vec<SocketAddr>), Error> {
    let timeout_duration = Duration::from_secs(globals.doh_timeout_sec);

    let headers: header::HeaderMap = match globals.auth_token.clone() {
      None => get_default_header(),
      Some(t) => {
        info!("Instantiating DoH client with http authorization header");
        let mut temporary_header = get_default_header();
        let token_str = format!("Bearer {}", &t);
        temporary_header.insert(
          header::AUTHORIZATION,
          header::HeaderValue::from_str(&token_str).unwrap(),
        );
        temporary_header
      }
    };

    let doh_method = match globals.doh_method.clone() {
      None => DoHMethod::POST,
      Some(t) => t,
    };

    // TODO:
    let (target_host_str, target_addresses) = resolve_by_bootstrap(
      &globals.bootstrap_dns,
      &globals.doh_target_url,
      globals.runtime_handle.clone(),
    )
    .await?;
    info!(
      "Via bootstrap DNS [{:?}], {:?} updated: {:?}",
      globals.bootstrap_dns, target_host_str, target_addresses
    );
    let target_addr = target_addresses[0].clone();

    // TODO: target addressが複数あった時の対応

    Ok((
      DoHClient {
        client: reqwest::Client::builder()
          .timeout(timeout_duration)
          .default_headers(headers)
          .user_agent(format!("doh-auth/{}", env!("CARGO_PKG_VERSION")))
          .resolve(&target_host_str, target_addr)
          .trust_dns(true)
          .build()
          .unwrap(),
        method: doh_method,
        bootstrap_dns: globals.bootstrap_dns,
        target_url: globals.doh_target_url.clone(),
      },
      target_addresses,
    ))
  }

  pub async fn make_doh_query(self, packet_buf: Vec<u8>) -> Result<Vec<u8>, Error> {
    // TODO: メッセージバッファの中身を一切確認していない。DNSメッセージの体裁を取っているか確認すべき？
    let response = match self.method {
      DoHMethod::GET => {
        let query_b64u = BASE64URL_NOPAD.encode(&packet_buf);
        let query_url = format!("{}?dns={}", &self.target_url, query_b64u);
        debug!("query url: {:?}", query_url);
        self.client.get(query_url).send().await?
      }
      DoHMethod::POST => {
        self
          .client
          .post(&self.target_url) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
          .body(packet_buf)
          .send()
          .await?
      }
    };

    // debug!("src address: {:?}", src_addr);
    // debug!("response: {:?}", response);

    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      bail!("{:?}", response.status());
    }

    let body = response.bytes().await?;
    Ok(body.to_vec())
  }
}
