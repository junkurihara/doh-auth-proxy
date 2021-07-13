use crate::errors::DoHError;
use data_encoding::BASE64URL_NOPAD;
use log::{debug, error, info, warn};
use reqwest;
use reqwest::header;
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
  pub fn new(
    token: Option<String>,
    method: Option<DoHMethod>,
    timeout_sec: u64,
  ) -> Result<Self, DoHError> {
    let timeout_duration = Duration::from_secs(timeout_sec);

    let headers: header::HeaderMap = match token {
      None => get_default_header(),
      Some(t) => {
        info!("Set DoH client with http authorization header");
        let mut temporary_header = get_default_header();
        let token_str = format!("Bearer {}", &t);
        temporary_header.insert(
          header::AUTHORIZATION,
          header::HeaderValue::from_str(&token_str).unwrap(),
        );
        temporary_header
      }
    };

    let doh_method = match method {
      None => DoHMethod::POST,
      Some(t) => t,
    };
    Ok(DoHClient {
      client: reqwest::Client::builder()
        .timeout(timeout_duration)
        .default_headers(headers)
        .user_agent(format!("doh-auth/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .unwrap(),
      method: doh_method,
    })
  }

  pub async fn make_doh_query(
    self,
    packet_buf: Vec<u8>,
    src_addr: std::net::SocketAddr,
    resolver_url: &str,
  ) -> Result<Vec<u8>, DoHError> {
    // TODO: メッセージバッファの中身を一切確認していない。DNSメッセージの体裁を取っているか確認すべき？
    let response = match self.method {
      DoHMethod::GET => {
        let query_b64u = BASE64URL_NOPAD.encode(&packet_buf);
        let query_url = format!("{}?dns={}", resolver_url, query_b64u);
        debug!("query url: {:?}", query_url);
        self
          .client
          .get(query_url)
          .send()
          .await
          .map_err(DoHError::Reqwest)?
      }
      DoHMethod::POST => self
        .client
        .post(resolver_url) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
        .body(packet_buf)
        .send()
        .await
        .map_err(DoHError::Reqwest)?,
    };

    debug!("src address: {:?}", src_addr);
    // debug!("response: {:?}", response);

    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      return Err(DoHError::StatusCode(response.status()));
    }

    let body = response.bytes().await.map_err(DoHError::Reqwest)?;
    Ok(body.to_vec())
  }
}
