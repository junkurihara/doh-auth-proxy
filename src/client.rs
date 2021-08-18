use crate::constants::*;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::http_bootstrap::HttpClient;
use crate::odoh::ODoHClientContext;
use data_encoding::BASE64URL_NOPAD;
use log::{debug, error, info, warn};
use reqwest::header;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

#[derive(Debug, Clone)]
pub enum DoHType {
  Standard,
  Oblivious,
}

impl DoHType {
  fn as_str(&self) -> String {
    match self {
      DoHType::Standard => String::from("application/dns-message"),
      DoHType::Oblivious => String::from("application/oblivious-dns-message"),
    }
  }
}

#[derive(Debug, Clone)]
pub enum DoHMethod {
  GET,
  POST,
}

#[derive(Debug, Clone)]
pub struct DoHClient {
  doh_type: DoHType,
  client: reqwest::Client,
  method: DoHMethod,
  bootstrap_dns: SocketAddr,
  nexthop_url: String, // target for DoH, relay for ODoH
  odoh_client_context: Option<ODoHClientContext>, // for odoh
}

impl DoHClient {
  pub async fn new(globals: Arc<Globals>, auth_token: &Option<String>) -> Result<Self, Error> {
    let (doh_type, nexthop_url) = match &globals.odoh_relay_url {
      Some(u) => {
        info!("ODoH is enabled: relay {}", u);
        let relay_url = Url::parse(u)?;
        let relay_scheme = relay_url.scheme();
        let relay_host_str = relay_url.host_str().unwrap();
        let relay_path_str = relay_url.path();
        let target_url = Url::parse(&globals.doh_target_url)?;
        let target_host_str = target_url.host_str().unwrap();
        let target_path_str = target_url.path();
        (
          DoHType::Oblivious,
          // TODO: mu-ODNSへ拡張するならばいじるのはこの部分だけ
          format!(
            "{}://{}{}?targethost={}&targetpath={}",
            relay_scheme, relay_host_str, relay_path_str, target_host_str, target_path_str
          ),
          // "https://odoh1.surfdomeinen.nl/proxy?targethost=odoh.cloudflare-dns.com&targetpath=/dns-query".to_string()
        )
      }
      None => (DoHType::Standard, globals.doh_target_url.clone()),
    };

    // build client
    let mut headers = header::HeaderMap::new();
    let ct = doh_type.as_str();
    headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
    headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());
    if let Some(t) = auth_token {
      debug!("Instantiating DoH client with http authorization header");
      let token_str = format!("Bearer {}", &t);
      headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&token_str).unwrap(),
      );
    }

    // When ODoH, nexthop target is the relay specified.
    let client = HttpClient::new(&globals, Some(&nexthop_url), Some(&headers))
      .await?
      .client;

    let doh_method = match globals.doh_method.clone() {
      None => DoHMethod::POST,
      Some(t) => t,
    };

    // When ODoH, first fetch configs
    let odoh_client_context = match doh_type {
      DoHType::Oblivious => Some(DoHClient::fetch_odoh_config_from_well_known(&globals).await?),
      DoHType::Standard => None,
    };
    // println!("{:#?}", odoh_client_context);

    Ok(DoHClient {
      doh_type,
      client,
      method: doh_method,
      bootstrap_dns: globals.bootstrap_dns,
      nexthop_url,
      odoh_client_context,
    })
  }

  async fn fetch_odoh_config_from_well_known(
    globals: &Arc<Globals>,
  ) -> Result<ODoHClientContext, Error> {
    // TODO: Add auth token when fetching config?
    // fetch public key from odoh target (well-known)
    info!("ODoH: Fetch server public key from {}", ODOH_CONFIG_PATH);
    let url = Url::parse(&globals.doh_target_url)?;
    let scheme = url.scheme(); // already checked at config.rs
    let host_str = url.host_str().unwrap();

    let simple_client = HttpClient::new(&globals, Some(&globals.doh_target_url), None)
      .await?
      .client;
    let response = simple_client
      .get(format!("{}://{}{}", scheme, host_str, ODOH_CONFIG_PATH))
      .send()
      .await?;
    if response.status() != reqwest::StatusCode::OK {
      error!("Failed to fetch ODoH config!: {:?}", response.status());
      bail!("{:?}", response.status());
    }
    let body = response.bytes().await?.to_vec();
    ODoHClientContext::new(&body)
  }

  pub async fn make_doh_query(
    &self,
    packet_buf: &Vec<u8>,
    globals: &Arc<Globals>,
    globals_cache: &Arc<RwLock<GlobalsCache>>,
  ) -> Result<Vec<u8>, Error> {
    match self.doh_type {
      DoHType::Standard => self.serve_doh_query(packet_buf).await,
      DoHType::Oblivious => {
        self
          .serve_oblivious_doh_query(packet_buf, globals, globals_cache)
          .await
      }
    }
  }

  async fn serve_doh_query(&self, packet_buf: &Vec<u8>) -> Result<Vec<u8>, Error> {
    // TODO: メッセージバッファの中身を一切確認していない。DNSメッセージの体裁を取っているか確認すべき？
    let response = match self.method {
      DoHMethod::GET => {
        let query_b64u = BASE64URL_NOPAD.encode(&packet_buf);
        let query_url = format!("{}?dns={}", &self.nexthop_url, query_b64u);
        debug!("query url: {:?}", query_url);
        self.client.get(query_url).send().await?
      }
      DoHMethod::POST => {
        self
          .client
          .post(&self.nexthop_url) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
          .body(packet_buf.clone())
          .send()
          .await?
      }
    };

    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      bail!("{:?}", response.status());
    }

    let body = response.bytes().await?;
    Ok(body.to_vec())
  }

  async fn serve_oblivious_doh_query(
    &self,
    packet_buf: &Vec<u8>,
    globals: &Arc<Globals>,
    globals_cache: &Arc<RwLock<GlobalsCache>>,
  ) -> Result<Vec<u8>, Error> {
    let client_ctx = match &self.odoh_client_context {
      Some(client_ctx) => client_ctx,
      None => bail!("[ODoH] ODoH client context is not configured"),
    };
    let encrypted_query_secret = client_ctx.encrypt_query(packet_buf);
    let (odoh_plaintext_query, encrypted_query_body, secret) = match encrypted_query_secret {
      Ok((p, q, s)) => (p, q, s),
      Err(e) => bail!("[ODoH] Failed to encrypt!: {}", e),
    };

    let response = match self.method {
      DoHMethod::GET => {
        let query_b64u = BASE64URL_NOPAD.encode(&encrypted_query_body);
        let query_url = format!("{}?dns={}", &self.nexthop_url, query_b64u);
        debug!("query url: {:?}", query_url);
        self.client.get(query_url).send().await?
      }
      DoHMethod::POST => {
        self
          .client
          .post(&self.nexthop_url) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
          .body(encrypted_query_body)
          .send()
          .await?
      }
    };

    // 401 or len=0 when 200, update doh client with renewed public key
    let clength = if let Some(l) = response.content_length() {
      l
    } else {
      bail!("Invalid content length");
    };
    if response.status() == reqwest::StatusCode::UNAUTHORIZED
      || (response.status() == reqwest::StatusCode::OK && clength == 0)
    {
      warn!("ODoH public key is expired. Refetch.");
      let mut gc = globals_cache.write().await;
      gc.update_doh_client(&globals).await?;
      drop(gc);
    }
    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      bail!("{:?}", response.status());
    }

    let body = response.bytes().await?;
    let dec_bytes = client_ctx.decrypt_response(&odoh_plaintext_query, &body, secret)?;

    Ok(dec_bytes.to_vec())
  }
}
