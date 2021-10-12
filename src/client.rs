use crate::constants::*;
use crate::error::*;
use crate::dns_message;
use crate::globals::{Globals, GlobalsCache};
use crate::http_bootstrap::HttpClient;
use crate::log::*;
use crate::odoh::ODoHClientContext;
use data_encoding::BASE64URL_NOPAD;
use reqwest::header;
use std::any::Any;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;
use urlencoding::decode;

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
        debug!("ODoH is enabled: relay {}", u);
        // Sample: "https://odoh1.surfdomeinen.nl/proxy?targethost=odoh.cloudflare-dns.com&targetpath=/dns-query"
        let relay_url = Url::parse(u)?;
        let relay_scheme = relay_url.scheme();
        let relay_host_str = match relay_url.port() {
          Some(port) => format!("{}:{}", relay_url.host_str().unwrap(), port),
          None => relay_url.host_str().unwrap().to_string(),
        };
        let relay_path_str = relay_url.path();
        let base = format!("{}://{}{}", relay_scheme, relay_host_str, relay_path_str);

        let target_url = Url::parse(&globals.doh_target_url)?;
        let target_host_str = match target_url.port() {
          Some(port) => format!("{}:{}", target_url.host_str().unwrap(), port),
          None => target_url.host_str().unwrap().to_string(),
        };
        let mut qs = HashMap::new();
        qs.insert("targethost", target_host_str);
        qs.insert("targetpath", target_url.path().to_string());

        // TODO: is it okay to remove percent encoding here? it maybe violation of some standard...
        // but in the draft RFC, "/" is not encoded to "%2F".
        // https://datatracker.ietf.org/doc/html/draft-pauly-dprive-oblivious-doh-06
        let combined = decode(Url::parse_with_params(&base, qs)?.as_str())
          .map_err(|e| anyhow!(e))?
          .to_string();

        // TODO: mu-ODNS拡張検討
        //   combined=nexthop_urlについての扱い。
        //   (intermediate_host, intermediate_path) の順序の扱いをどうするか？
        //   randomizedしたpathを作って、vec[combined]を生成するか、
        //   vec[(intermediate_candidates)]を用意して、都度randomized pathを生成してcombinedを作るか。
        (DoHType::Oblivious, combined)
      }
      None => (DoHType::Standard, globals.doh_target_url.clone()),
    };
    info!("Target (O)DoH URL: {}", nexthop_url);

    // build client
    let mut headers = header::HeaderMap::new();
    let ct = doh_type.as_str();
    headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
    headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());
    match doh_type {
      DoHType::Oblivious => {
        headers.insert(
          "Cache-Control",
          header::HeaderValue::from_str("no-cache, no-store").unwrap(),
        );
      }
      _ => (),
    };
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

    // TODO: Ping here to check client-server connection
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
    // fetch public key from odoh target (/.well-known)
    info!("[ODoH] Fetch server public key from {}", ODOH_CONFIG_PATH);
    let url = Url::parse(&globals.doh_target_url)?;
    let scheme = url.scheme(); // already checked at config.rs
    let host_str = match url.port() {
      Some(port) => format!("{}:{}", url.host_str().unwrap(), port),
      None => url.host_str().unwrap().to_string(),
    };

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
    // Check if the given packet buffer is consistent as a DNS query
    match dns_message::is_query(packet_buf){
      Ok(msg) => {
        debug!("Ok as a DNS query");
        debug!("TODO: check cache here for {:?} {:?}", msg.type_id(), msg.id());
      }
      Err(_) => {
        bail!("Invalid or not a DNS query") // Should build and return a synthetic reject response message?
      }
    }

    let response_result = match self.doh_type {
      DoHType::Standard => self.serve_doh_query(packet_buf).await,
      DoHType::Oblivious => {
        self
          .serve_oblivious_doh_query(packet_buf, globals, globals_cache)
          .await
      }
    };

    match response_result {
      Ok(response_buf) => {
        // Check if the returned packet buffer is consistent as a DNS response
        match dns_message::is_response(&response_buf){
          Ok(_msg) => {
            debug!("Ok as a DNS response"); // TODO: should rebuild buffer from decoded dns response _msg?
            Ok(response_buf)
          }
          Err(_) => {
            bail!("Invalid or not a DNS response") // Should build and return a synthetic reject response message?
          }
        }
      }
      Err(e) => Err(e)
    }

  }

  async fn serve_doh_query(&self, packet_buf: &Vec<u8>) -> Result<Vec<u8>, Error> {
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
