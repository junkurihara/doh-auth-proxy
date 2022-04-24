use crate::{
  cache::CacheObject,
  constants::*,
  dns_message::{self, Request},
  error::*,
  globals::Globals,
  http_bootstrap::HttpClient,
  log::*,
  odoh::ODoHClientContext,
};
use data_encoding::BASE64URL_NOPAD;
use futures::future;
use rand::{
  seq::SliceRandom,
  {thread_rng, Rng},
};
use reqwest::header;
use std::{collections::HashMap, sync::Arc};
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
  Get,
  Post,
}

#[derive(Debug, Clone)]
pub struct DoHClient {
  doh_type: DoHType,
  clients: Vec<HttpClient>, // configured for different relays (if ODoH) with a target
  method: DoHMethod,
  target_url: String,
  odoh_client_context: Option<ODoHClientContext>, // for odoh
}

impl DoHClient {
  pub async fn new(
    target_url_str: &str,
    relay_urls_str: Option<Vec<String>>,
    globals: Arc<Globals>,
    auth_token: &Option<String>,
  ) -> Result<Self> {
    let (doh_type, nexthop_urls) = match &relay_urls_str {
      Some(vect_u) => {
        let mut combined_vect: Vec<String> = Vec::new();
        for u in vect_u.iter() {
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

          let target_url = Url::parse(target_url_str)?;
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
          combined_vect.push(combined)
        }

        (DoHType::Oblivious, combined_vect)
      }
      None => (DoHType::Standard, vec![target_url_str.to_owned()]),
    };
    info!("Target (O)DoH URLs: {:#?}", nexthop_urls);

    // build client
    let mut headers = header::HeaderMap::new();
    let ct = doh_type.as_str();
    headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
    headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());
    if let DoHType::Oblivious = doh_type {
      headers.insert(
        "Cache-Control",
        header::HeaderValue::from_str("no-cache, no-store").unwrap(),
      );
    }

    if let Some(t) = auth_token {
      debug!("Instantiating DoH client with http authorization header");
      let token_str = format!("Bearer {}", &t);
      headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_str(&token_str).unwrap(),
      );
    }

    // When ODoH, nexthop target is the relay specified.
    // For each relay in Vec<String>, clients are configured in order to resolve
    // the relay url by the bootstrap DNS outside this proxy.
    let polls = nexthop_urls
      .iter()
      .map(|nexthop| HttpClient::new(&globals, nexthop, Some(&headers), true))
      .collect::<Vec<_>>();
    let clients = future::join_all(polls)
      .await
      .into_iter()
      .collect::<Result<Vec<_>>>()?;

    let doh_method = globals.doh_method.clone();

    // When ODoH, first fetch configs
    let odoh_client_context = match doh_type {
      DoHType::Oblivious => {
        Some(DoHClient::fetch_odoh_config_from_well_known(target_url_str, &globals).await?)
      }
      DoHType::Standard => None,
    };

    Ok(DoHClient {
      doh_type,
      clients,
      target_url: target_url_str.to_string(),
      method: doh_method,
      odoh_client_context,
    })
  }

  async fn fetch_odoh_config_from_well_known(
    target_url_str: &str,
    globals: &Arc<Globals>,
  ) -> Result<ODoHClientContext> {
    // TODO: Add auth token when fetching config?
    // fetch public key from odoh target (/.well-known)
    let url = Url::parse(target_url_str)?;
    let scheme = url.scheme(); // already checked at config.rs
    let host_str = match url.port() {
      Some(port) => format!("{}:{}", url.host_str().unwrap(), port),
      None => url.host_str().unwrap().to_string(),
    };

    let destination = format!("{}://{}{}", scheme, host_str, ODOH_CONFIG_PATH);
    info!("[ODoH] Fetch server public key from {}", destination);

    let simple_client = HttpClient::new(globals, target_url_str, None, true)
      .await?
      .client;
    let response = simple_client.get(destination).send().await?;
    if response.status() != reqwest::StatusCode::OK {
      error!("Failed to fetch ODoH config!: {:?}", response.status());
      bail!("{:?}", response.status());
    }
    let body = response.bytes().await?.to_vec();
    ODoHClientContext::new(&body)
  }

  pub async fn health_check(&self, globals: &Arc<Globals>) -> Result<()> {
    let q_msg = dns_message::build_query_message_a(HEALTHCHECK_TARGET_FQDN).unwrap();
    let packet_buf = dns_message::encode(&q_msg).unwrap();
    let res = self.make_doh_query(&packet_buf, globals).await?;
    ensure!(
      dns_message::is_response(&res).is_ok(),
      "Not a response in healthcheck for {}",
      self.target_url
    );
    let r_msg = dns_message::decode(&res).unwrap();
    ensure!(
      r_msg.header().response_code() == trust_dns_proto::op::response_code::ResponseCode::NoError,
      "Response is not OK: {:?} for {:?}",
      r_msg.header().response_code(),
      self.target_url
    );
    let answers = r_msg.answers().to_vec();
    ensure!(
      !answers.is_empty(),
      "Response has no answer: {:?} for {}",
      answers,
      self.target_url
    );
    let rdata: Vec<Option<&trust_dns_proto::rr::RData>> =
      answers.iter().map(|a| a.data()).collect();
    ensure!(
      rdata.iter().any(|r| r.is_some() && {
        match r.unwrap() {
          trust_dns_proto::rr::RData::A(a) => a.to_string() == *HEALTHCHECK_TARGET_ADDR,
          _ => false,
        }
      }),
      "Response has no or wrong rdata, maybe suspicious and polluted target: {:?} for {}",
      rdata,
      self.target_url
    );

    Ok(())
  }

  async fn build_response_from_cache(&self, res: CacheObject, query_id: u16) -> Result<Vec<u8>> {
    let mut cached_msg = res.message().to_owned();
    let remained_ttl = res.remained_ttl().as_secs() as u32;
    //TODO: more efficient way to update ttl
    for record in cached_msg.take_answers() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_answer(record);
    }
    for record in cached_msg.take_additionals() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_additional(record);
    }
    for record in cached_msg.take_name_servers() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_name_server(record);
    }
    cached_msg.set_id(query_id);

    dns_message::encode(&cached_msg)
  }

  pub async fn make_doh_query(&self, packet_buf: &[u8], globals: &Arc<Globals>) -> Result<Vec<u8>> {
    // Check if the given packet buffer is consistent as a DNS query
    let (req, query_id) = match dns_message::is_query(packet_buf) {
      Ok(query_message) => {
        debug!("Ok as a DNS query");
        let query_id = query_message.id();
        if let Ok(req) = Request::try_from(&query_message) {
          (req, query_id)
        } else {
          bail!("Not a valid DNS query");
        }
      }
      Err(_) => {
        bail!("Invalid or not a DNS query") // Should build and return a synthetic reject response message?
      }
    };

    // Check cache
    if let Some(res) = globals.cache.get(&req).await {
      debug!("Cache hit!: {:?}", res.message().queries());
      if let Ok(response_buf) = self.build_response_from_cache(res, query_id).await {
        return Ok(response_buf);
      } else {
        error!("Cached object is somewhat invalid");
      }
    }

    let response_result = match self.doh_type {
      DoHType::Standard => self.serve_doh_query(packet_buf).await,
      DoHType::Oblivious => self.serve_oblivious_doh_query(packet_buf, globals).await,
    };

    match response_result {
      Ok(response_buf) => {
        // Check if the returned packet buffer is consistent as a DNS response
        match dns_message::is_response(&response_buf) {
          Ok(response_message) => {
            debug!("Ok as a DNS response");
            if (globals.cache.put(req, &response_message).await).is_err() {
              error!("Failed to cache response");
            };
            // TODO: should rebuild buffer from decoded dns response _msg?
            Ok(response_buf)
          }
          Err(_) => {
            bail!("Invalid or not a DNS response") // Should build and return a synthetic reject response message?
          }
        }
      }
      Err(e) => Err(e),
    }
  }

  async fn serve_doh_query(&self, packet_buf: &[u8]) -> Result<Vec<u8>> {
    assert_eq!(self.clients.len(), 1);
    let response = match self.method {
      DoHMethod::Get => {
        let query_b64u = BASE64URL_NOPAD.encode(packet_buf);
        let query_url = format!("{}?dns={}", &self.target_url, query_b64u);
        debug!("query url: {:?}", query_url);
        self.clients[0].client.get(query_url).send().await?
      }
      DoHMethod::Post => {
        self.clients[0]
          .client
          .post(&self.target_url) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
          .body(packet_buf.to_owned())
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
    packet_buf: &[u8],
    globals: &Arc<Globals>,
  ) -> Result<Vec<u8>> {
    assert!(globals.odoh_relay_urls.is_some() && !self.clients.is_empty());

    let client_ctx = match &self.odoh_client_context {
      Some(client_ctx) => client_ctx,
      None => bail!("[ODoH] ODoH client context is not configured"),
    };
    let encrypted_query_secret = client_ctx.encrypt_query(packet_buf);
    let (odoh_plaintext_query, encrypted_query_body, secret) = match encrypted_query_secret {
      Ok((p, q, s)) => (p, q, s),
      Err(e) => bail!("[ODoH] Failed to encrypt!: {}", e),
    };

    let mid_relay_str = if let Some(s) = self.get_randomized_mid_relay_str(globals) {
      s
    } else {
      "".to_string()
    };

    // nexthop relay randomization
    let relay_idx = if globals.odoh_relay_randomization {
      let mut rng = rand::thread_rng();
      rng.gen::<usize>() % self.clients.len()
    } else {
      0
    };
    let combined_endpoint = format!("{}{}", &self.clients[relay_idx].endpoint, mid_relay_str);

    let response = match self.method {
      DoHMethod::Get => {
        let query_b64u = BASE64URL_NOPAD.encode(&encrypted_query_body);
        let query_url = format!("{}?dns={}", combined_endpoint, query_b64u);
        debug!("query url: {:?}", query_url);
        self.clients[relay_idx].client.get(query_url).send().await?
      }
      DoHMethod::Post => {
        self.clients[relay_idx]
          .client
          .post(&combined_endpoint) // TODO: bootstrap resolver must be used to get resolver_url, maybe hyper is better?
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
      globals.update_doh_client().await?;
    }
    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      bail!("{:?}", response.status());
    }

    let body = response.bytes().await?;
    let dec_bytes = client_ctx.decrypt_response(&odoh_plaintext_query, &body, secret)?;

    Ok(dec_bytes.to_vec())
  }

  fn get_randomized_mid_relay_str(&self, globals: &Arc<Globals>) -> Option<String> {
    // add randomized order of mu-ODoH intermediate relays
    let mut mid_relay_str = "".to_string();
    let max_mid_relays = &globals.max_mid_relays;
    if let Some(mid_relay_urls) = &globals.mid_relay_urls {
      if mid_relay_urls.is_empty() {
        return None;
      }
      let mut copied = mid_relay_urls.clone();
      let mut rng = thread_rng();
      copied.shuffle(&mut rng);
      let num = rng.gen_range(1..*max_mid_relays + 1);
      for idx in 0..num {
        let rurl = Url::parse(&copied[idx as usize]).unwrap();
        let rhost_str = match rurl.port() {
          Some(port) => format!("{}:{}", rurl.host_str().unwrap(), port),
          None => rurl.host_str().unwrap().to_string(),
        };
        let rpath_str = rurl.path().to_string();
        mid_relay_str = format!(
          "{}&relayhost[{}]={}&relaypath[{}]={}",
          mid_relay_str, idx, rhost_str, idx, rpath_str
        );
      }
      Some(mid_relay_str)
    } else {
      None
    }
  }
}
