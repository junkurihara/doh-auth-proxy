use super::{
  cache::Cache,
  dns_message::{self, Request},
  error::{DohClientError, DohClientResult},
  manipulation::{QueryManipulationResult, QueryManipulators},
  odoh_config_store::ODoHConfigStore,
  path_manage::{DoHPath, DoHPathManager},
  DoHMethod, DoHResponseType, DoHType,
};
use crate::{
  auth::Authenticator,
  globals::Globals,
  http_client::{HttpClientInner, ResolveIpResponse, ResolveIps},
  log::*,
  proxy::ProxyProtocol,
};
use async_trait::async_trait;
use data_encoding::BASE64URL_NOPAD;
use hickory_proto::op::Message;
use reqwest::header::{self, HeaderMap};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

/// DoH, ODoH, MODoH client
pub struct DoHClient {
  /// http client to make doh query
  http_client: Arc<RwLock<HttpClientInner>>,
  /// auth_client to retrieve id token
  auth_client: Option<Arc<Authenticator>>,
  /// path candidates with health flags
  pub(super) path_manager: Arc<DoHPathManager>,
  /// odoh config store
  odoh_configs: Option<Arc<ODoHConfigStore>>,
  /// DNS cache
  pub(super) cache: Arc<Cache>,
  /// DoH type
  doh_type: DoHType,
  /// DoH method
  doh_method: DoHMethod,
  /// base headers
  headers: header::HeaderMap,
  /// runtime handle
  pub(super) runtime_handle: tokio::runtime::Handle,
  /// health check interval
  pub(super) healthcheck_period_sec: tokio::time::Duration,
  /// Query manipulation pulugins
  query_manipulators: Option<QueryManipulators>,
  /// Query logging sender
  query_log_tx: crossbeam_channel::Sender<QueryLoggingBase>,
}

impl DoHClient {
  /// Create a new DoH client
  pub async fn new(
    globals: Arc<Globals>,
    http_client: Arc<RwLock<HttpClientInner>>,
    auth_client: Option<Arc<Authenticator>>,
  ) -> DohClientResult<Self> {
    // 1. build all path candidates from globals
    let path_manager = Arc::new(DoHPathManager::new(&globals)?);

    // 2. spawn odoh config service if odoh or modoh are enabled
    let odoh_configs = match &globals.proxy_config.nexthop_relay_config {
      Some(nexthop_relay_config) => {
        if nexthop_relay_config.odoh_relay_urls.is_empty() {
          return Err(DohClientError::ODoHNoRelayUrl);
        }
        let odoh_configs = Arc::new(ODoHConfigStore::new(http_client.clone(), &path_manager.targets()).await?);
        let odoh_config_clone = odoh_configs.clone();
        let term_notify = globals.term_notify.clone();
        globals
          .runtime_handle
          .spawn(async move { odoh_config_clone.start_service(term_notify).await });
        Some(odoh_configs)
      }
      None => None,
    };

    // doh type
    let doh_type = match &globals.proxy_config.nexthop_relay_config {
      Some(nexthop_relay_config) => {
        if nexthop_relay_config.odoh_relay_urls.is_empty() {
          DoHType::Standard
        } else {
          DoHType::Oblivious
        }
      }
      None => DoHType::Standard,
    };
    // base headers except for authorization
    let mut headers = header::HeaderMap::new();
    let ct = doh_type.as_str();
    headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
    headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());
    if let DoHType::Oblivious = doh_type {
      headers.insert("Cache-Control", header::HeaderValue::from_str("no-cache, no-store").unwrap());
    }

    // doh method
    let doh_method = match doh_type {
      DoHType::Standard => {
        if globals.proxy_config.target_config.use_get {
          DoHMethod::Get
        } else {
          DoHMethod::Post
        }
      }
      DoHType::Oblivious => DoHMethod::Post,
    };

    // cache
    let cache = Arc::new(Cache::new(globals.proxy_config.max_cache_size));

    // runtime handle
    let runtime_handle = globals.runtime_handle.clone();

    // health check period
    let healthcheck_period_sec = globals.proxy_config.healthcheck_period_sec;

    // query manipulators
    let query_manipulators: Option<QueryManipulators> = if let Some(q) = &globals.proxy_config.query_manipulation_config {
      q.as_ref().try_into().ok()
    } else {
      None
    };

    Ok(Self {
      http_client,
      auth_client,
      path_manager,
      odoh_configs,
      cache,
      doh_type,
      doh_method,
      headers,
      runtime_handle,
      healthcheck_period_sec,
      query_manipulators,
      query_log_tx: globals.query_log_tx.clone(),
    })
  }

  /// Log DNS message
  fn log_dns_message(
    &self,
    raw_packet: &[u8],
    proto: ProxyProtocol,
    src_addr: &SocketAddr,
    res_type: DoHResponseType,
    dst_path: Option<Arc<DoHPath>>,
    start: std::time::Instant,
  ) {
    let elapsed = start.elapsed();
    let Ok(dst_url) = dst_path.map(|p| p.as_url()).transpose() else {
      error!("Failed to get destination url from path");
      return;
    };
    if let Err(e) = self.query_log_tx.send(QueryLoggingBase::from((
      raw_packet.to_vec(),
      proto,
      src_addr.ip(),
      res_type,
      dst_url,
      elapsed,
    ))) {
      error!("Failed to send qeery log message: {e}")
    }
  }

  /// Make DoH query with intended automatic path selection.
  /// Also cache and plugins are enabled
  pub async fn make_doh_query(&self, packet_buf: &[u8], proto: ProxyProtocol, src: &SocketAddr) -> DohClientResult<Vec<u8>> {
    let start = std::time::Instant::now();

    // Check if the given packet buffer is consistent as a DNS query
    let query_msg = dns_message::is_query(packet_buf).map_err(|e| {
      error!("{e}");
      DohClientError::InvalidDnsQuery
    })?;
    // TODO: If error, should we build and return a synthetic reject response message?
    let query_id = query_msg.id();
    let req = Request::try_from(&query_msg).map_err(|e| {
      error!("Failed to parse DNS query, maybe invalid DNS query: {e}");
      DohClientError::InvalidDnsQuery
    })?;

    // Process query plugins from the beginning of vec, e.g., domain filtering, cloaking, etc.
    if let Some(manipulators) = &self.query_manipulators {
      let execution_result = manipulators.apply(&query_msg, &req.0[0]).await?;
      match execution_result {
        QueryManipulationResult::PassThrough => (),
        QueryManipulationResult::SyntheticResponseBlocked(response_msg) => {
          let res = dns_message::encode(&response_msg)?;
          self.log_dns_message(&res, proto, src, DoHResponseType::Blocked, None, start);
          return Ok(res);
        }
        QueryManipulationResult::SyntheticResponseOverridden(response_msg) => {
          let res = dns_message::encode(&response_msg)?;
          self.log_dns_message(&res, proto, src, DoHResponseType::Overridden, None, start);
          return Ok(res);
        }
      }
    }

    // Check cache and return if hit
    if let Some(res) = self.cache.get(&req).await {
      debug!("Cache hit!: {:?}", res.message().queries());
      if let Ok(response_buf) = res.build_response(query_id) {
        self.log_dns_message(&response_buf, proto, src, DoHResponseType::Cached, None, start);
        return Ok(response_buf);
      } else {
        error!("Cached object is somewhat invalid");
      }
    }

    // choose path
    let Some(path) = self.path_manager.get_path() else {
      return Err(DohClientError::NoPathAvailable);
    };

    // make doh query with the given path
    let (response_buf, response_message) = self.make_doh_query_inner(packet_buf, &path).await?;

    self.log_dns_message(&response_buf, proto, src, DoHResponseType::Normal, Some(path), start);

    // put message to cache
    if (self.cache.put(req, &response_message).await).is_err() {
      error!("Failed to cache a DNS response");
    };

    // should rebuild buffer from decoded dns response_msg? -> no need to do that.
    Ok(response_buf)
  }

  /// Make DoH query with a specifically given path.
  /// Note cache and plugins are disabled to be used for health check
  pub(super) async fn make_doh_query_inner(&self, packet_buf: &[u8], path: &Arc<DoHPath>) -> DohClientResult<(Vec<u8>, Message)> {
    let headers = self.build_headers().await?;
    let response_buf = match self.doh_type {
      DoHType::Standard => self.serve_doh_query(packet_buf, path, headers).await,
      DoHType::Oblivious => self.serve_oblivious_doh_query(packet_buf, path, headers).await,
    }?;
    // Check if the returned packet buffer is consistent as a DNS response
    // TODO: If error, should we build and return a synthetic reject response message?
    let response_message = dns_message::is_response(&response_buf).map_err(|e| {
      error!("{e}");
      DohClientError::InvalidDnsResponse
    })?;
    Ok((response_buf, response_message))
  }

  //// build headers for doh and odoh query with authorization if needed
  async fn build_headers(&self) -> DohClientResult<header::HeaderMap> {
    let mut headers = self.headers.clone();
    match &self.auth_client {
      Some(auth) => {
        debug!("build headers with http authorization header");
        let token = auth.bearer_token().await?;
        let token_str = format!("Bearer {}", &token);
        headers.insert(header::AUTHORIZATION, header::HeaderValue::from_str(&token_str).unwrap());
        Ok(headers)
      }
      None => Ok(headers),
    }
  }

  /// serve doh query
  async fn serve_doh_query(&self, packet_buf: &[u8], target_url: &Arc<DoHPath>, headers: HeaderMap) -> DohClientResult<Vec<u8>> {
    let target_url = target_url.as_url()?;
    debug!("[DoH] target url: {}", target_url.as_str());

    let response = match &self.doh_method {
      DoHMethod::Get => {
        let query_b64u = BASE64URL_NOPAD.encode(packet_buf);
        let query_url = format!("{}?dns={}", target_url.as_str(), query_b64u);
        // debug!("query url: {:?}", query_url);
        let lock = self.http_client.read().await;
        lock.get(query_url).headers(headers).send().await?
      }
      DoHMethod::Post => {
        let lock = self.http_client.read().await;
        lock
          .post(target_url)
          .headers(headers)
          .body(packet_buf.to_owned())
          .send()
          .await?
      }
    };

    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      return Err(DohClientError::DoHQueryError);
    }

    let body = response.bytes().await?;
    Ok(body.to_vec())
  }

  /// serve oblivious doh query
  async fn serve_oblivious_doh_query(
    &self,
    packet_buf: &[u8],
    odoh_path: &Arc<DoHPath>,
    headers: HeaderMap,
  ) -> DohClientResult<Vec<u8>> {
    let target_obj = odoh_path.target();
    let path_url = odoh_path.as_url()?;
    debug!("[ODoH] target url: {}", path_url.as_str());

    // odoh config
    if self.odoh_configs.is_none() {
      return Err(DohClientError::ODoHNoClientConfig);
    }
    let Some(odoh_config) = self.odoh_configs.as_ref().unwrap().get(target_obj).await else {
      return Err(DohClientError::ODoHNoClientConfig);
    };
    let Some(odoh_config) = odoh_config.as_ref() else {
      return Err(DohClientError::ODoHNoClientConfig);
    };

    // encrypt query
    let (odoh_plaintext_query, encrypted_query_body, secret) = odoh_config.encrypt_query(packet_buf)?;

    let response = match &self.doh_method {
      DoHMethod::Get => {
        return Err(DohClientError::ODoHGetNotAllowed);
      }
      DoHMethod::Post => {
        let lock = self.http_client.read().await;
        lock.post(path_url).headers(headers).body(encrypted_query_body).send().await?
      }
    };

    // 401 or len=0 when 200, update doh client with renewed public key
    // workaround related to reqwest-0.12, which returns always None with response.content_length()
    let Some(content_length) = response
      .headers()
      .get("content-length")
      .and_then(|v| v.to_str().map(|s| s.parse::<u16>().ok()).ok().flatten())
    else {
      return Err(DohClientError::ODoHInvalidContentLength);
    };
    if response.status() == reqwest::StatusCode::UNAUTHORIZED
      || (response.status() == reqwest::StatusCode::OK && content_length == 0)
    {
      warn!("ODoH public key might be expired. Refetch.");
      self
        .odoh_configs
        .as_ref()
        .unwrap()
        .update_odoh_config_from_well_known()
        .await?;
    }
    if response.status() != reqwest::StatusCode::OK {
      error!("DoH query error!: {:?}", response.status());
      return Err(DohClientError::DoHQueryError);
    }

    let body = response.bytes().await?;
    let dec_bytes = odoh_config.decrypt_response(&odoh_plaintext_query, &body, secret)?;

    Ok(dec_bytes.to_vec())
  }
}

// ResolveIps for DoHClient
#[async_trait]
impl ResolveIps for Arc<DoHClient> {
  type Error = DohClientError;
  /// Resolve ip addresses of the given domain name
  async fn resolve_ips(&self, target_url: &Url) -> DohClientResult<ResolveIpResponse> {
    let host_str = match target_url.host() {
      Some(url::Host::Domain(host_str)) => host_str,
      _ => {
        return Err(DohClientError::FailedToResolveIpsForHttpClient);
      }
    };
    let port = target_url
      .port()
      .unwrap_or_else(|| if target_url.scheme() == "https" { 443 } else { 80 });

    let fqdn = format!("{}.", host_str);
    let q_msg = dns_message::build_query_a(&fqdn)?;
    let packet_buf = dns_message::encode(&q_msg)?;
    // choose path
    let Some(path) = self.path_manager.get_path() else {
      return Err(DohClientError::NoPathAvailable);
    };
    // make doh query with the given path
    let (res, _) = self.make_doh_query_inner(&packet_buf, &path).await?;

    if dns_message::is_response(&res).is_err() {
      error!("Invalid response: {fqdn}");
      return Err(DohClientError::InvalidDnsResponse);
    }
    let r_msg = dns_message::decode(&res)?;
    if r_msg.header().response_code() != hickory_proto::op::response_code::ResponseCode::NoError {
      error!("erroneous response: {fqdn} {}", r_msg.header().response_code());
      return Err(DohClientError::FailedToResolveIpsForHttpClient);
    }
    let answers = r_msg.answers().to_vec();
    if answers.is_empty() {
      error!("answer is empty: {fqdn}");
      return Err(DohClientError::FailedToResolveIpsForHttpClient);
    }
    let rdata = answers.iter().map(|a| a.data());
    let addrs = rdata
      .flatten()
      .filter_map(|r| r.as_a())
      .filter_map(|a| format!("{}:{}", a, port).parse::<SocketAddr>().ok())
      .collect::<Vec<_>>();
    if addrs.is_empty() {
      error!("addrs is empty: {fqdn}");
      return Err(DohClientError::FailedToResolveIpsForHttpClient);
    }
    debug!("resolved endpoint ip by DoHClient for {:?}: {:?}", fqdn, addrs);
    Ok(ResolveIpResponse {
      hostname: host_str.to_string(),
      addresses: addrs,
    })
  }
}
