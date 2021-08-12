use crate::bootstrap::resolve_by_bootstrap;
use crate::constants::*;
use crate::error::*;
use crate::globals::Globals;
use chrono::{DateTime, Local};
use jwt_simple::prelude::*;
use log::{debug, error, info, warn};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Credential {
  username: String,
  password: String,
  client_id: String,
  token_api: String,
  id_token: Option<String>,
  refresh_token: Option<String>,
  validation_key: String,
}

impl Credential {
  pub fn new(
    username: &str,
    password: &str, // TODO: This should be called "API key"?
    client_id: &str,
    token_api: &str,
    validation_key: &str,
  ) -> Credential {
    return Credential {
      username: username.to_string(),
      password: password.to_string(),
      client_id: client_id.to_string(),
      token_api: token_api.to_string(),
      id_token: None,
      refresh_token: None,
      validation_key: validation_key.to_string(),
    };
  }

  pub fn id_token(&self) -> Option<String> {
    self.id_token.clone()
  }

  pub async fn login(&mut self, globals: &Arc<Globals>) -> Result<(), Error> {
    // token endpoint is resolved via bootstrap DNS resolver
    let token_endpoint = format!("{}{}", self.token_api, ENDPOINT_LOGIN_PATH);

    let (target_host_str, target_addresses) = resolve_by_bootstrap(
      &globals.bootstrap_dns,
      &token_endpoint,
      globals.runtime_handle.clone(),
    )
    .await?;
    let target_addr = target_addresses[0].clone();
    debug!(
      "Via bootstrap DNS [{:?}], token endpoint {:?} resolved: {:?}",
      &globals.bootstrap_dns, &token_endpoint, &target_addr
    );

    // TODO: maybe define as a struct for strongly typed definition
    let json_request = format!(
      "{{ \"auth\": {{\"username\": \"{}\", \"password\": \"{}\" }}, \"client_id\": \"{}\" }}",
      self.username, self.password, self.client_id
    );

    let client = reqwest::Client::builder()
      .user_agent(format!("doh-auth/{}", env!("CARGO_PKG_VERSION")))
      .resolve(&target_host_str, target_addr)
      .trust_dns(true)
      .build()
      .unwrap();
    let response = client
      .post(&token_endpoint)
      .header(reqwest::header::CONTENT_TYPE, "application/json")
      .body(json_request)
      .send()
      .await?;

    if response.status() != reqwest::StatusCode::OK {
      error!("Login error!: {:?}", response.status());
      bail!("{:?}", response.status());
    }

    // TODO: maybe define as a struct for strongly typed definition
    let text_body = response.text().await?;
    let json_response: serde_json::Value = serde_json::from_str(&text_body)?;
    self.id_token = if let Some(x) = json_response["Access"]["token"]["id"].as_str() {
      Some(x.to_string())
    } else {
      bail!("Invalid Id token format");
    };
    self.refresh_token = if let Some(x) = json_response["Access"]["token"]["refresh"].as_str() {
      Some(x.to_string())
    } else {
      bail!("Invalid refresh token format");
    };
    // check validity of id token
    match self.verify_id_token() {
      Ok(_) => (),
      Err(e) => bail!(
        "Invalid Id token! Carefully check if bootstrap DNS is poisoned! {}",
        e
      ),
    };
    debug!("Logged in: Token endpoint {}", token_endpoint);

    Ok(())
  }

  pub async fn refresh(&mut self, globals: &Arc<Globals>) -> Result<(), Error> {
    // refresh endpoint is resolved via configured system DNS resolver
    let refresh_endpoint = format!("{}{}", self.token_api, ENDPOINT_REFRESH_PATH);
    // let (target_host_str, target_addresses) = resolve_by_bootstrap(
    //   &globals.bootstrap_dns,
    //   &refresh_endpoint,
    //   globals.runtime_handle.clone(),
    // )
    // .await?;
    // let target_addr = target_addresses[0].clone();
    // info!(
    //   "Via bootstrap DNS [{:?}], refresh endpoint {:?} resolved: {:?}",
    //   &globals.bootstrap_dns, &refresh_endpoint, &target_addr
    // );

    let refresh_token = if let Some(r) = &self.refresh_token {
      r
    } else {
      bail!("No refresh token is configured. Should login again first.");
    };
    let id_token = if let Some(i) = &self.id_token {
      i
    } else {
      bail!("No Id token is configured. Must login again first.");
    };

    // TODO: maybe define as a struct for strongly typed definition
    let json_request = format!("{{ \"refresh_token\": \"{}\" }}", refresh_token);

    let client = reqwest::Client::builder()
      .user_agent(format!("doh-auth/{}", env!("CARGO_PKG_VERSION")))
      // .resolve(&target_host_str, target_addr)
      .trust_dns(true)
      .build()
      .unwrap();
    let response = client
      .post(&refresh_endpoint)
      .header(reqwest::header::CONTENT_TYPE, "application/json")
      .header(
        reqwest::header::AUTHORIZATION,
        &format!("Bearer {}", &id_token),
      )
      .body(json_request)
      .send()
      .await?;

    // TODO: maybe define as a struct for strongly typed definition
    let text_body = response.text().await?;
    let json_response: serde_json::Value = serde_json::from_str(&text_body)?;
    self.id_token = if let Some(x) = json_response["Access"]["token"]["id"].as_str() {
      Some(x.to_string())
    } else {
      bail!("Invalid Id token format");
    };
    debug!("Refreshed Id token: Refresh endpoint {}", refresh_endpoint);

    Ok(())
  }

  pub fn id_token_expires_in_secs(&self) -> Result<i64, Error> {
    // This returns unix time in secs
    let clm = self.verify_id_token()?;
    let expires_at: i64 = clm.expires_at.unwrap().as_secs() as i64;
    let dt: DateTime<Local> = Local::now();
    let timestamp = dt.timestamp();
    let expires_in_secs = expires_at - timestamp;
    if expires_in_secs < CREDENTIAL_REFRESH_MARGIN {
      // try to refresh immediately
      return Ok(0);
    }

    Ok(expires_in_secs)
  }

  fn verify_id_token(&self) -> Result<JWTClaims<NoCustomClaims>, Error> {
    // parse jwt
    let (id_token, meta) = if let Some(id_token) = &self.id_token {
      let meta = Token::decode_metadata(id_token)?;
      (id_token, meta)
    } else {
      bail!("No Id token is configured");
    };
    let pk_str = &self.validation_key;

    let mut options = VerificationOptions::default();
    options.allowed_audiences = Some(HashSet::from_strings(&[&self.client_id]));
    options.allowed_issuers = Some(HashSet::from_strings(&[&self.token_api]));

    let clm: JWTClaims<NoCustomClaims> = match Algorithm::from_str(meta.algorithm())? {
      Algorithm::ES256 => {
        let public_key = pk_str.parse::<p256::PublicKey>()?;
        let sec1key = public_key.to_encoded_point(false);
        let key = ES256PublicKey::from_bytes(sec1key.as_bytes())?;
        key.verify_token::<NoCustomClaims>(id_token, Some(options))?
      }
    };
    Ok(clm)
  }
}

#[derive(Debug)]
enum Algorithm {
  ES256,
}
impl FromStr for Algorithm {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Error> {
    match s {
      "ES256" => Ok(Algorithm::ES256),
      _ => Err(anyhow!("Invalid Algorithm Name")),
    }
  }
}
