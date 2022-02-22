/*
  credential.rs
*/
/*
  [Memo] 2021-10-07
  TODO: JSON requests and responses to a token server are not
  defined as strongly-typed ones. This may be need to be fixed
  by defining struct.
*/

use crate::constants::*;
use crate::error::*;
use crate::globals::Globals;
use crate::http_bootstrap::HttpClient;
use crate::log::*;
use chrono::{DateTime, Local};
use jwt_simple::prelude::*;
use p256::elliptic_curve::sec1::ToEncodedPoint;
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
  validation_key: Option<String>,
}

impl Credential {
  pub fn new(
    username: &str,
    password: &str, // TODO: This should be called "API key"?
    client_id: &str,
    token_api: &str,
  ) -> Credential {
    Credential {
      username: username.to_string(),
      password: password.to_string(),
      client_id: client_id.to_string(),
      token_api: token_api.to_string(),
      id_token: None,
      refresh_token: None,
      validation_key: None,
    }
  }

  pub fn id_token(&self) -> Option<String> {
    self.id_token.clone()
  }

  pub async fn login(&mut self, globals: &Arc<Globals>) -> Result<()> {
    // token endpoint is resolved via bootstrap DNS resolver
    let token_endpoint = format!("{}{}", self.token_api, ENDPOINT_LOGIN_PATH);
    let client = HttpClient::new(globals, &token_endpoint, None, true)
      .await?
      .client;
    // let client = http_client_resolved_by_bootstrap(&token_endpoint, globals, None).await?;

    // TODO: maybe define as a struct for strongly typed definition
    let json_request = format!(
      "{{ \"auth\": {{\"username\": \"{}\", \"password\": \"{}\" }}, \"client_id\": \"{}\" }}",
      self.username, self.password, self.client_id
    );

    let token_response = client
      .post(&token_endpoint)
      .header(reqwest::header::CONTENT_TYPE, "application/json")
      .body(json_request)
      .send()
      .await?;

    if token_response.status() != reqwest::StatusCode::OK {
      error!("Login error!: {:?}", token_response.status());
      bail!("{:?}", token_response.status());
    }

    // TODO: maybe define as a struct for strongly typed definition
    let text_body = token_response.text().await?;
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

    // jwks retrieval process and update self
    self
      .update_validation_key_matched_to_key_id(globals, self.get_meta_from_id_token()?)
      .await?;

    // check validity of id token
    match self.verify_id_token().await {
      Ok(_) => (),
      Err(e) => bail!(
        "Invalid Id token! Carefully check if bootstrap DNS is poisoned! {}",
        e
      ),
    };
    debug!("Logged in: Token endpoint {}", token_endpoint);

    Ok(())
  }

  pub async fn refresh(&mut self, globals: &Arc<Globals>) -> Result<()> {
    // refresh endpoint is NOT resolved via configured system DNS resolver. resolve by proxy itself
    let refresh_endpoint = format!("{}{}", self.token_api, ENDPOINT_REFRESH_PATH);
    let client = HttpClient::new(globals, &refresh_endpoint, None, false)
      .await?
      .client;

    let refresh_token = if let Some(r) = &self.refresh_token {
      r
    } else {
      bail!("No refresh token is configured. Should login again first.");
    };

    // TODO: maybe define as a struct for strongly typed definition
    let json_request = format!(
      "{{ \"refresh_token\": \"{}\", \"client_id\": \"{}\" }}",
      refresh_token, self.client_id
    );
    let response = client
      .post(&refresh_endpoint)
      .header(reqwest::header::CONTENT_TYPE, "application/json")
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

    // jwks retrieval process and update self
    self
      .update_validation_key_matched_to_key_id(globals, self.get_meta_from_id_token()?)
      .await?;

    // check validity of id token
    match self.verify_id_token().await {
      Ok(_) => (),
      Err(e) => bail!(
        "Invalid Id token! Carefully check if bootstrap DNS is poisoned! {}",
        e
      ),
    };
    debug!("Refreshed Id token: Refresh endpoint {}", refresh_endpoint);

    Ok(())
  }

  async fn update_validation_key_matched_to_key_id(
    &mut self,
    globals: &Arc<Globals>,
    meta: TokenMetadata,
  ) -> Result<()> {
    let jwks_endpoint = format!("{}{}", self.token_api, ENDPOINT_JWKS_PATH);
    let client = HttpClient::new(globals, &jwks_endpoint, None, true)
      .await?
      .client;
    let jwks_response = client.get(&jwks_endpoint).send().await?;
    let text_body = jwks_response.text().await?;
    let json_response: serde_json::Value = serde_json::from_str(&text_body)?;

    let arr_iter = if let Some(keys) = json_response.get("keys") {
      match keys.as_array() {
        Some(t) => t.iter(),
        None => bail!("jwks endpoint doesn't work! Invalid response format"),
      }
    } else {
      bail!("keys are missing in jwks response. jwks endpoint doesn't work!");
    };
    let arr_vec: Vec<&serde_json::Value> = if let Some(token_kid) = meta.key_id() {
      arr_iter
        .filter(|obj| {
          if let Some(jwk_id) = obj.get("kid") {
            jwk_id == token_kid
          } else {
            true // if jwk_id is not supplied at jwks endpoint, always true...
          }
        })
        .collect()
    } else {
      arr_iter.collect()
    };

    if arr_vec.is_empty() {
      bail!("No JWK matched to Id token is given at jwks endpoint!");
    }
    let mut matched = arr_vec[0].clone();
    let matched_jwk = match matched.as_object_mut() {
      Some(o) => o,
      None => bail!("Invalid jwk retrieved from jwks endpoint"),
    };
    matched_jwk.remove_entry("kid");
    let jwk_string = serde_json::to_string(matched_jwk)?;
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let pem = match Algorithm::from_str(meta.algorithm())? {
      Algorithm::ES256 => {
        let pk = p256::PublicKey::from_jwk_str(&jwk_string)?;
        pk.to_string()
      }
    };
    match &self.validation_key {
      None => {
        self.validation_key = Some(pem);
        debug!("Validation key was obtained and correctly set");
      }
      Some(p) => {
        if p.clone() != pem {
          warn!("Validation key possibly updated!: {}", pem);
          self.validation_key = Some(pem);
        }
      }
    };
    Ok(())
  }

  pub async fn id_token_expires_in_secs(&self) -> Result<i64> {
    // This returns unix time in secs
    let clm = self.verify_id_token().await?;
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

  pub fn get_meta_from_id_token(&self) -> Result<TokenMetadata> {
    // parse jwt
    if let Some(id_token) = &self.id_token {
      let meta = Token::decode_metadata(id_token)?;
      Ok(meta)
    } else {
      bail!("No Id token is configured");
    }
  }

  async fn verify_id_token(&self) -> Result<JWTClaims<NoCustomClaims>> {
    let meta = self.get_meta_from_id_token()?;
    let id_token = if let Some(id_token) = &self.id_token {
      id_token
    } else {
      bail!("No Id token is configured");
    };
    let pk_str = match &self.validation_key {
      None => bail!("validation key is not configured! login first!"),
      Some(pem) => pem,
    };

    let options = VerificationOptions {
      accept_future: true, // accept future
      allowed_audiences: Some(HashSet::from_strings(&[&self.client_id])),
      allowed_issuers: Some(HashSet::from_strings(&[&self.token_api])),
      ..Default::default()
    };

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
  fn from_str(s: &str) -> Result<Self> {
    match s {
      "ES256" => Ok(Algorithm::ES256),
      _ => Err(anyhow!("Invalid Algorithm Name")),
    }
  }
}
