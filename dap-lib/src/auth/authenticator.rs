use super::{
  message::{AuthenticationReqInner, AuthenticationRequest, AuthenticationResponse, JwksResponse},
  token::{Algorithm, TokenInner, VerificationKeyType},
};
use crate::{
  constants::{ENDPOINT_JWKS_PATH, ENDPOINT_LOGIN_PATH},
  error::*,
  globals::AuthenticationConfig,
  http::HttpClient,
  log::*,
};
use jwt_compact::alg::Es256;
use jwt_simple::prelude::{ES256PublicKey, JWTClaims, NoCustomClaims};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::{str::FromStr, sync::Arc};
use tokio::sync::RwLock;

/// Authenticator client
pub struct Authenticator {
  config: AuthenticationConfig,
  http_client: Arc<RwLock<HttpClient>>,
  id_token: Arc<RwLock<Option<TokenInner>>>,
  refresh_token: Arc<RwLock<Option<String>>>,
  validation_key: Arc<RwLock<Option<VerificationKeyType>>>,
}

impl Authenticator {
  /// Build authenticator
  pub async fn new(auth_config: &AuthenticationConfig, http_client: Arc<RwLock<HttpClient>>) -> Result<Self> {
    Ok(Self {
      config: auth_config.clone(),
      http_client,
      id_token: Arc::new(RwLock::new(None)),
      refresh_token: Arc::new(RwLock::new(None)),
      validation_key: Arc::new(RwLock::new(None)),
    })
  }

  /// Update jwks key
  async fn update_validation_key(&self) -> Result<()> {
    let id_token_lock = self.id_token.read().await;
    let Some(id_token) = id_token_lock.as_ref() else {
      return Err(DapError::AuthenticationError("No id token".to_string()));
    };
    let meta = id_token.decode_id_token().await?;
    drop(id_token_lock);

    let mut jwks_endpoint = self.config.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| DapError::Other(anyhow!("Failed to parse token api url".to_string())))?
      .push(ENDPOINT_JWKS_PATH);

    let client_lock = self.http_client.read().await;
    let res = client_lock
      .get(jwks_endpoint)
      .await
      .send()
      .await
      .map_err(|e| DapError::AuthenticationError(e.to_string()))?;
    drop(client_lock);

    if !res.status().is_success() {
      error!("Jwks retrieval error!: {:?}", res.status());
      return Err(DapError::AuthenticationError(format!(
        "Jwks retrieval error!: {:?}",
        res.status()
      )));
    }

    let jwks = res
      .json::<JwksResponse>()
      .await
      .map_err(|_e| DapError::AuthenticationError("Failed to parse jwks response".to_string()))?;

    let key_id = meta
      .key_id()
      .ok_or_else(|| DapError::AuthenticationError("No key id".to_string()))?;

    let matched_key = jwks.keys.iter().find(|x| {
      let kid = x["kid"].as_str().unwrap_or("");
      kid == key_id
    });
    if matched_key.is_none() {
      return Err(DapError::AuthenticationError(format!(
        "No JWK matched to Id token is given at jwks endpoint! key_id: {}",
        key_id
      )));
    }

    let mut matched = matched_key.unwrap().clone();
    let Some(matched_jwk) = matched.as_object_mut() else {
      return Err(DapError::AuthenticationError(
        "Invalid jwk retrieved from jwks endpoint".to_string(),
      ));
    };
    matched_jwk.remove_entry("kid");
    let Ok(jwk_string) = serde_json::to_string(matched_jwk) else {
      return Err(DapError::AuthenticationError("Failed to serialize jwk".to_string()));
    };
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let verification_key = match Algorithm::from_str(meta.algorithm())? {
      Algorithm::ES256 => {
        let pk =
          p256::PublicKey::from_jwk_str(&jwk_string).map_err(|e| DapError::AuthenticationError(e.to_string()))?;
        let sec1key = pk.to_encoded_point(false);

        // use jwt_compact::{
        //   alg::{Es256, VerifyingKey},
        //   jwk::JsonWebKey,
        //   Algorithm,
        // };
        // type PublicKey = <Es256 as Algorithm>::VerifyingKey;
        // let jwk: JsonWebKey<'_> = serde_json::from_str(&jwk_string).unwrap();

        // println!("{:?}", jwk);

        VerificationKeyType::ES256(ES256PublicKey::from_bytes(sec1key.as_bytes())?)
      }
      Algorithm::EdDSA => {
        // TODO: Ed25519

        todo!()
      }
    };

    let mut validation_key_lock = self.validation_key.write().await;
    validation_key_lock.replace(verification_key);
    drop(validation_key_lock);

    info!("validation key updated");

    Ok(())
  }

  /// Verify id token
  async fn verify_id_token(&self) -> Result<JWTClaims<NoCustomClaims>> {
    let vk_lock = self.validation_key.read().await;
    let Some(vk) = vk_lock.as_ref() else {
      return Err(DapError::AuthenticationError("No validation key".to_string()));
    };
    let verification_key = vk.to_owned();
    drop(vk_lock);

    let token_lock = self.id_token.read().await;
    let Some(token_inner) = token_lock.as_ref() else {
      return Err(DapError::AuthenticationError("No id token".to_string()));
    };
    let token = token_inner.clone();
    drop(token_lock);

    token.verify_id_token(&verification_key, &self.config).await
  }

  /// Login to the authentication server
  pub async fn login(&self) -> Result<()> {
    let mut login_endpoint = self.config.token_api.clone();
    login_endpoint
      .path_segments_mut()
      .map_err(|_| DapError::Other(anyhow!("Failed to parse token api url".to_string())))?
      .push(ENDPOINT_LOGIN_PATH);

    let json_request = AuthenticationRequest {
      auth: AuthenticationReqInner {
        username: self.config.username.clone(),
        password: self.config.password.clone(),
      },
      client_id: self.config.client_id.clone(),
    };

    let client_lock = self.http_client.read().await;
    let res = client_lock
      .post(login_endpoint)
      .await
      .json(&json_request)
      .send()
      .await
      .map_err(|e| DapError::AuthenticationError(e.to_string()))?;
    drop(client_lock);

    if !res.status().is_success() {
      error!("Login error!: {:?}", res.status());
      return Err(DapError::AuthenticationError(format!(
        "Login error!: {:?}",
        res.status()
      )));
    }

    // parse token
    let token = res
      .json::<AuthenticationResponse>()
      .await
      .map_err(|_e| DapError::AuthenticationError("Failed to parse token response".to_string()))?;

    if let Some(refresh) = &token.token.refresh {
      let mut refresh_token_lock = self.refresh_token.write().await;
      refresh_token_lock.replace(refresh.clone());
      drop(refresh_token_lock);
    }

    let mut id_token_lock = self.id_token.write().await;
    id_token_lock.replace(token.token);
    drop(id_token_lock);

    info!("Token retrieved");

    // update validation key
    self.update_validation_key().await?;

    // verify id token with validation key
    let Ok(_clm) = self.verify_id_token().await else {
      return Err(DapError::AuthenticationError(
        "Invalid Id token! Carefully check if target DNS or Token API is compromised!".to_string(),
      ));
    };

    info!("Login success!");
    Ok(())
  }

  // TODO: refresh by checking the expiration time
}
