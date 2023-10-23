use super::token::{TokenInner, TokenMeta};
use serde::{Deserialize, Serialize};

/// Authentication request
#[derive(Serialize)]
pub(super) struct AuthenticationRequest {
  pub auth: AuthenticationReqInner,
  pub client_id: String,
}
#[derive(Serialize)]
/// Auth req inner
pub(super) struct AuthenticationReqInner {
  pub username: String,
  pub password: String,
}

#[derive(Deserialize, Debug)]
/// Auth response
pub(super) struct AuthenticationResponse {
  pub token: TokenInner,
  pub metadata: TokenMeta,
  pub message: String,
}

#[derive(Deserialize, Debug)]
/// Jwks response
pub(super) struct JwksResponse {
  pub keys: Vec<serde_json::Value>,
}
