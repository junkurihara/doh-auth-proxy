use crate::bootstrap::resolve_by_bootstrap;
use crate::constants::*;
use crate::error::*;
use crate::globals::Globals;
use log::{debug, error, info, warn};
use serde_json;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Credential {
  username: String,
  password: String,
  client_id: String,
  token_api: String,
  id_token: Option<String>,
  refresh_token: Option<String>,
}

impl Credential {
  pub fn new(
    username: &str,
    password: &str, // TODO: This should be called "API key"?
    client_id: &str,
    token_api: &str,
  ) -> Credential {
    return Credential {
      username: username.to_string(),
      password: password.to_string(),
      client_id: client_id.to_string(),
      token_api: token_api.to_string(),
      id_token: None,
      refresh_token: None,
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
    info!(
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
    info!("Logged in: Token endpoint {}", token_endpoint);

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
    info!("Refreshed Id token: Refresh endpoint {}", refresh_endpoint);

    Ok(())
  }

  pub fn id_token_expires(&self) -> Result<(), Error> {
    Ok(())
  }
}
