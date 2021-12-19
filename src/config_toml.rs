use crate::error::*;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug)]
pub struct ConfigToml {
  pub listen_addresses: Option<Vec<String>>,
  pub bootstrap_dns: Option<String>,
  pub reboot_period: Option<usize>,
  pub target_urls: Option<Vec<String>>,
  pub use_get_method: Option<bool>,
  pub authentication: Option<Authentication>,
  pub anonymization: Option<Anonymization>,
}

#[derive(Deserialize, Debug)]
pub struct Anonymization {
  pub relay_urls: Vec<String>,
  pub relay_randomization: Option<bool>,
  pub mid_relay_urls: Option<Vec<String>>,
  pub max_mid_relays: Option<usize>,
}
#[derive(Deserialize, Debug)]
pub struct Authentication {
  pub token_api: String,
  pub credential_file: String,
}

impl ConfigToml {
  pub fn new(config_file: &str) -> Result<Self, Error> {
    let config_str = if let Ok(s) = fs::read_to_string(config_file) {
      s
    } else {
      bail!("Failed to read config file");
    };
    let parsed: Result<ConfigToml, Error> = toml::from_str(&config_str)
      .map_err(|e: toml::de::Error| anyhow!("Failed to parse toml config: {:?}", e));
    parsed
  }
}
