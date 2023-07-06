use crate::error::*;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Debug, Default)]
pub struct ConfigToml {
  pub listen_addresses: Option<Vec<String>>,
  pub bootstrap_dns: Option<String>,
  pub reboot_period: Option<usize>,
  pub max_cache_size: Option<usize>,
  pub target_urls: Option<Vec<String>>,
  pub target_randomization: Option<bool>,
  pub use_get_method: Option<bool>,
  pub authentication: Option<Authentication>,
  pub anonymization: Option<Anonymization>,
  pub plugins: Option<Plugins>,
}

#[derive(Deserialize, Debug)]
pub struct Plugins {
  pub domains_blocked_file: Option<String>,
  pub domains_overridden_file: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Anonymization {
  pub odoh_relay_urls: Option<Vec<String>>,
  pub odoh_relay_randomization: Option<bool>,
  pub mid_relay_urls: Option<Vec<String>>,
  pub max_mid_relays: Option<usize>,
}
#[derive(Deserialize, Debug)]
pub struct Authentication {
  pub token_api: Option<String>,
  pub credential_file: Option<String>,
}

impl ConfigToml {
  pub fn new(config_file: &str) -> Result<Self> {
    let Ok(config_str) = fs::read_to_string(config_file) else {
      bail!("Failed to read config file");
    };
    let parsed: Result<ConfigToml> =
      toml::from_str(&config_str).map_err(|e: toml::de::Error| anyhow!("Failed to parse toml config: {:?}", e));
    parsed
  }
}
