use super::utils_verifier::*;
use crate::{error::*, log::*};
use doh_auth_proxy_lib::{DoHMethod, NextHopRelayConfig, ProxyConfig, SubseqRelayConfig, TargetConfig};
use serde::Deserialize;
use std::fs;
use tokio::time::Duration;

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct ConfigToml {
  pub listen_addresses: Option<Vec<String>>,
  pub bootstrap_dns: Option<Vec<String>>,
  pub reboot_period: Option<usize>,
  pub max_cache_size: Option<usize>,
  pub target_urls: Option<Vec<String>>,
  pub target_randomization: Option<bool>,
  pub use_get_method: Option<bool>,
  pub authentication: Option<Authentication>,
  pub anonymization: Option<Anonymization>,
  pub plugins: Option<Plugins>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Plugins {
  pub domains_blocked_file: Option<String>,
  pub domains_overridden_file: Option<String>,
}

#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Anonymization {
  pub odoh_relay_urls: Option<Vec<String>>,
  pub odoh_relay_randomization: Option<bool>,
  pub mid_relay_urls: Option<Vec<String>>,
  pub max_mid_relays: Option<usize>,
}
#[derive(Deserialize, Debug, Default, PartialEq, Eq, Clone)]
pub struct Authentication {
  pub token_api: Option<String>,
  pub credential_file: Option<String>,
}

impl ConfigToml {
  pub fn new(config_file: &str) -> std::result::Result<Self, anyhow::Error> {
    let config_str = fs::read_to_string(config_file)?;

    toml::from_str(&config_str).map_err(|e| anyhow!(e))
  }
}

impl TryInto<ProxyConfig> for &ConfigToml {
  type Error = anyhow::Error;

  fn try_into(self) -> Result<ProxyConfig, Self::Error> {
    let mut proxy_config = ProxyConfig::default();

    /////////////////////////////
    // listen addresses
    if let Some(val) = &self.listen_addresses {
      if !val.iter().all(|v| verify_sock_addr(v).is_ok()) {
        bail!("Invalid listen address");
      }
      proxy_config.listen_addresses = val.iter().map(|x| x.parse().unwrap()).collect();
    };

    /////////////////////////////
    // bootstrap dns
    if let Some(val) = &self.bootstrap_dns {
      if !val.iter().all(|v| verify_sock_addr(v).is_ok()) {
        bail!("Invalid bootstrap DNS address");
      }
      proxy_config.bootstrap_dns = val.iter().map(|x| x.parse().unwrap()).collect()
    };
    info!("Bootstrap DNS: {:?}", proxy_config.bootstrap_dns);
    if let Some(val) = self.reboot_period {
      proxy_config.rebootstrap_period_sec = Duration::from_secs((val as u64) * 60);
    }
    info!(
      "Target DoH Address is re-fetched every {:?} min via Bootsrap DNS",
      proxy_config.rebootstrap_period_sec.as_secs() / 60
    );

    /////////////////////////////
    // cache size
    if let Some(val) = self.max_cache_size {
      proxy_config.max_cache_size = val;
    }
    info!("Max cache size: {} (entries)", proxy_config.max_cache_size);

    /////////////////////////////
    // DoH target and method
    if let Some(val) = &self.target_urls {
      if !val.iter().all(|x| verify_target_url(x).is_ok()) {
        bail!("Invalid target urls");
      }
      proxy_config.target_config.doh_target_urls = val.to_owned();
    }
    info!(
      "Target (O)DoH resolvers: {:?}",
      proxy_config.target_config.doh_target_urls
    );
    if let Some(val) = &self.target_randomization {
      if !val {
        proxy_config.target_config.target_randomization = false;
        info!("Target randomization is disbled");
      }
    }
    if let Some(val) = self.use_get_method {
      if val {
        proxy_config.target_config.doh_method = DoHMethod::Get;
        info!("Use GET method for query");
      }
    }

    Ok(proxy_config)
  }
}
