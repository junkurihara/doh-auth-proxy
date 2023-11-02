use super::{toml::ConfigToml, utils_verifier::*};
use crate::{constants::*, error::*, log::*};
use async_trait::async_trait;
use doh_auth_proxy_lib::{
  AuthenticationConfig, NextHopRelayConfig, ProxyConfig, QueryManipulationConfig, SubseqRelayConfig,
};
use hot_reload::{Reload, ReloaderError};
use std::{env, sync::Arc};
use tokio::time::Duration;

#[derive(PartialEq, Eq, Clone, Debug)]
/// Wrapper of config toml and manipulation plugin settings
pub struct TargetConfig {
  /// config toml
  pub config_toml: ConfigToml,
  /// manipulation plugin config
  pub query_manipulation_config: Option<Arc<QueryManipulationConfig>>,
}

#[derive(Clone)]
/// config toml reloader
pub struct ConfigReloader {
  pub config_path: String,
}

#[async_trait]
impl Reload<TargetConfig> for ConfigReloader {
  type Source = String;
  async fn new(source: &Self::Source) -> Result<Self, ReloaderError<TargetConfig>> {
    Ok(Self {
      config_path: source.clone(),
    })
  }

  async fn reload(&self) -> Result<Option<TargetConfig>, ReloaderError<TargetConfig>> {
    let config_toml = ConfigToml::new(&self.config_path)
      .map_err(|_e| ReloaderError::<TargetConfig>::Reload("Failed to reload config toml"))?;
    let query_manipulation_config: Option<QueryManipulationConfig> = (&config_toml)
      .try_into()
      .map_err(|_e| ReloaderError::<TargetConfig>::Reload("Failed to reload manipulation plugin config"))?;

    Ok(Some(TargetConfig {
      config_toml,
      query_manipulation_config: query_manipulation_config.map(Arc::new),
    }))
  }
}

impl TargetConfig {
  /// build new target config by loading query manipulation plugin configs
  pub async fn new(config_file: &str) -> anyhow::Result<Self> {
    let config_toml = ConfigToml::new(config_file)?;
    let query_manipulation_config: Option<QueryManipulationConfig> = (&config_toml).try_into()?;
    Ok(Self {
      config_toml,
      query_manipulation_config: query_manipulation_config.map(Arc::new),
    })
  }
}

impl TryInto<ProxyConfig> for &TargetConfig {
  type Error = anyhow::Error;

  fn try_into(self) -> Result<ProxyConfig, Self::Error> {
    let mut proxy_config = ProxyConfig::default();

    /////////////////////////////
    // listen addresses
    if let Some(val) = &self.config_toml.listen_addresses {
      if !val.iter().all(|v| verify_sock_addr(v).is_ok()) {
        bail!("Invalid listen address");
      }
      proxy_config.listen_addresses = val.iter().map(|x| x.parse().unwrap()).collect();
    };

    /////////////////////////////
    // bootstrap dns
    if let Some(val) = &self.config_toml.bootstrap_dns {
      if !val.iter().all(|v| verify_ip_addr(v).is_ok()) {
        bail!("Invalid bootstrap DNS address");
      }
      proxy_config.bootstrap_dns.ips = val.iter().map(|x| x.parse().unwrap()).collect()
    };
    info!("Bootstrap DNS: {:?}", proxy_config.bootstrap_dns.ips);

    /////////////////////////////
    // endpoint re-resolution period
    if let Some(val) = self.config_toml.endpoint_resolution_period {
      proxy_config.endpoint_resolution_period_sec = Duration::from_secs((val as u64) * 60);
    }
    info!(
      "Nexthop nodes (DoH target or (MO)DoH next hop relay) and auth server addresses are re-resolved every {:?} min via DoH itself or Bootsrap DNS",
      proxy_config.endpoint_resolution_period_sec.as_secs() / 60
    );

    /////////////////////////////
    // health check period
    if let Some(val) = self.config_toml.healthcheck_period {
      proxy_config.healthcheck_period_sec = Duration::from_secs((val as u64) * 60);
    }
    info!(
      "Check for health of all possible path candidates and purge DNS cache every {:?} min",
      proxy_config.healthcheck_period_sec.as_secs() / 60
    );

    /////////////////////////////
    // cache size
    if let Some(val) = self.config_toml.max_cache_size {
      proxy_config.max_cache_size = val;
    }
    info!("Max cache size: {} (entries)", proxy_config.max_cache_size);

    /////////////////////////////
    // DoH target and method
    if let Some(val) = &self.config_toml.target_urls {
      if !val.iter().all(|x| verify_target_url(x).is_ok()) {
        bail!("Invalid target urls");
      }
      proxy_config.target_config.doh_target_urls = val.iter().map(|v| url::Url::parse(v).unwrap()).collect();
    }
    info!(
      "Target (O)DoH resolvers: {:?}",
      proxy_config
        .target_config
        .doh_target_urls
        .iter()
        .map(|x| x.as_str())
        .collect::<Vec<_>>()
    );
    if let Some(val) = &self.config_toml.target_randomization {
      if !val {
        proxy_config.target_config.target_randomization = false;
        info!("Target randomization is disbled");
      }
    }
    if let Some(val) = self.config_toml.use_get_method {
      if val {
        proxy_config.target_config.use_get = true;
        info!("Use GET method for query");
      }
    }

    /////////////////////////////
    // Anonymization
    if let Some(anon) = &self.config_toml.anonymization {
      /////////////////////////////
      // odoh and next hop of modoh
      if let Some(odoh_relay_urls) = &anon.odoh_relay_urls {
        if !odoh_relay_urls.iter().all(|x| verify_target_url(x).is_ok()) {
          bail!("Invalid ODoH relay urls");
        }
        let mut nexthop_relay_config = NextHopRelayConfig {
          odoh_relay_urls: odoh_relay_urls.iter().map(|v| url::Url::parse(v).unwrap()).collect(),
          odoh_relay_randomization: true,
        };
        info!("[ODoH] Oblivious DNS over HTTPS is enabled");
        info!(
          "[ODoH] Nexthop relay URL: {:?}",
          nexthop_relay_config
            .odoh_relay_urls
            .iter()
            .map(|x| x.as_str())
            .collect::<Vec<_>>()
        );

        if let Some(val) = anon.odoh_relay_randomization {
          nexthop_relay_config.odoh_relay_randomization = val;
        }
        if nexthop_relay_config.odoh_relay_randomization {
          info!("ODoH relay randomization is enabled");
        }
        proxy_config.nexthop_relay_config = Some(nexthop_relay_config);

        /////////////////////////////
        // modoh
        if let Some(val) = &anon.mid_relay_urls {
          if !val.iter().all(|x| verify_target_url(x).is_ok()) {
            bail!("Invalid mid relay urls");
          }
          if val.is_empty() {
            bail!("mid_relay_urls must specify at least one relay url");
          }
          if anon.max_mid_relays.is_some() && anon.max_mid_relays.unwrap_or(1) > val.len() {
            bail!("max_mid_relays must be equal to or less than # of mid_relay_urls.");
          }
          let subseq_relay_config = SubseqRelayConfig {
            mid_relay_urls: val.iter().map(|v| url::Url::parse(v).unwrap()).collect(),
            max_mid_relays: anon.max_mid_relays.unwrap_or(1),
          };

          info!("[m-ODoH] Multiple-relay-based Oblivious DNS over HTTPS is enabled");
          info!(
            "[m-ODoH] Intermediate relay URLs employed after the next hop: {:?}",
            subseq_relay_config
              .mid_relay_urls
              .iter()
              .map(|x| x.as_str())
              .collect::<Vec<_>>()
          );
          info!(
            "[m-ODoH] Maximum number of intermediate relays after the nexthop: {}",
            subseq_relay_config.max_mid_relays
          );

          proxy_config.subseq_relay_config = Some(subseq_relay_config);
        }
      }
    }

    /////////////////////////////
    // Authentication
    // If credential exists, authorization header is also enabled.
    if let Some(auth) = &self.config_toml.authentication {
      if let (Some(credential_file), Some(token_api)) = (&auth.credential_file, &auth.token_api) {
        let cred_path = env::current_dir()?.join(credential_file);
        dotenv::from_path(cred_path).ok();
        let Ok(username) = env::var(CREDENTIAL_USERNAME_FIELD) else {
          bail!("No username is given in the credential file.");
        };
        let Ok(password) = env::var(CREDENTIAL_API_KEY_FIELD) else {
          bail!("No password is given in the credential file.");
        };
        let Ok(client_id) = env::var(CREDENTIAL_CLIENT_ID_FIELD) else {
          bail!("No client_id is given in the credential file.");
        };
        if verify_target_url(token_api).is_err() {
          bail!("Invalid token api urls");
        }
        info!("Token API: {}", token_api);

        let authentication_config = AuthenticationConfig {
          username,
          password,
          client_id,
          token_api: token_api.parse().unwrap(),
        };
        proxy_config.authentication_config = Some(authentication_config);
      }
    };

    ////////////////////////
    if proxy_config.authentication_config.is_some() {
      if proxy_config.nexthop_relay_config.is_some() {
        warn!("-----------------------------------");
        warn!("[NOTE!!!!] Both credential and ODoH nexthop proxy is set up.");
        warn!("[NOTE!!!!] This means the authorization token will be sent not to the target but to the proxy.");
        warn!("[NOTE!!!!] Check if this is your intended behavior.");
        warn!("-----------------------------------");
      } else {
        warn!("-----------------------------------");
        warn!("[NOTE!!!!] Authorization token will be sent to the target server!");
        warn!("[NOTE!!!!] Check if this is your intended behavior.");
        warn!("-----------------------------------");
      }
    }

    ////////////////////////
    // Plugins
    if self.config_toml.plugins.is_some() {
      info!("Query manipulation plugins are enabled");
      proxy_config.query_manipulation_config = self.query_manipulation_config.clone();
    }
    ////////////////////////

    Ok(proxy_config)
  }
}
