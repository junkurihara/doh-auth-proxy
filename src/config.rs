use crate::{
  client::{Cache, Credential, DoHMethod},
  config_toml::ConfigToml,
  constants::*,
  error::*,
  globals::Globals,
  log::*,
  plugins::{DomainBlockRule, DomainOverrideRule, QueryPlugin, QueryPluginsApplied},
};
use clap::Arg;
use std::{env, fs, sync::Arc};
use tokio::{runtime::Handle, sync::RwLock, time::Duration};

pub async fn parse_opts(runtime_handle: &Handle) -> Result<Arc<Globals>> {
  use crate::utils::{verify_sock_addr, verify_target_url};

  let _ = include_str!("../Cargo.toml");
  let options = clap::command!().arg(
    Arg::new("config_file")
      .long("config")
      .short('c')
      .required(true)
      .takes_value(true)
      .help("Configuration file path like \"doh-auth-proxy.toml\""),
  );

  let matches = options.get_matches();

  ///////////////////////////////
  // format with initial value //
  ///////////////////////////////
  let mut globals_local = Globals {
    listen_addresses: LISTEN_ADDRESSES
      .to_vec()
      .iter()
      .map(|x| x.parse().unwrap())
      .collect(),
    udp_buffer_size: UDP_BUFFER_SIZE,
    udp_channel_capacity: UDP_CHANNEL_CAPACITY,
    timeout_sec: Duration::from_secs(TIMEOUT_SEC),

    doh_target_urls: vec![DOH_TARGET_URL.to_string()],
    target_randomization: true,
    doh_method: DoHMethod::Post,
    odoh_relay_urls: None,
    odoh_relay_randomization: true,
    mid_relay_urls: None,
    max_mid_relays: 0,

    bootstrap_dns: BOOTSTRAP_DNS.to_string().parse().unwrap(),
    rebootstrap_period_sec: Duration::from_secs(REBOOTSTRAP_PERIOD_MIN * 60),

    max_connections: MAX_CONNECTIONS,
    counter: Default::default(),
    runtime_handle: runtime_handle.clone(),

    query_plugins: None,
    min_ttl: MIN_TTL,

    doh_clients: Arc::new(RwLock::new(None)),
    credential: Arc::new(RwLock::new(None)),
    cache: Arc::new(Cache::new(DEFAULT_DNS_CACHE_SIZE)),
  };
  /////////////////////////////
  //   reading toml file     //
  /////////////////////////////
  let config_file_path = matches.value_of("config_file").unwrap();
  let config = ConfigToml::new(config_file_path)?;

  /////////////////////////////
  // listen addresses
  if let Some(val) = config.listen_addresses {
    globals_local.listen_addresses = val
      .iter()
      .map(|x| {
        if verify_sock_addr(x.clone()).is_err() {
          panic!("Invalid listen address");
        }
        x.parse().unwrap()
      })
      .collect();
  };

  /////////////////////////////
  // bootstrap dns
  if let Some(val) = config.bootstrap_dns {
    if verify_sock_addr(val.clone()).is_err() {
      panic!("Invalid bootstrap DNS address");
    }
    globals_local.bootstrap_dns = val.parse().unwrap()
  };
  info!("Bootstrap DNS: {:?}", globals_local.bootstrap_dns);
  if let Some(val) = config.reboot_period {
    globals_local.rebootstrap_period_sec = Duration::from_secs((val as u64) * 60);
  }
  info!(
    "Target DoH Address is re-fetched every {:?} min",
    globals_local.rebootstrap_period_sec.as_secs() / 60
  );

  /////////////////////////////
  // cache size
  if let Some(val) = config.max_cache_size {
    globals_local.cache = Arc::new(Cache::new(val));
  }
  info!("Max cache size: {} (entries)", globals_local.cache.max_size);

  /////////////////////////////
  // DoH target and method
  if let Some(val) = config.target_urls {
    if !val.iter().all(|x| verify_target_url(x.to_string()).is_ok()) {
      bail!("Invalid target urls");
    }
    globals_local.doh_target_urls = val;
  }
  info!(
    "Target (O)DoH resolvers: {:?}",
    globals_local.doh_target_urls
  );
  if let Some(val) = config.target_randomization {
    if !val {
      globals_local.target_randomization = false
    }
  }
  if globals_local.target_randomization {
    info!("Target randomization is enabled");
  }
  if let Some(val) = config.use_get_method {
    if val {
      globals_local.doh_method = DoHMethod::Get;
      info!("Use GET method for query");
    }
  }

  /////////////////////////////
  // Query plugins
  let mut plugins_applied = QueryPluginsApplied::new();
  if let Some(plugins) = config.plugins {
    // domains blocked
    if let Some(blocked_names_file) = plugins.domains_blocked_file {
      let blocklist_path = env::current_dir()?.join(blocked_names_file);
      if let Ok(content) = fs::read_to_string(blocklist_path) {
        let truncate_vec: Vec<&str> = content.split('\n').filter(|c| !c.is_empty()).collect();
        plugins_applied.add(QueryPlugin::PluginDomainBlock(Box::new(
          DomainBlockRule::new(truncate_vec),
        )));
        info!("[Query plugin] Domain blocking is enabled");
      }
    }
    // domains overridden
    if let Some(overridden_names_file) = plugins.domains_overridden_file {
      let overridden_path = env::current_dir()?.join(overridden_names_file);
      if let Ok(content) = fs::read_to_string(overridden_path) {
        let truncate_vec: Vec<&str> = content.split('\n').filter(|c| !c.is_empty()).collect();
        plugins_applied.add(QueryPlugin::PluginDomainOverride(Box::new(
          DomainOverrideRule::new(truncate_vec),
        )));
        info!("[Query plugin] Domain overriding is enabled");
      }
    }
  };

  globals_local.query_plugins = Some(plugins_applied);

  /////////////////////////////
  // Anonymization
  if let Some(anon) = config.anonymization {
    if let Some(odoh_relay_urls) = anon.odoh_relay_urls {
      if !odoh_relay_urls
        .iter()
        .all(|x| verify_target_url(x.to_string()).is_ok())
      {
        bail!("Invalid ODoH relay urls");
      }
      globals_local.odoh_relay_urls = Some(odoh_relay_urls);
      info!("[ODoH] Oblivious DNS over HTTPS is enabled");
      info!(
        "[ODoH] Nexthop relay URL: {:?}",
        globals_local.odoh_relay_urls.clone().unwrap()
      );

      if let Some(val) = anon.odoh_relay_randomization {
        globals_local.odoh_relay_randomization = val;
      }
      if globals_local.odoh_relay_randomization {
        info!("ODoH relay randomization is enabled");
      }

      if let Some(val) = anon.mid_relay_urls {
        if !val.iter().all(|x| verify_target_url(x.to_string()).is_ok()) {
          bail!("Invalid mid relay urls");
        }
        if !val.is_empty() {
          globals_local.mid_relay_urls = Some(val);
        }
      }
      if let Some(val) = anon.max_mid_relays {
        globals_local.max_mid_relays = val;
      } else if globals_local.mid_relay_urls.is_some() {
        globals_local.max_mid_relays = 1usize;
      } else {
        globals_local.max_mid_relays = 0usize;
      }

      if globals_local.mid_relay_urls.is_some() {
        info!("[m-ODoH] Multiple-relay-based Oblivious DNS over HTTPS is enabled");
        info!(
          "[m-ODoH] Intermediate relay URLs employed after the next hop: {:?}",
          globals_local.mid_relay_urls.clone().unwrap()
        );
        info!(
          "[m-ODoH] Maximum number of intermediate relays after the nexthop: {}",
          anon.max_mid_relays.unwrap()
        );
      }
    }
  }

  /////////////////////////////
  // Authentication
  // If credential exists, authorization header is also enabled.
  // TODO: login password should be stored in keychain access like secure storage rather than dotenv.
  let credential = if let Some(auth) = config.authentication {
    if let (Some(credential_file), Some(token_api)) = (auth.credential_file, auth.token_api) {
      let cred_path = env::current_dir()?.join(credential_file);
      dotenv::from_path(&cred_path).ok();
      let username = if let Ok(x) = env::var(CREDENTIAL_USERNAME_FIELD) {
        x
      } else {
        bail!("No username is given in the credential file.");
      };
      let password = if let Ok(x) = env::var(CREDENTIAL_API_KEY_FIELD) {
        x
      } else {
        bail!("No password is given in the credential file.");
      };
      let client_id = if let Ok(x) = env::var(CREDENTIAL_CLIENT_ID_FIELD) {
        x
      } else {
        bail!("No client_id is given in the credential file.");
      };
      if verify_target_url(token_api.clone()).is_err() {
        bail!("Invalid target urls");
      }
      info!("Token API: {}", token_api);

      Some(Credential::new(
        &username, &password, &client_id, &token_api,
      ))
    } else {
      None
    }
  } else {
    None
  };

  // If credential exists, authorization header is also enabled.
  // TODO: login password should be stored in keychain access like secure storage rather than dotenv.

  ////////////////////////

  if let (Some(_), Some(_)) = (&credential, &globals_local.odoh_relay_urls) {
    warn!("-----------------------------------");
    warn!("[NOTE!!!!] Both credential and ODoH nexthop proxy is set up.");
    warn!("[NOTE!!!!] This means the authorization token will be sent not to the target but to the proxy.");
    warn!("[NOTE!!!!] Check if this is your intended behavior.");
    warn!("-----------------------------------");
  } else if let (Some(_), None) = (&credential, &globals_local.odoh_relay_urls) {
    warn!("-----------------------------------");
    warn!("[NOTE!!!!] Authorization token will be sent to the target server!");
    warn!("[NOTE!!!!] Check if this is your intended behavior.");
    warn!("-----------------------------------");
  }
  ////////////////////////

  *globals_local.credential.write().await = credential.clone();

  let globals = Arc::new(globals_local);

  Ok(globals)
}
