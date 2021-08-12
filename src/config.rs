use crate::client::DoHMethod;
use crate::constants::*;
use crate::credential::Credential;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use clap::Arg;
use dotenv;
use log::{debug, error, info, warn};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Handle;

pub async fn parse_opts(
  runtime_handle: Handle,
) -> Result<(Arc<Globals>, Arc<RwLock<GlobalsCache>>), Error> {
  use crate::utils::{verify_sock_addr, verify_target_url};
  // TODO: Args Optionで上書き

  let _ = include_str!("../Cargo.toml");
  let options = app_from_crate!()
    .arg(
      Arg::with_name("listen_addresses")
        .short("l")
        .long("listen-address")
        .takes_value(true)
        .multiple(true)
        .number_of_values(1)
        .validator(verify_sock_addr)
        .help("Address to listen to. To specify multiple addresses, set args like \"--listen-address=127.0.0.1:50053 --listen-address=\'[::1]:50053\'\""),
    )
    .arg(
      Arg::with_name("bootstrap_dns")
        .short("b")
        .long("bootstrap-dns")
        .takes_value(true)
        .default_value(BOOTSTRAP_DNS)
        .validator(verify_sock_addr)
        .help("DNS (Do53) resolver address for bootstrap"),
    )
    .arg(
      Arg::with_name("rebootstrap_period_min")
        .short("p")
        .long("reboot-period")
        .takes_value(true)
        .help("Minutes to re-fetch the IP addr of the target url host via the bootstrap DNS"),
    )
    .arg(
      Arg::with_name("doh_target_url")
        .short("t")
        .long("target-url")
        .takes_value(true)
        .default_value(DOH_TARGET_URL)
        .validator(verify_target_url)
        .help("URL of target DoH server like \"https://dns.google/dns-query\""),
    )
    .arg(
      Arg::with_name("credential_file_path")
      .short("c")
      .long("credential-file-path")
      .takes_value(true)
      .help("Credential env file path for login endpoint like \"./credential.env\""),
    )
    .arg(
      Arg::with_name("token_api")
      .short("a")
      .long("token-api")
      .takes_value(true)
      .validator(verify_target_url)
      .help("API url to retrieve and refresh tokens like \"https://example.com\", where /v1.0/tokens and /v1.0/refresh are used for login and refresh, respectively."),
    )
    .arg(
      Arg::with_name("doh_method_get")
        .short("g")
        .long("use-get-method")
        .help("Use Get method to query"),
    );

  let matches = options.get_matches();

  let listen_addresses: Vec<SocketAddr> = (match matches.values_of("listen_addresses") {
    None => LISTEN_ADDRESSES.to_vec(),
    Some(val) => val.collect(),
  })
  .iter()
  .map(|x| x.parse().unwrap())
  .collect();

  let bootstrap_dns: SocketAddr = matches.value_of("bootstrap_dns").unwrap().parse().unwrap();
  info!("Bootstrap DNS: {:?}", bootstrap_dns);
  let rebootstrap_period_min: u64 = match matches.value_of("rebootstrap_period_min") {
    None => REBOOTSTRAP_PERIOD_MIN,
    Some(s) => {
      let num: u64 = s.parse().unwrap();
      num
    }
  };
  let rebootstrap_period_sec = Duration::from_secs(rebootstrap_period_min * 60);
  info!(
    "Target DoH Address is re-fetched every {:?} min",
    rebootstrap_period_sec.as_secs() / 60
  );

  let doh_target_url: String = matches.value_of("doh_target_url").unwrap().to_string();
  info!("Target DoH URL: {:?}", doh_target_url);

  let doh_timeout_sec = DOH_TIMEOUT_SEC;
  let doh_method = match matches.is_present("doh_method_get") {
    true => {
      info!("Use GET method to query");
      Some(DoHMethod::GET)
    }
    _ => {
      info!("Use POST method to query");
      Some(DoHMethod::POST)
    }
  };

  // If credential exists, authorization header is also enabled.
  // TODO: login password should be stored in keychain access like secure storage rather than dotenv.
  let credential = if let Some(p) = matches.value_of("credential_file_path") {
    let cred_path = env::current_dir()?.join(p);
    dotenv::from_path(cred_path).ok();
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
    let token_api = if let Some(t) = matches.value_of("token_api") {
      t
    } else {
      bail!("Token API must be given when credential file is specified");
    };
    info!("Token API: {}", token_api);
    let validation_key = match env::var("validation_key") {
      Ok(validation_key_path) => match fs::read_to_string(validation_key_path) {
        Ok(content) => content,
        Err(e) => {
          bail!("Valid validation key must be given: {}", e);
        }
      },
      Err(e) => {
        bail!("No validation key path is given in credential file: {}", e);
      }
    };

    Some(Credential::new(
      &username,
      &password,
      &client_id,
      token_api,
      &validation_key,
    ))
  } else {
    None
  };

  let globals = Arc::new(Globals {
    doh_target_url,
    listen_addresses,
    udp_buffer_size: UDP_BUFFER_SIZE,
    udp_channel_capacity: UDP_CHANNEL_CAPACITY,
    udp_timeout: Duration::from_secs(UDP_TIMEOUT_SEC),
    doh_timeout_sec,
    doh_method,
    bootstrap_dns,
    rebootstrap_period_sec,

    runtime_handle,
    // client,
  });

  let globals_cache = Arc::new(RwLock::new(GlobalsCache {
    doh_target_addrs: None,
    doh_client: None,
    credential,
  }));

  Ok((globals, globals_cache))
}
