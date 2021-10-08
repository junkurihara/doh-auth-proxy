use crate::client::DoHMethod;
use crate::constants::*;
use crate::credential::Credential;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::log::*;
use clap::Arg;
use dotenv;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::RwLock;

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
        .help("URL of (O)DoH target server like \"https://dns.google/dns-query\""),
    )
    .arg(
      Arg::with_name("odoh_relay_url")
        .short("r")
        .long("relay-url")
        .takes_value(true)
        .validator(verify_target_url)
        .help("URL of ODoH relay server like \"https://relay.example.com/relay\"")
    )
    .arg(
      Arg::with_name("credential_file_path")
      .short("c")
      .long("credential-file-path")
      .takes_value(true)
      .help("Credential env file path for login endpoint like \"./credential.env\"")
    )
    .arg(
      Arg::with_name("token_api")
      .short("a")
      .long("token-api")
      .takes_value(true)
      .validator(verify_target_url)
      .help("API url to retrieve and refresh tokens and validation keys (jwks) like \"https://example.com/v1.0\", where /tokens and /refresh are used for login and refresh, respectively. Also /jwks is used for jwks retrieval.")
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
  info!("Target DoH URL: {}", doh_target_url);

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

  let odoh_relay_url: Option<String> = match matches.value_of("odoh_relay_url") {
    Some(s) => {
      info!("[ODoH] Oblivious DNS over HTTPS is enabled");
      Some(s.to_string())
    }
    None => None,
  };

  // If credential exists, authorization header is also enabled.
  // TODO: login password should be stored in keychain access like secure storage rather than dotenv.
  let credential = if let Some(p) = matches.value_of("credential_file_path") {
    let cred_path = env::current_dir()?.join(p);
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
    let token_api = if let Some(t) = matches.value_of("token_api") {
      t
    } else {
      bail!("Token API must be given when credential file is specified");
    };
    info!("Token API: {}", token_api);

    Some(Credential::new(&username, &password, &client_id, token_api))
  } else {
    None
  };

  ////////////////////////

  if let (Some(_), Some(_)) = (&credential, &odoh_relay_url) {
    warn!("-----------------------------------");
    warn!("[NOTE!!!!] Both credential and ODoH proxy is set up.");
    warn!("[NOTE!!!!] This means the authorization token will be sent not to target but to proxy.");
    warn!("[NOTE!!!!] Check if this is your intended behavior.");
    warn!("-----------------------------------");
  } else if let (Some(_), None) = (&credential, &odoh_relay_url) {
    warn!("-----------------------------------");
    warn!("[NOTE!!!!] Authorization token will be sent to the target server!");
    warn!("[NOTE!!!!] Check if this is your intended behavior.");
    warn!("-----------------------------------");
  }
  ////////////////////////

  let globals = Arc::new(Globals {
    listen_addresses,
    udp_buffer_size: UDP_BUFFER_SIZE,
    udp_channel_capacity: UDP_CHANNEL_CAPACITY,
    timeout_sec: Duration::from_secs(TIMEOUT_SEC),

    doh_target_url,
    doh_method,
    odoh_relay_url,
    bootstrap_dns,
    rebootstrap_period_sec,

    max_connections: MAX_CONNECTIONS,
    counter: Default::default(),
    runtime_handle,
  });

  let globals_cache = Arc::new(RwLock::new(GlobalsCache {
    doh_client: None,
    credential,
  }));

  Ok((globals, globals_cache))
}
