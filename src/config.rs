use crate::client::DoHMethod;
use crate::config_toml::ConfigToml;
use crate::constants::*;
use crate::credential::Credential;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use crate::log::*;
use clap::Arg;
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
  // TODO: According to the suggestion in "Designing for Tussle in Encrypted DNS" (HotNets'21),
  // multiple (O)DoH servers should be specified and used in randomized fashion in this proxy.
  // To this end, 'Global' objects should have Vec<DoHClient> object as clients configured with different target servers.
  // TODO: This also should be applied for "multiple relays". reconsider how to store Vec<DoHClient> in global config.

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
        .multiple(true)
        .default_value(DOH_TARGET_URL)
        .validator(verify_target_url)
        .help("URL of (O)DoH target server like \"https://dns.google/dns-query\". You can specify multiple servers by repeatedly set this option, then one of given servers is randomly chosen every time."),
    )
    .arg(
      Arg::with_name("odoh_relay_url")
        .short("r")
        .long("relay-url")
        .takes_value(true)
        .multiple(true)
        .validator(verify_target_url)
        .number_of_values(1)
        .help("URL of ODoH nexthop relay server like \"https://relay.example.com/relay\"")
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
    )
    .arg(
      Arg::with_name("mid_relay_url")
        .short("m")
        .long("mid-relay-url")
        .takes_value(true)
        .multiple(true)
        .validator(verify_target_url)
        .number_of_values(1)
        .help("URL of multiple-relay-based ODoH's intermediate relay like \"https://relay.example.com/inter-relay\"")
    )
    .arg(
      Arg::with_name("max_mid_relays")
        .short("n")
        .long("max-mid-relays")
        .takes_value(true)
        .default_value("0")
        .help("Maximum number of intermediate relays between nexthop and target"),
    )
    .arg(
      Arg::with_name("config_file")
      .long("config")
      .takes_value(true)
      .help("Configuration file path like \"doh-auth-proxy.toml\""),
    );

  let matches = options.get_matches();

  /////////////////////////////
  // reading toml file first //
  /////////////////////////////
  if let Some(file_path) = matches.value_of("config_file") {
    let parsed_toml = ConfigToml::new(file_path);
    println!("{:#?}", parsed_toml);
  }
  let target_randomization = true;
  let odoh_relay_randomization = true;
  /////////////////////////////

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

  let doh_target_urls: Vec<String> = matches
    .values_of("doh_target_url")
    .unwrap()
    .map(|x| x.to_string())
    .collect();
  info!("Target (O)DoH resolvers: {:?}", doh_target_urls);

  let doh_method = match matches.is_present("doh_method_get") {
    true => {
      info!("Use GET method to query");
      Some(DoHMethod::Get)
    }
    _ => {
      info!("Use POST method to query");
      Some(DoHMethod::Post)
    }
  };

  let odoh_relay_urls: Option<Vec<String>> = match matches.values_of("odoh_relay_url") {
    Some(s) => {
      info!("[ODoH] Oblivious DNS over HTTPS is enabled");
      info!(
        "[ODoH] Nexthop relay URL: {:?}",
        s.clone().collect::<Vec<&str>>()
      );
      Some(s.map(|x| x.to_string()).collect())
    }
    None => None,
  };

  let mid_relay_urls: Option<Vec<String>> = matches
    .values_of("mid_relay_url")
    .map(|s| s.map(|x| x.to_string()).collect());
  let max_mid_relays = match matches.value_of("max_mid_relays") {
    None => {
      if mid_relay_urls.is_some() {
        1usize
      } else {
        0usize
      }
    }
    Some(s) => s.parse().unwrap(),
  };

  if mid_relay_urls.is_some() {
    info!("[m-ODoH] Multiple-relay-based Oblivious DNS over HTTPS is enabled");
    info!(
      "[m-ODoH] Intermediate relay URLs employed after the next hop: {:?}",
      mid_relay_urls.clone().unwrap()
    );
    info!(
      "[m-ODoH] Maximum number of intermediate relays after the nexthop: {}",
      max_mid_relays
    );
  }

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

  if let (Some(_), Some(_)) = (&credential, &odoh_relay_urls) {
    warn!("-----------------------------------");
    warn!("[NOTE!!!!] Both credential and ODoH nexthop proxy is set up.");
    warn!("[NOTE!!!!] This means the authorization token will be sent not to the target but to the proxy.");
    warn!("[NOTE!!!!] Check if this is your intended behavior.");
    warn!("-----------------------------------");
  } else if let (Some(_), None) = (&credential, &odoh_relay_urls) {
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

    doh_target_urls,
    target_randomization,
    doh_method,
    odoh_relay_urls,
    odoh_relay_randomization,
    mid_relay_urls,
    max_mid_relays,
    bootstrap_dns,
    rebootstrap_period_sec,

    max_connections: MAX_CONNECTIONS,
    counter: Default::default(),
    runtime_handle,
  });

  let globals_cache = Arc::new(RwLock::new(GlobalsCache {
    doh_clients: None,
    credential,
  }));

  Ok((globals, globals_cache))
}
