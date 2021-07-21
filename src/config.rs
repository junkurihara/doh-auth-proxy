use crate::client::{DoHClient, DoHMethod};
use crate::constants::*;
use crate::error::*;
use crate::globals::{Globals, GlobalsCache};
use clap::Arg;
use tokio::runtime::Handle;
// use log::{debug, error, info, warn};
use std::fs;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

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
      Arg::with_name("token_file_path")
        .short("s")
        .long("token-file-path")
        .takes_value(true)
        .help("JWT file path like \"./token.example\""),
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
  let rebootstrap_period_min: u64 = match matches.value_of("rebootstrap_period_min") {
    None => REBOOTSTRAP_PERIOD_MIN,
    Some(s) => {
      let num: u64 = s.parse().unwrap();
      num
    }
  };
  let doh_target_url: String = matches.value_of("doh_target_url").unwrap().to_string();

  let doh_timeout_sec = DOH_TIMEOUT_SEC;
  let doh_method = Some(DoHMethod::POST); //TODO: update method

  let auth_token: Option<String> = match matches.value_of("token_file_path") {
    Some(p) => {
      match fs::read_to_string(p) {
        Ok(content) => {
          let truncate_vec: Vec<&str> = content.split("\n").collect();
          if truncate_vec.len() > 0 {
            // TODO: validate token as JWT
            Some(truncate_vec[0].to_string())
          } else {
            None
          }
        }
        Err(_) => None,
      }
    }
    None => None,
  };

  let rebootstrap_period_sec = Duration::from_secs(rebootstrap_period_min * 60);

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
    auth_token,

    runtime_handle,
    // client,
  });

  let (client, target_addrs) = DoHClient::new(globals.clone()).await?;
  // debug!("{:?}", globals.auth_token);

  let globals_cache = Arc::new(RwLock::new(GlobalsCache {
    doh_target_addrs: target_addrs,
    doh_client: client,
  }));

  Ok((globals, globals_cache))
}
