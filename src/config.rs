use crate::client::{DoHClient, DoHMethod};
use crate::constants::*;
use crate::globals::Globals;
use clap::Arg;
// use log::{debug, error, info, warn};
use std::fs;

pub fn parse_opts(globals: &mut Globals) {
  use crate::utils::{verify_sock_addr, verify_target_url};
  // TODO: Args Optionで上書き

  let _ = include_str!("../Cargo.toml");
  let options = app_from_crate!()
    .arg(
      Arg::with_name("listen_address")
        .short("l")
        .long("listen-address")
        .takes_value(true)
        .default_value(LISTEN_ADDRESS)
        .validator(verify_sock_addr)
        .help("Address to listen to"),
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
  globals.listen_address = matches.value_of("listen_address").unwrap().parse().unwrap();

  globals.doh_target_url = matches.value_of("doh_target_url").unwrap().to_string();

  if let Some(p) = matches.value_of("token_file_path") {
    if let Ok(content) = fs::read_to_string(p) {
      let truncate_vec: Vec<&str> = content.split("\n").collect();
      if truncate_vec.len() > 0 {
        // TODO: validate token as JWT
        globals.auth_token = Some(truncate_vec[0].to_string());
        // override client if token is given
        // TODO: update method
        globals.client = DoHClient::new(
          globals.auth_token.clone(),
          Some(DoHMethod::POST),
          globals.doh_timeout_sec,
        )
        .unwrap();
        // debug!("{:?}", globals.auth_token);
      }
    }
  }
}
