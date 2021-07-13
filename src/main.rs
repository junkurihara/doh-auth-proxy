#[macro_use]
extern crate clap;

mod bootstrap;
mod client;
mod config;
mod constants;
mod errors;
mod globals;
mod proxy;
mod udpserver;
mod utils;
use crate::constants::*;
use client::DoHClient;
use config::parse_opts;
use globals::Globals;
use log::{debug, error, info, warn};
use proxy::Proxy;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();
    info!("Start DoH w/ Auth Proxy");

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    runtime_builder.thread_name("doh-auth-proxy");
    let runtime = runtime_builder.build().unwrap();

    let bootstrap_dns = BOOTSTRAP_DNS.parse().unwrap();
    let mut globals = Globals {
        doh_target_url: DOH_TARGET_URL.to_string(),
        listen_address: LISTEN_ADDRESS.parse().unwrap(),
        udp_buffer_size: UDP_BUFFER_SIZE,
        udp_channel_capacity: UDP_CHANNEL_CAPACITY,
        udp_timeout: Duration::from_secs(UDP_TIMEOUT_SEC),
        doh_timeout_sec: DOH_TIMEOUT_SEC,
        bootstrap_dns,
        auth_token: None,

        runtime_handle: runtime.handle().clone(),
        client: DoHClient::new(None, None, DOH_TIMEOUT_SEC, bootstrap_dns, DOH_TARGET_URL).unwrap(),
    };

    parse_opts(&mut globals);

    let proxy = Proxy {
        globals: Arc::new(globals),
    };
    runtime.block_on(proxy.entrypoint()).unwrap();
}
