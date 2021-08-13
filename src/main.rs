#[macro_use]
extern crate clap;

mod bootstrap;
mod client;
mod config;
mod constants;
mod credential;
mod error;
mod exitcodes;
mod globals;
mod proxy;
mod tcpserver;
mod udpserver;
mod utils;
use config::parse_opts;
use log::{debug, error, info, warn};
use proxy::Proxy;
// use std::env;
use tokio;

fn main() {
    // env::set_var("RUST_LOG", "debug");
    env_logger::init();
    info!("Start DoH w/ Auth Proxy");

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    runtime_builder.thread_name("doh-auth-proxy");
    let runtime = runtime_builder.build().unwrap();

    runtime.block_on(async {
        let (globals, globals_cache) = parse_opts(runtime.handle().clone()).await.unwrap();

        let proxy = Proxy {
            globals,
            globals_cache,
        };
        proxy.entrypoint().await.unwrap()
    }); //.unwrap();
}
