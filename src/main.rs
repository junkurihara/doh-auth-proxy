#[macro_use]
extern crate clap;

mod client;
mod config;
mod constants;
mod counter;
mod credential;
mod dns_message;
mod error;
mod exitcodes;
mod globals;
mod http_bootstrap;
mod log;
mod odoh;
mod proxy;
mod tcpserver;
mod udpserver;
mod utils;
use crate::log::*;
use config::parse_opts;
use proxy::Proxy;
// use std::env;
use std::io::Write;
use tokio;

fn main() {
    // env::set_var("RUST_LOG", "info");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let ts = buf.timestamp();
            writeln!(
                buf,
                "{} [{}] {}",
                ts,
                record.level(),
                // record.target(),
                record.args(),
                // record.file().unwrap_or("unknown"),
                // record.line().unwrap_or(0),
            )
        })
        .init();
    info!("Start DoH w/ Auth Proxy");

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder.enable_all();
    runtime_builder.thread_name("doh-auth-proxy");
    let runtime = runtime_builder.build().unwrap();

    runtime.block_on(async {
        let (globals, globals_cache) = match parse_opts(runtime.handle().clone()).await {
            Ok(g) => g,
            Err(e) => {
                error!("{}", e);
                std::process::exit(exitcodes::EXIT_ON_OPTION_FAILURE);
            }
        };

        let proxy = Proxy {
            globals,
            globals_cache,
        };
        proxy.entrypoint().await.unwrap()
    }); //.unwrap();
}
