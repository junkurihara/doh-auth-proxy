mod cache;
mod client;
mod config;
mod config_toml;
mod constants;
mod credential;
mod dns_message;
mod error;
mod exitcodes;
mod globals;
mod http_bootstrap;
mod log;
mod odoh;
mod plugins;
mod proxy;
mod servers;
mod utils;
use crate::{config::parse_opts, log::*, proxy::Proxy};
// use std::env;
use std::io::Write;

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
    let globals = match parse_opts(runtime.handle()).await {
      Ok(g) => g,
      Err(e) => {
        error!("{}", e);
        std::process::exit(exitcodes::EXIT_ON_OPTION_FAILURE);
      }
    };

    let proxy = Proxy { globals };
    proxy.entrypoint().await.unwrap()
  });
}
