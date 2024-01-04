#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod config;
mod constants;
mod error;
mod log;

use crate::{
  config::{parse_opts, ConfigReloader, TargetConfig},
  constants::CONFIG_WATCH_DELAY_SECS,
  log::*,
};
use doh_auth_proxy_lib::{entrypoint, ProxyConfig};
use hot_reload::{ReloaderReceiver, ReloaderService};

fn main() {
  init_logger();

  let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name("doh-auth-proxy");
  let runtime = runtime_builder.build().unwrap();

  runtime.block_on(async {
    // Initially load options
    let Ok(parsed_opts) = parse_opts() else {
      error!("Invalid toml file");
      std::process::exit(1);
    };

    if !parsed_opts.watch {
      if let Err(e) = proxy_service_without_watcher(&parsed_opts.config_file_path, runtime.handle().clone()).await {
        error!("proxy service existed: {e}");
        std::process::exit(1);
      }
    } else {
      let (config_service, config_rx) = ReloaderService::<ConfigReloader, TargetConfig>::new(
        &parsed_opts.config_file_path,
        CONFIG_WATCH_DELAY_SECS,
        false,
      )
      .await
      .unwrap();

      tokio::select! {
        Err(e) = config_service.start() => {
          error!("config reloader service exited: {e}");
          std::process::exit(1);
        }
        Err(e) = proxy_service_with_watcher(config_rx, runtime.handle().clone()) => {
          error!("proxy service existed: {e}");
          std::process::exit(1);
        }
      }
    }
  });
}

async fn proxy_service_without_watcher(
  config_file_path: &str,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(), anyhow::Error> {
  info!("Start DNS proxy service");
  let config = match TargetConfig::new(config_file_path).await {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid toml file: {e}");
      std::process::exit(1);
    }
  };

  let proxy_conf = match (&config).try_into() as Result<ProxyConfig, anyhow::Error> {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid configuration: {e}");
      return Err(anyhow::anyhow!(e));
    }
  };

  entrypoint(&proxy_conf, &runtime_handle, None)
    .await
    .map_err(|e| anyhow::anyhow!(e))
}

async fn proxy_service_with_watcher(
  mut config_rx: ReloaderReceiver<TargetConfig>,
  runtime_handle: tokio::runtime::Handle,
) -> Result<(), anyhow::Error> {
  info!("Start proxy service with dynamic config reloader");
  // Initial loading
  config_rx.changed().await?;
  let reloaded = config_rx.borrow().clone().unwrap();
  let mut proxy_conf = match (&reloaded).try_into() as Result<ProxyConfig, anyhow::Error> {
    Ok(v) => v,
    Err(e) => {
      error!("Invalid configuration: {e}");
      return Err(anyhow::anyhow!(e));
    }
  };

  // Notifier for proxy service termination
  let term_notify = std::sync::Arc::new(tokio::sync::Notify::new());

  // Continuous monitoring
  loop {
    tokio::select! {
      res = entrypoint(&proxy_conf, &runtime_handle, Some(term_notify.clone())) => {
        error!("proxy entrypoint exited: {}", if res.is_err() { res.unwrap_err().to_string() } else { "".to_string() });
        break;
      }
      _ = config_rx.changed() => {
        if config_rx.borrow().is_none() {
          error!("Something wrong in config reloader receiver");
          break;
        }
        let config_toml = config_rx.borrow().clone().unwrap();
        match (&config_toml).try_into() as Result<ProxyConfig, anyhow::Error> {
          Ok(p) => {
            proxy_conf = p
          },
          Err(e) => {
            error!("Invalid configuration. Configuration does not updated: {e}");
            continue;
          }
        };
        info!("Configuration updated. Terminate all spawned proxy services and force to re-bind TCP/UDP sockets");
        term_notify.notify_waiters();
      }
      else => break
    }
  }

  Err(anyhow::anyhow!("proxy or continuous monitoring service exited"))
}
