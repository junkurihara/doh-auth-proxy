use crate::{config::Opts, constants::QUERY_LOG_EVENT_NAME};
use std::str::FromStr;
pub use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*};

const TOKEN_SERVER_CLIENT_PKG_NAME: &str = "rust-token-server-client";

pub fn init_logger(parsed_opts: &Opts) {
  let level_string = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
  let level = tracing::Level::from_str(level_string.as_str()).unwrap_or(tracing::Level::INFO);

  let passed_pkg_names = [
    env!("CARGO_PKG_NAME").replace('-', "_"),
    TOKEN_SERVER_CLIENT_PKG_NAME.replace('-', "_"),
  ];

  // This limits the logger to emits only this crate with any level, for included crates it will emit only INFO or above level.
  let stdio_layer = fmt::layer()
    .with_line_number(true)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact()
    .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
      (passed_pkg_names
        .iter()
        .any(|pkg_name| metadata.target().starts_with(pkg_name))
        && metadata.level() <= &level)
        || metadata.level() <= &tracing::Level::INFO.min(level)
    }));

  let reg = tracing_subscriber::registry().with(stdio_layer);

  if let Some(query_log_path) = &parsed_opts.query_log_path {
    let query_log_file = open_log_file(query_log_path);
    let query_log_layer_base = fmt::layer()
      .with_line_number(false)
      .with_thread_ids(false)
      .with_thread_names(false)
      .with_target(false)
      .with_level(false);

    if parsed_opts.json_query_log {
      let query_log_layer_base = query_log_layer_base
        .with_timer(fmt::time::ChronoLocal::new("%s".to_string()))
        .json()
        .with_span_list(false)
        .with_current_span(false);
      let reg = reg.with(query_log_layer_base.with_writer(query_log_file).with_filter(QueryLogFilter));
      reg.init();
    } else {
      let query_log_layer_base = query_log_layer_base.compact().with_ansi(false);
      let reg = reg.with(query_log_layer_base.with_writer(query_log_file).with_filter(QueryLogFilter));
      reg.init();
    }
    println!("Query logging is enabled");
    return;
  }
  reg.init();
}

/// Query log filter
struct QueryLogFilter;
impl<S> tracing_subscriber::layer::Filter<S> for QueryLogFilter {
  fn enabled(&self, metadata: &tracing::Metadata<'_>, _: &tracing_subscriber::layer::Context<'_, S>) -> bool {
    metadata
      .target()
      .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
      && metadata.name().contains(QUERY_LOG_EVENT_NAME)
      && metadata.level() <= &tracing::Level::INFO
  }
}

#[inline]
/// Create a file for logging
fn open_log_file(path: &str) -> std::fs::File {
  // crate a file if it does not exist
  std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(path)
    .expect("Failed to open query log file")
}
