pub use tracing::{error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logger() {
  let global_level_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

  // This limits the logger to emits only this crate with any level, for included crates it will emit only INFO or above level.
  let stdio_layer = fmt::layer()
    .with_line_number(true)
    .with_thread_ids(false)
    .with_thread_names(true)
    .with_target(true)
    .with_level(true)
    .compact()
    .with_filter(tracing_subscriber::filter::filter_fn(move |metadata| {
      metadata
        .target()
        .starts_with(env!("CARGO_PKG_NAME").replace('-', "_").as_str())
        || metadata.level() <= &tracing::Level::INFO
    }));

  let reg = tracing_subscriber::registry().with(global_level_filter).with(stdio_layer);
  reg.init();
}
