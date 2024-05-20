use clap::{Arg, ArgAction};

/// Parsed options
pub struct Opts {
  /// Configuration file path
  pub config_file_path: String,
  /// Activate dynamic reloading of the config file via continuous monitoring
  pub watch: bool,
  /// Query log path
  pub query_log_path: Option<String>,
  /// Query log in json format
  pub json_query_log: bool,
}

/// Parse arg values passed from cli
pub fn parse_opts() -> Result<Opts, anyhow::Error> {
  let _ = include_str!("../../Cargo.toml");
  let options = clap::command!()
    .arg(
      Arg::new("config_file")
        .long("config")
        .short('c')
        .value_name("FILE")
        .required(true)
        .help("Configuration file path like ./config.toml"),
    )
    .arg(
      Arg::new("watch")
        .long("watch")
        .short('w')
        .action(ArgAction::SetTrue)
        .help("Activate dynamic reloading of the config file via continuous monitoring"),
    )
    .arg(
      Arg::new("query_log")
        .long("query-log")
        .short('q')
        .value_name("PATH")
        .help("Enable query logging. Unless specified, it is disabled."),
    )
    .arg(
      Arg::new("json_query_log")
        .long("json-query-log")
        .short('j')
        .action(ArgAction::SetTrue)
        .requires("query_log")
        .help("Enable query logging in json format. Unless specified, it is recorded in human-readable compact format. Must be used with --query-log option."),
    );
  let matches = options.get_matches();

  ///////////////////////////////////
  let config_file_path = matches.get_one::<String>("config_file").unwrap().to_owned();
  let watch = matches.get_one::<bool>("watch").unwrap().to_owned();
  let query_log_path = matches.get_one::<String>("query_log").map(|s| s.to_owned());
  let json_query_log = *matches.get_one::<bool>("json_query_log").unwrap_or(&false);

  Ok(Opts {
    config_file_path,
    watch,
    query_log_path,
    json_query_log,
  })
}
