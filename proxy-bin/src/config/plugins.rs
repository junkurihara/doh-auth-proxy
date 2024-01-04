use super::toml::ConfigToml;
use crate::error::*;
use doh_auth_proxy_lib::QueryManipulationConfig;
use std::{env, fs, path::PathBuf};

/// Read query manipulation settings from paths specified in config toml
impl TryFrom<&ConfigToml> for Option<QueryManipulationConfig> {
  type Error = anyhow::Error;

  fn try_from(value: &ConfigToml) -> Result<Self, Self::Error> {
    if value.plugins.is_none() {
      // debug!("Query manipulation plugins are disabled");
      return Ok(None);
    }
    if value.plugins.as_ref().unwrap().domains_overridden_file.is_none()
      && value.plugins.as_ref().unwrap().domains_blocked_file.is_none()
    {
      // debug!("Query manipulation plugins are disabled");
      return Ok(None);
    }

    // debug!("Query manipulation plugins are enabled");
    let plugins = value.plugins.as_ref().unwrap();

    let mut query_manipulation_config = QueryManipulationConfig::default();

    // override
    if let Some(override_path) = &plugins.domains_overridden_file {
      // debug!("Read: Query override plugin");
      let path = Some(env::current_dir()?.join(override_path)).ok_or(anyhow!("Invalid plugin file path"))?;
      query_manipulation_config.domain_override = Some(read_plugin_file(&path)?);
    }
    // block
    if let Some(block_path) = &plugins.domains_blocked_file {
      // debug!("Read: Query block plugin");
      let path = Some(env::current_dir()?.join(block_path)).ok_or(anyhow!("Invalid plugin file path"))?;
      query_manipulation_config.domain_block = Some(read_plugin_file(&path)?);
    }

    Ok(Some(query_manipulation_config))
  }
}

/// Read plugin files
fn read_plugin_file(path: &PathBuf) -> anyhow::Result<Vec<String>> {
  let content = fs::read_to_string(path)?;
  let truncate_vec: Vec<String> = content
    .split('\n')
    .filter(|c| !c.is_empty())
    .map(|v| v.to_string())
    .collect();
  Ok(truncate_vec)
}
