mod plugin_block_domains;
mod plugin_override_domains;
mod regexp_vals;

use crate::dns_message::{build_response_given_ipaddr, build_response_nx, QueryKey};
use crate::error::*;
use crate::log::*;
pub use plugin_block_domains::DomainBlockRule;
pub use plugin_override_domains::DomainOverrideRule;
use trust_dns_proto::op::Message;

#[derive(Debug, Clone)]
pub struct QueryPluginExecutionResult {
  pub action: QueryPluginAction,
  pub response_msg: Option<Message>,
}

#[derive(Debug, Clone)]
pub enum QueryPluginAction {
  Blocked,
  Overridden,
  Pass,
}

#[derive(Debug, Clone)]
pub struct QueryPluginsApplied(pub Vec<QueryPlugin>);

impl QueryPluginsApplied {
  pub fn new() -> Self {
    QueryPluginsApplied(Vec::new())
  }

  pub fn add(&mut self, plugin: QueryPlugin) {
    self.0.push(plugin);
  }

  pub fn execute(
    self,
    dns_msg: &Message,
    q_key: &QueryKey,
    min_ttl: u32,
  ) -> Result<QueryPluginExecutionResult> {
    let mut response = QueryPluginExecutionResult {
      action: QueryPluginAction::Pass,
      response_msg: None,
    };

    for plugin in self.0 {
      match plugin {
        QueryPlugin::PluginDomainOverride(override_rule) => {
          if let Some(mapsto) = override_rule.find_mapping(q_key) {
            debug!(
              "[Overridden] {} {:?} {:?} maps to {:?}",
              q_key.query_name, q_key.query_type, q_key.query_class, mapsto.0
            );
            response.action = QueryPluginAction::Overridden;
            response.response_msg = Some(build_response_given_ipaddr(
              dns_msg, q_key, &mapsto.0, min_ttl,
            )?);
            break;
          }
        }
        QueryPlugin::PluginDomainBlock(block_rule) => match block_rule.in_blocklist(q_key) {
          Ok(v) => {
            if v {
              debug!(
                "[Blocked] {} {:?} {:?}",
                q_key.query_name, q_key.query_type, q_key.query_class
              );
              response.action = QueryPluginAction::Blocked;
              response.response_msg = Some(build_response_nx(dns_msg));
            }
          }
          Err(e) => {
            error!("Error while checking if query is blocked: {}", e);
          }
        },
      }
    }
    Ok(response)
  }
}

#[derive(Debug, Clone)]
pub enum QueryPlugin {
  PluginDomainBlock(Box<DomainBlockRule>),
  PluginDomainOverride(Box<DomainOverrideRule>),
}
