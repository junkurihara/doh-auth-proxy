mod domain_block;
mod domain_override;
mod regexp_vals;

use super::dns_message::QueryKey;
use crate::{error::DapError, QueryManipulationConfig};
use async_trait::async_trait;
use domain_block::DomainBlockRule;
use domain_override::DomainOverrideRule;
use hickory_proto::op::Message;

/// Result of application of query manipulation for a given query
pub enum QueryManipulationResult {
  /// Pass the query with no manipulator application
  PassThrough,
  /// By the query manipulation, synthetic response is generated
  SyntheticResponse(Message),
}

#[async_trait]
/// Query plugin defining trait
pub trait QueryManipulation {
  type Error;

  /// Apply query plugin
  async fn apply(&self, query_message: &Message, query_key: &QueryKey) -> Result<QueryManipulationResult, Self::Error>;
}

/// Query manipulators
pub struct QueryManipulator {
  /// vector of query manipulators
  /// TODO: consider that dynamic dispatch might be slower than enum
  manipulators: Vec<Box<dyn QueryManipulation<Error = DapError> + Send + Sync>>,
}

impl TryFrom<&QueryManipulationConfig> for QueryManipulator {
  type Error = anyhow::Error;
  fn try_from(config: &QueryManipulationConfig) -> std::result::Result<Self, Self::Error> {
    let mut manipulators: Vec<Box<dyn QueryManipulation<Error = DapError> + Send + Sync>> = Vec::new();

    let domain_override_rule: Option<DomainOverrideRule> = config.try_into()?;
    let domain_block_rule: Option<DomainBlockRule> = config.try_into()?;

    if let Some(domain_override) = domain_override_rule {
      manipulators.push(Box::new(domain_override) as Box<dyn QueryManipulation<Error = DapError> + Send + Sync>);
    }
    if let Some(domain_block) = domain_block_rule {
      manipulators.push(Box::new(domain_block) as Box<dyn QueryManipulation<Error = DapError> + Send + Sync>);
    }

    Ok(QueryManipulator { manipulators })
  }
}

impl QueryManipulator {
  /// get manipulator num
  pub fn len(&self) -> usize {
    self.manipulators.len()
  }
  /// check if domain_block_rule is enabled
  pub fn is_domain_block_enabled(&self) -> bool {
    // self.manipulators.iter().any(|m| m<DomainBlockRule>());
    todo!()
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[tokio::test]
  async fn manipulator_works() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_block: Some(vec!["www.google.com".to_string(), "*.google.com".to_string()]),
      domain_override: Some(vec![
        "www.google.com   1.2.3.4".to_string(),
        "www.google.com   ::1".to_string(),
      ]),
      ..Default::default()
    };

    let manipulators: Result<QueryManipulator, _> = (&query_manipulation_config).try_into();

    assert!(manipulators.is_ok());
    let manipulators = manipulators.unwrap();
    assert_eq!(manipulators.len(), 2);
  }
}
