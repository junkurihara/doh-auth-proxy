mod domain_block;
mod domain_override;
mod regexp_vals;

use super::dns_message::QueryKey;
use async_trait::async_trait;
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

// pub struct QueryManipulator {
//   manipulators: Vec<Box<dyn QueryManipulation<Error = anyhow::Error> + Send + Sync>>,
// }
