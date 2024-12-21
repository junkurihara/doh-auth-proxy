use super::{
  super::{
    dns_message::{build_response_nx, QueryKey},
    error::DohClientError,
  },
  inspect_query_name, QueryManipulation, QueryManipulationResult,
};
use crate::{
  constants::{BLOCK_MESSAGE_HINFO_CPU, BLOCK_MESSAGE_HINFO_OS},
  log::*,
  QueryManipulationConfig,
};
use async_trait::async_trait;
use hickory_proto::{op::Message, rr};
use match_domain::DomainMatchingRule;

#[async_trait]
impl QueryManipulation for DomainBlockRule {
  type Error = DohClientError;

  /// Apply query plugin
  async fn apply(&self, query_message: &Message, query_key: &QueryKey) -> Result<QueryManipulationResult, DohClientError> {
    if !self.in_blocklist(query_key)? {
      return Ok(QueryManipulationResult::PassThrough);
    }
    debug!(
      "[Blocked] {} {:?} {:?}",
      query_key.query_name, query_key.query_type, query_key.query_class
    );
    let response_msg = build_response_block(query_message);
    Ok(QueryManipulationResult::SyntheticResponseBlocked(response_msg))
  }
}

/// Build a synthetic response message for blocked domain
/// By default, NXDOMAIN is returned with block message in HINFO record
fn build_response_block(query_message: &Message) -> Message {
  let mut msg = build_response_nx(query_message);
  let hinfo = rr::rdata::HINFO::new(BLOCK_MESSAGE_HINFO_CPU.to_string(), BLOCK_MESSAGE_HINFO_OS.to_string());
  msg.add_answer(rr::Record::from_rdata(
    query_message.queries()[0].name().clone(),
    0,
    rr::RData::HINFO(hinfo),
  ));
  msg
}

#[derive(Debug, Clone)]
/// DomainBlockRule is a query manipulation rule that blocks queries based on domain matching
pub struct DomainBlockRule {
  /// inner domain matching rule
  inner: DomainMatchingRule,
}

impl TryFrom<&QueryManipulationConfig> for Option<DomainBlockRule> {
  type Error = DohClientError;
  fn try_from(config: &QueryManipulationConfig) -> std::result::Result<Self, Self::Error> {
    let Some(config_domain_block) = &config.domain_block else {
      return Ok(None);
    };
    let inner = DomainMatchingRule::try_from(config_domain_block.as_slice())?;
    Ok(Some(DomainBlockRule { inner }))
  }
}

impl DomainBlockRule {
  /// Check if the query key is in blocklist
  pub fn in_blocklist(&self, q_key: &QueryKey) -> anyhow::Result<bool> {
    // remove final dot and convert to lowercase
    let nn = inspect_query_name(q_key.query_name.as_str())?;
    Ok(self.inner.is_matched(&nn))
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use hickory_proto::rr;

  #[test]
  fn block_works() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_block: Some(vec![
        "www.google.com".to_string(),
        "*.google.com".to_string(),
        "yahoo.co.*".to_string(),
      ]),
      ..Default::default()
    };

    let domain_block_rule: Option<DomainBlockRule> = (&query_manipulation_config).try_into().unwrap();
    assert!(domain_block_rule.is_some());
    let domain_block_rule = domain_block_rule.unwrap();

    let mut q_key = QueryKey {
      query_name: "invalid.as.fqdn.com".to_string(),
      query_type: rr::RecordType::A,
      query_class: rr::DNSClass::IN,
    };
    assert!(domain_block_rule.in_blocklist(&q_key).is_err());

    q_key.query_name = "wwxx.google.com.".to_string();
    assert!(domain_block_rule.in_blocklist(&q_key).unwrap());

    q_key.query_name = "www.yahoo.com.".to_string();
    assert!(!domain_block_rule.in_blocklist(&q_key).unwrap());

    q_key.query_name = "yahoo.co.jp.".to_string();
    assert!(domain_block_rule.in_blocklist(&q_key).unwrap());
  }

  #[test]
  fn block_works_regardless_of_dns0x20() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_block: Some(vec!["GOOGLE.com".to_string()]),
      ..Default::default()
    };

    let domain_block_rule: Option<DomainBlockRule> = (&query_manipulation_config).try_into().unwrap();
    assert!(domain_block_rule.is_some());
    let domain_block_rule = domain_block_rule.unwrap();

    let mut q_key = QueryKey {
      query_name: "www.google.com.".to_string(),
      query_type: rr::RecordType::A,
      query_class: rr::DNSClass::IN,
    };
    assert!(domain_block_rule.in_blocklist(&q_key).unwrap());

    q_key.query_name = "WWW.gOoGlE.COM.".to_string();
    assert!(domain_block_rule.in_blocklist(&q_key).unwrap());
  }
}
