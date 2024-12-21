use super::{
  super::{
    dns_message::{build_response_given_ipaddr, build_response_refused, QueryKey},
    error::DohClientError,
  },
  inspect_query_name, QueryManipulation, QueryManipulationResult,
};
use crate::{
  constants::{NOT_FORWARDED_MESSAGE_HINFO_CPU, NOT_FORWARDED_MESSAGE_HINFO_OS},
  log::*,
};
use async_trait::async_trait;
use hickory_proto::{op::Message, rr};
use match_domain::DomainMatchingRule;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/* -------------------------------------------------------- */
/// Default not-forwarded domains
const DEFAULT_NOT_FORWARDED_DOMAINS: &[&str] = &[
  // https://www.rfc-editor.org/rfc/rfc9462.html#name-caching-forwarders
  "resolver.arpa",
];
/// Default localhost
const DEFAULT_LOCAL_DOMAINS: &[&str] = &["localhost", "localhost.localdomain"];
/// Default broadcast
const DEFAULT_BROADCAST_DOMAINS: &[&str] = &["broadcasthost"];

#[inline]
fn build_local_v4_response(query_message: &Message, query_key: &QueryKey) -> anyhow::Result<Message> {
  let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
  build_response_given_ipaddr(query_message, query_key, &addr, 0)
}
#[inline]
fn build_local_v6_response(query_message: &Message, query_key: &QueryKey) -> anyhow::Result<Message> {
  let addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
  build_response_given_ipaddr(query_message, query_key, &addr, 0)
}
#[inline]
// only v4
fn build_broadcast_response(query_message: &Message, query_key: &QueryKey) -> anyhow::Result<Message> {
  let addr = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
  build_response_given_ipaddr(query_message, query_key, &addr, 0)
}
/* -------------------------------------------------------- */

#[async_trait]
impl QueryManipulation for DefaultRule {
  type Error = DohClientError;

  /// Apply query plugin
  async fn apply(&self, query_message: &Message, query_key: &QueryKey) -> Result<QueryManipulationResult, DohClientError> {
    let q_name = inspect_query_name(&query_key.query_name)?;

    // Check if the query is for not-forwarded domains
    if self.is_not_forwarded(q_name.as_str())? {
      debug!(
        "[Not-Forwarded] {} {:?} {:?}",
        query_key.query_name, query_key.query_type, query_key.query_class
      );
      let response_msg = build_response_not_forwarded(query_message);
      return Ok(QueryManipulationResult::SyntheticResponseNotForwarded(response_msg));
    }

    // Check if the query is for localhost
    if self.is_localhost(q_name.as_str()) {
      debug!(
        "[LocalHost] {} {:?} {:?}",
        query_key.query_name, query_key.query_type, query_key.query_class
      );

      let response_msg = match query_key.query_type {
        rr::RecordType::A => build_local_v4_response(query_message, query_key)?,
        rr::RecordType::AAAA => build_local_v6_response(query_message, query_key)?,
        _ => build_response_refused(query_message),
      };
      return Ok(QueryManipulationResult::SyntheticResponseDefaultHost(response_msg));
    }

    // Check if the query is for broadcast
    if self.is_broadcast(q_name.as_str()) {
      debug!(
        "[Broadcast] {} {:?} {:?}",
        query_key.query_name, query_key.query_type, query_key.query_class
      );

      let response_msg = match query_key.query_type {
        rr::RecordType::A => build_broadcast_response(query_message, query_key)?,
        _ => build_response_refused(query_message),
      };
      return Ok(QueryManipulationResult::SyntheticResponseDefaultHost(response_msg));
    }

    return Ok(QueryManipulationResult::PassThrough);
  }
}

/// Build a synthetic response message for default not-forwarded domains
fn build_response_not_forwarded(query_message: &Message) -> Message {
  let mut msg = build_response_refused(query_message);
  let hinfo = rr::rdata::HINFO::new(
    NOT_FORWARDED_MESSAGE_HINFO_CPU.to_string(),
    NOT_FORWARDED_MESSAGE_HINFO_OS.to_string(),
  );
  msg.add_answer(rr::Record::from_rdata(
    query_message.queries()[0].name().clone(),
    0,
    rr::RData::HINFO(hinfo),
  ));
  msg
}

#[derive(Debug, Clone)]
/// NotForwardedRule is a query manipulation rule that refuses queries based on domain matching
/// This is a default rule, handling the regulations of IETF RFC
pub struct DefaultRule {
  /// inner domain matching rule
  not_forwarded: DomainMatchingRule,
}

impl DefaultRule {
  /// Create a new NotForwardedRule
  pub fn new() -> Self {
    let not_forwarded = DomainMatchingRule::try_from(DEFAULT_NOT_FORWARDED_DOMAINS).unwrap();
    DefaultRule { not_forwarded }
  }

  /// Check if the query key is in blocklist
  fn is_not_forwarded(&self, q_name: &str) -> anyhow::Result<bool> {
    Ok(self.not_forwarded.is_matched(q_name))
  }

  /// Check if the query key is for localhost
  fn is_localhost(&self, q_name: &str) -> bool {
    DEFAULT_LOCAL_DOMAINS.iter().any(|&d| d.eq(q_name))
  }
  /// Check if the query key is for broadcast
  fn is_broadcast(&self, q_name: &str) -> bool {
    DEFAULT_BROADCAST_DOMAINS.iter().any(|&d| d.eq(q_name))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn default_works() {
    let default_rule = DefaultRule::new();

    assert!(default_rule.is_not_forwarded("resolver.arpa").unwrap());
    assert!(default_rule.is_not_forwarded("_dns.resolver.arpa").unwrap());
    assert!(default_rule.is_localhost("localhost"));
    assert!(default_rule.is_localhost("localhost.localdomain"));
    assert!(!default_rule.is_localhost("localhost.localdomain.com"));
    assert!(!default_rule.is_localhost("x.localhost.localdomain"));
    assert!(default_rule.is_broadcast("broadcasthost"));
    assert!(!default_rule.is_broadcast("broadcasthost.com"));
  }
}
