use super::{
  super::{
    dns_message::{build_response_nx, QueryKey},
    error::DohClientError,
  },
  regexp_vals::*,
  QueryManipulation, QueryManipulationResult,
};
use crate::{
  constants::{BLOCK_MESSAGE_HINFO_CPU, BLOCK_MESSAGE_HINFO_OS},
  log::*,
  QueryManipulationConfig,
};
use anyhow::bail;
use async_trait::async_trait;
use cedarwood::Cedar;
use hickory_proto::{op::Message, rr};
use regex::Regex;

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
pub struct DomainBlockRule {
  prefix_cedar: Cedar,
  suffix_cedar: Cedar,
  prefix_dict: Vec<String>,
  suffix_dict: Vec<String>,
}

impl TryFrom<&QueryManipulationConfig> for Option<DomainBlockRule> {
  type Error = DohClientError;
  fn try_from(config: &QueryManipulationConfig) -> std::result::Result<Self, Self::Error> {
    let Some(config_domain_block) = &config.domain_block else {
      return Ok(None);
    };

    let start_with_star = Regex::new(r"^\*\..+").unwrap();
    let end_with_star = Regex::new(r".+\.\*$").unwrap();
    // TODO: currently either one of prefix or suffix match with '*' is supported
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap();
    let dict: Vec<String> = config_domain_block
      .iter()
      .map(|d| if start_with_star.is_match(d) { &d[2..] } else { d })
      .filter(|x| re.is_match(x) || (x.split('.').count() == 1))
      .map(|y| y.to_ascii_lowercase())
      .collect();
    let prefix_dict: Vec<String> = dict
      .iter()
      .filter(|d| end_with_star.is_match(d))
      .map(|d| d[..d.len() - 2].to_string())
      .collect();
    let suffix_dict: Vec<String> = dict
      .iter()
      .filter(|d| !end_with_star.is_match(d))
      .map(|d| reverse_string(d))
      .collect();

    let prefix_kv: Vec<(&str, i32)> = prefix_dict
      .iter()
      .map(AsRef::as_ref)
      .enumerate()
      .map(|(k, s)| (s, k as i32))
      .collect();
    let mut prefix_cedar = Cedar::new();
    prefix_cedar.build(&prefix_kv);

    let suffix_kv: Vec<(&str, i32)> = suffix_dict
      .iter()
      .map(AsRef::as_ref)
      .enumerate()
      .map(|(k, s)| (s, k as i32))
      .collect();
    let mut suffix_cedar = Cedar::new();
    suffix_cedar.build(&suffix_kv);

    Ok(Some(DomainBlockRule {
      prefix_cedar,
      suffix_cedar,
      prefix_dict,
      suffix_dict,
    }))
  }
}

impl DomainBlockRule {
  fn find_suffix_match(&self, query_domain: &str) -> bool {
    let rev_nn = reverse_string(query_domain);
    let matched_items = self
      .suffix_cedar
      .common_prefix_iter(&rev_nn)
      .map(|(x, _)| self.suffix_dict[x as usize].clone());

    let mut matched_as_domain = matched_items.filter(|found| {
      if found.len() == rev_nn.len() {
        true
      } else if let Some(nth) = rev_nn.chars().nth(found.chars().count()) {
        nth.to_string() == "."
      } else {
        false
      }
    });
    matched_as_domain.next().is_some()
  }

  fn find_prefix_match(&self, query_domain: &str) -> bool {
    let matched_items = self
      .prefix_cedar
      .common_prefix_iter(query_domain)
      .map(|(x, _)| self.prefix_dict[x as usize].clone());

    let mut matched_as_domain = matched_items.filter(|found| {
      if let Some(nth) = query_domain.chars().nth(found.chars().count()) {
        nth.to_string() == "."
      } else {
        false
      }
    });
    matched_as_domain.next().is_some()
  }

  pub fn in_blocklist(&self, q_key: &QueryKey) -> anyhow::Result<bool> {
    // remove final dot
    let mut nn = q_key.clone().query_name.to_ascii_lowercase();
    match nn.pop() {
      Some(dot) => {
        if dot != '.' {
          bail!("Invalid query name as fqdn (missing final dot): {}", nn);
        }
      }
      None => {
        bail!("Missing query name");
      }
    }

    if self.find_suffix_match(&nn) {
      debug!("[with cw] suffix/exact match found: {}", nn);
      return Ok(true);
    }

    if self.find_prefix_match(&nn) {
      debug!("[with cw] prefix match found: {}", nn);
      return Ok(true);
    }

    // TODO: other matching patterns

    Ok(false)
  }
}

fn reverse_string(text: &str) -> String {
  text.chars().rev().collect::<String>()
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
