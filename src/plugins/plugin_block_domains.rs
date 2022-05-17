use super::constants::*;
use crate::dns_message::QueryKey;
use crate::error::*;
use crate::log::*;
use cedarwood::Cedar;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct DomainBlockRule {
  prefix_cedar: Cedar,
  suffix_cedar: Cedar,
  prefix_dict: Vec<String>,
  suffix_dict: Vec<String>,
}

impl DomainBlockRule {
  pub fn new(vec_domain_str: Vec<&str>) -> DomainBlockRule {
    let start_with_star = Regex::new(r"^\*\..+").unwrap();
    let end_with_star = Regex::new(r".+\.\*$").unwrap();
    // TODO: currently either one of prefix or suffix match with '*' is supported
    let re = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN_OR_PREFIX, r"$")).unwrap();
    let dict: Vec<String> = vec_domain_str
      .iter()
      .map(|d| {
        if start_with_star.is_match(d) {
          &d[2..]
        } else {
          d
        }
      })
      .filter(|x| re.is_match(x) || (x.split('.').count() == 1))
      .map(|y| y.to_string())
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

    DomainBlockRule {
      prefix_cedar,
      suffix_cedar,
      prefix_dict,
      suffix_dict,
    }
  }

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

  pub fn in_blocklist(&self, q_key: &QueryKey) -> Result<bool> {
    // remove final dot
    let mut nn = q_key.clone().query_name;
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
  #[test]
  fn block_works() {
    let domain_block_rule = DomainBlockRule::new(vec!["www.google.com", "*.google.com"]);

    let mut q_key = QueryKey {
      query_name: "invalid.as.fqdn.com".to_string(),
      query_type: trust_dns_proto::rr::RecordType::A,
      query_class: trust_dns_proto::rr::DNSClass::IN,
    };
    assert!(domain_block_rule.in_blocklist(&q_key).is_err());

    q_key.query_name = "wwxx.google.com.".to_string();
    assert!(domain_block_rule.in_blocklist(&q_key).unwrap());

    q_key.query_name = "www.yahoo.com.".to_string();
    assert!(!domain_block_rule.in_blocklist(&q_key).unwrap());
  }
}
