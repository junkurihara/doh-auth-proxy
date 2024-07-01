use super::{
  super::{
    dns_message::{build_response_given_ipaddr, QueryKey},
    error::DohClientError,
  },
  regexp_vals::*,
  QueryManipulation, QueryManipulationResult,
};
use crate::{log::*, QueryManipulationConfig};
use async_trait::async_trait;
use hickory_proto::{op::Message, rr};
use regex::Regex;
use rustc_hash::FxHashMap as HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[async_trait]
impl QueryManipulation for DomainOverrideRule {
  type Error = DohClientError;

  /// Apply query plugin
  async fn apply(&self, query_message: &Message, query_key: &QueryKey) -> Result<QueryManipulationResult, DohClientError> {
    let Some(mapsto) = self.find_mapping(query_key) else {
      return Ok(QueryManipulationResult::PassThrough);
    };
    debug!(
      "[Overridden] {} {:?} {:?} maps to {:?}",
      query_key.query_name, query_key.query_type, query_key.query_class, mapsto.0
    );
    let response_msg = build_response_given_ipaddr(query_message, query_key, &mapsto.0, self.min_ttl)?;
    Ok(QueryManipulationResult::SyntheticResponseOverridden(response_msg))
  }
}

#[derive(Debug, Clone)]
pub struct MapsTo(pub IpAddr);
impl MapsTo {
  pub fn new(override_target: &str) -> Option<MapsTo> {
    // let re_domain = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"$")).unwrap();
    let re_ipv4 = Regex::new(&format!("{}{}{}", r"^", REGEXP_IPV4, r"$")).unwrap();
    let re_ipv6 = Regex::new(&format!("{}{}{}", r"^", REGEXP_IPV6, r"$")).unwrap();

    if re_ipv4.is_match(override_target) {
      if let Ok(ipv4addr) = override_target.parse::<Ipv4Addr>() {
        Some(MapsTo(IpAddr::V4(ipv4addr)))
      } else {
        None
      }
    } else if re_ipv6.is_match(override_target) {
      if let Ok(ipv6addr) = override_target.parse::<Ipv6Addr>() {
        Some(MapsTo(IpAddr::V6(ipv6addr)))
      } else {
        None
      }
    } else {
      None
    }
  }
}

#[derive(Debug, Clone)]
pub struct DomainOverrideRule {
  inner: HashMap<String, Vec<MapsTo>>,
  min_ttl: u32,
}

impl TryFrom<&QueryManipulationConfig> for Option<DomainOverrideRule> {
  type Error = DohClientError;

  fn try_from(config: &QueryManipulationConfig) -> std::result::Result<Self, Self::Error> {
    let Some(config_domain_override) = &config.domain_override else {
      return Ok(None);
    };
    let regex_domain_split_space = Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"\s+\S+$"))?;
    let domain_target_pairs = config_domain_override
      .iter()
      .filter(|x| regex_domain_split_space.is_match(x))
      .map(|x| x.split_whitespace());

    let mut inner: HashMap<String, Vec<MapsTo>> = HashMap::default();
    for domain_target_pair in domain_target_pairs {
      let split: Vec<&str> = domain_target_pair.collect();
      if split.len() != 2 {
        warn!("Invalid override rule: {}", split[0]);
      } else if let Some(maps_to) = MapsTo::new(split[1]) {
        inner.entry(split[0].to_ascii_lowercase()).or_default().push(maps_to);
      }
    }
    Ok(Some(DomainOverrideRule {
      inner,
      min_ttl: config.min_ttl,
    }))
  }
}

impl DomainOverrideRule {
  pub fn find_mapping(&self, q_key: &QueryKey) -> Option<&MapsTo> {
    let q_type = q_key.query_type;
    // remove final dot
    let mut nn = q_key.clone().query_name.to_ascii_lowercase();
    match nn.pop() {
      Some(dot) => {
        if dot != '.' {
          return None;
        }
      }
      None => {
        warn!("Null request!");
        return None;
      }
    }
    // find matches
    if let Some(targets) = self.inner.get(&nn) {
      targets.iter().find(|x| match x {
        MapsTo(IpAddr::V4(_)) => q_type == rr::RecordType::A,
        MapsTo(IpAddr::V6(_)) => q_type == rr::RecordType::AAAA,
      })
    } else {
      None
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn override_works_only_v4() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_override: Some(vec![
        "www.google.com   1.2.3.4".to_string(),
        "www.github.com   4.3.2.1".to_string(),
      ]),
      ..Default::default()
    };

    let domain_override_rule: Option<DomainOverrideRule> = (&query_manipulation_config).try_into().unwrap();
    assert!(domain_override_rule.is_some());
    let domain_override_rule = domain_override_rule.unwrap();

    let mut q_key = QueryKey {
      query_name: "www.google.com.".to_string(),
      query_type: rr::RecordType::A,
      query_class: rr::DNSClass::IN,
    };
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    q_key.query_name = "www.github.com.".to_string();
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1)));

    q_key.query_name = "www.yahoo.com.".to_string();
    assert!(domain_override_rule.find_mapping(&q_key).is_none());
  }

  #[test]
  fn override_works_v4_v6() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_override: Some(vec![
        "www.google.com   1.2.3.4".to_string(),
        "www.google.com   ::1".to_string(),
      ]),
      ..Default::default()
    };

    let domain_override_rule: Option<DomainOverrideRule> = (&query_manipulation_config).try_into().unwrap();
    assert!(domain_override_rule.is_some());
    let domain_override_rule = domain_override_rule.unwrap();

    let mut q_key = QueryKey {
      query_name: "www.google.com.".to_string(),
      query_type: rr::RecordType::A,
      query_class: rr::DNSClass::IN,
    };
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    q_key.query_type = rr::RecordType::AAAA;
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));
    println!("{:?}", domain_override_rule);
  }

  #[test]
  fn override_works_regardless_of_dns0x20() {
    let query_manipulation_config = QueryManipulationConfig {
      domain_override: Some(vec![
        "www.gOOGle.com   1.2.3.4".to_string(),
        "www.google.com   ::1".to_string(),
      ]),
      ..Default::default()
    };

    let domain_override_rule: Option<DomainOverrideRule> = (&query_manipulation_config).try_into().unwrap();
    assert!(domain_override_rule.is_some());
    let domain_override_rule = domain_override_rule.unwrap();

    let q_key = QueryKey {
      query_name: "Www.GOOGLE.coM.".to_string(),
      query_type: rr::RecordType::A,
      query_class: rr::DNSClass::IN,
    };
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
  }
}
