use super::constants::*;
use crate::dns_message::QueryKey;
use crate::log::*;
use regex::Regex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use trust_dns_proto::rr::record_type::RecordType;

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
pub struct DomainOverrideRule(HashMap<String, Vec<MapsTo>>);

impl DomainOverrideRule {
  pub fn new(vec_domain_map_str: Vec<&str>) -> DomainOverrideRule {
    let redomain_split_space =
      Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"\s+\S+$")).unwrap();
    let hm: HashMap<String, Vec<MapsTo>> = vec_domain_map_str
      .iter()
      .filter(|x| redomain_split_space.is_match(x)) // filter by primary key (domain)
      .filter_map(|x| {
        let split: Vec<&str> = x.split_whitespace().collect();
        if split.len() != 2 {
          warn!("Invalid override rule: {}", split[0]);
          None
        } else {
          let targets: Vec<MapsTo> = split[1].split(',').filter_map(MapsTo::new).collect();
          let original_len = split[1].split(',').count();
          let res = match original_len == targets.len() {
            true => Some((split[0].to_string(), targets)),
            false => {
              warn!("Invalid override rule: {}", split[0]);
              None
            }
          };
          res
        }
      })
      .collect();
    DomainOverrideRule(hm)
  }

  pub fn find_mapping(&self, q_key: &QueryKey) -> Option<&MapsTo> {
    let q_type = q_key.query_type;
    // remove final dot
    let mut nn = q_key.clone().query_name;
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
    if let Some(targets) = self.0.get(&nn) {
      targets.iter().find(|x| match x {
        MapsTo(IpAddr::V4(_)) => q_type == RecordType::A,
        MapsTo(IpAddr::V6(_)) => q_type == RecordType::AAAA,
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
  fn override_works() {
    let domain_override_rule =
      DomainOverrideRule::new(vec!["www.google.com   1.2.3.4", "www.github.com   4.3.2.1"]);

    let mut q_key = QueryKey {
      query_name: "www.google.com.".to_string(),
      query_type: trust_dns_proto::rr::RecordType::A,
      query_class: trust_dns_proto::rr::DNSClass::IN,
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
}
