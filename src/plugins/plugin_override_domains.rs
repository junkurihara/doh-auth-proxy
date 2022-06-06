use super::regexp_vals::*;
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

impl From<Vec<&str>> for DomainOverrideRule {
  fn from(vec_domain_map_str: Vec<&str>) -> Self {
    let redomain_split_space =
      Regex::new(&format!("{}{}{}", r"^", REGEXP_DOMAIN, r"\s+\S+$")).unwrap();
    let mut hm: HashMap<String, Vec<MapsTo>> = HashMap::new();
    for domain_target in vec_domain_map_str
      .iter()
      .filter(|x| redomain_split_space.is_match(x))
      .map(|x| x.split_whitespace())
    {
      let split: Vec<&str> = domain_target.collect();
      if split.len() != 2 {
        warn!("Invalid override rule: {}", split[0]);
      } else if let Some(maps_to) = MapsTo::new(split[1]) {
        hm.entry(split[0].to_ascii_lowercase())
          .or_insert(Vec::new())
          .push(maps_to);
      }
    }
    DomainOverrideRule(hm)
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
  fn override_works_only_v4() {
    let domain_override_rule =
      DomainOverrideRule::from(vec!["www.google.com   1.2.3.4", "www.github.com   4.3.2.1"]);

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

  #[test]
  fn override_works_v4_v6() {
    let domain_override_rule =
      DomainOverrideRule::from(vec!["www.google.com   1.2.3.4", "www.google.com   ::1"]);

    let mut q_key = QueryKey {
      query_name: "www.google.com.".to_string(),
      query_type: trust_dns_proto::rr::RecordType::A,
      query_class: trust_dns_proto::rr::DNSClass::IN,
    };
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));

    q_key.query_type = trust_dns_proto::rr::RecordType::AAAA;
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(
      res.unwrap().0,
      IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
    );
    println!("{:?}", domain_override_rule);
  }

  #[test]
  fn override_works_regardless_of_dns0x20() {
    let domain_override_rule = DomainOverrideRule::from(vec!["www.gOOGle.com   1.2.3.4"]);

    let q_key = QueryKey {
      query_name: "Www.GOOGLE.coM.".to_string(),
      query_type: trust_dns_proto::rr::RecordType::A,
      query_class: trust_dns_proto::rr::DNSClass::IN,
    };
    let res = domain_override_rule.find_mapping(&q_key);
    assert!(res.is_some());
    assert_eq!(res.unwrap().0, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
  }
}
