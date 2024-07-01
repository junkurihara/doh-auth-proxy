use super::{
  error::{DohClientError, DohClientResult},
  DoHType,
};
use crate::globals::Globals;
use itertools::Itertools;
use rand::Rng;
use std::sync::{
  atomic::{AtomicBool, Ordering},
  Arc,
};
use url::Url;

#[derive(Eq, PartialEq, Hash)]
/// scheme
enum Scheme {
  Http,
  Https,
}
impl Scheme {
  pub fn as_str(&self) -> &'static str {
    match self {
      Scheme::Http => "http",
      Scheme::Https => "https",
    }
  }
}
impl TryFrom<&str> for Scheme {
  type Error = DohClientError;
  fn try_from(s: &str) -> DohClientResult<Self> {
    match s {
      "http" => Ok(Self::Http),
      "https" => Ok(Self::Https),
      _ => Err(DohClientError::FailedToBuildDohUrl),
    }
  }
}
#[derive(Eq, PartialEq, Hash)]
/// DoH target resolver
pub struct DoHTarget {
  /// authority like "dns.google:443"
  authority: String,
  /// path like "/dns-query" that must start from "/"
  path: String,
  /// scheme
  scheme: Scheme,
}
impl DoHTarget {
  /// get authority
  pub fn authority(&self) -> &str {
    &self.authority
  }
  /// get scheme
  pub fn scheme(&self) -> &str {
    self.scheme.as_str()
  }
}

/// ODoH and MODoH relay
struct DoHRelay {
  /// authority like "dns.google:443"
  authority: String,
  /// path like "/proxy" that must start from "/"
  path: String,
  /// scheme
  scheme: Scheme,
  /// can be the next hop relay of a client
  can_be_next_hop: bool,
}

/// struct representing a specific path to the target resolver
pub struct DoHPath {
  /// target resolver
  target: Arc<DoHTarget>,
  /// ordered list of relays, the first one must be flagged as can_be_next_hop
  relays: Vec<Arc<DoHRelay>>,
  /// health flag
  is_healthy: IsHealthy,
  /// doh type
  doh_type: DoHType,
}
impl DoHPath {
  /// build url from the path
  pub fn as_url(&self) -> DohClientResult<Url> {
    // standard doh
    match self.doh_type {
      DoHType::Standard => {
        if !self.relays.is_empty() {
          return Err(DohClientError::FailedToBuildDohUrl);
        }
        let mut url = Url::parse(format!("{}://{}", self.target.scheme.as_str(), &self.target.authority).as_str())?;
        url.set_path(&self.target.path);
        Ok(url)
      }
      DoHType::Oblivious => {
        if self.relays.is_empty() || !self.relays[0].can_be_next_hop {
          return Err(DohClientError::FailedToBuildDohUrl);
        }
        let mut url = Url::parse(format!("{}://{}", &self.relays[0].scheme.as_str(), &self.relays[0].authority).as_str())?;
        url.set_path(&self.relays[0].path);
        url
          .query_pairs_mut()
          .append_pair("targethost", self.target.authority.as_str())
          .append_pair("targetpath", self.target.path.as_str());

        // odoh or modoh
        for (idx, relay) in self.relays[1..].iter().enumerate().take(self.relays.len() - 1) {
          url
            .query_pairs_mut()
            .append_pair(format!("relayhost[{}]", idx + 1).as_str(), relay.authority.as_str())
            .append_pair(format!("relaypath[{}]", idx + 1).as_str(), relay.path.as_str());
        }
        Ok(url)
      }
    }
  }

  /// check if the path is looped
  pub fn is_looped(&self) -> bool {
    let mut seen = vec![self.target.authority.clone()];
    for relay in &self.relays {
      if seen.contains(&relay.authority) {
        return true;
      }
      seen.push(relay.authority.clone());
    }
    false
  }

  /// check if the path is healthy
  pub fn is_healthy(&self) -> bool {
    self.is_healthy.get()
  }

  /// flag healthy on
  pub fn make_healthy(&self) {
    self.is_healthy.make_healthy();
  }

  /// flag healthy off
  pub fn make_unhealthy(&self) {
    self.is_healthy.make_unhealthy();
  }

  /// Get target
  pub fn target(&self) -> &Arc<DoHTarget> {
    &self.target
  }
}

/// represents the health of a path
struct IsHealthy(AtomicBool);
impl IsHealthy {
  fn new() -> Self {
    Self(AtomicBool::new(true))
  }
  fn make_healthy(&self) {
    self.0.store(true, Ordering::Relaxed);
  }
  fn make_unhealthy(&self) {
    self.0.store(false, Ordering::Relaxed);
  }
  fn get(&self) -> bool {
    self.0.load(Ordering::Relaxed)
  }
}

/// Manages all possible paths
pub struct DoHPathManager {
  /// all possible paths
  /// first dimension: depends on doh target resolver
  /// second dimension: depends on next-hop relays. for the standard doh, its is one dimensional.
  /// third dimension: actual paths. for the standard doh, its is one dimensional.
  pub(super) paths: Vec<Vec<Vec<Arc<DoHPath>>>>,
  /// target randomization
  target_randomization: bool,
  /// next-hop randomization
  nexthop_randomization: bool,
}
impl DoHPathManager {
  /// get target list
  pub fn targets(&self) -> Vec<Arc<DoHTarget>> {
    self
      .paths
      .iter()
      .map(|per_target| per_target[0][0].target.clone())
      .collect::<Vec<_>>()
  }
  /// get a healthy path according to the randomization policy
  pub fn get_path(&self) -> Option<Arc<DoHPath>> {
    let healthy_paths = self
      .paths
      .iter()
      .map(|per_target| {
        per_target
          .iter()
          .map(|per_next_hop| {
            per_next_hop
              .iter()
              .filter(|path| path.is_healthy())
              .cloned()
              .collect::<Vec<_>>()
          })
          .filter(|per_next_hop| !per_next_hop.is_empty())
          .collect::<Vec<_>>()
      })
      .filter(|per_target| !per_target.is_empty())
      .collect::<Vec<_>>();

    if healthy_paths.is_empty() {
      return None;
    }
    let mut rng = rand::thread_rng();
    let target_idx = if self.target_randomization {
      rng.gen_range(0..healthy_paths.len())
    } else {
      0
    };
    let nexthop_idx = if self.nexthop_randomization {
      rng.gen_range(0..healthy_paths[target_idx].len())
    } else {
      0
    };
    let path_idx = rng.gen_range(0..healthy_paths[target_idx][nexthop_idx].len());
    Some(healthy_paths[target_idx][nexthop_idx][path_idx].clone())
  }

  /// build all possible paths without loop
  pub fn new(globals: &Arc<Globals>) -> DohClientResult<Self> {
    let targets = globals.proxy_config.target_config.doh_target_urls.iter().map(|url| {
      Arc::new(DoHTarget {
        authority: url.authority().to_string(),
        path: url.path().to_string(),
        scheme: Scheme::try_from(url.scheme()).unwrap_or(Scheme::Https),
      })
    });

    // standard doh
    if globals.proxy_config.nexthop_relay_config.is_none() {
      let paths = targets
        .map(|target| {
          vec![vec![Arc::new(DoHPath {
            target,
            relays: vec![],
            is_healthy: IsHealthy::new(),
            doh_type: DoHType::Standard,
          })]]
        })
        .collect::<Vec<_>>();
      return Ok(Self {
        paths,
        target_randomization: globals.proxy_config.target_config.target_randomization,
        nexthop_randomization: false,
      });
    }

    // odoh and modoh
    let nexthop_relay_config = globals.proxy_config.nexthop_relay_config.as_ref().unwrap();
    let nexthops = nexthop_relay_config.odoh_relay_urls.iter().map(|url| {
      Arc::new(DoHRelay {
        authority: url.authority().to_string(),
        path: url.path().to_string(),
        scheme: Scheme::try_from(url.scheme()).unwrap_or(Scheme::Https),
        can_be_next_hop: true,
      })
    });
    let subseq_relay_config = globals.proxy_config.subseq_relay_config.as_ref();
    let subseq_relay_paths = subseq_relay_config.map(|v| {
      let subseq_relays = v.mid_relay_urls.iter().map(|url| {
        Arc::new(DoHRelay {
          authority: url.authority().to_string(),
          path: url.path().to_string(),
          scheme: Scheme::try_from(url.scheme()).unwrap_or(Scheme::Https),
          can_be_next_hop: false,
        })
      });
      let max = v.max_mid_relays.min(subseq_relays.len());
      let mut paths_after_nexthop = vec![];
      (0..max + 1).for_each(|num| {
        let x: Vec<_> = subseq_relays.clone().permutations(num).collect();
        paths_after_nexthop.extend(x);
      });
      paths_after_nexthop
    });
    let relay_paths = nexthops.clone().map(|nexthop| {
      let relays = match &subseq_relay_paths {
        None => vec![vec![nexthop.clone()]],
        Some(subseq_relay_paths) => subseq_relay_paths
          .iter()
          .map(|subseq_relay_path| {
            let mut relays = vec![nexthop.clone()];
            relays.extend(subseq_relay_path.clone());
            relays
          })
          .collect::<Vec<_>>(),
      };
      relays
    });

    // build path object
    let maybe_looped_paths = targets.map(|target| {
      relay_paths
        .clone()
        .map(|relay_path| {
          relay_path
            .iter()
            .map(|relays| {
              Arc::new(DoHPath {
                target: target.clone(),
                relays: relays.clone(),
                is_healthy: IsHealthy::new(),
                doh_type: DoHType::Oblivious,
              })
            })
            .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
    });

    // remove looped paths
    let loop_free_paths = maybe_looped_paths
      .map(|per_target| {
        let loop_free = per_target.iter().map(|per_next_hop| {
          per_next_hop
            .iter()
            .filter(|path| !path.is_looped())
            .cloned()
            .collect::<Vec<_>>()
        });
        loop_free.filter(|per_next_hop| !per_next_hop.is_empty()).collect::<Vec<_>>()
      })
      .filter(|per_target| !per_target.is_empty())
      .collect::<Vec<_>>();

    Ok(Self {
      paths: loop_free_paths,
      target_randomization: globals.proxy_config.target_config.target_randomization,
      nexthop_randomization: nexthop_relay_config.odoh_relay_randomization,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use urlencoding::decode;

  #[tokio::test]
  async fn build_url_works() {
    let target = Arc::new(DoHTarget {
      authority: "dns.google".to_string(),
      path: "/dns-query".to_string(),
      scheme: Scheme::Https,
    });
    let relay1 = Arc::new(DoHRelay {
      authority: "relay1.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: true,
    });
    let relay2 = Arc::new(DoHRelay {
      authority: "relay2.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: false,
    });
    let relay3 = Arc::new(DoHRelay {
      authority: "relay3.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: false,
    });
    let path = Arc::new(DoHPath {
      target,
      relays: vec![relay1, relay2, relay3],
      is_healthy: IsHealthy::new(),
      doh_type: DoHType::Oblivious,
    });
    let url = path.as_url().unwrap();
    let decoded = decode(url.as_str()).unwrap();

    assert_eq!(decoded, "https://relay1.dns.google/proxy?targethost=dns.google&targetpath=/dns-query&relayhost[1]=relay2.dns.google&relaypath[1]=/proxy&relayhost[2]=relay3.dns.google&relaypath[2]=/proxy");
  }

  #[tokio::test]
  async fn is_looped_works() {
    let target = Arc::new(DoHTarget {
      authority: "dns.google".to_string(),
      path: "/dns-query".to_string(),
      scheme: Scheme::Https,
    });
    let relay1 = Arc::new(DoHRelay {
      authority: "relay1.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: true,
    });
    let relay2 = Arc::new(DoHRelay {
      authority: "relay2.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: false,
    });
    let relay3 = Arc::new(DoHRelay {
      authority: "relay3.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: false,
    });
    let mut path = DoHPath {
      target,
      relays: vec![relay1, relay2, relay3],
      is_healthy: IsHealthy::new(),
      doh_type: DoHType::Oblivious,
    };
    assert!(!path.is_looped());

    let relay4 = Arc::new(DoHRelay {
      authority: "relay1.dns.google".to_string(),
      path: "/proxy".to_string(),
      scheme: Scheme::Https,
      can_be_next_hop: true,
    });

    path.relays.push(relay4);
    assert!(path.is_looped());
  }
}
