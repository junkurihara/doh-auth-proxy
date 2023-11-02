use crate::log::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum CounterType {
  Tcp,
  Udp,
}
impl CounterType {
  fn as_str(&self) -> &'static str {
    match self {
      CounterType::Tcp => "TCP",
      CounterType::Udp => "UDP",
    }
  }
}

#[derive(Debug, Clone, Default)]
/// Connection counter
pub struct ConnCounter {
  pub cnt_total: Arc<AtomicUsize>,
  pub cnt_udp: Arc<AtomicUsize>,
  pub cnt_tcp: Arc<AtomicUsize>,
}

impl ConnCounter {
  pub fn get_current_total(&self) -> usize {
    self.cnt_total.load(Ordering::Relaxed)
  }

  pub fn get_current(&self, ctype: CounterType) -> usize {
    match ctype {
      CounterType::Tcp => self.cnt_tcp.load(Ordering::Relaxed),
      CounterType::Udp => self.cnt_udp.load(Ordering::Relaxed),
    }
  }

  pub fn increment(&self, ctype: CounterType) -> usize {
    self.cnt_total.fetch_add(1, Ordering::Relaxed);
    let c = match ctype {
      CounterType::Tcp => self.cnt_tcp.fetch_add(1, Ordering::Relaxed),
      CounterType::Udp => self.cnt_udp.fetch_add(1, Ordering::Relaxed),
    };

    debug!(
      "{} connection count++: {} (total = {})",
      &ctype.as_str(),
      self.get_current(ctype),
      self.get_current_total()
    );
    c
  }

  pub fn decrement(&self, ctype: CounterType) {
    let cnt;
    match ctype {
      CounterType::Tcp => {
        let res = {
          cnt = self.cnt_tcp.load(Ordering::Relaxed);
          cnt > 0
            && self
              .cnt_tcp
              .compare_exchange(cnt, cnt - 1, Ordering::Relaxed, Ordering::Relaxed)
              != Ok(cnt)
        };
        if res {}
      }
      CounterType::Udp => {
        let res = {
          cnt = self.cnt_udp.load(Ordering::Relaxed);
          cnt > 0
            && self
              .cnt_udp
              .compare_exchange(cnt, cnt - 1, Ordering::Relaxed, Ordering::Relaxed)
              != Ok(cnt)
        };
        if res {}
      }
    };
    self.cnt_total.store(
      self.cnt_udp.load(Ordering::Relaxed) + self.cnt_tcp.load(Ordering::Relaxed),
      Ordering::Relaxed,
    );

    debug!(
      "{} connection count--: {} (total = {})",
      &ctype.as_str(),
      self.get_current(ctype),
      self.get_current_total()
    );
  }
}
