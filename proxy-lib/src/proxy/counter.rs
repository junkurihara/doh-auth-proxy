use crate::log::*;
use std::sync::atomic::{AtomicUsize, Ordering};

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

#[derive(Debug, Default)]
/// Connection counter inner that is an increment-only counter
pub struct CounterInner {
  /// total number of incoming connections
  cnt_in: AtomicUsize,
  /// total number of served connections
  cnt_out: AtomicUsize,
}

impl CounterInner {
  /// output difference between cnt_in and cnt_out as current in-flight connection count
  pub fn get_current(&self) -> isize {
    self.cnt_in.load(Ordering::Relaxed) as isize - self.cnt_out.load(Ordering::Relaxed) as isize
  }
  /// increment cnt_in and output current in-flight connection count
  pub fn increment(&self) -> isize {
    let total_in = self.cnt_in.fetch_add(1, Ordering::Relaxed) as isize;
    total_in + 1 - self.cnt_out.load(Ordering::Relaxed) as isize
  }
  /// increment cnt_out and output current in-flight connection count
  pub fn decrement(&self) -> isize {
    let total_out = self.cnt_out.fetch_add(1, Ordering::Relaxed) as isize;
    self.cnt_in.load(Ordering::Relaxed) as isize - total_out - 1
  }
}

#[derive(Debug, Default)]
/// Connection counter
pub struct ConnCounter {
  pub cnt_udp: CounterInner,
  pub cnt_tcp: CounterInner,
}

impl ConnCounter {
  pub fn get_current_total(&self) -> isize {
    self.cnt_tcp.get_current() + self.cnt_udp.get_current()
  }

  pub fn get_current(&self, ctype: CounterType) -> isize {
    match ctype {
      CounterType::Tcp => self.cnt_tcp.get_current(),
      CounterType::Udp => self.cnt_udp.get_current(),
    }
  }

  pub fn increment(&self, ctype: CounterType) -> isize {
    let c = match ctype {
      CounterType::Tcp => self.cnt_tcp.increment(),
      CounterType::Udp => self.cnt_udp.increment(),
    };

    debug!(
      "{} connection count++: {} (total = {})",
      &ctype.as_str(),
      self.get_current(ctype),
      self.get_current_total()
    );
    c
  }

  pub fn decrement(&self, ctype: CounterType) -> isize {
    let c = match ctype {
      CounterType::Tcp => self.cnt_tcp.decrement(),
      CounterType::Udp => self.cnt_udp.decrement(),
    };

    debug!(
      "{} connection count--: {} (total = {})",
      &ctype.as_str(),
      self.get_current(ctype),
      self.get_current_total()
    );
    c
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_counter_inner() {
    let counter = CounterInner::default();
    assert_eq!(counter.get_current(), 0);
    assert_eq!(counter.increment(), 1);
    assert_eq!(counter.get_current(), 1);
    assert_eq!(counter.increment(), 2);
    assert_eq!(counter.get_current(), 2);
    assert_eq!(counter.decrement(), 1);
    assert_eq!(counter.get_current(), 1);
    assert_eq!(counter.decrement(), 0);
    assert_eq!(counter.get_current(), 0);
  }

  #[test]
  fn test_conn_counter() {
    let counter = ConnCounter::default();
    assert_eq!(counter.get_current_total(), 0);
    assert_eq!(counter.get_current(CounterType::Tcp), 0);
    assert_eq!(counter.get_current(CounterType::Udp), 0);
    assert_eq!(counter.increment(CounterType::Tcp), 1);
    assert_eq!(counter.get_current_total(), 1);
    assert_eq!(counter.get_current(CounterType::Tcp), 1);
    assert_eq!(counter.get_current(CounterType::Udp), 0);
    assert_eq!(counter.increment(CounterType::Tcp), 2);
    assert_eq!(counter.get_current_total(), 2);
    assert_eq!(counter.get_current(CounterType::Tcp), 2);
    assert_eq!(counter.get_current(CounterType::Udp), 0);
    assert_eq!(counter.increment(CounterType::Udp), 1);
    assert_eq!(counter.get_current_total(), 3);
    assert_eq!(counter.get_current(CounterType::Tcp), 2);
    assert_eq!(counter.get_current(CounterType::Udp), 1);
    assert_eq!(counter.decrement(CounterType::Tcp), 1);
    assert_eq!(counter.get_current_total(), 2);
    assert_eq!(counter.get_current(CounterType::Tcp), 1);
    assert_eq!(counter.get_current(CounterType::Udp), 1);
    assert_eq!(counter.decrement(CounterType::Tcp), 0);
    assert_eq!(counter.get_current_total(), 1);
    assert_eq!(counter.get_current(CounterType::Tcp), 0);
    assert_eq!(counter.get_current(CounterType::Udp), 1);
    assert_eq!(counter.decrement(CounterType::Udp), 0);
    assert_eq!(counter.get_current_total(), 0);
    assert_eq!(counter.get_current(CounterType::Tcp), 0);
    assert_eq!(counter.get_current(CounterType::Udp), 0);
  }
}
