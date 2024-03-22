use super::dns_message::{self, Request};
use crate::{error::*, log::*};
use hashlink::{linked_hash_map::RawEntryMut, LinkedHashMap};
use hickory_proto::op::Message;
use tokio::{
  sync::Mutex,
  time::{Duration, Instant},
};

#[derive(Debug, Clone)]
/// Cache object
pub struct CacheObject {
  message: Message,
  create_at: Instant,
  expire_at: Instant,
}

impl CacheObject {
  /// Check if cache object is expired
  pub fn expired(&self) -> bool {
    self.expire_at < Instant::now()
  }
  /// Get message
  pub fn message(&self) -> &Message {
    &self.message
  }
  /// Get expire time
  pub fn expire_at(&self) -> Instant {
    self.expire_at
  }
  #[allow(dead_code)]
  /// Get create time
  pub fn create_at(&self) -> Instant {
    self.create_at
  }
  /// Get remained ttl
  pub fn remained_ttl(&self) -> Duration {
    self.expire_at().saturating_duration_since(Instant::now())
  }
  /// Build a response message from cache object
  pub fn build_response(&self, query_id: u16) -> anyhow::Result<Vec<u8>> {
    let mut cached_msg = self.message().to_owned();
    let remained_ttl = self.remained_ttl().as_secs() as u32;
    // TODO: more efficient way to update ttl
    for record in cached_msg.take_answers() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_answer(record);
    }
    for record in cached_msg.take_additionals() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_additional(record);
    }
    for record in cached_msg.take_name_servers() {
      let mut record = record;
      record.set_ttl(remained_ttl);
      cached_msg.add_name_server(record);
    }
    cached_msg.set_id(query_id);

    dns_message::encode(&cached_msg)
  }
}

#[derive(Debug)]
// DNS response message cache
pub struct Cache {
  pub cache: Mutex<LinkedHashMap<Request, CacheObject>>, // LRU cache
  pub max_size: usize,
}

impl Cache {
  /// Create a new cache
  pub fn new(max_size: usize) -> Self {
    Cache {
      cache: Mutex::new(LinkedHashMap::new()),
      max_size,
    }
  }

  /// Put a response message into cache
  pub async fn put(&self, key: Request, response_message: &Message) -> Result<()> {
    if !((response_message.response_code() == hickory_proto::op::ResponseCode::NoError)
      || (response_message.response_code() == hickory_proto::op::ResponseCode::NXDomain))
    {
      return Ok(());
    }

    // TODO: Override if configured
    let min_ttl = response_message.answers().iter().map(|rr| rr.ttl()).min().unwrap_or(0);
    if min_ttl == 0 {
      return Ok(());
    }

    let now = Instant::now();
    let mut response_message_clone = response_message.clone();
    response_message_clone.set_id(0); // when cache hit, update with given query id to respond
    let cache_object = CacheObject {
      message: response_message_clone,
      create_at: now,
      expire_at: now + Duration::from_secs(min_ttl as u64),
    };

    if self.size().await >= self.max_size {
      let mut lru_cache = self.cache.lock().await;
      lru_cache.pop_front().ok_or(()).map_err(|_| anyhow!("Invalid cache"))?;
      drop(lru_cache);
    }
    let mut lru_cache = self.cache.lock().await;
    lru_cache.insert(key, cache_object);
    drop(lru_cache);
    Ok(())
  }

  /// Get a response message from cache
  pub async fn get(&self, key: &Request) -> Option<CacheObject> {
    let mut lru_cache = self.cache.lock().await;
    let res = match lru_cache.raw_entry_mut().from_key(key) {
      RawEntryMut::Occupied(mut found) => {
        // Cache hit, move entry to the back.
        found.to_back();
        let entry = found.get();
        if !entry.expired() {
          debug!(
            "Found non-expired cached content for {:?} TTL = {:?} (secs)",
            key.0[0].query_name,
            entry.remained_ttl().as_secs()
          );
          Some(entry.to_owned())
        } else {
          debug!("Found cached content but expired for {:?}", key.0[0].query_name,);
          found.remove_entry();
          None
        }
      }
      RawEntryMut::Vacant(_) => None,
    };
    drop(lru_cache);
    res
  }

  /// Get the size of cache
  pub async fn size(&self) -> usize {
    let lru_cache = self.cache.lock().await;
    let res = lru_cache.len();
    drop(lru_cache);
    res
  }

  /// Purges expired entries, returns the number of purged entries
  pub async fn purge_expired_entries(&self) -> usize {
    let lru_cache_clone = self.cache.lock().await.clone();
    let expired = lru_cache_clone.iter().filter(|(_, v)| v.expired()).clone();

    let mut count = 0;
    for entry in expired {
      let mut lru_cache = self.cache.lock().await;
      lru_cache.remove_entry(entry.0);
      drop(lru_cache);

      count += 1;
    }
    // debug!("Purged {} expired entries", count);

    count
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::doh_client::dns_message::build_query_a;
  use hickory_client::{
    client::{AsyncClient, ClientHandle},
    proto::iocompat::AsyncIoTokioAsStd,
    rr::{DNSClass, Name, RecordType},
    tcp::TcpClientStream,
  };
  use std::str::FromStr;
  use tokio::net::TcpStream as TokioTcpStream;

  #[tokio::test]
  async fn test_cache() {
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TokioTcpStream>>::new(([1, 1, 1, 1], 53).into());
    let client = AsyncClient::new(stream, sender, None);
    // await the connection to be established
    let (mut client, bg) = client.await.expect("connection failed");
    tokio::spawn(bg);

    let fqdn1 = "www.google.com.";
    let fqdn2 = "www.facebook.com.";

    // Specify the name, note the final '.' which specifies it's an FQDN
    let name1 = Name::from_str(fqdn1).unwrap();
    let name2 = Name::from_str(fqdn2).unwrap();
    let response1 = client.query(name1, DNSClass::IN, RecordType::A).await.unwrap();
    let response2 = client.query(name2, DNSClass::IN, RecordType::A).await.unwrap();

    let msg1 = Message::from(response1);
    let msg2 = Message::from(response2);

    let query_msg1 = build_query_a(fqdn1).unwrap();
    let query_msg2 = build_query_a(fqdn2).unwrap();
    let rkey1 = Request::try_from(&query_msg1).unwrap();
    let rkey2 = Request::try_from(&query_msg2).unwrap();

    let cache = Cache::new(1);
    cache.put(rkey1.clone(), &msg1).await.unwrap();
    assert!(cache.get(&rkey1).await.is_some());
    cache.put(rkey2.clone(), &msg2).await.unwrap();
    assert!(cache.get(&rkey2).await.is_some());
    assert!(cache.get(&rkey1).await.is_none());
    let mut v2 = cache.get(&rkey2).await.unwrap();
    v2.expire_at = v2.create_at();

    assert!(cache.get(&rkey2).await.is_some());
    let mut lru_cache = cache.cache.lock().await;
    let res = lru_cache.insert(rkey2.clone(), v2.clone());
    drop(lru_cache);

    assert!(res.is_some());
    assert!(cache.get(&rkey2).await.is_none());

    let mut lru_cache = cache.cache.lock().await;
    let _res = lru_cache.insert(rkey2.clone(), v2);
    drop(lru_cache);

    assert_eq!(cache.size().await, 1);
    cache.purge_expired_entries().await;
    assert_eq!(cache.size().await, 0);
  }
}
