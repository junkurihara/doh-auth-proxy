// Handle packet buffer of DNS message (encode/decode)
use anyhow::{anyhow, bail};
use hickory_proto::{
  op::{update_message::MAX_PAYLOAD_LEN, Edns, Message, MessageType, OpCode, Query},
  rr::{
    domain::Name,
    rdata::{A, AAAA},
    DNSClass, RData, Record, RecordType,
  },
  serialize::binary::{BinDecodable, BinEncodable},
  xfer::DnsRequestOptions,
};
use std::{net::IpAddr, str::FromStr};

#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
/// QueryKey is a tuple of query name, query type and query class
/// https://github.com/aaronriekenberg/rust-doh-proxy/blob/master/src/doh/request_key.rs
pub struct QueryKey {
  pub query_name: String,
  pub query_type: RecordType,
  pub query_class: DNSClass,
}
#[derive(Debug, Clone, Hash, Eq, PartialEq, Ord, PartialOrd)]
/// Request is a sorted list of QueryKey
pub struct Request(pub Vec<QueryKey>);
impl TryFrom<&Message> for Request {
  type Error = anyhow::Error;

  fn try_from(message: &Message) -> anyhow::Result<Self, Self::Error> {
    let q_num = message.queries().len();
    if q_num == 0 {
      bail!("No query in message");
    }

    let mut query_keys = Vec::with_capacity(q_num);
    for query in message.queries() {
      let mut name_string = query.name().to_string();
      name_string.make_ascii_lowercase();

      query_keys.push(QueryKey {
        query_name: name_string,
        query_type: query.query_type(),
        query_class: query.query_class(),
      });
    }
    query_keys.sort();
    Ok(Request(query_keys))
  }
}

/// Check if the message is a DNS query
pub fn is_query(packet_buf: &[u8]) -> anyhow::Result<Message> {
  is(packet_buf, MessageType::Query)
}

/// Check if the message is a DNS response
pub fn is_response(packet_buf: &[u8]) -> anyhow::Result<Message> {
  is(packet_buf, MessageType::Response)
}

/// Check if the message is a DNS query or response
fn is(packet_buf: &[u8], mtype: MessageType) -> anyhow::Result<Message> {
  let msg = decode(packet_buf)?;
  if msg.message_type() == mtype {
    Ok(msg)
  } else {
    match mtype {
      MessageType::Query => {
        bail!("Not a DNS query, {:?}", msg);
      }
      MessageType::Response => {
        bail!("Not a DNS response, {:?}", msg);
      }
    }
  }
}

/// Decode a DNS message
pub fn decode(packet_buf: &[u8]) -> anyhow::Result<Message> {
  Message::from_bytes(packet_buf).map_err(|e| anyhow!("Undecodable packet buffer as DNS message: {}", e))
}

/// Encode a DNS message
pub fn encode(msg: &Message) -> anyhow::Result<Vec<u8>> {
  msg.to_bytes().map_err(|e| anyhow!("Failed to encode DNS message: {}", e))
}

/// Build a DNS query message for A record
pub fn build_query_a(fqdn: &str) -> anyhow::Result<Message> {
  let qname: Name = Name::from_ascii(fqdn).unwrap();
  let mut query = Query::query(qname, RecordType::A);
  query.set_query_class(DNSClass::IN);

  let options = DnsRequestOptions::default();
  let id: u16 = rand::random();

  let mut msg = Message::new();
  msg
    .add_query(query)
    .set_id(id)
    .set_message_type(MessageType::Query)
    .set_op_code(OpCode::Query)
    .set_recursion_desired(options.recursion_desired);
  if options.use_edns {
    msg
      .extensions_mut()
      .get_or_insert_with(Edns::new)
      .set_max_payload(MAX_PAYLOAD_LEN)
      .set_version(0);
  }
  Ok(msg)
}

/// Build a DNS response message with NXDOMAIN
pub fn build_response_nx(msg: &Message) -> Message {
  let mut res = msg.clone();
  res.set_message_type(hickory_proto::op::MessageType::Response);
  // res.set_response_code(hickory_proto::op::ResponseCode::ServFail);
  res.set_response_code(hickory_proto::op::ResponseCode::NXDomain);
  res
}

/// Build a DNS response message with REFUSED
pub fn build_response_refused(msg: &Message) -> Message {
  let mut res = msg.clone();
  res.set_message_type(hickory_proto::op::MessageType::Response);
  res.set_response_code(hickory_proto::op::ResponseCode::Refused);
  res
}

/// Build a DNS response message for given QueryKey and IP address
pub fn build_response_given_ipaddr(msg: &Message, q_key: &QueryKey, ipaddr: &IpAddr, min_ttl: u32) -> anyhow::Result<Message> {
  let mut res = msg.clone();
  res.set_message_type(hickory_proto::op::MessageType::Response);
  res.set_response_code(hickory_proto::op::ResponseCode::NoError);
  let name = Name::from_str(&q_key.query_name)?;
  match ipaddr {
    IpAddr::V4(ipv4) => {
      res.insert_answers(vec![Record::from_rdata(name, min_ttl, RData::A(A(*ipv4)))]);
    }
    IpAddr::V6(ipv6) => {
      res.insert_answers(vec![Record::from_rdata(name, min_ttl, RData::AAAA(AAAA(*ipv6)))]);
    }
  }
  Ok(res)
}
