// Handle packet buffer of DNS message (encode/decode)
use crate::error::*;
use crate::log::*;
use trust_dns_proto::{
  op::{Message, MessageType},
  rr::domain::Name,
  serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};

pub fn is_query(packet_buf: &[u8]) -> Result<Message> {
  is(packet_buf, MessageType::Query)
}

pub fn is_response(packet_buf: &[u8]) -> Result<Message> {
  is(packet_buf, MessageType::Response)
}

fn is(packet_buf: &[u8], mtype: MessageType) -> Result<Message> {
  match decode(packet_buf) {
    Ok(msg) => {
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
    Err(e) => Err(e),
  }
}

pub fn decode(packet_buf: &[u8]) -> Result<Message> {
  let mut dec = BinDecoder::new(packet_buf);
  match Message::read(&mut dec) {
    Ok(res) => Ok(res),
    Err(e) => {
      warn!("Undecodable packet buffer as DNS message: {}", e);
      bail!("Undecodable packet buffer as DNS message");
    }
  }
}

pub fn encode(msg: &Message) -> Result<Vec<u8>> {
  let mut packet_buf: Vec<u8> = Vec::new();
  let mut enc = BinEncoder::new(&mut packet_buf);
  match msg.emit(&mut enc) {
    Ok(_) => Ok(packet_buf),
    Err(e) => {
      warn!("error encoding message request buffer {}", e);
      bail!("error encoding message request buffer");
    }
  }
}

pub fn build_query_message_a(fqdn: &str) -> Result<Message> {
  let qname: Name = Name::from_ascii(fqdn).unwrap();
  let mut query = trust_dns_proto::op::Query::new();
  query.set_name(qname);
  query.set_query_type(trust_dns_proto::rr::record_type::RecordType::A);
  query.set_query_class(trust_dns_proto::rr::dns_class::DNSClass::IN);
  let mut msg = Message::new();
  msg.set_message_type(MessageType::Query);
  msg.add_query(query);
  Ok(msg)
}
