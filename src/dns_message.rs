// Handle packet buffer of DNS message (encode/decode)
use crate::error::*;
use crate::log::*;
use trust_dns_proto::{
  op::Message,
  serialize::binary::{BinDecodable, BinDecoder},
};

pub fn is_query(packet_buf: &[u8]) -> Result<Message> {
  is(packet_buf, trust_dns_proto::op::MessageType::Query)
}

pub fn is_response(packet_buf: &[u8]) -> Result<Message> {
  is(packet_buf, trust_dns_proto::op::MessageType::Response)
}

fn is(packet_buf: &[u8], mtype: trust_dns_proto::op::MessageType) -> Result<Message> {
  match decode(packet_buf) {
    Ok(msg) => {
      if msg.message_type() == mtype {
        Ok(msg)
      } else {
        match mtype {
          trust_dns_proto::op::MessageType::Query => {
            bail!("Not a DNS query, {:?}", msg);
          }
          trust_dns_proto::op::MessageType::Response => {
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
