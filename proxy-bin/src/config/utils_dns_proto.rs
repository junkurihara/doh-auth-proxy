use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const PREFIX_UDP: &str = "udp://";
const PREFIX_TCP: &str = "tcp://";
const DEFAULT_DNS_PORT: u16 = 53;

/// Parse as string in the form of "<proto>://<ip_addr>:<port>", where "<proto>://" can be omitted and then it will be treated as "udp://".
/// ":<port>" can also be omitted and then it will be treated as ":53".
/// - <proto>: "udp" or "tcp"
/// - <ip_addr>: IPv4 or IPv6 address, where IPv6 address must be enclosed in square brackets like "[::1]"
/// - <port>: port number, which must be explicitly specified.
pub(crate) fn parse_proto_sockaddr_str<T: AsRef<str>>(val: T) -> anyhow::Result<(String, SocketAddr)> {
  let val = val.as_ref();

  // parse proto
  let (proto, val_rest) = if val.starts_with(PREFIX_UDP) {
    ("udp", val.strip_prefix(PREFIX_UDP).unwrap())
  } else if val.starts_with(PREFIX_TCP) {
    ("tcp", val.strip_prefix(PREFIX_TCP).unwrap())
  } else {
    ("udp", val)
  };

  // parse socket address
  let socket_addr = if val.contains('[') && val.contains(']') {
    // ipv6
    let mut split = val_rest.strip_prefix('[').unwrap().split(']').filter(|s| !s.is_empty());
    let ip_part = split
      .next()
      .ok_or(anyhow::anyhow!("Invalid IPv6 address specified"))?
      .parse::<Ipv6Addr>()?;
    let port_part = if let Some(port_part) = split.next() {
      anyhow::ensure!(port_part.starts_with(':'), "Invalid port number specified");
      port_part.strip_prefix(':').unwrap().parse::<u16>()?
    } else {
      DEFAULT_DNS_PORT
    };
    SocketAddr::new(IpAddr::V6(ip_part), port_part)
  } else {
    // ipv4
    let mut split = val_rest.split(':').filter(|s| !s.is_empty());
    let ip_part = split
      .next()
      .ok_or(anyhow::anyhow!("Invalid IPv4 address specified"))?
      .parse::<Ipv4Addr>()?;
    let port_part = if let Some(port_part) = split.next() {
      port_part.parse::<u16>()?
    } else {
      DEFAULT_DNS_PORT
    };
    SocketAddr::new(IpAddr::V4(ip_part), port_part)
  };

  Ok((proto.to_owned(), socket_addr))
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_parse_proto_sockaddr_str() {
    let (proto, socket_addr) = parse_proto_sockaddr_str("tcp://[::1]:50053").unwrap();
    assert_eq!(proto, "tcp");
    assert_eq!(socket_addr, SocketAddr::from((Ipv6Addr::LOCALHOST, 50053)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("tcp://[::1]").unwrap();
    assert_eq!(proto, "tcp");
    assert_eq!(socket_addr, SocketAddr::from((Ipv6Addr::LOCALHOST, 53)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("[::1]:50053").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from((Ipv6Addr::LOCALHOST, 50053)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("[::1]").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from((Ipv6Addr::LOCALHOST, 53)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("udp://8.8.8.8:50053").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from(([8, 8, 8, 8], 50053)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("udp://8.8.8.8").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from(([8, 8, 8, 8], 53)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("8.8.8.8:50053").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from(([8, 8, 8, 8], 50053)));

    let (proto, socket_addr) = parse_proto_sockaddr_str("8.8.8.8").unwrap();
    assert_eq!(proto, "udp");
    assert_eq!(socket_addr, SocketAddr::from(([8, 8, 8, 8], 53)));
  }
}
