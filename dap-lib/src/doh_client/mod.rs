mod cache;
mod dns_message;
mod doh_client_healthcheck;
mod doh_client_main;
mod manipulation;
mod odoh;
mod odoh_config_store;
mod path_manage;

pub use doh_client_main::DoHClient;

#[derive(PartialEq, Eq, Debug, Clone)]
/// DoH method, GET or POST
pub enum DoHMethod {
  Get,
  Post,
}

#[derive(Debug, Clone)]
/// DoH type, Standard or Oblivious
pub(super) enum DoHType {
  Standard,
  Oblivious,
}

impl DoHType {
  fn as_str(&self) -> String {
    match self {
      DoHType::Standard => String::from("application/dns-message"),
      DoHType::Oblivious => String::from("application/oblivious-dns-message"),
    }
  }
}
