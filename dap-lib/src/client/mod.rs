mod doh_client_main;

pub use doh_client_main::DoHClient;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DoHMethod {
  Get,
  Post,
}
