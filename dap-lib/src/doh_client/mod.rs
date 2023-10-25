mod doh_client_healthcheck;
mod doh_client_main;
mod odoh_config_service;
mod path_manage;

pub use doh_client_main::DoHClient;

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum DoHMethod {
  Get,
  Post,
}
