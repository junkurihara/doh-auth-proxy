// functions to verify the startup arguments as correct
use std::net::SocketAddr;
use url::Url;

pub(crate) fn verify_sock_addr(arg_val: String) -> Result<(), String> {
  match arg_val.parse::<SocketAddr>() {
    Ok(_addr) => Ok(()),
    Err(_) => Err(format!(
      "Could not parse \"{}\" as a valid socket address (with port).",
      arg_val
    )),
  }
}

pub(crate) fn verify_target_url(arg_val: String) -> Result<(), String> {
  let url = match Url::parse(&arg_val) {
    Ok(addr) => addr,
    Err(_) => return Err(format!("Could not parse \"{}\" as a valid url.", arg_val)),
  };

  match url.scheme() {
    "http" => (),
    "https" => (),
    _ => return Err("Invalid scheme".to_string()),
  };

  if url.cannot_be_a_base() {
    return Err("Invalid scheme".to_string());
  }
  Ok(())
}
