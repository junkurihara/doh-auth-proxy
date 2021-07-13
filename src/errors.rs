use reqwest;
use std::io;

#[derive(Debug)]
pub enum DoHError {
  Io(io::Error),
  Reqwest(reqwest::Error),
  StatusCode(reqwest::StatusCode),
}
