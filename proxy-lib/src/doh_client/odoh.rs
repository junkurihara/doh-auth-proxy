// Based on https://github.com/DNSCrypt/doh-server/blob/master/src/libdoh/src/odoh.rs
use super::error::{DohClientError, DohClientResult};
use crate::log::*;
use bytes::Bytes;
use odoh_rs::{
  parse, ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage, ObliviousDoHMessagePlaintext, OdohSecret,
};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Debug, Clone)]
/// ODoH config
pub struct ODoHConfig {
  #[allow(dead_code)]
  authority: String,
  inner: ObliviousDoHConfigContents,
}

impl ODoHConfig {
  /// Create a new ODoHConfig
  pub fn new(authority: &str, configs_vec: &[u8]) -> DohClientResult<Self> {
    let odoh_configs: ObliviousDoHConfigs = parse(&mut (<&[u8]>::clone(&configs_vec)))?;
    info!("[ODoH] Update ODoH configs: {authority}");
    let client_config = match odoh_configs.into_iter().next() {
      Some(t) => t,
      None => return Err(DohClientError::ODoHNoClientConfig),
    };
    let inner: ObliviousDoHConfigContents = client_config.into();

    Ok(ODoHConfig {
      authority: authority.to_owned(),
      inner,
    })
  }

  /// Encrypt query
  pub fn encrypt_query(&self, plaintext_query: &[u8]) -> DohClientResult<(ObliviousDoHMessagePlaintext, Bytes, OdohSecret)> {
    debug!("[ODoH] Encrypt query");
    let mut rng = StdRng::from_entropy();

    // TODO: Padding bytes should be add? Padding be handled by a client issuing plaintext queries.
    // add a random padding for testing purpose
    // let padding_len = rng.gen_range(0..10);
    // let query = ObliviousDoHMessagePlaintext::new(&plaintext_query, padding_len);
    // debug!("[ODoH] Encrypting DNS message with {} bytes of padding", padding_len);
    let query = ObliviousDoHMessagePlaintext::new(plaintext_query, 0);
    let (query_enc, cli_secret) = odoh_rs::encrypt_query(&query, &self.inner, &mut rng)?;
    let query_body = odoh_rs::compose(&query_enc)?.freeze();
    Ok((query, query_body, cli_secret))
  }

  /// Decrypt response
  pub fn decrypt_response(
    &self,
    plaintext_query: &ObliviousDoHMessagePlaintext,
    encrypted_response: &Bytes,
    client_secret: OdohSecret,
  ) -> DohClientResult<Bytes> {
    debug!("[ODoH] Decrypt query");
    let response_enc: ObliviousDoHMessage = parse(&mut (encrypted_response.clone()))?;
    let response_dec = odoh_rs::decrypt_response(plaintext_query, &response_enc, client_secret)?;
    debug!("[ODoH] Successfully decrypted");

    Ok(response_dec.into_msg())
  }
}
