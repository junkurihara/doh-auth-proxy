use async_trait::async_trait;
use hot_reload::*;

// Reloader service handler
pub struct AuthReloader {}

// Reloader trait implementation
#[async_trait]
impl Reload<()> for AuthReloader {
  type Source = ();
  async fn new(source: &Self::Source) -> Result<Self, ReloaderError<()>> {
    Ok(Self {})
  }

  async fn reload(&self) -> Result<Option<()>, ReloaderError<()>> {
    Ok(Some(()))
  }
}
