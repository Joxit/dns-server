use hickory_client::proto::{
  error::ProtoError,
  h2::{HttpsClientStream, HttpsClientStreamBuilder},
  iocompat::AsyncIoTokioAsStd,
};
use rustls::ClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::warn;

const ALPN_H2: &[u8] = b"h2";

#[derive(Debug, Clone)]
pub enum ClientType {
  CloudFlare,
  Google,
}

impl From<String> for ClientType {
  fn from(value: String) -> Self {
    match value.to_lowercase().as_str() {
      "cloudflare" => ClientType::CloudFlare,
      "google" => ClientType::Google,
      _ => ClientType::CloudFlare,
    }
  }
}

pub async fn get_client(client_type: ClientType) -> Result<HttpsClientStream, ProtoError> {
  let (ip, dns) = match client_type {
    ClientType::CloudFlare => (
      SocketAddr::from(([1, 1, 1, 1], 443)),
      "cloudflare-dns.com".to_string(),
    ),
    ClientType::Google => (
      SocketAddr::from(([8, 8, 8, 8], 443)),
      "dns.google".to_string(),
    ),
  };

  HttpsClientStreamBuilder::with_client_config(Arc::new(client_config_tls12()))
    .build::<AsyncIoTokioAsStd<tokio::net::TcpStream>>(ip, dns)
    .await
}

fn client_config_tls12() -> ClientConfig {
  use rustls::RootCertStore;
  let mut root_store = RootCertStore::empty();
  let (added, ignored) =
    root_store.add_parsable_certificates(&rustls_native_certs::load_native_certs().unwrap());

  if ignored > 0 {
    warn!(
      "failed to parse {} certificate(s) from the native root store",
      ignored
    );
  }

  if added == 0 {
    panic!("no valid certificates found in the native root store");
  }

  let mut client_config = ClientConfig::builder()
    .with_safe_default_cipher_suites()
    .with_safe_default_kx_groups()
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(root_store)
    .with_no_client_auth();

  client_config.alpn_protocols = vec![ALPN_H2.to_vec()];
  client_config
}
