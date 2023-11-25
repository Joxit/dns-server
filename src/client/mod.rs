use hickory_server::resolver::config::NameServerConfigGroup;

#[derive(Debug, Clone)]
pub enum ClientType {
  CloudFlare,
  Google,
  CloudFlareH2,
  GoogleH2,
}

impl From<String> for ClientType {
  fn from(value: String) -> Self {
    match value.to_lowercase().as_str() {
      "cloudflare" => ClientType::CloudFlare,
      "google" => ClientType::Google,
      "cloudflare:h2" => ClientType::CloudFlareH2,
      "google:h2" => ClientType::GoogleH2,
      _ => ClientType::CloudFlare,
    }
  }
}

impl Into<NameServerConfigGroup> for ClientType {
  fn into(self) -> NameServerConfigGroup {
    match self {
      ClientType::Google => NameServerConfigGroup::google(),
      ClientType::CloudFlare => NameServerConfigGroup::cloudflare(),
      ClientType::CloudFlareH2 => NameServerConfigGroup::cloudflare_https(),
      ClientType::GoogleH2 => NameServerConfigGroup::google_https(),
    }
  }
}
