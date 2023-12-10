use clap::{
  builder::{PossibleValue, TypedValueParser, ValueParserFactory},
  Arg, Command,
};
use hickory_server::resolver::config::NameServerConfigGroup;

#[derive(Debug, Clone)]
pub enum ClientType {
  CloudFlare,
  Google,
  CloudFlareTLS,
  GoogleTLS,
  CloudFlareH2,
  GoogleH2,
}

impl Into<NameServerConfigGroup> for ClientType {
  fn into(self) -> NameServerConfigGroup {
    match self {
      ClientType::Google => NameServerConfigGroup::google(),
      ClientType::CloudFlare => NameServerConfigGroup::cloudflare(),
      ClientType::GoogleTLS => NameServerConfigGroup::google_tls(),
      ClientType::CloudFlareTLS => NameServerConfigGroup::cloudflare_tls(),
      ClientType::CloudFlareH2 => NameServerConfigGroup::cloudflare_https(),
      ClientType::GoogleH2 => NameServerConfigGroup::google_https(),
    }
  }
}

#[derive(Clone)]
pub struct ClientTypeParser {}

impl ClientTypeParser {
  pub fn new() -> Self {
    Self {}
  }

  fn possible_vals() -> Vec<&'static str> {
    vec!["cloudflare", "google", "cloudflare:tls", "google:tls", "cloudflare:h2", "google:h2"]
  }
}

impl TypedValueParser for ClientTypeParser {
  type Value = ClientType;

  fn parse_ref(
    &self,
    cmd: &Command,
    arg: Option<&Arg>,
    value: &std::ffi::OsStr,
  ) -> Result<Self::Value, clap::Error> {
    use clap::error::{ContextKind, ContextValue};
    match value.to_string_lossy().to_lowercase().as_str() {
      "cloudflare" => Ok(ClientType::CloudFlare),
      "google" => Ok(ClientType::Google),
      "cloudflare:tls" => Ok(ClientType::CloudFlareTLS),
      "google:tls" => Ok(ClientType::GoogleTLS),
      "cloudflare:h2" => Ok(ClientType::CloudFlareH2),
      "google:h2" => Ok(ClientType::GoogleH2),
      _ => {
        let mut error = clap::Error::new(clap::error::ErrorKind::InvalidValue).with_cmd(cmd);
        error.insert(
          ContextKind::InvalidArg,
          ContextValue::String(arg.unwrap().to_string()),
        );
        error.insert(
          ContextKind::InvalidValue,
          ContextValue::String(value.to_string_lossy().to_string()),
        );
        error.insert(
          ContextKind::ValidValue,
          ContextValue::Strings(
            Self::possible_vals()
              .iter()
              .map(|value| value.to_string())
              .collect(),
          ),
        );
        Err(error)
      }
    }
  }

  fn possible_values(&self) -> Option<Box<dyn Iterator<Item = PossibleValue> + '_>> {
    let vals = Self::possible_vals();
    let values: Vec<PossibleValue> = vals.iter().map(|name| PossibleValue::new(name)).collect();
    Some(Box::new(values.into_iter()))
  }
}

impl ValueParserFactory for ClientType {
  type Parser = ClientTypeParser;
  fn value_parser() -> <Self as ValueParserFactory>::Parser {
    ClientTypeParser::new()
  }
}
