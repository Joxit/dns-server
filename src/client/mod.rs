use anyhow::{anyhow, bail, Result};
use clap::{
  builder::{PossibleValue, TypedValueParser, ValueParserFactory},
  Arg, Command,
};
use hickory_server::resolver::config::NameServerConfigGroup;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
  CloudFlare,
  Google,
  CloudFlareTLS,
  GoogleTLS,
  CloudFlareH2,
  GoogleH2,
  CustomDNS(IpAddr, u16),
  CustomTLS(IpAddr, String, u16),
  CustomH2(IpAddr, String, u16),
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
      ClientType::CustomDNS(ip, port) => NameServerConfigGroup::from_ips_clear(&[ip], port, true),
      ClientType::CustomTLS(ip, domain, port) => {
        NameServerConfigGroup::from_ips_tls(&[ip], port, domain, true)
      }
      ClientType::CustomH2(ip, domain, port) => {
        NameServerConfigGroup::from_ips_https(&[ip], port, domain, true)
      }
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
    vec![
      "cloudflare",
      "google",
      "cloudflare:tls",
      "google:tls",
      "cloudflare:h2",
      "google:h2",
    ]
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

impl TryFrom<&str> for ClientType {
  type Error = anyhow::Error;

  fn try_from(s: &str) -> Result<ClientType, Self::Error> {
    let regex = Regex::new(r"^(?<ip>\d+.\d+.\d+.\d+)(:(?<port>\d+)?)?$").unwrap();
    let Some(caps) = regex.captures(s) else {
      bail!("The option is not recognized");
    };
    let ip: IpAddr = caps
      .name("ip")
      .map_or(Err(anyhow!("IP of the dns server not found")), |ip| {
        Ok(ip.as_str().parse::<Ipv4Addr>()?.into())
      })?;

    let port = caps.name("port").map_or(Ok(None), |port| {
      let p = port.as_str().parse::<u16>()?;
      if p > 0 {
        Ok(Some(p))
      } else {
        Err(anyhow!("Port must be greater than 0. found {}", p))
      }
    })?;

    Ok(ClientType::CustomDNS(ip, port.unwrap_or(53)))
  }
}

#[cfg(test)]
mod test {
  use super::*;

  fn ipv4(ip: &str) -> IpAddr {
    IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap())
  }

  #[test]
  pub fn covert_custom_dns() {
    let ip = ClientType::try_from("1.1.1.1");
    let ip_port = ClientType::try_from("1.1.1.1:1053");

    assert!(ip.is_ok());
    assert!(ip_port.is_ok());

    assert_eq!(ip.unwrap(), ClientType::CustomDNS(ipv4("1.1.1.1"), 53));
    assert_eq!(
      ip_port.unwrap(),
      ClientType::CustomDNS(ipv4("1.1.1.1"), 1053)
    );

    assert!(ClientType::try_from("1.1.1.1:-53").is_err());
    assert!(ClientType::try_from("1.1.1.1:0").is_err());
    assert!(ClientType::try_from("example.com:53").is_err());
    assert!(ClientType::try_from("example.com").is_err());
    assert!(ClientType::try_from("256.255.254.253").is_err());
  }
}
