use anyhow::{anyhow, bail, Result};
use clap::{
  builder::{PossibleValue, TypedValueParser, ValueParserFactory},
  Arg, Command,
};
use hickory_server::resolver::config::NameServerConfigGroup;
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
      "ipv4:port",
      "[ipv6]:port",
      "ipv4:port:<tls|h2>:domain",
      "[ipv6]:port:<tls|h2>:domain",
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
      s => match ClientType::try_from(s) {
        Ok(client) => Ok(client),
        Err(client_err) => {
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
          if !client_err.to_string().is_empty() {
            error.insert(
              ContextKind::SuggestedValue,
              ContextValue::String(client_err.to_string()),
            );
          }
          Err(error)
        }
      },
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
    let regex =
      Regex::new(r"^((?<ipv4>\d+.\d+.\d+.\d+)|\[(?<ipv6>[a-fA-F0-9:]+)\])(:(?<port>\d+)?:?((?<proto>h2|tls):(?<domain>.*))?)?$")
        .unwrap();
    let Some(caps) = regex.captures(s) else {
      bail!("");
    };

    let ip4: Result<IpAddr> = caps
      .name("ipv4")
      .map_or(Err(anyhow!("IP of the dns server not found")), |ip| {
        Ok(ip.as_str().parse::<Ipv4Addr>()?.into())
      });

    let ip: IpAddr = caps
      .name("ipv6")
      .map_or(ip4, |ip| Ok(ip.as_str().parse::<Ipv6Addr>()?.into()))?;

    let port = caps.name("port").map_or(Ok(None), |port| {
      let p = port.as_str().parse::<u16>()?;
      if p > 0 {
        Ok(Some(p))
      } else {
        Err(anyhow!("Port must be greater than 0. found {}", p))
      }
    })?;

    let proto = caps
      .name("proto")
      .map_or(None, |proto| Some(proto.as_str()));

    let domain = caps
      .name("domain")
      .map_or(None, |domain| Some(domain.as_str().to_string()));

    match proto {
      Some("tls") => Ok(ClientType::CustomTLS(
        ip,
        domain.ok_or_else(|| anyhow!("No domain found for TLS connection."))?,
        port.unwrap_or(853),
      )),
      Some("h2") => Ok(ClientType::CustomH2(
        ip,
        domain.ok_or_else(|| anyhow!("No domain found for TLS connection."))?,
        port.unwrap_or(443),
      )),
      None => Ok(ClientType::CustomDNS(ip, port.unwrap_or(53))),
      _ => bail!("The protocol {} is not supported", proto.unwrap()),
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  fn ipv4(ip: &str) -> IpAddr {
    IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap())
  }
  fn ipv6(ip: &str) -> IpAddr {
    IpAddr::V6(ip.parse::<Ipv6Addr>().unwrap())
  }

  #[test]
  pub fn covert_custom_dns() {
    let ip4 = ClientType::try_from("1.1.1.1");
    let ip4_port = ClientType::try_from("1.1.1.1:1053");
    let ip6 = ClientType::try_from("[2606:4700:4700::1111]");
    let ip6_port = ClientType::try_from("[2606:4700:4700::1111]:1053");

    assert!(ip4.is_ok());
    assert!(ip4_port.is_ok());
    assert!(ip6.is_ok());
    assert!(ip6_port.is_ok());

    assert_eq!(ip4.unwrap(), ClientType::CustomDNS(ipv4("1.1.1.1"), 53));
    assert_eq!(
      ip4_port.unwrap(),
      ClientType::CustomDNS(ipv4("1.1.1.1"), 1053)
    );
    assert_eq!(
      ip6.unwrap(),
      ClientType::CustomDNS(ipv6("2606:4700:4700::1111"), 53)
    );
    assert_eq!(
      ip6_port.unwrap(),
      ClientType::CustomDNS(ipv6("2606:4700:4700::1111"), 1053)
    );

    assert!(ClientType::try_from("1.1.1.1:-53").is_err());
    assert!(ClientType::try_from("1.1.1.1:0").is_err());
    assert!(ClientType::try_from("2606:4700:4700::111").is_err());
    assert!(ClientType::try_from("6:4:4:2:1").is_err());
    assert!(ClientType::try_from("example.com:53").is_err());
    assert!(ClientType::try_from("example.com").is_err());
    assert!(ClientType::try_from("256.255.254.253").is_err());
  }

  #[test]
  pub fn covert_custom_tls() {
    let cloudflare = "cloudflare-dns.com";
    let ip4 = ClientType::try_from("1.1.1.1:tls:cloudflare-dns.com");
    let ip4_port = ClientType::try_from("1.1.1.1:1853:tls:cloudflare-dns.com");
    let ip6 = ClientType::try_from("[2606:4700:4700::1111]:tls:cloudflare-dns.com");
    let ip6_port = ClientType::try_from("[2606:4700:4700::1111]:1853:tls:cloudflare-dns.com");

    assert!(ip4.is_ok());
    assert!(ip4_port.is_ok());

    assert_eq!(
      ip4.unwrap(),
      ClientType::CustomTLS(ipv4("1.1.1.1"), cloudflare.to_string(), 853)
    );
    assert_eq!(
      ip4_port.unwrap(),
      ClientType::CustomTLS(ipv4("1.1.1.1"), cloudflare.to_string(), 1853)
    );
    assert_eq!(
      ip6.unwrap(),
      ClientType::CustomTLS(ipv6("2606:4700:4700::1111"), cloudflare.to_string(), 853)
    );
    assert_eq!(
      ip6_port.unwrap(),
      ClientType::CustomTLS(ipv6("2606:4700:4700::1111"), cloudflare.to_string(), 1853)
    );

    assert!(ClientType::try_from("1.1.1.1:853:tls").is_err());
    assert!(ClientType::try_from("1.1.1.1:-853:tls:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("1.1.1.1:0:tls:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("example.com:853:tls:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("example.com:tls:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("256.255.254.253:tls:cloudflare-dns.com").is_err());
  }

  #[test]
  pub fn covert_custom_h2() {
    let cloudflare = "cloudflare-dns.com";
    let ip4 = ClientType::try_from("1.1.1.1:h2:cloudflare-dns.com");
    let ip4_port = ClientType::try_from("1.1.1.1:1443:h2:cloudflare-dns.com");
    let ip6 = ClientType::try_from("[2606:4700:4700::1111]:h2:cloudflare-dns.com");
    let ip6_port = ClientType::try_from("[2606:4700:4700::1111]:1443:h2:cloudflare-dns.com");

    assert!(ip4.is_ok());
    assert!(ip4_port.is_ok());

    assert_eq!(
      ip4.unwrap(),
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare.to_string(), 443)
    );
    assert_eq!(
      ip4_port.unwrap(),
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare.to_string(), 1443)
    );
    assert_eq!(
      ip6.unwrap(),
      ClientType::CustomH2(ipv6("2606:4700:4700::1111"), cloudflare.to_string(), 443)
    );
    assert_eq!(
      ip6_port.unwrap(),
      ClientType::CustomH2(ipv6("2606:4700:4700::1111"), cloudflare.to_string(), 1443)
    );

    assert!(ClientType::try_from("1.1.1.1:443:h2").is_err());
    assert!(ClientType::try_from("1.1.1.1:-443:h2:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("1.1.1.1:0:h2:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("6:4700:4700::111:h2:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("example.com:443:h2:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("example.com:h2:cloudflare-dns.com").is_err());
    assert!(ClientType::try_from("256.255.254.253:h2:cloudflare-dns.com").is_err());
  }
}
