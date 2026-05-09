use anyhow::{anyhow, bail, ensure, Result};
use clap::{
  builder::{PossibleValue, TypedValueParser, ValueParserFactory},
  Arg, Command,
};
use hickory_server::resolver::config::{ConnectionConfig, NameServerConfig, CLOUDFLARE, GOOGLE};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum ClientType {
  CloudFlare,
  Google,
  CloudFlareTLS,
  GoogleTLS,
  CloudFlareH2,
  GoogleH2,
  CloudFlareH3,
  GoogleH3,
  CloudFlareQuic,
  GoogleQuic,
  CustomDNS(IpAddr, u16),
  CustomTLS(IpAddr, String, u16),
  CustomH2(IpAddr, String, Option<Arc<str>>, u16),
  CustomH3(IpAddr, String, Option<Arc<str>>, u16),
  CustomQuic(IpAddr, String, u16),
}

impl Into<Vec<NameServerConfig>> for ClientType {
  fn into(self) -> Vec<NameServerConfig> {
    match self {
      ClientType::Google => GOOGLE.udp().collect(),
      ClientType::CloudFlare => CLOUDFLARE.udp().collect(),
      ClientType::GoogleTLS => GOOGLE.tls().collect(),
      ClientType::CloudFlareTLS => CLOUDFLARE.tls().collect(),
      ClientType::CloudFlareH2 => CLOUDFLARE.https().collect(),
      ClientType::GoogleH2 => GOOGLE.https().collect(),
      ClientType::CloudFlareH3 => CLOUDFLARE.h3().collect(),
      ClientType::GoogleH3 => GOOGLE.h3().collect(),
      ClientType::CloudFlareQuic => CLOUDFLARE.quic().collect(),
      ClientType::GoogleQuic => GOOGLE.quic().collect(),
      ClientType::CustomDNS(ip, port) => {
        let mut connection = ConnectionConfig::udp();
        connection.port = port;
        let mut name_server = NameServerConfig::udp(ip);
        name_server.connections = vec![connection];
        vec![name_server]
      }
      ClientType::CustomTLS(ip, domain, port) => {
        let mut connection = ConnectionConfig::tls(domain.clone().into());
        connection.port = port;
        let mut name_server = NameServerConfig::tls(ip, domain.into());
        name_server.connections = vec![connection];
        vec![name_server]
      }
      ClientType::CustomH2(ip, domain, path, port) => {
        let mut connection = ConnectionConfig::https(domain.clone().into(), path.clone());
        connection.port = port;
        let mut name_server = NameServerConfig::https(ip, domain.into(), path);
        name_server.connections = vec![connection];
        vec![name_server]
      }
      ClientType::CustomH3(ip, domain, path, port) => {
        let mut connection = ConnectionConfig::h3(domain.clone().into(), path.clone());
        connection.port = port;
        let mut name_server = NameServerConfig::h3(ip, domain.into(), path);
        name_server.connections = vec![connection];
        vec![name_server]
      }
      ClientType::CustomQuic(ip, domain, port) => {
        let mut connection = ConnectionConfig::quic(domain.clone().into());
        connection.port = port;
        let mut name_server = NameServerConfig::quic(ip, domain.into());
        name_server.connections = vec![connection];
        vec![name_server]
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
      "cloudflare:h3",
      "google:h3",
      "cloudflare:quic",
      "google:quic",
      "ipv4:port",
      "[ipv6]:port",
      "ipv4:<tls|h2|h3|quic>:domain",
      "[ipv6]:<tls|h2|h3|quic>:domain",
      "ipv4:port:<tls|h2|h3|quic>:domain",
      "[ipv6]:port:<tls|h2|h3|quic>:domain",
      "ipv4:<h2|h3>:domain",
      "[ipv6]:<h2|h3>:domain:/path",
      "ipv4:port:<h2|h3>:domain:/path",
      "[ipv6]:port:<h2|h3>:domain:/path",
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
      "cloudflare:h3" => Ok(ClientType::CloudFlareH3),
      "google:h3" => Ok(ClientType::GoogleH3),
      "cloudflare:quic" => Ok(ClientType::CloudFlareQuic),
      "google:quic" => Ok(ClientType::GoogleQuic),
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
      Regex::new(r"^((?<ipv4>\d+.\d+.\d+.\d+)|\[(?<ipv6>[a-fA-F0-9:]+)\])(:(?<port>\d+)?:?((?<proto>h2|tls|h3|quic):(?<domain>[^:]*)(:(?<path>/.*))?)?)?$")
        .unwrap();

    let Some(caps) = regex.captures(s) else {
      bail!("Cannot retrieve dns server configuration");
    };

    let ip = match (caps.name("ipv4"), caps.name("ipv6")) {
      (Some(ip4), _) => ip4.as_str().parse::<Ipv4Addr>()?.into(),
      (_, Some(ip6)) => ip6.as_str().parse::<Ipv6Addr>()?.into(),
      _ => bail!("IP of the dns server not found"),
    };

    let port = caps.name("port").map_or(Ok(None), |port| {
      let p = port.as_str().parse::<u16>()?;
      if p > 0 {
        Ok(Some(p))
      } else {
        bail!("Port must be greater than 0 found {}", p)
      }
    })?;

    let proto = caps.name("proto").map(|proto| proto.as_str());

    let domain = caps
      .name("domain")
      .map(|domain| domain.as_str().to_string());

    let path = caps.name("path").map(|s| s.as_str().into());

    match proto {
      Some("tls") => {
        ensure!(
          path.is_none(),
          "Path should not be set using {}",
          proto.unwrap()
        );
        Ok(ClientType::CustomTLS(
          ip,
          domain.ok_or_else(|| anyhow!("No domain found for TLS connection."))?,
          port.unwrap_or(853),
        ))
      }
      Some("h2") => Ok(ClientType::CustomH2(
        ip,
        domain.ok_or_else(|| anyhow!("No domain found for H2 connection."))?,
        path,
        port.unwrap_or(443),
      )),
      Some("h3") => Ok(ClientType::CustomH3(
        ip,
        domain.ok_or_else(|| anyhow!("No domain found for H3 connection."))?,
        path,
        port.unwrap_or(443),
      )),
      Some("quic") => {
        ensure!(
          path.is_none(),
          "Path should not be set using {}",
          proto.unwrap()
        );
        Ok(ClientType::CustomQuic(
          ip,
          domain.ok_or_else(|| anyhow!("No domain found for QUIC connection."))?,
          port.unwrap_or(853),
        ))
      }
      None => {
        ensure!(
          path.is_none(),
          "Path should not be set using {}",
          proto.unwrap()
        );
        Ok(ClientType::CustomDNS(ip, port.unwrap_or(53)))
      }
      _ => bail!("The protocol {} is not supported", proto.unwrap()),
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  fn assert_ok(s: &str, expected: ClientType) {
    let c = ClientType::try_from(s);
    assert!(matches!(c, Ok(_)), "`{s}` should be OK but found {c:?}");
    assert_eq!(c.unwrap(), expected);
  }

  fn assert_err(s: &str) {
    let c = ClientType::try_from(s);
    assert!(matches!(c, Err(_)), "`{s}` should be Err but found {c:?}")
  }

  fn ipv4(ip: &str) -> IpAddr {
    IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap())
  }

  fn ipv6(ip: &str) -> IpAddr {
    IpAddr::V6(ip.parse::<Ipv6Addr>().unwrap())
  }

  fn cloudflare() -> String {
    "cloudflare-dns.com".to_string()
  }

  #[test]
  pub fn covert_custom_dns() -> anyhow::Result<()> {
    assert_ok("1.1.1.1", ClientType::CustomDNS(ipv4("1.1.1.1"), 53));
    assert_ok("1.1.1.1:1053", ClientType::CustomDNS(ipv4("1.1.1.1"), 1053));
    assert_ok(
      "[2606:4700:4700::1111]",
      ClientType::CustomDNS(ipv6("2606:4700:4700::1111"), 53),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1053",
      ClientType::CustomDNS(ipv6("2606:4700:4700::1111"), 1053),
    );

    assert_err("1.1.1.1:-53");
    assert_err("1.1.1.1:0");
    assert_err("1.1.1.1:/path");
    assert_err("1.1.1.1:1853:/path");
    assert_err("2606:4700:4700::111");
    assert_err("6:4:4:2:1");
    assert_err("example.com:53");
    assert_err("example.com");
    assert_err("256.255.254.253");
    assert_err("[2606:4700:4700::1111]:/path");
    assert_err("[2606:4700:4700::1111]:1053:/path");
    Ok(())
  }

  #[test]
  pub fn covert_custom_tls() {
    assert_ok(
      "1.1.1.1:tls:cloudflare-dns.com",
      ClientType::CustomTLS(ipv4("1.1.1.1"), cloudflare(), 853),
    );
    assert_ok(
      "1.1.1.1:1853:tls:cloudflare-dns.com",
      ClientType::CustomTLS(ipv4("1.1.1.1"), cloudflare(), 1853),
    );
    assert_ok(
      "[2606:4700:4700::1111]:tls:cloudflare-dns.com",
      ClientType::CustomTLS(ipv6("2606:4700:4700::1111"), cloudflare(), 853),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1853:tls:cloudflare-dns.com",
      ClientType::CustomTLS(ipv6("2606:4700:4700::1111"), cloudflare(), 1853),
    );

    assert_err("1.1.1.1:853:tls");
    assert_err("1.1.1.1:-853:tls:cloudflare-dns.com");
    assert_err("1.1.1.1:0:tls:cloudflare-dns.com");
    assert_err("1.1.1.1:tls:cloudflare-dns.com:/path");
    assert_err("1.1.1.1:1853:tls:cloudflare-dns.com:/path");
    assert_err("example.com:853:tls:cloudflare-dns.com");
    assert_err("example.com:tls:cloudflare-dns.com");
    assert_err("256.255.254.253:tls:cloudflare-dns.com");
    assert_err("[2606:4700:4700::1111]:tls:cloudflare-dns.com:/path");
    assert_err("[2606:4700:4700::1111]:1853:tls:cloudflare-dns.com:/path");
  }

  #[test]
  pub fn covert_custom_h2() {
    assert_ok(
      "1.1.1.1:h2:cloudflare-dns.com",
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare(), None, 443),
    );
    assert_ok(
      "1.1.1.1:h2:cloudflare-dns.com:/path",
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare(), Some("/path".into()), 443),
    );
    assert_ok(
      "1.1.1.1:1443:h2:cloudflare-dns.com",
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare(), None, 1443),
    );
    assert_ok(
      "1.1.1.1:1443:h2:cloudflare-dns.com:/path",
      ClientType::CustomH2(ipv4("1.1.1.1"), cloudflare(), Some("/path".into()), 1443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:h2:cloudflare-dns.com",
      ClientType::CustomH2(ipv6("2606:4700:4700::1111"), cloudflare(), None, 443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:h2:cloudflare-dns.com:/path",
      ClientType::CustomH2(
        ipv6("2606:4700:4700::1111"),
        cloudflare(),
        Some("/path".into()),
        443,
      ),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1443:h2:cloudflare-dns.com",
      ClientType::CustomH2(ipv6("2606:4700:4700::1111"), cloudflare(), None, 1443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1443:h2:cloudflare-dns.com:/path",
      ClientType::CustomH2(
        ipv6("2606:4700:4700::1111"),
        cloudflare(),
        Some("/path".into()),
        1443,
      ),
    );

    assert_err("1.1.1.1:443:h2");
    assert_err("1.1.1.1:-443:h2:cloudflare-dns.com");
    assert_err("1.1.1.1:0:h2:cloudflare-dns.com");
    assert_err("6:4700:4700::111:h2:cloudflare-dns.com");
    assert_err("example.com:443:h2:cloudflare-dns.com");
    assert_err("example.com:h2:cloudflare-dns.com");
    assert_err("256.255.254.253:h2:cloudflare-dns.com");
  }

  #[test]
  pub fn covert_custom_h3() {
    assert_ok(
      "1.1.1.1:h3:cloudflare-dns.com",
      ClientType::CustomH3(ipv4("1.1.1.1"), cloudflare(), None, 443),
    );
    assert_ok(
      "1.1.1.1:h3:cloudflare-dns.com:/path",
      ClientType::CustomH3(ipv4("1.1.1.1"), cloudflare(), Some("/path".into()), 443),
    );
    assert_ok(
      "1.1.1.1:1443:h3:cloudflare-dns.com",
      ClientType::CustomH3(ipv4("1.1.1.1"), cloudflare(), None, 1443),
    );
    assert_ok(
      "1.1.1.1:1443:h3:cloudflare-dns.com:/path",
      ClientType::CustomH3(ipv4("1.1.1.1"), cloudflare(), Some("/path".into()), 1443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:h3:cloudflare-dns.com",
      ClientType::CustomH3(ipv6("2606:4700:4700::1111"), cloudflare(), None, 443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:h3:cloudflare-dns.com:/path",
      ClientType::CustomH3(
        ipv6("2606:4700:4700::1111"),
        cloudflare(),
        Some("/path".into()),
        443,
      ),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1443:h3:cloudflare-dns.com",
      ClientType::CustomH3(ipv6("2606:4700:4700::1111"), cloudflare(), None, 1443),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1443:h3:cloudflare-dns.com:/path",
      ClientType::CustomH3(
        ipv6("2606:4700:4700::1111"),
        cloudflare(),
        Some("/path".into()),
        1443,
      ),
    );

    assert_err("1.1.1.1:443:h3");
    assert_err("1.1.1.1:-443:h3:cloudflare-dns.com");
    assert_err("1.1.1.1:0:h3:cloudflare-dns.com");
    assert_err("6:4700:4700::111:h3:cloudflare-dns.com");
    assert_err("example.com:443:h3:cloudflare-dns.com");
    assert_err("example.com:h3:cloudflare-dns.com");
    assert_err("256.255.254.253:h3:cloudflare-dns.com");
  }

  #[test]
  pub fn covert_custom_quic() {
    assert_ok(
      "1.1.1.1:quic:cloudflare-dns.com",
      ClientType::CustomQuic(ipv4("1.1.1.1"), cloudflare(), 853),
    );
    assert_ok(
      "1.1.1.1:1853:quic:cloudflare-dns.com",
      ClientType::CustomQuic(ipv4("1.1.1.1"), cloudflare(), 1853),
    );
    assert_ok(
      "[2606:4700:4700::1111]:quic:cloudflare-dns.com",
      ClientType::CustomQuic(ipv6("2606:4700:4700::1111"), cloudflare(), 853),
    );
    assert_ok(
      "[2606:4700:4700::1111]:1853:quic:cloudflare-dns.com",
      ClientType::CustomQuic(ipv6("2606:4700:4700::1111"), cloudflare(), 1853),
    );

    assert_err("1.1.1.1:853:quic");
    assert_err("1.1.1.1:-853:quic:cloudflare-dns.com");
    assert_err("1.1.1.1:0:quic:cloudflare-dns.com");
    assert_err("1.1.1.1:quic:cloudflare-dns.com:/path");
    assert_err("1.1.1.1:1853:quic:cloudflare-dns.com:/path");
    assert_err("6:4700:4700::111:quic:cloudflare-dns.com");
    assert_err("example.com:853:quic:cloudflare-dns.com");
    assert_err("example.com:quic:cloudflare-dns.com");
    assert_err("256.255.254.253:quic:cloudflare-dns.com");
    assert_err("[2606:4700:4700::1111]:quic:cloudflare-dns.com:/path");
    assert_err("[2606:4700:4700::1111]:1853:quic:cloudflare-dns.com:/path");
  }
}
