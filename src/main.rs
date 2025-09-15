use crate::authority::{DefaultAuthority, DomainBlacklistAuthority, ZoneBlacklistAuthority};
use crate::client::*;
use anyhow::{anyhow, bail, Context, Result};
use clap::{builder::ArgPredicate, Parser};
use hickory_server::{
  authority::{AuthorityObject, Catalog},
  proto::rr::LowerName,
  proto::rustls::default_provider,
  resolver::Name,
  ServerFuture,
};
use ip::{IpRange, IpRangeVec};
use ipnet::IpNet;
use rustls::pki_types::pem::PemObject;
use rustls::{
  pki_types::{CertificateDer, PrivateKeyDer},
  server::ResolvesServerCert,
  sign::{CertifiedKey, SingleCertAndKey},
};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::{
  net::{TcpListener, UdpSocket},
  runtime,
};
use tokio_graceful::Shutdown;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub mod authority;
pub mod client;
pub mod ip;

/// Create a DNS server you can configure to block some domain and zones. You can use UDP or DNS over TLS/TCP (DoT) or DNS over HTTPS/H2 (DoH) as listeners (frontend) and resolver (backend).
#[derive(Parser, Debug)]
#[structopt(name = "dns-server", author, version, about)]
pub struct DNSServer {
  /// Listen port of the classic DNS server over UDP.
  #[arg(long = "port", short = 'p', default_value = "53")]
  port: u16,
  /// Listen adress of the server.
  #[arg(long = "listen", short = 'l', default_value = "0.0.0.0")]
  listen: String,
  /// Number of workers to setup
  #[arg(long = "workers", default_value = "4")]
  worker: usize,
  /// File containing a list of exact domains to block.
  #[arg(long = "blacklist")]
  blacklist: Option<PathBuf>,
  /// Default IP address to return when the domain is blocked instead of an empty NoError response.
  #[arg(long = "default-ip")]
  default_ip: Option<Ipv4Addr>,
  /// File containing a list of zone of domains to block, this will block the domain and all subdomains.
  #[arg(long = "zone-blacklist")]
  zone_blacklist: Option<PathBuf>,
  /// Setup your trusted dns resolver, could be cloudflare or google with UDP, TLS or H2. The port is optional when you are using custom IP. When you use TLS or H2 protocols, you must add the domain name too.
  #[arg(long = "dns-server", default_value = "cloudflare:h2")]
  dns_server: ClientType,
  /// Activate https/h2 server beside classic DNS server over UDP.
  #[arg(
    long = "h2",
    default_value_if("h2_port", ArgPredicate::IsPresent, Some("true"))
  )]
  h2: bool,
  /// Listen port of the https/h2 server.
  #[arg(long = "h2-port", default_value("443"))]
  h2_port: u16,
  /// Listen port of the https/h2 server.
  #[arg(long = "h2-path", default_value("/"))]
  h2_path: String,
  /// Activate DNS over TLS (TCP) server beside classic DNS server over UDP.
  #[arg(
    long = "tls",
    default_value_if("tls_port", ArgPredicate::IsPresent, Some("true"))
  )]
  tls: bool,
  /// Listen port of the Dns over TLS (TCP) server.
  #[arg(long = "tls-port", default_value("853"))]
  tls_port: u16,
  /// Path of the certificate for the https/h2 server.
  #[arg(long = "tls-certificate")]
  tls_certificate: Option<PathBuf>,
  /// Path of the private key for the https/h2 server.
  #[arg(long = "tls-private-key")]
  tls_private_key: Option<PathBuf>,
  /// IP using Local-Use IPv4/IPv6 Translation Prefix (rfc8215).
  #[arg(long = "rfc8215-ips")]
  rfc8215_ips: Option<PathBuf>,
  /// Networks denied to access the server
  #[arg(long = "deny-networks")]
  deny_networks: Option<PathBuf>,
  /// Networks allowed to access the server
  #[arg(long = "allow-networks")]
  allow_networks: Option<PathBuf>,
}

fn main() -> Result<()> {
  logger();
  let args = DNSServer::parse();

  let runtime = runtime::Builder::new_multi_thread()
    .enable_all()
    .worker_threads(args.worker)
    .thread_name("dns-server-runtime")
    .build()
    .context("failed to initialize Tokio Runtime")?;

  let catalog = runtime.block_on(args.generate_catalog())?;

  let mut server = ServerFuture::with_access(
    catalog,
    &args.get_networks(&args.deny_networks)?,
    &args.get_networks(&args.allow_networks)?,
  );

  info!("Will listen UDP requests on {}:{}", args.listen, args.port);
  let udp_socket = runtime
    .block_on(UdpSocket::bind((args.listen.clone(), args.port)))
    .with_context(|| anyhow!("could not bind to UDP socket {}:{}", args.listen, args.port))?;

  let _guard = runtime.enter();
  server.register_socket(udp_socket);

  if args.h2 {
    info!(
      "Will listen HTTPS/H2 resquests on {}:{}",
      args.listen, args.h2_port
    );
    let https_listener = runtime
      .block_on(TcpListener::bind((args.listen.clone(), args.h2_port)))
      .with_context(|| format!("could not bind HTTPS port {}:{}", args.listen, args.h2_port))?;

    let _guard = runtime.enter();

    server
      .register_https_listener(
        https_listener,
        Duration::from_secs(2),
        args.get_certificates()?,
        None,
        args.h2_path.clone(),
      )
      .with_context(|| "could not register HTTPS listener")?;
  }

  if args.tls {
    info!(
      "Will listen TLS/TCP resquests on {}:{}",
      args.listen, args.tls_port
    );
    let tls_listener = runtime
      .block_on(TcpListener::bind((args.listen.clone(), args.tls_port)))
      .with_context(|| format!("could not bind TLS port {}:{}", args.listen, args.tls_port))?;

    let _guard = runtime.enter();
    server
      .register_tls_listener(
        tls_listener,
        Duration::from_secs(2),
        args.get_certificates()?,
      )
      .context("could not register TLS listener")?;
  }

  let shutdown = Shutdown::default();
  runtime.block_on(shutdown.shutdown_with_limit(Duration::from_secs(5)))?;

  Ok(())
}

impl DNSServer {
  async fn generate_catalog(&self) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    let name = Name::root();

    for domain in self.get_blacklist(&self.zone_blacklist)?.iter() {
      let authority = ZoneBlacklistAuthority::new(domain.clone(), self.default_ip.clone());
      catalog.upsert(domain.clone(), vec![Arc::new(authority)]);
    }

    let mut root_authorities: Vec<Arc<dyn AuthorityObject>> = vec![];
    let domains_blacklisted = self.get_blacklist(&self.blacklist)?;
    if !domains_blacklisted.is_empty() {
      print!("{:?}", domains_blacklisted);
      let authority = DomainBlacklistAuthority::new(domains_blacklisted, self.default_ip.clone());
      root_authorities.push(Arc::new(authority));
    }

    let authority = DefaultAuthority::new(self.dns_server.clone().into(), self.get_rfc8215_ips()?);
    root_authorities.push(Arc::new(authority));
    catalog.upsert(LowerName::new(&name), root_authorities);

    Ok(catalog)
  }

  fn get_rfc8215_ips(&self) -> Result<IpRangeVec> {
    let ip_ranges: Vec<IpRange> = if let Some(path) = &self.rfc8215_ips {
      let error = format!("RFC8215: Failed to process `{}` file", path.display());
      let mut file = std::fs::File::open(path).with_context(|| error.clone())?;
      let mut buffer = String::new();
      file
        .read_to_string(&mut buffer)
        .with_context(|| error.clone())?;

      buffer
        .split("\n")
        .map(|ip_range| ip_range.trim())
        .filter(|ip_range| !ip_range.is_empty())
        .map(|ip_range| IpRange::try_from(ip_range).with_context(|| error.clone()))
        .collect::<Result<Vec<IpRange>>>()?
    } else {
      vec![]
    };

    Ok(IpRangeVec::new(ip_ranges))
  }

  fn get_networks(&self, path: &Option<PathBuf>) -> Result<Vec<IpNet>> {
    if let Some(path) = path {
      let error = format!("Networks: Failed to process `{}` file", path.display());
      let mut file = std::fs::File::open(path).with_context(|| error.clone())?;
      let mut buffer = String::new();
      file
        .read_to_string(&mut buffer)
        .with_context(|| error.clone())?;

      let networks = buffer
        .split("\n")
        .map(|network| network.trim())
        .filter(|network| !network.is_empty())
        .map(|network| IpNet::from_str(network).with_context(|| error.clone()))
        .collect::<Result<Vec<IpNet>>>()?;
      Ok(networks)
    } else {
      Ok(vec![])
    }
  }

  fn get_blacklist(&self, list: &Option<PathBuf>) -> Result<HashSet<LowerName>> {
    match &list {
      Some(path) => {
        let error = format!("Blacklist: Failed to process `{}` file", path.display());
        let mut file = std::fs::File::open(path).with_context(|| error.clone())?;
        let mut buffer = String::new();
        file
          .read_to_string(&mut buffer)
          .with_context(|| error.clone())?;

        buffer
          .split("\n")
          .map(|domain| domain.trim().trim_end_matches("."))
          .filter(|domain| !domain.is_empty())
          .map(|domain| LowerName::from_str(&format!("{}.", domain)).with_context(|| error.clone()))
          .collect::<Result<HashSet<LowerName>>>()
      }
      None => Ok(HashSet::new()),
    }
  }

  fn get_certificates(&self) -> Result<Arc<dyn ResolvesServerCert>> {
    let cert_path = if let Some(path) = &self.tls_certificate {
      path
    } else {
      bail!("Missing tls certificate");
    };
    let key_path = if let Some(path) = &self.tls_private_key {
      path
    } else {
      bail!("Missing tls private key");
    };

    let cert_chain = CertificateDer::pem_file_iter(&cert_path)?.collect::<Result<Vec<_>, _>>()?;

    let key = if let Ok(key) = PrivateKeyDer::from_pem_file(&key_path) {
      key
    } else if let Ok(key) =
      PrivateKeyDer::try_from(std::fs::read(&key_path).context("Error reading tls private key")?)
    {
      key
    } else {
      bail!("Unsupported tls private key")
    };

    let certified_key = CertifiedKey::from_der(cert_chain, key, &default_provider())?;

    Ok(Arc::new(SingleCertAndKey::from(certified_key)))
  }
}

fn logger() {
  let filter = tracing_subscriber::EnvFilter::builder()
    .with_default_directive(tracing::Level::WARN.into())
    .from_env()
    .expect("Fail to create logger");

  let formatter = tracing_subscriber::fmt::layer();

  tracing_subscriber::registry()
    .with(formatter)
    .with(filter)
    .init();
}
