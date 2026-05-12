use crate::client::ClientType;
use clap::Parser;
use hickory_server::net::{runtime::TokioRuntimeProvider, DnsError, NetError};
use hickory_server::proto::rr::{Record, RecordData, RecordType};
use hickory_server::resolver::{
  config::{NameServerConfig, ResolverConfig},
  lookup::Lookup,
  TokioResolver,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod client;

/// Use DNS client to try your dns server. You can use UDP or DNS over TLS/TCP (DoT) or DNS over HTTPS/H2 (DoH) or DNS over Quic (DoQ) or DNS over HTTP3 (DoH3).
#[derive(Parser, Debug)]
#[command(name = "dns-resolve", author, version, about)]
pub struct DNSResolve {
  /// Setup your dns server.
  #[arg(long = "dns-server", default_value = "cloudflare:h2")]
  dns_server: ClientType,
  /// Type of query to issue, e.g. A, AAAA, NS, etc.
  #[clap(short = 't', long = "type", default_value = "A")]
  record_type: RecordType,
  // List of domain names to resolve
  domain: Vec<String>,
}

/// Run the resolve program
#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
  logger();
  DNSResolve::parse().exec().await
}

impl DNSResolve {
  pub async fn exec(&self) -> anyhow::Result<()> {
    let name_servers: Vec<NameServerConfig> = self.dns_server.clone().into();
    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let resolver =
      TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()).build()?;

    for domain in &self.domain {
      println!(
        "\nQuerying for {} {} from {:?}",
        domain, self.record_type, self.dns_server
      );
      match resolver.lookup(domain, self.record_type).await {
        Ok(lookup) => Self::print_lookup(&lookup),
        Err(err) => Self::print_err(&err),
      }
    }
    println!();

    Ok(())
  }

  fn print_lookup(lookup: &Lookup) {
    println!("Success for query {}", lookup.query());

    let message = lookup.message();

    if !message.answers.is_empty() {
      println!("\n;; ANSWER SECTION:");
      message.answers.iter().for_each(Self::print_record);
    }

    if !message.authorities.is_empty() {
      println!("\n;; AUTHORITY SECTION:");
      message.authorities.iter().for_each(Self::print_record);
    }

    if !message.additionals.is_empty() {
      println!("\n;; ADDITIONAL SECTION:");
      message.additionals.iter().for_each(Self::print_record);
    }
  }

  fn print_record<D: RecordData>(record: &Record<D>) {
    println!(
      "{} {} {} {} {}",
      record.name,
      record.ttl,
      record.dns_class,
      record.record_type(),
      record.data,
    );
  }

  fn print_err(err: &NetError) {
    if let NetError::Dns(DnsError::NoRecordsFound(no_records)) = err {
      println!("NoRecordsFound for query {}", no_records.query);
      if let Some(r) = &no_records.soa {
        Self::print_record(r);
      }
    } else {
      return println!("{err:?}");
    };
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
