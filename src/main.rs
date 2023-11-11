use crate::authority::{BlacklistAuthority, H2BlacklistAuthority, NoneAuthority};
use crate::client::*;
use clap::Parser;
use hickory_server::{authority::Catalog, proto::rr::LowerName, resolver::Name, ServerFuture};
use std::collections::HashSet;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use tokio::{net::UdpSocket, runtime};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub mod authority;
pub mod client;

#[derive(Parser, Debug)]
#[structopt(name = "dns-server", author, version, about)]
pub struct DNSServer {
  #[arg(long = "port", short = 'p', default_value = "53")]
  port: u16,
  #[arg(long = "listen", short = 'l', default_value = "0.0.0.0")]
  listen: String,
  #[arg(long = "workers", default_value = "4")]
  worker: usize,
  #[arg(long = "blacklist")]
  blacklist: Option<PathBuf>,
  #[arg(long = "default-ip")]
  default_ip: Option<Ipv4Addr>,
  #[arg(long = "zone-blacklist")]
  zone_blacklist: Option<PathBuf>,
  #[arg(long = "dns-server", default_value = "cloudflare")]
  dns_server: ClientType,
  #[arg(long = "doh")]
  dns_over_https: bool,
}

fn main() {
  logger();
  let args = DNSServer::parse();

  let runtime = runtime::Builder::new_multi_thread()
    .enable_all()
    .worker_threads(args.worker)
    .thread_name("dns-server-runtime")
    .build()
    .expect("failed to initialize Tokio Runtime");

  let catalog = runtime.block_on(args.generate_catalog());

  let mut server = ServerFuture::new(catalog);

  let udp_socket = runtime
    .block_on(UdpSocket::bind((args.listen.clone(), args.port)))
    .unwrap_or_else(|err| {
      panic!(
        "could not bind to UDP socket {}:{} : {err}",
        args.listen, args.port
      )
    });

  let _guard = runtime.enter();
  server.register_socket(udp_socket);
  match runtime.block_on(server.block_until_done()) {
    Ok(()) => {}
    Err(e) => {
      let error_msg = format!(
        "Hickory DNS {} has encountered an error: {}",
        hickory_server::version(),
        e
      );

      panic!("{}", error_msg);
    }
  };
}

impl DNSServer {
  async fn generate_catalog(&self) -> Catalog {
    let mut catalog = Catalog::new();
    let name = Name::root();

    for domain in self.get_blacklist(&self.zone_blacklist).iter() {
      let authority = NoneAuthority::new(domain.clone(), self.default_ip.clone());
      catalog.upsert(domain.clone(), Box::new(Arc::new(authority)));
    }

    if self.dns_over_https {
      let authority = H2BlacklistAuthority::new(
        name.clone(),
        self.get_blacklist(&self.blacklist),
        self.dns_server.clone().into(),
        self.default_ip.clone(),
        get_client(self.dns_server.clone()).await.unwrap(),
      );
      catalog.upsert(LowerName::new(&name), Box::new(Arc::new(authority)));
    } else {
      let authority = BlacklistAuthority::new(
        name.clone(),
        self.get_blacklist(&self.blacklist),
        self.dns_server.clone().into(),
        self.default_ip.clone(),
      );
      catalog.upsert(LowerName::new(&name), Box::new(Arc::new(authority)));
    };

    catalog
  }

  fn get_blacklist(&self, list: &Option<PathBuf>) -> HashSet<LowerName> {
    match &list {
      Some(path) => {
        let mut file = std::fs::File::open(path).unwrap();
        let mut buffer = String::new();
        file.read_to_string(&mut buffer).unwrap();
        let mut set: HashSet<LowerName> = HashSet::new();

        buffer
          .split("\n")
          .map(|domain| domain.trim().trim_end_matches("."))
          .filter(|domain| !domain.is_empty())
          .for_each(|domain| {
            let lower_name = LowerName::from_str(&format!("{}.", domain)).unwrap();
            set.insert(lower_name);
          });

        set
      }
      None => HashSet::new(),
    }
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
