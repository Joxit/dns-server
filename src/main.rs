use clap::Parser;
use hickory_server::authority::ZoneType;
use hickory_server::resolver::Name;
use hickory_server::{
  authority::AuthorityObject,
  authority::Catalog,
  proto::rr::LowerName,
  resolver::config::NameServerConfigGroup,
  store::forwarder::{ForwardAuthority, ForwardConfig},
  ServerFuture,
};

use std::str::FromStr;
use std::sync::Arc;
use tokio::{net::UdpSocket, runtime};

#[derive(Parser, Debug)]
#[structopt(name = "dns-server", author, version, about)]
pub struct DNSServer {
  #[arg(long = "port", short = 'p', default_value = "53")]
  port: u16,
  #[arg(long = "workers", default_value = "4")]
  worker: usize,
}

fn main() {
  let args = DNSServer::parse();

  let runtime = runtime::Builder::new_multi_thread()
    .enable_all()
    .worker_threads(args.worker)
    .thread_name("dns-server-runtime")
    .build()
    .expect("failed to initialize Tokio Runtime");

  let catalog = generate_catalog();

  let mut server = ServerFuture::new(catalog);

  let udp_socket = runtime
    .block_on(UdpSocket::bind(("0.0.0.0", args.port)))
    .unwrap_or_else(|err| panic!("could not bind to UDP socket 0.0.0.0:{} : {err}", args.port));

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

fn generate_catalog() -> Catalog {
  let mut catalog = Catalog::new();
  let authority_config = ForwardConfig {
    name_servers: NameServerConfigGroup::cloudflare(),
    options: None,
  };
  let authority =
    ForwardAuthority::try_from_config(Name::root(), ZoneType::Primary, &authority_config).unwrap();

  catalog.upsert(
    LowerName::from_str(".").unwrap(),
    Box::new(Arc::new(authority)) as Box<dyn AuthorityObject>,
  );

  catalog
}
