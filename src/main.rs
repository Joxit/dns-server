use crate::authority::BlacklistAuthority;
use clap::Parser;
use hickory_server::resolver::Name;
use hickory_server::{
  authority::AuthorityObject, authority::Catalog, proto::rr::LowerName,
  resolver::config::NameServerConfigGroup, ServerFuture,
};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::{net::UdpSocket, runtime};

pub mod authority;

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
  let name = Name::root();
  let blacklist_authority = BlacklistAuthority::new(
    name.clone(),
    HashSet::new(),
    NameServerConfigGroup::cloudflare(),
  );

  catalog.upsert(
    LowerName::new(&name),
    Box::new(Arc::new(blacklist_authority)) as Box<dyn AuthorityObject>,
  );

  catalog
}
