use crate::{
  authority::{forge_or_error, to_prefixed_ip},
  ip::IpRangeVec,
};
use anyhow::{anyhow, Context, Result};
use core::net::IpAddr;
use hickory_server::{
  authority::{
    Authority, LookupControlFlow, LookupOptions, MessageRequest, UpdateResult, ZoneType,
  },
  proto::rr::{LowerName, RecordType},
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use regex::Regex;
use std::{collections::HashMap, path::PathBuf, str::FromStr, sync::Arc};
use tokio::{fs::read_to_string, sync::RwLock, time::sleep};
use tracing::{debug, error, info, warn};

#[derive(Default, Clone, Debug)]
struct LocalDNSResolver {
  pub name_ip: HashMap<LowerName, IpAddr>,
}

pub struct LocalDNSAuthority {
  rfc8215_ips: IpRangeVec,
  origin: LowerName,
  local_dns_resolver: Arc<RwLock<LocalDNSResolver>>,
}

async fn read_local_dns_file(local_dns_file: &PathBuf) -> Result<HashMap<LowerName, IpAddr>> {
  let content = read_to_string(&local_dns_file)
    .await
    .with_context(|| anyhow!("Cannot read Local DNS file {}", local_dns_file.display()))?;
  let mut local_dns = HashMap::default();
  let regex = Regex::new("#.*$")?;
  let lines = content
    .split("\n")
    .map(|line| regex.replace_all(line, "").trim().to_string())
    .filter(|line| !line.is_empty());

  for line in lines {
    let parts: Vec<&str> = line
      .split_whitespace()
      .map(|part| part.trim())
      .filter(|part| !part.is_empty())
      .collect();
    if parts.len() < 2 {
      warn!("Ignoring {}", line);
      continue;
    }

    let (ip, names) = parts.split_first().unwrap();
    for name in names.iter() {
      let name = name.trim_end_matches(".").to_string() + ".";
      debug!("Add {} {}", ip, name);

      let ip = IpAddr::from_str(ip)?;
      let lower_name = LowerName::from_str(&name)?;

      local_dns.insert(lower_name, ip);
    }
  }

  Ok(local_dns)
}

impl LocalDNSAuthority {
  pub fn new(local_dns_file: PathBuf, rfc8215_ips: IpRangeVec) -> Self {
    info!("Local DNS file {:?}", local_dns_file);
    let write_local_dns = Arc::new(RwLock::new(LocalDNSResolver::default()));
    let local_dns_resolver = write_local_dns.clone();

    tokio::spawn(async move {
      let five = std::time::Duration::from_secs(5 * 60);
      loop {
        match read_local_dns_file(&local_dns_file).await {
          Ok(name_ip) => write_local_dns.clone().write_owned().await.name_ip = name_ip,
          Err(err) => error!("Cannot update local DNS: {}", err),
        }
        sleep(five).await;
      }
    });

    Self {
      rfc8215_ips,
      origin: LowerName::default(),
      local_dns_resolver,
    }
  }
}

#[async_trait::async_trait]
impl Authority for LocalDNSAuthority {
  type Lookup = ForwardLookup;

  fn zone_type(&self) -> ZoneType {
    ZoneType::Primary
  }

  fn is_axfr_allowed(&self) -> bool {
    false
  }

  async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
    UpdateResult::Ok(false)
  }

  fn origin(&self) -> &LowerName {
    &self.origin
  }

  async fn lookup(
    &self,
    _name: &LowerName,
    _query_type: RecordType,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    LookupControlFlow::Skip
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    let name = request_info.query.name();
    let local_dns_resolver = self.local_dns_resolver.clone();
    let ip = local_dns_resolver
      .read_owned()
      .await
      .name_ip
      .get(name)
      .map(|ip| {
        if self.rfc8215_ips.contains_sock_addr(request_info.src) {
          to_prefixed_ip(ip)
        } else {
          *ip
        }
      });
    if request_info.query.query_type().is_ip_addr() && ip.is_some() {
      forge_or_error(ip, request_info)
    } else {
      LookupControlFlow::Skip
    }
  }

  async fn get_nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    LookupControlFlow::Skip
  }
}
