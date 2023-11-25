use crate::authority::forge_ip_record;
use hickory_resolver::{config::NameServerConfigGroup, Name};
use hickory_server::{
  authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  server::RequestInfo,
  store::forwarder::{ForwardAuthority, ForwardConfig, ForwardLookup},
};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct BlacklistAuthority {
  blacklisted: HashSet<LowerName>,
  inner: ForwardAuthority,
  default_ip: Option<Ipv4Addr>,
}

impl BlacklistAuthority {
  pub fn new(
    name: Name,
    blacklisted: HashSet<LowerName>,
    name_servers: NameServerConfigGroup,
    default_ip: Option<Ipv4Addr>,
  ) -> Self {
    info!("Domains {:?} will be ingnored", blacklisted);
    let authority_config = ForwardConfig {
      name_servers,
      options: None,
    };
    let forward_authority =
      ForwardAuthority::try_from_config(name.clone(), ZoneType::Primary, &authority_config)
        .unwrap();
    Self {
      blacklisted,
      inner: forward_authority,
      default_ip,
    }
  }
}

#[async_trait::async_trait]
impl Authority for BlacklistAuthority {
  type Lookup = ForwardLookup;

  fn zone_type(&self) -> ZoneType {
    self.inner.zone_type()
  }

  fn is_axfr_allowed(&self) -> bool {
    self.inner.is_axfr_allowed()
  }

  async fn update(&self, update: &MessageRequest) -> UpdateResult<bool> {
    self.inner.update(update).await
  }

  fn origin(&self) -> &LowerName {
    self.inner.origin()
  }

  async fn lookup(
    &self,
    name: &LowerName,
    query_type: RecordType,
    lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    self.inner.lookup(name, query_type, lookup_options).await
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    if self.blacklisted.contains(request_info.query.name()) {
      warn!("Domain name ignored {}", request_info.query.name());
      if let Some(ip) = self.default_ip {
        Ok(forge_ip_record(ip, request_info))
      } else {
        Err(LookupError::ResponseCode(ResponseCode::NoError))
      }
    } else {
      self.inner.search(request_info, lookup_options).await
    }
  }

  async fn get_nsec_records(
    &self,
    name: &LowerName,
    lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    self.inner.get_nsec_records(name, lookup_options).await
  }
}
