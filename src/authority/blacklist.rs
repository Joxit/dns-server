use hickory_server::{
  authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  resolver::{config::NameServerConfigGroup, Name},
  server::RequestInfo,
  store::forwarder::{ForwardAuthority, ForwardConfig, ForwardLookup},
};
use std::collections::HashSet;
use tracing::{info,warn};

pub struct BlacklistAuthority {
  blacklisted: HashSet<LowerName>,
  inner: ForwardAuthority,
}

impl BlacklistAuthority {
  pub fn new(
    name: Name,
    blacklisted: HashSet<LowerName>,
    name_servers: NameServerConfigGroup,
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
      return Err(LookupError::ResponseCode(ResponseCode::NXDomain));
    }
    self.inner.search(request_info, lookup_options).await
  }

  async fn get_nsec_records(
    &self,
    name: &LowerName,
    lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    self.inner.get_nsec_records(name, lookup_options).await
  }
}
