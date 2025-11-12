use crate::authority::forge_or_error;
use hickory_resolver::Name;
use hickory_server::{
  authority::{
    Authority, LookupControlFlow, LookupError, LookupOptions, MessageRequest, UpdateResult,
    ZoneType,
  },
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::{info, warn};

pub struct DomainBlacklistAuthority {
  blacklisted: HashSet<LowerName>,
  default_ip: Option<IpAddr>,
  origin: LowerName,
}

impl DomainBlacklistAuthority {
  pub fn new(blacklisted: HashSet<LowerName>, default_ip: Option<IpAddr>) -> Self {
    info!("Domains {:?} will be ingnored", blacklisted);
    Self {
      blacklisted,
      default_ip,
      origin: LowerName::new(&Name::root()),
    }
  }
}

#[async_trait::async_trait]
impl Authority for DomainBlacklistAuthority {
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
    name: &LowerName,
    _query_type: RecordType,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    if self.blacklisted.contains(name) {
      LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
    } else {
      LookupControlFlow::Skip
    }
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    if self.blacklisted.contains(request_info.query.name()) {
      warn!("Domain name ignored {}", request_info.query.name());
      forge_or_error(self.default_ip, request_info)
    } else {
      LookupControlFlow::Skip
    }
  }

  async fn get_nsec_records(
    &self,
    name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    if self.blacklisted.contains(name) {
      warn!("Domain name ignored {}", name);
      LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
    } else {
      LookupControlFlow::Skip
    }
  }
}
