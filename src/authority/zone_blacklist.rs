use crate::authority::forge_or_error;
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
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct ZoneBlacklistAuthority {
  origin: LowerName,
  default_ip: Option<Ipv4Addr>,
}

impl ZoneBlacklistAuthority {
  pub fn new(name: LowerName, default_ip: Option<Ipv4Addr>) -> Self {
    info!("Domain zone {} will be ignored", name);
    Self {
      origin: name,
      default_ip,
    }
  }
}

#[async_trait::async_trait]
impl Authority for ZoneBlacklistAuthority {
  type Lookup = ForwardLookup;

  fn zone_type(&self) -> ZoneType {
    ZoneType::Primary
  }

  fn is_axfr_allowed(&self) -> bool {
    false
  }

  async fn update(&self, _update: &MessageRequest) -> UpdateResult<bool> {
    Err(ResponseCode::NoError)
  }

  fn origin(&self) -> &LowerName {
    &self.origin
  }

  async fn lookup(
    &self,
    _name: &LowerName,
    _rtype: RecordType,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    warn!("Domain name ignored {}", request_info.query.name());
    forge_or_error(self.default_ip, request_info)
  }

  async fn get_nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
  }
}
