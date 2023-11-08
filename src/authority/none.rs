use crate::authority::forge_ip_record;
use hickory_server::{
  authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct NoneAuthority {
  origin: LowerName,
  default_ip: Option<Ipv4Addr>,
}

impl NoneAuthority {
  pub fn new(name: LowerName, default_ip: Option<Ipv4Addr>) -> Self {
    info!("Domain zone {} will be ingnored", name);
    Self {
      origin: name,
      default_ip,
    }
  }
}

#[async_trait::async_trait]
impl Authority for NoneAuthority {
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
    _query_type: RecordType,
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    Err(LookupError::ResponseCode(ResponseCode::NoError))
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    warn!("Domain name ignored {}", request_info.query.name());
    if let Some(ip) = self.default_ip {
      Ok(forge_ip_record(ip, request_info))
    } else {
      Err(LookupError::ResponseCode(ResponseCode::NoError))
    }
  }

  async fn get_nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    Err(LookupError::ResponseCode(ResponseCode::NoError))
  }
}
