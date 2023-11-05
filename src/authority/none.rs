use hickory_server::{
  authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};

use tracing::{info, warn};

pub struct NoneAuthority {
  origin: LowerName,
}

impl NoneAuthority {
  pub fn new(name: LowerName) -> Self {
    info!("Domain zone {} will be ingnored", name);
    Self { origin: name }
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
    Err(ResponseCode::NXDomain)
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
    Err(LookupError::ResponseCode(ResponseCode::NXDomain))
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    warn!("Domain name ignored {}", request_info.query.name());
    Err(LookupError::ResponseCode(ResponseCode::NXDomain))
  }

  async fn get_nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    Err(LookupError::ResponseCode(ResponseCode::NXDomain))
  }
}
