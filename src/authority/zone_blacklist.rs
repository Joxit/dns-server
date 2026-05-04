use crate::authority::forge_or_error;
use hickory_server::proto::{
  op::ResponseCode,
  rr::{LowerName, RecordType, TSigResponseContext},
};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
  AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
};
use std::net::IpAddr;
use tracing::{info, warn};

pub struct ZoneBlacklistAuthority {
  origin: LowerName,
  default_ip: Option<IpAddr>,
}

impl ZoneBlacklistAuthority {
  pub fn new(name: LowerName, default_ip: Option<IpAddr>) -> Self {
    info!("Domain zone {} will be ignored", name);
    Self {
      origin: name,
      default_ip,
    }
  }
}

#[async_trait::async_trait]
impl ZoneHandler for ZoneBlacklistAuthority {
  fn zone_type(&self) -> ZoneType {
    ZoneType::Primary
  }

  fn axfr_policy(&self) -> AxfrPolicy {
    AxfrPolicy::Deny
  }

  async fn update(
    &self,
    _update: &Request,
    _now: u64,
  ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
    (Err(ResponseCode::NoError), None)
  }

  fn origin(&self) -> &LowerName {
    &self.origin
  }

  async fn lookup(
    &self,
    _name: &LowerName,
    _rtype: RecordType,
    _request_info: Option<&RequestInfo<'_>>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
  }

  async fn search(
    &self,
    request: &Request,
    _lookup_options: LookupOptions,
  ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
    let request_info = request.request_info().unwrap();
    warn!("Domain name ignored {}", request_info.query.name());
    (forge_or_error(self.default_ip, request_info), None)
  }

  async fn nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
  }
}
