use crate::authority::forge_or_error;
use hickory_server::proto::{
  op::ResponseCode,
  rr::{domain::Name, LowerName, RecordType, TSigResponseContext},
};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::zone_handler::{
  AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
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
impl ZoneHandler for DomainBlacklistAuthority {
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
    name: &LowerName,
    _rtype: RecordType,
    _request_info: Option<&RequestInfo<'_>>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    if self.blacklisted.contains(name) {
      warn!("Domain name ignored {}", name);
      LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
    } else {
      LookupControlFlow::Skip
    }
  }

  async fn search(
    &self,
    request: &Request,
    _lookup_options: LookupOptions,
  ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
    let request_info = request.request_info().unwrap();
    if self.blacklisted.contains(request_info.query.name()) {
      warn!("Domain name ignored {}", request_info.query.name());
      (forge_or_error(self.default_ip, request_info), None)
    } else {
      (LookupControlFlow::Skip, None)
    }
  }

  async fn nsec_records(
    &self,
    name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    if self.blacklisted.contains(name) {
      warn!("Domain name ignored {}", name);
      LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
    } else {
      LookupControlFlow::Skip
    }
  }
}
