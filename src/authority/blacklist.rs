use crate::{
  authority::{forge_ip_record, ipv4_to_prefixed_ipv6_records},
  ip::IpRangeVec,
};
use hickory_resolver::{
  config::NameServerConfigGroup,
  name_server::{ConnectionProvider, GenericConnector, TokioConnectionProvider},
  Name,
};
use hickory_server::{
  authority::{
    Authority, LookupControlFlow, LookupError, LookupOptions, MessageRequest, UpdateResult,
    ZoneType,
  },
  proto::{
    op::{Query, ResponseCode},
    rr::{LowerName, RecordType},
  },
  server::RequestInfo,
  store::forwarder::{ForwardAuthority, ForwardConfig, ForwardLookup},
};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use tracing::{info, warn};

pub struct BlacklistAuthority<P: ConnectionProvider = TokioConnectionProvider> {
  blacklisted: HashSet<LowerName>,
  inner: ForwardAuthority<P>,
  default_ip: Option<Ipv4Addr>,
  rfc8215_ips: IpRangeVec,
}

impl BlacklistAuthority {
  pub fn new(
    name: Name,
    blacklisted: HashSet<LowerName>,
    name_servers: NameServerConfigGroup,
    default_ip: Option<Ipv4Addr>,
    rfc8215_ips: IpRangeVec,
  ) -> Self {
    info!("Domains {:?} will be ingnored", blacklisted);
    let authority_config = ForwardConfig {
      name_servers,
      options: None,
    };

    let forward_authority =
      ForwardAuthority::builder_with_config(authority_config, GenericConnector::default())
        .with_domain(name.clone())
        .build()
        .unwrap();
    Self {
      blacklisted,
      inner: forward_authority,
      default_ip,
      rfc8215_ips,
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
  ) -> LookupControlFlow<Self::Lookup> {
    self.inner.lookup(name, query_type, lookup_options).await
  }

  async fn search(
    &self,
    request_info: RequestInfo<'_>,
    lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    if self.blacklisted.contains(request_info.query.name()) {
      warn!("Domain name ignored {}", request_info.query.name());
      if let Some(ip) = self.default_ip {
        LookupControlFlow::Break(Ok(forge_ip_record(ip, request_info)))
      } else {
        LookupControlFlow::Break(Err(LookupError::ResponseCode(ResponseCode::NoError)))
      }
    } else {
      match self
        .inner
        .search(request_info.clone(), lookup_options)
        .await
      {
        LookupControlFlow::Continue(Ok(res)) | LookupControlFlow::Break(Ok(res)) => {
          LookupControlFlow::Break(Ok(res))
        }
        LookupControlFlow::Continue(Err(err)) | LookupControlFlow::Break(Err(err)) => {
          if request_info.query.query_type() == RecordType::AAAA
            && self.rfc8215_ips.contains_sock_addr(request_info.src)
          {
            let mut query = Query::query(request_info.query.name().into(), RecordType::A);
            query.set_query_class(request_info.query.query_class());
            let lower_query = query.into();
            let a_request = RequestInfo::new(
              request_info.src,
              request_info.protocol,
              request_info.header,
              &lower_query,
            );
            match self.inner.search(a_request, lookup_options).await {
              LookupControlFlow::Continue(Ok(a_res)) | LookupControlFlow::Break(Ok(a_res)) => {
                return LookupControlFlow::Break(Ok(ipv4_to_prefixed_ipv6_records(a_res.0)));
              }
              _ => {}
            };
          }

          LookupControlFlow::Break(Err(err))
        }
        _ => LookupControlFlow::Skip,
      }
    }
  }

  async fn get_nsec_records(
    &self,
    name: &LowerName,
    lookup_options: LookupOptions,
  ) -> LookupControlFlow<Self::Lookup> {
    self.inner.get_nsec_records(name, lookup_options).await
  }
}
