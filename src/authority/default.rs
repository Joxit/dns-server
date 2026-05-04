use crate::{authority::ipv4_to_prefixed_ipv6_records, ip::IpRangeVec};
use hickory_server::proto::{
  op::{Query, ResponseCode},
  rr::{domain::Name, LowerName, RecordType, TSigResponseContext},
};
use hickory_server::resolver::{
  config::NameServerConfig, lookup::Lookup as ResolverLookup, net::runtime::TokioRuntimeProvider,
  ConnectionProvider,
};
use hickory_server::server::{Request, RequestInfo};
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::zone_handler::{
  AuthLookup, AxfrPolicy, LookupControlFlow, LookupOptions, ZoneHandler, ZoneType,
};

pub struct DefaultAuthority<P: ConnectionProvider = TokioRuntimeProvider> {
  inner: ForwardZoneHandler<P>,
  rfc8215_ips: IpRangeVec,
}

impl DefaultAuthority {
  pub fn new(name_servers: Vec<NameServerConfig>, rfc8215_ips: IpRangeVec) -> Self {
    let authority_config = ForwardConfig {
      name_servers: name_servers,
      options: None,
    };

    let forward_authority =
      ForwardZoneHandler::builder_with_config(authority_config, TokioRuntimeProvider::default())
        .with_domain(Name::root())
        .build()
        .unwrap();
    Self {
      inner: forward_authority,
      rfc8215_ips,
    }
  }
}

#[async_trait::async_trait]
impl ZoneHandler for DefaultAuthority {
  fn zone_type(&self) -> ZoneType {
    self.inner.zone_type()
  }

  fn axfr_policy(&self) -> AxfrPolicy {
    AxfrPolicy::Deny
  }

  async fn update(
    &self,
    update: &Request,
    now: u64,
  ) -> (Result<bool, ResponseCode>, Option<TSigResponseContext>) {
    self.inner.update(update, now).await
  }

  fn origin(&self) -> &LowerName {
    self.inner.origin()
  }

  async fn lookup(
    &self,
    name: &LowerName,
    rtype: RecordType,
    request_info: Option<&RequestInfo<'_>>,
    lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    let request_info = request_info.unwrap();
    match self
      .inner
      .lookup(&name, rtype, Some(request_info), lookup_options)
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
          let lower_query = query.clone().into();
          let mut a_request = request_info.clone();
          a_request.query = &lower_query;

          match self
            .inner
            .lookup(&name, RecordType::A, Some(&a_request), lookup_options)
            .await
          {
            LookupControlFlow::Continue(Ok(a_res)) | LookupControlFlow::Break(Ok(a_res)) => {
              let records = ipv4_to_prefixed_ipv6_records(a_res);
              let lookup = ResolverLookup::new_with_max_ttl(query, records);
              return LookupControlFlow::Break(Ok(AuthLookup::Resolved(lookup)));
            }
            _ => {}
          };
        }

        LookupControlFlow::Break(Err(err))
      }
      _ => LookupControlFlow::Skip,
    }
  }

  async fn search(
    &self,
    request: &Request,
    lookup_options: LookupOptions,
  ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
    let request_info = request.request_info().unwrap();
    (
      self
        .lookup(
          request_info.query.name(),
          request_info.query.query_type(),
          Some(&request_info),
          lookup_options,
        )
        .await,
      None,
    )
  }

  async fn nsec_records(
    &self,
    name: &LowerName,
    lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    self.inner.nsec_records(name, lookup_options).await
  }
}
