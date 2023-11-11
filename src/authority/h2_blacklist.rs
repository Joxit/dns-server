use crate::authority::forge_ip_record;
use hickory_client::{
  proto::h2::HttpsClientStream,
  proto::op::Message,
  proto::xfer::{DnsRequest, DnsRequestOptions, DnsRequestSender, DnsResponse, FirstAnswer},
};
use hickory_server::{
  authority::{Authority, LookupError, LookupOptions, MessageRequest, UpdateResult, ZoneType},
  proto::{
    op::ResponseCode,
    rr::{LowerName, RecordType},
  },
  resolver::{config::NameServerConfigGroup, lookup::Lookup as ResolverLookup, Name},
  server::RequestInfo,
  store::forwarder::{ForwardAuthority, ForwardConfig, ForwardLookup},
};
use std::{
  collections::HashSet,
  net::Ipv4Addr,
  sync::Arc,
  time::{Duration, Instant},
};
use tracing::{info, warn};

pub struct H2BlacklistAuthority {
  blacklisted: HashSet<LowerName>,
  inner: ForwardAuthority,
  default_ip: Option<Ipv4Addr>,
  doh_client: HttpsClientStream,
}

impl H2BlacklistAuthority {
  pub fn new(
    name: Name,
    blacklisted: HashSet<LowerName>,
    name_servers: NameServerConfigGroup,
    default_ip: Option<Ipv4Addr>,
    doh_client: HttpsClientStream,
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
      doh_client,
    }
  }
}

#[async_trait::async_trait]
impl Authority for H2BlacklistAuthority {
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
    _lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    if self.blacklisted.contains(request_info.query.name()) {
      warn!("Domain name ignored {}", request_info.query.name());
      if let Some(ip) = self.default_ip {
        return Ok(forge_ip_record(ip, request_info));
      } else {
        return Err(LookupError::ResponseCode(ResponseCode::NoError));
      }
    }

    let mut client = self.doh_client.clone();
    let mut message = Message::new();
    message.add_query(request_info.query.original().clone());
    let request = DnsRequest::new(message, DnsRequestOptions::default());

    let response = client
      .send_message(request.clone())
      .first_answer()
      .await
      .unwrap();

    Ok(dns_response_to_lookup(&response))
  }

  async fn get_nsec_records(
    &self,
    name: &LowerName,
    lookup_options: LookupOptions,
  ) -> Result<Self::Lookup, LookupError> {
    self.inner.get_nsec_records(name, lookup_options).await
  }
}

pub fn dns_response_to_lookup(response: &DnsResponse) -> ForwardLookup {
  let query = response.query().unwrap();
  let records = response.answers();
  let valid_until = Instant::now() + Duration::from_secs(u64::from(records[0].ttl()));

  let lookup =
    ResolverLookup::new_with_deadline(query.clone(), Arc::new([records[0].clone()]), valid_until);
  ForwardLookup(lookup)
}
