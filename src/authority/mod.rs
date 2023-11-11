use hickory_server::{
  proto::rr::{rdata::A, Record, RecordType},
  resolver::lookup::Lookup as ResolverLookup,
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use std::net::Ipv4Addr;
use std::sync::Arc;
mod blacklist;
mod h2_blacklist;
mod none;

pub(crate) use crate::authority::blacklist::BlacklistAuthority;
pub(crate) use crate::authority::h2_blacklist::H2BlacklistAuthority;
pub(crate) use crate::authority::none::NoneAuthority;

pub fn forge_ip_record(ip: Ipv4Addr, request_info: RequestInfo<'_>) -> ForwardLookup {
  let mut record = Record::with(request_info.query.name().into(), RecordType::A, u32::MAX);
  record.set_data(Some(hickory_server::proto::rr::RData::A(A(ip))));
  let lookup =
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), Arc::new([record]));
  return ForwardLookup(lookup);
}
