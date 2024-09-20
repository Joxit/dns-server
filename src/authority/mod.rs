use hickory_client::rr::rdata::AAAA;
use hickory_server::{
  proto::rr::{rdata::A, RData, Record, RecordType},
  resolver::lookup::Lookup as ResolverLookup,
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use std::{
  net::{Ipv4Addr, Ipv6Addr},
  sync::Arc,
};
mod blacklist;
mod none;

pub(crate) use crate::authority::blacklist::BlacklistAuthority;
pub(crate) use crate::authority::none::NoneAuthority;

pub fn forge_ip_record(ip: Ipv4Addr, request_info: RequestInfo<'_>) -> ForwardLookup {
  let mut record = Record::with(request_info.query.name().into(), RecordType::A, u32::MAX);
  record.set_data(Some(RData::A(A(ip))));
  let lookup =
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), Arc::new([record]));
  return ForwardLookup(lookup);
}

fn ipv4_to_prefixed_ipv6(ip: &Ipv4Addr) -> Ipv6Addr {
  let [a, b, c, d] = ip.octets();
  let g = ((a as u16) << 8) + (b as u16);
  let h = ((c as u16) << 8) + (d as u16);
  Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, g, h)
}

pub fn ipv4_to_prefixed_ipv6_records(ipv4_records: ResolverLookup) -> ForwardLookup {
  let records: Vec<Record> = ipv4_records
    .records()
    .iter()
    .map(|r| {
      let mut record = Record::with(r.name().clone(), r.record_type(), r.ttl());
      if let Some(data) = r.data() {
        if let Ok(a) = data.clone().into_a() {
          record.set_data(Some(RData::AAAA(AAAA(ipv4_to_prefixed_ipv6(&a)))));
          record.set_record_type(RecordType::AAAA);
        } else {
          record.set_data(Some(data.clone()));
        }
      }
      record
    })
    .collect();

  let lookup = ResolverLookup::new_with_max_ttl(
    ipv4_records.query().clone(),
    records.into_boxed_slice().into(),
  );
  return ForwardLookup(lookup);
}
