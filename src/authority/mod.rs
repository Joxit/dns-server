use hickory_client::proto::rr::rdata::AAAA;
use hickory_resolver::lookup::Lookup as ResolverLookup;
use hickory_server::{
  proto::rr::{rdata::A, RData, Record},
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
  let record = Record::from_rdata(request_info.query.name().into(), u32::MAX, RData::A(A(ip)));
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
      if let Ok(a) = r.data().clone().into_a() {
        Record::from_rdata(
          r.name().clone(),
          r.ttl(),
          RData::AAAA(AAAA(ipv4_to_prefixed_ipv6(&a))),
        )
      } else {
        Record::from_rdata(r.name().clone(), r.ttl(), r.data().clone())
      }
    })
    .collect();

  let lookup = ResolverLookup::new_with_max_ttl(
    ipv4_records.query().clone(),
    records.into_boxed_slice().into(),
  );
  return ForwardLookup(lookup);
}
