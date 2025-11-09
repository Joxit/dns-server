use hickory_client::proto::rr::rdata::AAAA;
use hickory_resolver::lookup::Lookup as ResolverLookup;
use hickory_server::{
  authority::LookupControlFlow,
  proto::rr::{rdata::A, RData, Record},
  server::RequestInfo,
  store::forwarder::ForwardLookup,
};
use std::{
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
  sync::Arc,
};
mod default;
mod domain_blacklist;
mod local_dns;
mod zone_blacklist;

pub(crate) use crate::authority::default::DefaultAuthority;
pub(crate) use crate::authority::domain_blacklist::DomainBlacklistAuthority;
pub(crate) use crate::authority::local_dns::LocalDNSAuthority;
pub(crate) use crate::authority::zone_blacklist::ZoneBlacklistAuthority;

pub fn forge_or_error(
  ip: Option<IpAddr>,
  request_info: RequestInfo<'_>,
) -> LookupControlFlow<ForwardLookup> {
  let lookup = if let Some(ip) = ip {
    let rdata = match ip {
      IpAddr::V4(ip) => RData::A(A(ip)),
      IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
    };
    let record = Record::from_rdata(request_info.query.name().into(), 600, rdata);
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), Arc::new([record]))
  } else {
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), Arc::new([]))
  };
  LookupControlFlow::Break(Ok(ForwardLookup(lookup)))
}

fn ipv4_to_prefixed_ipv6(ip: &Ipv4Addr) -> Ipv6Addr {
  let [a, b, c, d] = ip.octets();
  let g = ((a as u16) << 8) + (b as u16);
  let h = ((c as u16) << 8) + (d as u16);
  Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, g, h)
}

pub fn to_prefixed_ip(ip: &IpAddr) -> IpAddr {
  match ip {
    IpAddr::V4(ip) => IpAddr::V6(ipv4_to_prefixed_ipv6(ip)),
    IpAddr::V6(ip) => IpAddr::V6(*ip),
  }
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
