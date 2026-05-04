use hickory_server::proto::rr::{
  rdata::{A, AAAA},
  RData, Record,
};
use hickory_server::resolver::lookup::Lookup as ResolverLookup;
use hickory_server::server::RequestInfo;
use hickory_server::zone_handler::{AuthLookup, LookupControlFlow};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
) -> LookupControlFlow<AuthLookup> {
  let lookup = if let Some(ip) = ip {
    let rdata = match ip {
      IpAddr::V4(ip) => RData::A(A(ip)),
      IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
    };
    let record = Record::from_rdata(request_info.query.name().into(), 600, rdata);
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), [record])
  } else {
    ResolverLookup::new_with_max_ttl(request_info.query.original().clone(), [])
  };
  LookupControlFlow::Break(Ok(AuthLookup::Resolved(lookup)))
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

pub fn ipv4_to_prefixed_ipv6_records(ipv4_records: AuthLookup) -> Vec<Record> {
  ipv4_records
    .iter()
    .map(|r| match r.data.clone().ip_addr() {
      Some(IpAddr::V4(a)) => Record::from_rdata(
        r.name.clone(),
        r.ttl,
        RData::AAAA(AAAA(ipv4_to_prefixed_ipv6(&a))),
      ),
      _ => Record::from_rdata(r.name.clone(), r.ttl, r.data.clone()),
    })
    .collect()
}
