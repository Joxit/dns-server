use anyhow::Result;
// use rustls::pki_types::Ipv4Addr;
use ipnet::IpNet;
use std::{cmp::Ordering, net::IpAddr};

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Copy, Debug)]
pub struct IpRange {
  start: u128,
  end: u128,
}

#[derive(PartialEq, PartialOrd, Eq, Ord, Clone, Debug)]
pub struct IpRangeVec {
  ranges: Vec<IpRange>,
}

impl TryFrom<&str> for IpRange {
  type Error = anyhow::Error;
  fn try_from(s: &str) -> Result<IpRange, Self::Error> {
    let range = match s.parse::<IpNet>()? {
      IpNet::V4(ip) => IpRange {
        start: ip.network().to_bits() as u128,
        end: ip.broadcast().to_bits() as u128,
      },
      IpNet::V6(ip) => IpRange {
        start: ip.network().to_bits(),
        end: ip.broadcast().to_bits(),
      },
    };
    Ok(range)
  }
}

impl IpRangeVec {
  fn new(ranges: Vec<IpRange>) -> Self {
    let mut ranges = ranges.clone();
    ranges.sort();
    Self { ranges }
  }

  fn contains(&self, ip: IpAddr) -> bool {
    let bits = match ip {
      IpAddr::V4(ip) => ip.to_bits() as u128,
      IpAddr::V6(ip) => ip.to_bits(),
    };

    self
      .ranges
      .binary_search_by(|probe| {
        if probe.start <= bits && bits <= probe.end {
          Ordering::Equal
        } else if probe.end < bits {
          Ordering::Less
        } else {
          Ordering::Greater
        }
      })
      .is_ok()
  }
}

#[cfg(test)]
mod test {

  use super::*;

  fn get_private_range_vec() -> IpRangeVec {
    let ranges = vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]
      .into_iter()
      .map(|range| IpRange::try_from(range).unwrap())
      .collect();
    IpRangeVec::new(ranges)
  }

  #[test]
  fn ordering() {
    let ranges: Vec<IpRange> = vec!["fd00::/8", "172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"]
      .into_iter()
      .map(|range| IpRange::try_from(range).unwrap())
      .collect();
    let expected = get_private_range_vec().ranges;

    assert_eq!(expected, IpRangeVec::new(ranges).ranges);
  }

  #[test]
  fn contains_all() {
    let ip_range_vec = get_private_range_vec();

    vec![
      "10.0.0.0",
      "10.128.128.128",
      "10.255.255.255",
      "172.16.0.0",
      "172.25.255.255",
      "172.31.255.255",
      "192.168.128.128",
      "192.168.0.0",
      "192.168.255.255",
      "fd00::",
      "fdff:ffff:ffff:ffff::",
      "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
    ]
    .iter()
    .map(|ip| ip.parse::<IpAddr>().unwrap())
    .for_each(|ip| assert!(ip_range_vec.contains(ip), "{}", ip));
  }

  #[test]
  fn does_not_contain_all() {
    let ip_range_vec = get_private_range_vec();

    vec![
      "9.255.255.255",
      "11.0.0.0",
      "172.15.255.255",
      "172.32.0.0",
      "192.167.255.255",
      "192.169.0.0",
      "fcff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
      "fe00::",
    ]
    .iter()
    .map(|ip| ip.parse::<IpAddr>().unwrap())
    .for_each(|ip| assert!(!ip_range_vec.contains(ip), "{}", ip));
  }
}
