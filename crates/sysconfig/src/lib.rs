#[macro_use]
extern crate log;
#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate sysctl;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;
// #[cfg(target_os = "macos")]
// extern crate pfctl;
extern crate smoltcp;


pub mod dns;
pub mod route;
pub mod neigh;
pub mod firewall;
pub mod ip_forwarding;


pub use smoltcp::wire::IpCidr;
pub use smoltcp::wire::Ipv4Cidr;
pub use smoltcp::wire::Ipv6Cidr;
pub use smoltcp::wire::EthernetAddress;


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn ipv6_cidr_from_netmask(address: Ipv6Addr, netmask: Ipv6Addr) -> Result<Ipv6Cidr, smoltcp::Error> {
    const IPV6_SEGMENT_BITS: u8 = 16;

    let mask = netmask.segments();
    let mut mask_iter = mask.into_iter();

    let mut prefix_len = 0u8;
    for &segment in &mut mask_iter {
        if segment == 0xffff {
            prefix_len += IPV6_SEGMENT_BITS;
        } else if segment == 0 {
            break;
        } else {
            let prefix_bits = (!segment).leading_zeros() as u8;
            if segment << prefix_bits != 0 {
                return Err(smoltcp::Error::Illegal);
            }
            prefix_len += prefix_bits;
            break;
        }
    }

    for &segment in mask_iter {
        if segment != 0 {
            return Err(smoltcp::Error::Illegal);
        }
    }

    Ok(Ipv6Cidr::new(address.into(), prefix_len))
}

pub fn ipv4_cidr_from_netmask(address: Ipv4Addr, netmask: Ipv4Addr) -> Result<Ipv4Cidr, smoltcp::Error> {
    Ipv4Cidr::from_netmask(address.into(), netmask.into())
}

pub fn ip_cidr_from_netmask(addr: IpAddr, netmask: IpAddr) -> Result<IpCidr, smoltcp::Error> {
    match (addr, netmask) {
        (IpAddr::V4(v4_addr), IpAddr::V4(v4_netmask)) => {
            let v4_cidr = ipv4_cidr_from_netmask(v4_addr, v4_netmask)?;
            Ok(IpCidr::Ipv4(v4_cidr))
        },
        (IpAddr::V6(v6_addr), IpAddr::V6(v6_netmask)) => {
            let v6_cidr = ipv6_cidr_from_netmask(v6_addr, v6_netmask)?;
            Ok(IpCidr::Ipv6(v6_cidr))
        },
        _ => Err(smoltcp::Error::Illegal),
    }
}

pub fn netmask_from_ipcidr(cidr: IpCidr) -> IpAddr {
    match cidr {
        IpCidr::Ipv4(v4_cidr) => {
            IpAddr::from(v4_cidr.netmask().0)
        },
        IpCidr::Ipv6(v6_cidr) => {
            if v6_cidr.prefix_len() == 0 {
                return IpAddr::from(Ipv6Addr::UNSPECIFIED);
            }

            let number = std::u128::MAX << (128 - v6_cidr.prefix_len());
            let data = [
                ((number >> 120) & 0xff) as u8,
                ((number >> 112) & 0xff) as u8,
                ((number >> 104) & 0xff) as u8,
                ((number >>  96) & 0xff) as u8,
                ((number >>  88) & 0xff) as u8,
                ((number >>  80) & 0xff) as u8,
                ((number >>  72) & 0xff) as u8,
                ((number >>  64) & 0xff) as u8,
                ((number >>  56) & 0xff) as u8,
                ((number >>  48) & 0xff) as u8,
                ((number >>  40) & 0xff) as u8,
                ((number >>  32) & 0xff) as u8,
                ((number >>  24) & 0xff) as u8,
                ((number >>  16) & 0xff) as u8,
                ((number >>   8) & 0xff) as u8,
                ((number >>   0) & 0xff) as u8,
            ];

            IpAddr::from(Ipv6Addr::from(data))
        },
        _ => unreachable!(),
    }
}