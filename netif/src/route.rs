#![allow(non_camel_case_types, non_snake_case, dead_code, unused_variables, 
    unused_mut, unused_unsafe, unused_imports, unused_assignments)]

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

use sys;
use HwAddr;
use ipnetwork::IpNetwork;
use ipnetwork::ip_mask_to_prefix;


use std::ffi::CStr;
use std::io;
use std::ptr;
use std::mem;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::string::ToString;


bitflags! {
    pub struct Flags: i32 {
        const RTF_UP = sys::RTF_UP;
        const RTF_GATEWAY = sys::RTF_GATEWAY;
        const RTF_HOST = sys::RTF_HOST;
        const RTF_REJECT = sys::RTF_REJECT;
        const RTF_DYNAMIC = sys::RTF_DYNAMIC;
        const RTF_MODIFIED = sys::RTF_MODIFIED;
        const RTF_DONE = sys::RTF_DONE;
        const RTF_DELCLONE = sys::RTF_DELCLONE;
        const RTF_CLONING = sys::RTF_CLONING;
        const RTF_XRESOLVE = sys::RTF_XRESOLVE;
        const RTF_LLINFO = sys::RTF_LLINFO;
        const RTF_LLDATA = sys::RTF_LLDATA;
        const RTF_STATIC = sys::RTF_STATIC;
        const RTF_BLACKHOLE = sys::RTF_BLACKHOLE;
        const RTF_NOIFREF = sys::RTF_NOIFREF;
        const RTF_PROTO2 = sys::RTF_PROTO2;
        const RTF_PROTO1 = sys::RTF_PROTO1;
        const RTF_PRCLONING = sys::RTF_PRCLONING;
        const RTF_WASCLONED = sys::RTF_WASCLONED;
        const RTF_PROTO3 = sys::RTF_PROTO3;
        const RTF_PINNED = sys::RTF_PINNED;
        const RTF_LOCAL = sys::RTF_LOCAL;
        const RTF_BROADCAST = sys::RTF_BROADCAST;
        const RTF_MULTICAST = sys::RTF_MULTICAST;
        const RTF_IFSCOPE = sys::RTF_IFSCOPE;
        const RTF_CONDEMNED = sys::RTF_CONDEMNED;
        const RTF_IFREF = sys::RTF_IFREF;
        const RTF_PROXY = sys::RTF_PROXY;
        const RTF_ROUTER = sys::RTF_ROUTER;
        const RTF_DEAD = sys::RTF_DEAD;
        const RTPRF_OURS = sys::RTPRF_OURS;
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}",
            format!("{:?}", self).replace("RTF_", "").replace(" | ", ","))
    }
}

bitflags! {
    pub struct RtmAddrFlags: i32 {
        const RTA_DST = sys::RTA_DST;
        const RTA_GATEWAY = sys::RTA_GATEWAY;
        const RTA_NETMASK = sys::RTA_NETMASK;
        const RTA_GENMASK = sys::RTA_GENMASK;
        const RTA_IFP = sys::RTA_IFP;
        const RTA_IFA = sys::RTA_IFA;
        const RTA_AUTHOR = sys::RTA_AUTHOR;
        const RTA_BRD = sys::RTA_BRD;
    }
}

impl fmt::Display for RtmAddrFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}",
            format!("{:?}", self).replace("RTA_", "").replace(" | ", ","))
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SockAddr {
    IpAddr(IpAddr),
    HwAddr(HwAddr),
}

impl SockAddr {
    pub fn from_libc_sockaddr_bytes(sa: &[u8]) -> Option<SockAddr> {
        let sa_len = sa[0];
        let sa_family = sa[1] as i32;
        let sa_data = &sa[2..16];
        match sa_family {
            sys::AF_INET  => {
                let in_addr = [ sa[ 4], sa[ 5], sa[6], sa[7] ];
                Some(SockAddr::IpAddr(IpAddr::V4(Ipv4Addr::from(in_addr))))
            }
            sys::AF_INET6 => {
                let in6_addr = [
                    sa[7+0], sa[7+1], sa[7+2], sa[7+3],
                    sa[7+4], sa[7+5], sa[7+6], sa[7+7],
                    sa[7+8], sa[7+9], sa[7+10], sa[7+11],
                    sa[7+12], sa[7+13], sa[7+14], sa[7+15],
                ];
                Some(SockAddr::IpAddr(IpAddr::V6(Ipv6Addr::from(in6_addr))))
            }
            sys::AF_LINK => {
                let sdl = sa.as_ptr() as *const sys::sockaddr_dl;
                let sdl_index = unsafe { (*sdl).sdl_index as u32 };
                let sdl_nlen = unsafe { (*sdl).sdl_nlen as usize };
                let sdl_alen = unsafe { (*sdl).sdl_alen as usize };
                let sdl_data = unsafe { (*sdl).sdl_data };

                if sdl_alen == 6 && sdl_nlen + sdl_alen < sdl_data.len() {
                    let hwaddr = HwAddr::from([sdl_data[sdl_nlen] as u8,
                                       sdl_data[sdl_nlen + 1] as u8,
                                       sdl_data[sdl_nlen + 2] as u8,
                                       sdl_data[sdl_nlen + 3] as u8,
                                       sdl_data[sdl_nlen + 4] as u8,
                                       sdl_data[sdl_nlen + 5] as u8]);
                    Some(SockAddr::HwAddr(hwaddr))
                } else {
                    None
                }
            }
            _ => None
        }
    }

    pub fn is_ip(&self) -> bool {
        match *self {
            SockAddr::IpAddr(_) => true,
            _ => false
        }
    }

    pub fn is_hw(&self) -> bool {
        match *self {
            SockAddr::HwAddr(_) => true,
            _ => false
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match *self {
            SockAddr::IpAddr(ip) => Some(ip),
            _ => None
        }
    }

    pub fn hw(&self) -> Option<HwAddr> {
        match *self {
            SockAddr::HwAddr(hw) => Some(hw),
            _ => None
        }
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    IpNetwork(IpNetwork),
    IpAddress(IpAddr)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Gateway {
    IpAddress(IpAddr),
    HwAddr(HwAddr),
    Interface(String),
    Link(u32)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    destination: Destination,
    gateway: Gateway,
    ifname: String,
    flags: Flags
}


impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Destination::IpNetwork(nw) => nw.fmt(f),
            Destination::IpAddress(ip) => ip.fmt(f)
        }
    }
}

impl fmt::Display for Gateway {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Gateway::IpAddress(ip) => ip.fmt(f),
            Gateway::HwAddr(hw) => hw.fmt(f),
            Gateway::Interface(ref ifname) => ifname.fmt(f),
            Gateway::Link(ifindex) => write!(f, "LINK#{}", ifindex)
        }
    }
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:40} {:40} {:55} {:40}",
            format!("{}", self.destination),
            format!("{}", self.gateway),
            format!("{}", self.flags),
            self.ifname)
    }
}


pub fn list() -> Result<Vec<Table>, io::Error>{
    // inet4: libc::AF_INET, inet6: libc::AF_INET6, all: 0
    let family = 0;
    let flags = 0;
    let mut lenp: usize = 0;

    let mib: [i32; 6] = [
        sys::CTL_NET, sys::AF_ROUTE, 0,
        family, sys::NET_RT_DUMP, flags
    ];
    let null: *const i32 = ptr::null();
    let mut ret: sys::c_int = 0;

    ret = unsafe {
        sys::sysctl(mib.as_ptr() as *mut i32,
                    6,
                    null as *mut sys::c_void,
                    &mut lenp,
                    null as *mut sys::c_void,
                    0)
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    
    let mut buf = vec![0u8; lenp];
    let buf_ptr = buf.as_ptr();

    ret = unsafe {
        sys::sysctl(mib.as_ptr() as *mut i32,
                    6,
                    buf_ptr as *mut sys::c_void,
                    &mut lenp,
                    null as *mut sys::c_void,
                    0)
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut routing_table = vec![];

    let rt_msghdr_size = mem::size_of::<sys::rt_msghdr>();

    let mut start: usize = 0;
    loop {
        let end = start + rt_msghdr_size;
        if start >= lenp {
            break;
        }
        let rtm_bytes = &buf[start..end];

        let rtm = rtm_bytes.as_ptr() as *const sys::rt_msghdr;
        let rtm_msglen = unsafe { (*rtm).rtm_msglen as usize };
        let rtm_type = unsafe { (*rtm).rtm_type as u8 };
        let rtm_index = unsafe { (*rtm).rtm_index as u32 };
        let rtm_flags = Flags::from_bits( unsafe { (*rtm).rtm_flags as i32 } ).unwrap();
        let rtm_addrs = unsafe { (*rtm).rtm_addrs as i32 };

        let dest_size = buf[end] as usize;
        let dest_start = end;
        let dest_end   = end +  dest_size;
        let dest_sockaddr_bytes = &buf[dest_start..dest_end];
        
        let dest_sa = dest_sockaddr_bytes.as_ptr() as *const sys::sockaddr;

        let gateway_start = dest_end;
        let gateway_end   = gateway_start+(rtm_msglen-rt_msghdr_size-dest_size);
        let gateway_sockaddr_bytes = &buf[gateway_start..gateway_end];

        let gateway_sa = gateway_sockaddr_bytes.as_ptr() as *const sys::sockaddr;

        let destination_addr = SockAddr::from_libc_sockaddr_bytes(dest_sockaddr_bytes);
        let gateway_addr = SockAddr::from_libc_sockaddr_bytes(gateway_sockaddr_bytes);
        
        match destination_addr {
            Some(dst_addr) => {
                let ifname = sys::if_index_to_name(rtm_index);
                if dst_addr.is_ip() {
                    let dst_ip = dst_addr.ip().unwrap();
                    let dst = if rtm_flags.contains(Flags::RTF_IFSCOPE) {
                        let prefix = match dst_ip{
                            IpAddr::V4(ipv4_addr) => format!("{:b}", u32::from(ipv4_addr)).len(),
                            IpAddr::V6(ipv6_addr) => format!("{:b}", u128::from(ipv6_addr)).len(),
                        };
                        Destination::IpNetwork(IpNetwork::new(dst_ip, prefix as u8).unwrap())
                    } else {
                        Destination::IpAddress(dst_ip)
                    };

                    let gw = if gateway_addr.is_none() {
                        if rtm_flags.contains(Flags::RTF_IFSCOPE) {
                            Gateway::Interface(ifname.clone())
                        } else if rtm_flags.contains(Flags::RTF_HOST) {
                            Gateway::Interface(ifname.clone())
                        } else {
                            Gateway::Link(rtm_index)
                        }
                    } else {
                        match gateway_addr.unwrap() {
                            SockAddr::IpAddr(ip) => Gateway::IpAddress(ip),
                            SockAddr::HwAddr(hw) => Gateway::HwAddr(hw),
                        }
                    };
                    routing_table.push(Table {
                        destination: dst,
                        gateway: gw,
                        ifname: ifname,
                        flags: rtm_flags
                    })
                }
            },
            None => {}
        }
        start += rtm_msglen;
    }

    Ok(routing_table)
}

