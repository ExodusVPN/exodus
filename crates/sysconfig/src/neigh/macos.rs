use crate::route::rt_msghdr;
use crate::route::sa_to_ipaddr;
use crate::route::RTM_MSGHDR_LEN;
use crate::route::align;
use crate::route::Addr;

use libc;
use smoltcp::wire::EthernetAddress;

use std::io;
use std::ptr;
use std::mem;
use std::net::IpAddr;


pub const RTF_LLDATA: libc::c_int = 0x400;
pub const RTF_DEAD: libc::c_int   = 0x20000000;
pub const RTPRF_OURS: libc::c_int = libc::RTF_PROTO3;


// https://opensource.apple.com/source/network_cmds/network_cmds-543.200.16/arp.tproj/arp.c
// https://opensource.apple.com/source/network_cmds/network_cmds-543.200.16/ndp.tproj/ndp.c
// bin: ifconfig
// https://opensource.apple.com/source/network_cmds/network_cmds-543.200.16/ifconfig.tproj/
// 
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html
// 
pub fn list<'a>(buffer: &'a mut Vec<u8>) -> Result<NeighTable<'a>, io::Error>{
    // ARP/NDP
    // $ ndp -an
    // $ arp -an
    let mut mib: [libc::c_int; 6] = [0; 6];
    let mut len: libc::size_t = 0;
    let family = 0;  // inet4 & inet6
    mib[0] = libc::CTL_NET;
    mib[1] = libc::PF_ROUTE;     // libc::AF_ROUTE
    mib[2] = 0;
    mib[3] = family;
    mib[4] = libc::NET_RT_FLAGS; // libc::NET_RT_DUMPX_FLAGS
    mib[5] = libc::RTF_LLINFO;   // flags
    
    let mib_ptr = &mib as *const libc::c_int as *mut libc::c_int;

    if unsafe { libc::sysctl(mib_ptr, 6, ptr::null_mut(), &mut len, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    buffer.resize(len as usize, 0);

    let buffer_ptr: *mut u8 = buffer.as_mut_ptr() as _;
    if unsafe { libc::sysctl(mib_ptr, 6, buffer_ptr as _, &mut len, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    if buffer_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok(NeighTable { buffer: &mut buffer[..len], offset: 0 })
}

#[derive(Debug, Clone)]
pub struct Neigh {
    pub ip_addr: IpAddr,
    pub link_addr: EthernetAddress,
    pub link_index: u32,
}


pub struct NeighTable<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> Iterator for NeighTable<'a> {
    type Item = Neigh;

    fn next(&mut self) -> Option<Self::Item> {
        let buffer = &mut self.buffer[self.offset..];

        if buffer.len() < RTM_MSGHDR_LEN {
            return None;
        }

        let ip_addr;
        let link_addr;
        let link_index;

        unsafe {
            let rtm_hdr = mem::transmute::<*const u8, &rt_msghdr>(buffer.as_ptr());
            assert!(rtm_hdr.rtm_addrs < libc::RTAX_MAX);
            assert_eq!(rtm_hdr.rtm_version as i32, libc::RTM_VERSION);
            assert_eq!(rtm_hdr.rtm_errno, 0);

            let rtm_pkt_len = rtm_hdr.rtm_msglen as usize;
            self.offset += rtm_pkt_len;

            let rtm_pkt = &mut buffer[..rtm_pkt_len];
            assert!(rtm_pkt.len() >= rtm_pkt_len);
            let mut rtm_payload = &mut rtm_pkt[RTM_MSGHDR_LEN..rtm_pkt_len];

            // IP_ADDR
            let sa = mem::transmute::<*const u8, &libc::sockaddr>(rtm_payload.as_ptr());
            let sa_len    = sa.sa_len as usize;
            match sa_to_ipaddr(sa as *const libc::sockaddr) {
                Addr::V4(v4_addr) => {
                    ip_addr = IpAddr::from(v4_addr);
                },
                Addr::V6(v6_addr) => {
                    ip_addr = IpAddr::from(v6_addr);
                },
                Addr::Link { .. } => {
                    // return self.next();
                    unreachable!();
                },
            }
            rtm_payload = &mut rtm_payload[align(sa_len)..];

            // LINK_ADDR
            let sa = mem::transmute::<*const u8, &libc::sockaddr>(rtm_payload.as_ptr());
            let sa_len    = sa.sa_len as usize;
            match sa_to_ipaddr(sa as *const libc::sockaddr) {
                Addr::V4(v4_addr) => {
                    return self.next();
                },
                Addr::V6(v6_addr) => {
                    return self.next();
                },
                Addr::Link { ifindex, mac } => {
                    link_index = ifindex;
                    if mac.is_none() {
                        return self.next();
                    }
                    link_addr = mac.unwrap();
                },
            }
        }

        Some(Neigh { ip_addr, link_addr, link_index })
    }
}