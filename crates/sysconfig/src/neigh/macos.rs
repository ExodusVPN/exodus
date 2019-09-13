use libc;
use smoltcp::wire::IpCidr;
use smoltcp::wire::EthernetAddress;


use std::io;
use std::ptr;
use std::mem;

pub const RTF_LLDATA: libc::c_int = 0x400;
pub const RTF_DEAD: libc::c_int   = 0x20000000;
pub const RTPRF_OURS: libc::c_int = libc::RTF_PROTO3;


pub fn list() -> Result<(), io::Error>{
    // ARP/NDP
    let mut mib: [libc::c_int; 6] = [0; 6];
    let mut len: libc::size_t = 0;
    let family = 0;  // inet4 & inet6
    mib[0] = libc::CTL_NET;
    mib[1] = libc::PF_ROUTE;     // libc::AF_ROUTE
    mib[2] = 0;
    mib[3] = family;
    mib[4] = libc::NET_RT_FLAGS; // libc::NET_RT_DUMPX_FLAGS
    mib[5] = libc::RTF_LLINFO;   // flags
    
    
    Ok(())
}