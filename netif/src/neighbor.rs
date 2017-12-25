#![allow(non_camel_case_types, non_snake_case, dead_code, unused_variables, 
    unused_mut, unused_unsafe, unused_imports)]


// Note: linux not support yet.
// #![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
#![cfg(any(target_os = "macos", target_os = "freebsd"))]

extern crate libc;

use std::ffi::CStr;
use std::io;
use std::ptr;
use std::mem;

pub const RTF_LLINFO: libc::c_int = 0x400;


#[repr(C)]
#[allow(non_snake_case)]
pub struct sockaddr_inarp {
    pub sin_len: libc::c_uchar,
    pub sin_family: libc::c_uchar,
    pub sin_port: libc::c_ushort,
    pub sin_addr: libc::in_addr,
    pub sin_srcaddr: libc::in_addr,
    pub sin_tos: libc::c_ushort,
    pub sin_other: libc::c_ushort
}


#[repr(C)]
#[allow(non_snake_case)]
#[derive(Debug)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type 
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,       // identify sender
    pub rtm_seq: libc::c_int,       // for sender to identify action
    pub rtm_errno: libc::c_int,     // why failed
    pub rtm_use: libc::c_int,       // from rtentry
    pub rtm_inits: libc::uint32_t,  // which metrics we are initializing
    pub rtm_rmx: rt_metrics,        // metrics themselves
}

// These numbers are used by reliable protocols for determining
// retransmission behavior and are included in the routing structure.
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct rt_metrics {
    pub rmx_locks: libc::uint32_t,       // Kernel leaves these values alone
    pub rmx_mtu: libc::uint32_t,         // MTU for this path
    pub rmx_hopcount: libc::uint32_t,    // max hops expected
    pub rmx_expire: libc::int32_t,       // lifetime for route, e.g. redirect
    pub rmx_recvpipe: libc::uint32_t,    // inbound delay-bandwidth product
    pub rmx_sendpipe: libc::uint32_t,    // outbound delay-bandwidth product
    pub rmx_ssthresh: libc::uint32_t,    // outbound gateway buffer limit
    pub rmx_rtt: libc::uint32_t,         // estimated round trip time
    pub rmx_rttvar: libc::uint32_t,      // estimated rtt variance
    pub rmx_pksent: libc::uint32_t,      // packets sent using this route
    pub rmx_state: libc::uint32_t,       // route state
    pub rmx_filler: [libc::uint32_t; 3], // will be used for T/TCP later
}


#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct sockaddr_dl {
    pub sdl_len: libc::c_uchar,
    pub sdl_family: libc::c_uchar,
    pub sdl_index: libc::c_ushort,
    pub sdl_type: libc::c_uchar,
    pub sdl_nlen: libc::c_uchar,
    pub sdl_alen: libc::c_uchar,
    pub sdl_slen: libc::c_uchar,
    pub sdl_data: [libc::c_char; 12],
}


pub fn ipv4_to_sockaddr_inarp(ip: std::net::Ipv4Addr) -> sockaddr_inarp {
    let mut reply: sockaddr_inarp = unsafe { ::std::mem::zeroed() };

    reply.sin_len = ::std::mem::size_of::<sockaddr_inarp>() as u8;
    reply.sin_family = libc::AF_INET as u8;
    reply.sin_addr = libc::in_addr { s_addr: u32::from(ip) };

    reply
}

pub fn arp_tables(){
    // IPv4 ARP tables
    let mib: [i32; 6] = [
        libc::CTL_NET, libc::PF_ROUTE    , 0,
        libc::AF_INET, libc::NET_RT_FLAGS, RTF_LLINFO
    ];
    let mut needed: usize = 0;
    let oldp: *const i32 = ptr::null();
    let newp: *const i32 = ptr::null();
    let mut st: libc::c_int;
    unsafe {
        let ret = libc::sysctl(
                        mib.as_ptr() as *mut i32,
                        6,
                        oldp as *mut libc::c_void,
                        &mut needed,
                        newp as *mut libc::c_void,
                        0);
        
        if ret < 0 {
            // error
            println!("[DEBUG] ret_code: {:?} needed: {:?}", ret, needed);
            return ();
        }
        if needed == 0 {
            // empty table
            println!("[ WARN] empty table.");
            return ();
        }

        let mut buf = vec![0u8; needed];
        let buf_ptr = buf.as_ptr();

        loop {
            buf.clear();
            buf.resize(needed, 0u8);

            st = libc::sysctl(
                        mib.as_ptr() as *mut i32,
                        6,
                        buf_ptr as *mut libc::c_void,
                        &mut needed,
                        oldp as *mut libc::c_void,
                        0);

            let err = io::Error::last_os_error();
            let errorno = err.raw_os_error();
            if st == 0 || errorno != Some(libc::ENOMEM) {
                break;
            }
            needed += needed / 8;
        }
        if st == -1 {
            println!("[DEBUG] actual retrieval of routing table.");
            return ();
        }

        let rt_msghdr_size = mem::size_of::<rt_msghdr>();           // 92 bytes
        let rt_metrics_size = mem::size_of::<rt_metrics>();         // 56 bytes
        let sockaddr_inarp_size = mem::size_of::<sockaddr_inarp>(); // 16 bytes
        let sockaddr_dl_size = mem::size_of::<sockaddr_dl>();       // 20 bytes

        let mut start: usize = 0;
        let mut end: usize = rt_msghdr_size;

        loop {
            if start >= needed {
                break;
            }
            let rtm_bytes = &buf[start..end];
            let rtm_msglen = rtm_bytes[0] as usize;
            let sin_addr = ::std::net::Ipv4Addr::from([
                buf[end+4], buf[end+5], buf[end+6], buf[end+7]
            ]);
            let sdl_bytes = &buf[end+16..(end+16+(rtm_msglen-92-16))];
            let sdl_index: u16 = sdl_bytes[2] as u16 | sdl_bytes[3] as u16;

            let ifname_buf: [u8; libc::IF_NAMESIZE] = [0u8; libc::IF_NAMESIZE];
            let ifname_cstr = CStr::from_bytes_with_nul_unchecked(&ifname_buf);
            libc::if_indextoname(sdl_index as u32, ifname_cstr.as_ptr() as *mut i8);
            let ifname = ifname_cstr.to_str().unwrap();

            start += rtm_msglen;
            end = start + rt_msghdr_size;
            println!("sdl_index: {:?} ifname: {} sin_addr: {:?} ", sdl_index, ifname, sin_addr);
        }
    }
}

pub fn ndp_neighbors() {
    // IPv6 neighbors

}


fn main() {
    arp_tables();
    ndp_neighbors();
}

