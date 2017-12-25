#![allow(non_camel_case_types, non_snake_case, dead_code, unused_variables, 
    unused_mut, unused_unsafe, unused_imports, unused_assignments)]

#![cfg(any(target_os = "macos", target_os = "freebsd"))]

extern crate libc;
extern crate ipnetwork;

use std::ffi::CStr;
use std::io;
use std::ptr;
use std::mem;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::string::ToString;

use ipnetwork::IpNetwork;


#[derive(Eq, PartialEq)]
pub struct HwAddr(pub [u8; 6]);

impl HwAddr {
    pub fn is_empty(&self) -> bool {
        self.0[0] == 0
        && self.0[1] == 0
        && self.0[2] == 0
        && self.0[3] == 0
        && self.0[4] == 0
        && self.0[5] == 0
    }
}

impl fmt::Debug for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5])
    }
}

pub struct UnixAddr(pub [u8; 104]);

impl ToString for UnixAddr {
    fn to_string(&self) -> String {
        let cstr = unsafe { CStr::from_bytes_with_nul_unchecked( &self.0 ) };
        cstr.to_str().unwrap().to_string()
    }
}

impl PartialEq for UnixAddr {
    fn eq(&self, other: &UnixAddr) -> bool {
        &self.0[..] == &other.0[..]
    }
}

impl Eq for UnixAddr {}

impl fmt::Debug for UnixAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "UnixAddr({})", self.to_string())
    }
}


#[derive(Debug, Eq, PartialEq)]
pub struct DataLink {
    index: u32,
    name: String,
    hwaddr: Option<HwAddr>
}


#[derive(Debug, Eq, PartialEq)]
pub enum RouteAddr {
    IpNetwork(IpNetwork),
    IpAddress(::std::net::IpAddr),
    DataLink(DataLink)
}

#[derive(Debug, Eq, PartialEq)]
pub enum SockAddr {
    IpAddr(::std::net::IpAddr),
    UnixAddr(UnixAddr),
    HwAddr(HwAddr),
}
// impl Eq

impl SockAddr {
    pub fn from_libc_sockaddr_bytes(sa: &[u8]) -> Option<SockAddr> {
        let sa_len = sa[0];
        let sa_family = sa[1] as i32;
        let sa_data = &sa[2..16];
        match sa_family {
            libc::AF_UNIX  => {
                let mut sun_path: [u8; 104] = [0; 104];
                sun_path.copy_from_slice(unsafe { mem::transmute(&sa[2..]) });
                Some(SockAddr::UnixAddr(UnixAddr(sun_path)))
            }
            libc::AF_INET  => {
                let in_addr = [ sa[ 4], sa[ 5], sa[6], sa[7] ];
                Some(SockAddr::IpAddr(IpAddr::V4(Ipv4Addr::from(in_addr))))
            }
            libc::AF_INET6 => {
                let in6_addr = [
                    sa[7+0], sa[7+1], sa[7+2], sa[7+3],
                    sa[7+4], sa[7+5], sa[7+6], sa[7+7],
                    sa[7+8], sa[7+9], sa[7+10], sa[7+11],
                    sa[7+12], sa[7+13], sa[7+14], sa[7+15],
                ];
                Some(SockAddr::IpAddr(IpAddr::V6(Ipv6Addr::from(in6_addr))))
            }
            libc::AF_LINK => {
                let sdl_nlen = sa[5];
                let mut a = 0;
                let mut b = 0;
                let mut c = 0;
                let mut d = 0;
                let mut e = 0;
                let mut f = 0;

                if sa.len() < 14 {
                    return None;
                }

                if sa.len() > 13 {    
                    a = sa[8];
                    b = sa[8+1];
                    c = sa[8+2];
                    d = sa[8+3];
                    e = sa[8+4];
                    f = sa[8+5];
                }
                let sdl_index: u16 = (sa[2] as u16) | (sa[3] as u16);
                // println!("AF_LINK sdl_index: {:?}", sdl_index);
                Some(SockAddr::HwAddr(HwAddr([a, b, c, d, e, f])))
            }
            _ => None
        }
    }
}

pub fn if_indextoname(ifindex: u32) -> String{
    let ifname_buf: [u8; libc::IF_NAMESIZE] = [0u8; libc::IF_NAMESIZE];
    unsafe {
        let ifname_cstr = CStr::from_bytes_with_nul_unchecked(&ifname_buf);
        libc::if_indextoname(ifindex, ifname_cstr.as_ptr() as *mut i8);
        ifname_cstr.to_str().unwrap().to_string()
    }
}


pub fn rtable(){
    // inet4: libc::AF_INET, inet6: libc::AF_INET6, all: 0
    let family = 0;
    let flags = 0;
    let mut lenp: usize = 0;

    let mib: [i32; 6] = [
        libc::CTL_NET, libc::AF_ROUTE    , 0,
        family       , libc::NET_RT_DUMP , flags
    ];
    let null: *const i32 = ptr::null();
    let mut ret: libc::c_int = 0;
    unsafe {
        ret = libc::sysctl(
                        mib.as_ptr() as *mut i32,
                        6,
                        null as *mut libc::c_void,
                        &mut lenp,
                        null as *mut libc::c_void,
                        0);
        if ret < 0 {
            println!("[ERROR] ret_code: {:?}", ret);
            return ();
        }
        let mut buf = vec![0u8; lenp];
        let buf_ptr = buf.as_ptr();

        ret = libc::sysctl(
                mib.as_ptr() as *mut i32,
                6,
                buf_ptr as *mut libc::c_void,
                &mut lenp,
                null as *mut libc::c_void,
                0);
        if ret < 0 {
            println!("[ERROR] ret_code: {:?}", ret);
            return ();
        }

        let rt_msghdr_size = 92;
        let rt_metrics_size = 56;
        let sockaddr_size = 16;
        let sockaddr_inarp_size = 16;
        let sockaddr_dl_size = 20;

        let mut start: usize = 0;
        let mut end: usize = rt_msghdr_size;

        loop {
            if start >= lenp {
                break;
            }
            let rtm_bytes = &buf[start..end];
            let rtm_msglen = ((rtm_bytes[0] as u16) | (rtm_bytes[1] as u16)) as usize;
            let rtm_type = rtm_bytes[3];
            let rtm_index = (rtm_bytes[4] as u16) | (rtm_bytes[5] as u16);
            let rtm_flags = (rtm_bytes[6] as i32)
                            | (rtm_bytes[6+1] as i32)
                            | (rtm_bytes[6+2] as i32)
                            | (rtm_bytes[6+3] as i32);
            let rtm_addrs = (rtm_bytes[10] as i32)
                            | (rtm_bytes[10+1] as i32)
                            | (rtm_bytes[10+2] as i32)
                            | (rtm_bytes[10+3] as i32);

            let dest_size = buf[end] as usize;
            let dest_start = end;
            let dest_end   = end +  dest_size;
            let dest_sockaddr_bytes = &buf[dest_start..dest_end];

            let gateway_start = dest_end;
            let gateway_end   = gateway_start+(rtm_msglen-rt_msghdr_size-dest_size);
            let gateway_sockaddr_bytes = &buf[gateway_start..gateway_end];

            let dest = SockAddr::from_libc_sockaddr_bytes(dest_sockaddr_bytes);
            let gateway = SockAddr::from_libc_sockaddr_bytes(gateway_sockaddr_bytes);
            

            if dest.is_some() && gateway.is_some(){
                if dest == Some(SockAddr::IpAddr(IpAddr::V4(Ipv4Addr::new(192, 168, 199, 1)))) {
                    // println!("rtm_msglen: {:?}, rtm_type: {:?}, rtm_index: {:?}, rtm_flags: {:?}, rtm_addrs: {:?}",
                    //             rtm_msglen,
                    //             rtm_type,
                    //             rtm_index,
                    //             rtm_flags,
                    //             rtm_addrs);
                    // println!("{:?}", rtm_bytes);
                    // println!("{:?}", dest_sockaddr_bytes);
                }
                match gateway {
                    Some(sock_addr) => match sock_addr {
                        _ => {
                            println!("dest: {:60} \t gateway(LINK#{:2}): {:?}", 
                                format!("{:?}", dest.unwrap()),
                                rtm_index,
                                sock_addr);
                        }
                    },
                    None => {}
                }
                // println!("{:?}", gateway_sockaddr_bytes);
            }
            start += rtm_msglen;
            end = start + rt_msghdr_size;
        }
    }
}


/*
macOS:
    $ netstat -rn
    $ cargo run --bin route
*/

fn main (){
    rtable();
}

