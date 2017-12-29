// Note: linux not support yet.
// #![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
#![cfg(any(target_os = "macos", target_os = "freebsd"))]


use sys;
use HwAddr;

use std::io;
use std::ptr;
use std::mem;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::IpAddr;



#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    ifname: String,
    ifindex: u32,
    ipaddr: IpAddr,
    hwaddr: HwAddr
}

impl fmt::Display for Table {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:19} at {} on {}(#{})",
            format!("{}", self.ipaddr),
            self.hwaddr,
            self.ifname,
            self.ifindex)
    }
}


#[allow(non_snake_case)]
pub mod V4 {
    // IPv4 ARP Tables
    use super::*;

    pub fn list() -> Result<Vec<Table>, io::Error> {
        let mib: [i32; 6] = [
            sys::CTL_NET, sys::PF_ROUTE    , 0,
            sys::AF_INET, sys::NET_RT_FLAGS, sys::RTF_LLINFO
        ];
        let mut needed: usize = 0;
        let oldp: *const i32 = ptr::null();
        let newp: *const i32 = ptr::null();
        
        let ret = unsafe {
            sys::sysctl(mib.as_ptr() as *mut i32,
                        6,
                        oldp as *mut sys::c_void,
                        &mut needed,
                        newp as *mut sys::c_void,
                        0)
        };
        if ret < 0 {
            // error
            return Err(io::Error::last_os_error());
        }
        
        let mut table: Vec<Table> = vec![];

        if needed == 0 {
            // empty table
            return Ok(table);
        }

        let mut buf = vec![0u8; needed];
        let mut st: sys::c_int;
        let buf_ptr = buf.as_ptr();

        loop {
            buf.clear();
            buf.resize(needed, 0u8);

            st = unsafe {
                sys::sysctl(mib.as_ptr() as *mut i32,
                            6,
                            buf_ptr as *mut sys::c_void,
                            &mut needed,
                            oldp as *mut sys::c_void,
                            0)
            };

            let err = io::Error::last_os_error();
            let errorno = err.raw_os_error();
            if st == 0 || errorno != Some(sys::ENOMEM) {
                break;
            }
            needed += needed / 8;
        }

        if st == -1 {
            // actual retrieval of routing table
            return Err(io::Error::last_os_error());
        }

        let rt_msghdr_size = mem::size_of::<sys::rt_msghdr>();
        let sockaddr_inarp_size = mem::size_of::<sys::sockaddr_inarp>();

        let mut start: usize = 0;
        
        loop {
            let end: usize = start + rt_msghdr_size;
            if start >= needed {
                break;
            }

            let rtm_bytes = &buf[start..end];
            let rtm = rtm_bytes.as_ptr() as *const sys::rt_msghdr;
            let rtm_msglen = unsafe { (*rtm).rtm_msglen as usize };

            let sa_inarp_bytes = &buf[end..end + sockaddr_inarp_size];
            let sa_inarp = sa_inarp_bytes.as_ptr() as *const sys::sockaddr_inarp;

            let sin_addr = IpAddr::V4(Ipv4Addr::from( unsafe {
                (*sa_inarp).sin_addr.s_addr.to_be()
            }));

            let sdl_bytes = &buf[end+sockaddr_inarp_size..];
            let sdl = sdl_bytes.as_ptr() as *const sys::sockaddr_dl;
            let sdl_index = unsafe { (*sdl).sdl_index as u32 };
            let sdl_nlen = unsafe { (*sdl).sdl_nlen as usize };
            let sdl_alen = unsafe { (*sdl).sdl_alen as usize };
            let sdl_data = unsafe { (*sdl).sdl_data };

            assert_eq!(sdl_alen, 6);
            assert_eq!(sdl_nlen + sdl_alen < sdl_data.len(), true);

            let hwaddr = HwAddr::from([sdl_data[sdl_nlen] as u8,
                                       sdl_data[sdl_nlen + 1] as u8,
                                       sdl_data[sdl_nlen + 2] as u8,
                                       sdl_data[sdl_nlen + 3] as u8,
                                       sdl_data[sdl_nlen + 4] as u8,
                                       sdl_data[sdl_nlen + 5] as u8]);

            let ifname = sys::if_index_to_name(sdl_index);

            table.push(Table {
                ifname: ifname,
                ifindex: sdl_index,
                ipaddr: sin_addr,
                hwaddr: hwaddr
            });

            start += rtm_msglen;
        }
        Ok(table)
    }
}

#[allow(non_snake_case)]
pub mod V6 {
    use super::*;

    // IPv6 NDP Tables
    pub fn list() -> Result<Table, io::Error> {
        unimplemented!();
    }
}
