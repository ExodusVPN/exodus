use std::{mem, ptr};
use std::net::Ipv4Addr;

#[cfg(target_os = "macos")]
use libc::{c_uchar, c_uint};
#[cfg(target_os = "linux")]
use libc::{c_uint, c_ushort};

use libc::{in_addr, sockaddr, sockaddr_in};
use libc::AF_INET as _AF_INET;

use error::*;


/// A wrapper for `sockaddr_in`.
#[derive(Copy, Clone)]
pub struct SockAddr(sockaddr_in);

#[cfg(target_os = "linux")]
const AF_INET: c_ushort = _AF_INET as c_ushort;

#[cfg(target_os = "macos")]
const AF_INET: c_uchar = _AF_INET as c_uchar;

impl SockAddr {
    /// Create a new `SockAddr` from a generic `sockaddr`.
    pub fn new(value: &sockaddr) -> Result<Self> {
        if value.sa_family != AF_INET {
            return Err(ErrorKind::InvalidTunAddress.into());
        }

        unsafe { Self::unchecked(value) }
    }

    ///  Create a new `SockAddr` and not check the source.
    pub unsafe fn unchecked(value: &sockaddr) -> Result<Self> {
        Ok(SockAddr(ptr::read(value as *const _ as *const _)))
    }

    /// Get a generic pointer to the `SockAddr`.
    pub unsafe fn as_ptr(&self) -> *const sockaddr {
        &self.0 as *const _ as *const sockaddr
    }
}

#[cfg(target_os = "linux")]
impl From<Ipv4Addr> for SockAddr {
    fn from(ip: Ipv4Addr) -> SockAddr {
        let parts = ip.octets();
        let mut addr = unsafe { mem::zeroed::<sockaddr_in>() };

        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        addr.sin_addr = in_addr {
            s_addr: ((parts[3] as c_uint) << 24) | ((parts[2] as c_uint) << 16) | ((parts[1] as c_uint) << 8) |
                ((parts[0] as c_uint)),
        };

        SockAddr(addr)
    }
}

#[cfg(target_os = "macos")]
impl From<Ipv4Addr> for SockAddr {
    fn from(ip: Ipv4Addr) -> SockAddr {
        let parts = ip.octets();
        let mut addr = unsafe { mem::zeroed::<sockaddr_in>() };

        addr.sin_family = AF_INET;
        // macOS special field
        addr.sin_len = 8;
        addr.sin_port = 0;
        addr.sin_addr = in_addr {
            s_addr: ((parts[3] as c_uint) << 24) | ((parts[2] as c_uint) << 16) | ((parts[1] as c_uint) << 8) |
                ((parts[0] as c_uint)),
        };

        SockAddr(addr)
    }
}

impl Into<Ipv4Addr> for SockAddr {
    fn into(self) -> Ipv4Addr {
        let ip = self.0.sin_addr.s_addr;

        Ipv4Addr::new(((ip) & 0xff) as u8,
                      ((ip >> 8) & 0xff) as u8,
                      ((ip >> 16) & 0xff) as u8,
                      ((ip >> 24) & 0xff) as u8)
    }
}

impl Into<sockaddr> for SockAddr {
    fn into(self) -> sockaddr {
        unsafe { mem::transmute(self.0) }
    }
}

impl Into<sockaddr_in> for SockAddr {
    fn into(self) -> sockaddr_in {
        self.0
    }
}
