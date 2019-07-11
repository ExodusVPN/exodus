use libc;

use std::mem;
use std::ptr;
use std::net::Ipv4Addr;
use std::io::{self, Read, Write, Error, ErrorKind};
use std::os::unix::io::AsRawFd;


#[cfg(target_os = "linux")]
use libc::{c_uint, c_ushort};
#[cfg(target_os = "macos")]
use libc::{c_uint, c_uchar};

use libc::{sockaddr, sockaddr_in, in_addr};


#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;


/// A wrapper for `sockaddr_in`.
#[derive(Copy, Clone)]
pub struct SockAddr(sockaddr_in);

#[cfg(target_os = "linux")]
const AF_INET: c_ushort = libc::AF_INET as c_ushort;

#[cfg(target_os = "macos")]
const AF_INET: c_uchar = libc::AF_INET as c_uchar;

impl SockAddr {
    /// Create a new `SockAddr` from a generic `sockaddr`.
    pub fn new(value: &sockaddr) -> Result<Self, io::Error> {
        if value.sa_family != AF_INET {
            return Err(Error::new(ErrorKind::InvalidInput, "Invalid Address"))
        }

        unsafe { Self::unchecked(value) }
    }

    ///  Create a new `SockAddr` and not check the source.
    pub unsafe fn unchecked(value: &sockaddr) -> Result<Self, io::Error> {
        Ok(SockAddr(ptr::read(value as *const _ as *const _)))
    }

    /// Get a generic pointer to the `SockAddr`.
    pub unsafe fn as_ptr(&self) -> *const sockaddr {
        &self.0 as *const _ as *const sockaddr
    }
}

impl From<Ipv4Addr> for SockAddr {
    fn from(ip: Ipv4Addr) -> SockAddr {
        let     parts = ip.octets();
        let mut addr  = unsafe { mem::zeroed::<sockaddr_in>() };

        addr.sin_family = AF_INET;
        addr.sin_port   = 0;
        addr.sin_addr   = in_addr { s_addr:
            ((parts[3] as c_uint) << 24) |
            ((parts[2] as c_uint) << 16) |
            ((parts[1] as c_uint) <<  8) |
            ((parts[0] as c_uint))
        };

        SockAddr(addr)
    }
}

impl Into<Ipv4Addr> for SockAddr {
    fn into(self) -> Ipv4Addr {
        let ip = self.0.sin_addr.s_addr;

        Ipv4Addr::new(
            ((ip      ) & 0xff) as u8,
            ((ip >>  8) & 0xff) as u8,
            ((ip >> 16) & 0xff) as u8,
            ((ip >> 24) & 0xff) as u8)
    }
}

impl Into<sockaddr> for SockAddr {
    fn into(self) -> sockaddr {
        unsafe {
            mem::transmute(self.0)
        }
    }
}

impl Into<sockaddr_in> for SockAddr {
    fn into(self) -> sockaddr_in {
        self.0
    }
}



impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let amount = unsafe { libc::read(self.as_raw_fd(), buf.as_mut_ptr() as *mut _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amount as usize)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let amount = unsafe { libc::write(self.as_raw_fd(), buf.as_ptr() as *const _, buf.len()) };
        if amount < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amount as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[cfg(feature = "mio")]
mod mio {
    use std::io;
    use std::os::unix::io::AsRawFd;

    use mio::{Ready, Poll, PollOpt, Token};
    use mio::event::Evented;
    use mio::unix::EventedFd;

    impl Evented for super::Device {
        fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
            EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
        }

        fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt) -> io::Result<()> {
            EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
        }

        fn deregister(&self, poll: &Poll) -> io::Result<()> {
            EventedFd(&self.as_raw_fd()).deregister(poll)
        }
    }
}