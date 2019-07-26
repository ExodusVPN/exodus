// https://tools.ietf.org/html/rfc3549
// /usr/include/linux/netlink.h

use libc;


mod netlink;
mod rtnetlink;

pub use self::netlink::*;
pub use self::rtnetlink::*;

/// Max supported message length for netlink messages supported by the kernel
// https://www.spinics.net/lists/netdev/msg431592.html
pub const MAX_NL_LENGTH: usize     = 32768;  // 32K
pub const SOL_NETLINK: libc::c_int =   270;

pub const AF_NETLINK: u8 = 16;
pub const AF_ROUTE: u8   = AF_NETLINK;


#[derive(Debug)]
pub struct Request<T: Sized> {
    header   : nlmsghdr,
    // Subsystem data
    ancillary: T,
}

impl<T> Request<T> {
    pub fn new(header: nlmsghdr, ancillary: T) -> Self {
        let size = std::mem::size_of::<T>() + std::mem::size_of::<nlmsghdr>();
        assert!(size <= MAX_NL_LENGTH);

        Self { header, ancillary }
    }

    pub const fn size(&self) -> usize {
        std::mem::size_of::<Self>()
    }

    pub fn fill_size(&mut self) {
        self.header.nlmsg_len = self.size() as u32;
    }

    pub fn as_ptr(&self) -> *const Self {
        self
    }

    pub fn as_mut_ptr(&mut self) -> *mut Self {
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.as_ptr() as *const u8;
        let len = std::mem::size_of::<Self>();

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let ptr = self.as_mut_ptr() as *mut u8;
        let len = std::mem::size_of::<Self>();

        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }
}
