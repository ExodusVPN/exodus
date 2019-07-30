
mod netlink;
mod neighbour;
mod route;
mod link;
mod addr;

pub use self::netlink::*;
pub use self::neighbour::*;
pub use self::route::*;
pub use self::link::*;
pub use self::addr::*;


/// Max supported message length for netlink messages supported by the kernel
// https://www.spinics.net/lists/netdev/msg431592.html
pub const MAX_NL_LENGTH: usize = 32768;  // 32K

const NLA_ALIGNTO: usize       = 4;

#[inline]
pub const fn align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nlmsg<T: Sized> {
    header   : nlmsghdr,
    // Subsystem data
    ancillary: T,
}

impl<T> nlmsg<T> {
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