
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

#[inline]
pub const fn alloc() -> [u8; MAX_NL_LENGTH] {
    [0u8; MAX_NL_LENGTH]
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nlmsg<H: Sized, P: Sized> {
    header   : nlmsghdr,
    // subsystem header
    ancillary: H,
    payload: P,
}

impl<T, P> nlmsg<T, P> {
    pub fn new(header: nlmsghdr, ancillary: T, payload: P) -> Self {
        let size = std::mem::size_of::<nlmsghdr>() + std::mem::size_of::<T>() + std::mem::size_of::<P>();
        debug_assert!(size <= MAX_NL_LENGTH);
        
        Self { header, ancillary, payload }
    }

    pub const fn size(&self) -> usize {
        std::mem::size_of::<Self>()
    }

    pub fn fill_size(&mut self) {
        self.header.nlmsg_len = self.size() as u32;
    }
}


macro_rules! impl_as_ref_for_struct {
    ($type:ty) => (
        impl AsRef<[u8]> for $type {
            fn as_ref(&self) -> &[u8] {
                let len = std::mem::size_of::<Self>();
                let ptr = self as *const Self as *const u8;
                unsafe { std::slice::from_raw_parts(ptr, len) }
            }
        }

        impl AsMut<[u8]> for $type {
            fn as_mut(&mut self) -> &mut [u8] {
                let len = std::mem::size_of::<Self>();
                let ptr = self as *mut Self as *mut u8;
                unsafe { std::slice::from_raw_parts_mut(ptr, len) }
            }
        }
    );
}

impl_as_ref_for_struct!(ifa_cacheinfo);
impl_as_ref_for_struct!(ifaddrmsg);
impl_as_ref_for_struct!(ifinfomsg);
impl_as_ref_for_struct!(nda_cacheinfo);
impl_as_ref_for_struct!(ndmsg);
impl_as_ref_for_struct!(ndt_config);
impl_as_ref_for_struct!(ndt_stats);
impl_as_ref_for_struct!(ndtmsg);
impl_as_ref_for_struct!(nduseroptmsg);
impl_as_ref_for_struct!(nl_mmap_hdr);
impl_as_ref_for_struct!(nl_mmap_req);
impl_as_ref_for_struct!(nlmsghdr);
impl_as_ref_for_struct!(rtmsg);
        
impl<H: Sized, P: Sized> AsRef<[u8]> for nlmsg<H, P> {
    fn as_ref(&self) -> &[u8] {
        let len = std::mem::size_of::<Self>();
        let ptr = self as *const Self as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }
}

impl<H: Sized, P: Sized> AsMut<[u8]> for nlmsg<H, P> {
    fn as_mut(&mut self) -> &mut [u8] {
        let len = std::mem::size_of::<Self>();
        let ptr = self as *mut Self as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }
}