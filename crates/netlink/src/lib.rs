#[macro_use]
extern crate log;
extern crate libc;
#[macro_use]
extern crate bitflags;
extern crate byteorder;


#[macro_use]
pub mod macros;
#[allow(non_camel_case_types, non_upper_case_globals)]
pub mod sys;
pub mod packet;
pub mod route;
pub mod socket;


/// Max supported message length for netlink messages supported by the kernel
// https://www.spinics.net/lists/netdev/msg431592.html
pub const MAX_NL_LENGTH: usize     = 32768;  // 32K

#[inline]
pub fn alloc_response() -> [u8; MAX_NL_LENGTH] {
    // https://www.spinics.net/lists/netdev/msg431592.html
    [0u8; MAX_NL_LENGTH]
}