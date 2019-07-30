#[macro_use]
extern crate log;
extern crate libc;
#[macro_use]
extern crate bitflags;
extern crate byteorder;


pub mod packet;
pub mod route;
pub mod socket;

#[inline]
pub const fn alloc_response() -> [u8; packet::MAX_NL_LENGTH] {
    [0u8; packet::MAX_NL_LENGTH]
}
