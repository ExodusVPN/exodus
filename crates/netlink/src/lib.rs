#[macro_use]
extern crate log;
extern crate libc;
#[macro_use]
extern crate bitflags;
extern crate byteorder;

#[allow(non_camel_case_types, non_upper_case_globals)]
pub mod sys;
pub mod packet;
pub mod route;
pub mod socket;


#[inline]
pub const fn alloc_response() -> [u8; packet::MAX_NL_LENGTH] {
    [0u8; packet::MAX_NL_LENGTH]
}
