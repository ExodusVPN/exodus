#![allow(non_camel_case_types, non_snake_case, dead_code)]
#![cfg(all(target_os = "linux"))]

extern crate libc;

pub use libc::SOL_PACKET;

pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;

// pub const SIOCGIFMTU:   libc::c_ulong = 0x8921;
pub const SIOCGIFMTU: libc::c_uint = 0x00008921;
pub const SIOCSIFMTU: libc::c_uint = 0x00008922;
pub const SIOCGIFMETRIC: libc::c_uint = 0x0000891d;
pub const SIOCSIFMETRIC: libc::c_uint = 0x0000891e;


pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;
pub const ETH_P_ALL:    libc::c_short = 0x0003;
pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;
pub const IFF_TAP:      libc::c_int   = 0x0002;
pub const IFF_NO_PI:    libc::c_int   = 0x1000;

