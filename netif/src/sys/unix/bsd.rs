#![allow(non_camel_case_types, non_snake_case, dead_code)]
#![cfg(all(not(target_os = "linux")))]

extern crate libc;

use std::ffi::CString;

// macOS
pub const SIOCGIFMTU: libc::c_ulong = 0xc0206933;
pub const SIOCSIFMTU: libc::c_ulong = 0x80206934;
pub const SIOCGIFMETRIC: libc::c_ulong = 0xc0206917;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x80206918;



