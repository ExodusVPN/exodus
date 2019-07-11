extern crate libc;
#[macro_use]
extern crate ioctl_sys;

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sys;

pub use sys::*;