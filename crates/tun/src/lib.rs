extern crate libc;
#[macro_use]
extern crate ioctl_sys;
#[cfg(feature = "mio")]
extern crate mio;


#[cfg(any(target_os = "linux", target_os = "macos"))]
mod sys;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use sys::*;
