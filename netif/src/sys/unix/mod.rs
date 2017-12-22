// #![cfg(unix)]

use libc;


#[cfg(target_os = "macos")]
#[path = "bsd.rs"]
mod sys;
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod sys;

pub use self::sys::*;
