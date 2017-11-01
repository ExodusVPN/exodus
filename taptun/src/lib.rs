#[allow(dead_code)]

#[allow(unused_imports)]
#[macro_use(trace, debug, info, warn, error, log)]
extern crate logging;

#[macro_use]
extern crate error_chain;
extern crate futures;

extern crate mio;
#[macro_use]
extern crate tokio_core;

#[cfg(unix)]
extern crate libc;

#[cfg(unix)]
#[macro_use]
extern crate ioctl_sys;


pub mod error;
pub mod tun;

