#[allow(dead_code)]

// unused_imports
// #[macro_use]
extern crate log;
extern crate pretty_env_logger;

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

