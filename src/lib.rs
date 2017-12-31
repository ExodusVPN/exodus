#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]

#[allow(unused_imports)]
#[macro_use]
extern crate cfg_if;
#[allow(unused_imports)]
#[macro_use]
extern crate bitflags;
extern crate byteorder;
#[allow(unused_imports)]
#[macro_use]
extern crate logging;
extern crate ctrlc;
extern crate rand;
extern crate ring;
extern crate tun;

extern crate ipnetwork;
extern crate smoltcp;

extern crate libc;
extern crate nix;


pub mod signal;
