#![feature(i128_type)]


#[macro_use]
extern crate cfg_if;
#[macro_use]
extern crate bitflags;
extern crate libc;
extern crate nix;
extern crate ipnetwork;
extern crate smoltcp;

#[cfg(windows)]
extern crate winapi;

pub mod sys;
pub mod interface;

mod hwaddr;
mod raw_socket;
pub use hwaddr::HwAddr;
pub use raw_socket::RawSocket;
pub use raw_socket::LinkLayer;

pub mod neighbor;
pub mod route;


