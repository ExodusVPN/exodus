#[macro_use]
extern crate log;
#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate sysctl;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;
// #[cfg(target_os = "macos")]
// extern crate pfctl;
extern crate smoltcp;


pub mod dns;
pub mod route;
pub mod neigh;
pub mod firewall;
pub mod ip_forwarding;