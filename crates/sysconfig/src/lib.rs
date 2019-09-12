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

pub mod dns;
pub mod ip_forwarding;
pub mod firewall;
pub mod route;