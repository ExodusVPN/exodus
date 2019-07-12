#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate nix;
#[cfg(unix)]
extern crate sysctl as sysctl_sys;

#[cfg(target_os = "macos")]
extern crate core_foundation;
#[cfg(target_os = "macos")]
extern crate system_configuration;
// #[cfg(target_os = "macos")]
// extern crate pfctl;

pub mod dns;
pub mod sysctl;
pub mod firewall;
pub mod route;