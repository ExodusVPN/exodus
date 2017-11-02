
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use self::macos as platform;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux as platform;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub mod platform {
    pub fn create() -> Result<Tun> {
        unimplemented!();
    }
}

pub mod sockaddr;
pub mod configuration;

pub use self::platform::{create, Device, tokio};
pub use self::configuration::Configuration;


use std::fmt::Debug;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

use mio::event::Evented;

use error::*;

pub trait Tun: Read + Write + Debug + Evented {
    fn name(&self) -> &str;

    fn address(&self) -> Result<Ipv4Addr>;
    fn set_address(&mut self, value: Ipv4Addr) -> Result<()>;

    fn broadcast(&self) -> Result<Ipv4Addr>;
    fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()>;

    fn destination(&self) -> Result<Ipv4Addr>;
    fn set_destination(&mut self, value: Ipv4Addr) -> Result<()>;

    fn netmask(&self) -> Result<Ipv4Addr>;
    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()>;
    /// https://en.wikipedia.org/wiki/Maximum_transmission_unit
    fn mtu(&self) -> Result<i32>;
    fn set_mtu(&mut self, value: i32) -> Result<()>;

    fn flags(&self) -> Result<i16>;
    fn set_flags(&mut self, value: i16) -> Result<()>;

    fn set_enabled(&mut self, value: bool) -> Result<()>;
}
