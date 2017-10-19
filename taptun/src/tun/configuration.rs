use std::net::Ipv4Addr;

use error::*;

#[derive(Clone, Default, Debug)]
pub struct Configuration {
    pub name: Option<String>,
    pub address: Option<Ipv4Addr>,
    pub destination: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub mtu: Option<i32>,
    pub enabled: bool,
}

impl Configuration {
    pub fn name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn address(&mut self, value: Ipv4Addr) -> &mut Self {
        self.address = Some(value);
        self
    }

    pub fn destination(&mut self, value: Ipv4Addr) -> &mut Self {
        self.destination = Some(value);
        self
    }

    pub fn broadcast(&mut self, value: Ipv4Addr) -> &mut Self {
        self.broadcast = Some(value);
        self
    }

    pub fn netmask(&mut self, value: Ipv4Addr) -> &mut Self {
        self.netmask = Some(value);
        self
    }

    pub fn mtu(&mut self, value: i32) -> &mut Self {
        self.mtu = Some(value);
        self
    }

    pub fn up(&mut self) -> &mut Self {
        self.enabled = true;
        self
    }

    pub fn down(&mut self) -> &mut Self {
        self.enabled = false;
        self
    }
}

pub trait Configurable {
    fn from_configuration(configuration: &Configuration) -> Result<Self>
    where
        Self: Sized;
    fn configure(&mut self, configuration: &Configuration) -> Result<()>;
}
