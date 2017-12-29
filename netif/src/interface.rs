#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]


use std::net::IpAddr;
use std::fmt;


use sys;
use nix;
use nix::sys::socket::{EtherAddr, SockAddr};
use nix::net::if_::{InterfaceFlags};
use nix::ifaddrs::InterfaceAddress;


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Addr {
    Ip(IpAddr),
    Ether(EtherAddr),
    Broadcast(IpAddr),
    Netmask(IpAddr),
    Destination(IpAddr),
    Gateway(IpAddr)
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NetworkInterface {
    pub name : String,
    pub index: usize,
    pub flags: InterfaceFlags,
    pub mtu  : usize,
    pub addrs: Vec<Addr>
}

impl fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addrs = self.addrs.iter()
            .map(|addr| format!("\t{:?}", addr))
            .collect::<Vec<String>>()
            .join("\n");
        write!(f, "{}: flags={:X}<{}> mtu {} index: {}\n{}",
                self.name,
                self.flags.bits(),
                format!("{:?}", self.flags).replace("IFF_", "").replace(" | ", ","),
                self.mtu,
                self.index,
                addrs)
    }
}

impl NetworkInterface {
    pub fn is_loopback(&self) -> bool {
        self.flags.contains(InterfaceFlags::IFF_LOOPBACK)
    }
    pub fn is_tap(&self) -> bool {
        !self.is_loopback() 
        && self.flags.contains(InterfaceFlags::IFF_BROADCAST)
    }

    pub fn is_tun(&self) -> bool {
        !self.is_tap()
        && self.flags.contains(InterfaceFlags::IFF_POINTOPOINT)
    }
}


pub fn interfaces () -> Vec<NetworkInterface> {
    let mut ifaces: Vec<NetworkInterface> = vec![];

    fn fill (ifaddr: &InterfaceAddress, iface: &mut NetworkInterface){
        if ifaddr.address.is_some() {
            let sock_addr = ifaddr.address.unwrap();
            // let addr_family = sock_addr.family();
            match sock_addr {
                SockAddr::Inet(inet_addr) => {
                    iface.addrs.push(Addr::Ip(inet_addr.to_std().ip()));
                },
                SockAddr::Unix(_) => { },
                #[cfg(any(target_os = "android", target_os = "linux"))]
                SockAddr::Netlink(_) => { },
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                SockAddr::SysControl(_) => { },
                #[cfg(any(target_os = "dragonfly",
                          target_os = "freebsd",
                          target_os = "ios",
                          target_os = "macos",
                          target_os = "netbsd",
                          target_os = "openbsd",
                          target_os = "android",
                          target_os = "linux"))]
                SockAddr::Ether(ether_addr) => {
                    iface.addrs.push(Addr::Ether(ether_addr));
                }
            }
        }

        if ifaddr.netmask.is_some() {
            let sock_addr = ifaddr.netmask.unwrap();
            match sock_addr {
                SockAddr::Inet(inet_addr) => {
                    iface.addrs.push(Addr::Netmask(inet_addr.to_std().ip()));
                },
                _ => {}
            }
        }

        if ifaddr.broadcast.is_some() {
            let sock_addr = ifaddr.broadcast.unwrap();
            match sock_addr {
                SockAddr::Inet(inet_addr) => {
                    iface.addrs.push(Addr::Broadcast(inet_addr.to_std().ip()));
                },
                _ => {}
            }
        }

        if ifaddr.destination.is_some() {
            let sock_addr = ifaddr.destination.unwrap();
            match sock_addr {
                SockAddr::Inet(inet_addr) => {
                    iface.addrs.push(Addr::Destination(inet_addr.to_std().ip()));
                },
                _ => {}
            }
        }
    }

    for ifaddr in nix::ifaddrs::getifaddrs().unwrap() {
        let name = ifaddr.interface_name.clone();
        
        let mut found = false;

        for iface in &mut ifaces {
            if iface.name == name {
                found = true;
                fill(&ifaddr, iface);
            }
        }

        if !found {
            let if_index = sys::if_name_to_index(&name);
            let if_mtu   = sys::if_name_to_mtu(&name).unwrap();
            let mut iface = NetworkInterface {
                name : name.clone(),
                index: if_index as usize,
                flags: ifaddr.flags,
                mtu  : if_mtu as usize,
                addrs: vec![]
            };
            fill(&ifaddr, &mut iface);
            ifaces.push(iface);
        }
    }
    ifaces
}


