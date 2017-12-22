

use ::{sys, nix, libc};


use nix::sys::socket::{EtherAddr, SockAddr, AddressFamily};
use nix::net::if_::{InterfaceFlags, if_nametoindex};
use nix::ifaddrs::InterfaceAddress;

use std::ffi::{CStr, CString};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, 
    SocketAddr, SocketAddrV4, SocketAddrV6
};
use std::mem;
use std::io;
use std::fmt;
use std::ptr;
use std::time::Duration;


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

#[repr(C)]
#[derive(Debug)]
pub struct ifreq {
    ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    ifr_mtu: libc::c_int
}

#[cfg(target_os = "linux")]
fn if_name_to_mtu(name: &str) -> Option<usize> {
    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_mtu: 0
    };

    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }

    let fd = unsafe {
        let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                              sys::ETH_P_ALL.to_be() as i32);
        if fd == -1 {
            // let err = Err(io::Error::last_os_error());
            return None
        }
        fd
    };
    unsafe {
        let res = libc::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq);
        if res == -1 {
            // let err = Err(io::Error::last_os_error());
            return None;
        }
    }
    Some(ifreq.ifr_mtu as usize)
}

#[cfg(target_os = "macos")]
fn if_name_to_mtu(name: &str) -> Option<usize> {
    let fd = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd == -1 {
            // let err = Err(io::Error::last_os_error());
            return None
        }
        fd
    };

    let mut ifreq = ifreq {
        ifr_name: [0; libc::IF_NAMESIZE],
        ifr_mtu: 0
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as libc::c_char
    }

    unsafe {
        let res = libc::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq);
        if res == -1 {
            // let err = Err(io::Error::last_os_error());
            return None;
        }
    }
    Some(ifreq.ifr_mtu as usize)
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
                SockAddr::Unix(_) => {
                    // PASS
                }
                #[cfg(any(target_os = "android", target_os = "linux"))]
                SockAddr::Netlink(_) => {
                    // PASS
                },
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                SockAddr::SysControl(_) => {
                    // PASS
                },
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
            let if_index = if_nametoindex(name.as_str()).unwrap();
            let if_mtu   = if_name_to_mtu(&name).unwrap();
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


