#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]

use HwAddr;
use sys;
use nix;
use nix::sys::socket::{LinkAddr, SockAddr};
use nix::ifaddrs::InterfaceAddress;
pub use ipnetwork::Ipv6Network;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ffi::CStr;
use std::ffi::CString;

use std::fmt;
use std::io;
use std::mem;


pub type Flags = nix::net::if_::InterfaceFlags;

// #[derive(Clone, Debug, Eq, Hash, PartialEq)]
// pub struct LoopbackInterface {
//     name : String,
//     index: u32,
//     flags: Flags,
//     mtu  : u32,
//     v4_addr: Ipv4Addr,
//     netmask: Ipv4Addr,
//     v6_addr: Ipv6Network
// }

// #[derive(Clone, Debug, Eq, Hash, PartialEq)]
// pub struct TapInterface {
//     name : String,
//     index: u32,
//     flags: Flags,
//     mtu  : u32,
//     v4_addr: Ipv4Addr,
//     netmask: Ipv4Addr,
//     broadcast: Ipv4Addr,
//     v6_addr: Ipv6Network
// }


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Interface {
    name : String,
    index: u32,
    flags: Flags,
    mtu  : u32,

    hwaddr: Option<HwAddr>,

    // inet4 info
    addr: Option<Ipv4Addr>,
    dstaddr: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    broadcast: Option<Ipv4Addr>,

    // inet6 info
    v6_addr: Option<Ipv6Network>,
}

impl Interface {
    pub fn with_index(ifindex: u32) -> Result<Interface, io::Error> {
        let ifname = {
            let ifname_buf: [u8; sys::IF_NAMESIZE] = [0u8; sys::IF_NAMESIZE];
            let size = unsafe {
                let ifname_cstr = CStr::from_bytes_with_nul_unchecked(&ifname_buf);
                
                let ptr = ifname_cstr.as_ptr() as *mut i8;

                sys::if_indextoname(ifindex, ptr);
                let mut pos: usize = ifname_buf.len() - 1;
                while pos != 0 {
                    if ifname_buf[pos] != 0 {
                        if pos + 1 < ifname_buf.len() {
                            pos += 1;
                        }
                        break;
                    }
                    pos -= 1;
                }
                pos
            };

            if size == 0 {
                return Err(io::Error::new(io::ErrorKind::NotFound, "Ooops ..."))
            }
            let buffer = &ifname_buf[..size];
            String::from_utf8(buffer.to_vec()).unwrap()
        };

        Interface::with_name(&ifname)
    }

    pub fn with_name(ifname: &str) -> Result<Interface, io::Error> {
        let fd = unsafe { sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
        }
        
        let index: u32 = unsafe { sys::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) };

        let mut ifreq: sys::ifreq = unsafe { mem::zeroed() };
        for (i, byte) in ifname.as_bytes().iter().enumerate() {
            if i < sys::IF_NAMESIZE {
                ifreq.ifr_name[i] = *byte as sys::c_char
            }
        }
        
        let mtu: u32 = unsafe {
            if sys::ioctl(fd, sys::SIOCGIFMTU, &ifreq) < 0 {
                return Err(io::Error::last_os_error())
            }
            ifreq.ifru.mtu as u32
        };


        let mut iface = Interface {
            name : ifname.clone().to_string(),
            index: index,
            flags: Flags::from_bits(0).unwrap(),
            mtu  : mtu,
            
            hwaddr   : None,
            addr     : None,
            dstaddr  : None,
            netmask  : None,
            broadcast: None,
            v6_addr  : None
        };
        
        let mut fill_flags = false;

        for ifaddr in nix::ifaddrs::getifaddrs().unwrap() {
            if ifname != ifaddr.interface_name.as_str() {
                continue;
            }
            iface.flags = ifaddr.flags;
            fill_flags = true;
            fill(&ifaddr, &mut iface);
        }

        unsafe { sys::close(fd); }

        Ok(iface)
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.contains(Flags::IFF_LOOPBACK)
    }

    pub fn is_tap(&self) -> bool {
        !self.is_loopback() 
        && self.flags.contains(Flags::IFF_BROADCAST)
    }

    pub fn is_tun(&self) -> bool {
        // IFF_NO_PI
        cfg!(target_os = "linux")
        && !self.is_tap()
        && self.flags.contains(Flags::IFF_POINTOPOINT)
    }

    pub fn is_utun(&self) -> bool {
        cfg!(target_os = "macos")
        && !self.is_tap()
        && self.flags.contains(Flags::IFF_POINTOPOINT)
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }
    
    pub fn addr(&self) -> Option<Ipv4Addr> {
        self.addr
    }

    pub fn dstaddr(&self) -> Option<Ipv4Addr> {
        self.dstaddr
    }

    pub fn netmask(&self) -> Option<Ipv4Addr> {
        self.netmask
    }
    
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        self.broadcast
    }

    pub fn v6_addr(&self) -> Option<Ipv6Network> {
        self.v6_addr
    }
}


impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "{}: flags={:X}<{}> mtu {} index: {}",
                self.name,
                self.flags.bits(),
                format!("{:?}", self.flags).replace("IFF_", "").replace(" | ", ","),
                self.mtu,
                self.index);
        if self.hwaddr.is_some(){
            let _ = write!(f, "\n    ether {}", self.hwaddr.unwrap());
        }
        if !self.flags.contains(Flags::IFF_POINTOPOINT) {
            if self.addr.is_some() && self.netmask.is_some() {
                let _ = write!(f, "\n    inet {} netmask {}", self.addr.unwrap(), self.netmask.unwrap());
                if self.flags.contains(Flags::IFF_BROADCAST) && self.broadcast.is_some() {
                    let _ = write!(f, " broadcast {}", self.broadcast.unwrap());
                }
            }
        } else {
            if self.addr.is_some() && self.dstaddr.is_some() {
                let _ = write!(f, "\n    inet {} --> {}", self.addr.unwrap(), self.dstaddr.unwrap());
            }
        }

        if self.v6_addr.is_some(){
            let _ = write!(f, "\n    inet6 {}", self.v6_addr.unwrap());
        }
        Ok(())
    }
}

fn fill (ifaddr: &InterfaceAddress, iface: &mut Interface){
    if ifaddr.address.is_some() {
        let sock_addr = ifaddr.address.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                match inet_addr.to_std().ip() {
                    IpAddr::V4(v4_addr) => {
                        iface.addr = Some(v4_addr);
                    },
                    IpAddr::V6(v6_addr) => {
                        iface.v6_addr = Some(Ipv6Network::new(v6_addr, 128).unwrap());
                    }
                }
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
            SockAddr::Link(link_addr) => {
                iface.hwaddr = Some(HwAddr::from(link_addr.addr()));
            }
        }
    }

    if ifaddr.netmask.is_some() {
        let sock_addr = ifaddr.netmask.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                match inet_addr.to_std().ip() {
                    IpAddr::V4(v4_addr) => {
                        iface.netmask = Some(v4_addr);
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }

    if ifaddr.broadcast.is_some() {
        let sock_addr = ifaddr.broadcast.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                match inet_addr.to_std().ip() {
                    IpAddr::V4(v4_addr) => {
                        iface.broadcast = Some(v4_addr);
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }

    if ifaddr.destination.is_some() {
        let sock_addr = ifaddr.destination.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                match inet_addr.to_std().ip() {
                    IpAddr::V4(v4_addr) => {
                        iface.dstaddr = Some(v4_addr);
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }
}

pub fn interfaces () -> Vec<Interface> {
    let mut ifaces: Vec<Interface> = vec![];
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
            let mut iface = Interface {
                name : name.clone(),
                index: if_index as u32,
                flags: ifaddr.flags,
                mtu  : if_mtu as u32,

                hwaddr   : None,
                addr     : None,
                dstaddr  : None,
                netmask  : None,
                broadcast: None,
                v6_addr  : None
            };
            fill(&ifaddr, &mut iface);
            ifaces.push(iface);
        }
    }
    ifaces
}


