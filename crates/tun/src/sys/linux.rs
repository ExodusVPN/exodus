use super::SockAddr;

use libc::{sockaddr, c_void, c_char, c_uchar, c_short, c_ushort, c_int, c_uint, c_ulong};

use std::ptr;
use std::mem;
use std::ffi::{CStr, CString};
use std::net::Ipv4Addr;
use std::io::{self, Error, ErrorKind};
use std::os::unix::io::{RawFd, AsRawFd, IntoRawFd};


pub const IFNAMSIZ: usize      = 16;
pub const IFF_UP:      c_short = 0x1;
pub const IFF_RUNNING: c_short = 0x40;
pub const IFF_TUN:   c_short   = 0x0001;
pub const IFF_NO_PI: c_short   = 0x1000;


#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifmap {
    pub mem_start: c_ulong,
    pub mem_end:   c_ulong,
    pub base_addr: c_ushort,
    pub irq:       c_uchar,
    pub dma:       c_uchar,
    pub port:      c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifsu {
    pub raw_hdlc_proto: *mut c_void,
    pub cisco:          *mut c_void,
    pub fr:             *mut c_void,
    pub fr_pvc:         *mut c_void,
    pub fr_pvc_info:    *mut c_void,
    pub sync:           *mut c_void,
    pub te1:            *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct if_settings {
    pub type_: c_uint,
    pub size:  c_uint,
    pub ifsu:  ifsu,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifrn {
    pub name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr:      sockaddr,
    pub dstaddr:   sockaddr,
    pub broadaddr: sockaddr,
    pub netmask:   sockaddr,
    pub hwaddr:    sockaddr,

    pub flags:    c_short,
    pub ivalue:   c_int,
    pub mtu:      c_int,
    pub map:      ifmap,
    pub slave:    [c_char; IFNAMSIZ],
    pub newname:  [c_char; IFNAMSIZ],
    pub data:     *mut c_void,
    pub settings: if_settings,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifrn: ifrn,
    pub ifru: ifru,
}

ioctl!(bad read siocgifflags with 0x8913; ifreq);
ioctl!(bad write siocsifflags with 0x8914; ifreq);
ioctl!(bad read siocgifaddr with 0x8915; ifreq);
ioctl!(bad write siocsifaddr with 0x8916; ifreq);
ioctl!(bad read siocgifdstaddr with 0x8917; ifreq);
ioctl!(bad write siocsifdstaddr with 0x8918; ifreq);
ioctl!(bad read siocgifbrdaddr with 0x8919; ifreq);
ioctl!(bad write siocsifbrdaddr with 0x891a; ifreq);
ioctl!(bad read siocgifnetmask with 0x891b; ifreq);
ioctl!(bad write siocsifnetmask with 0x891c; ifreq);
ioctl!(bad read siocgifmtu with 0x8921; ifreq);
ioctl!(bad write siocsifmtu with 0x8922; ifreq);
ioctl!(bad write siocsifname with 0x8923; ifreq);

ioctl!(write tunsetiff with b'T', 202; c_int);
ioctl!(write tunsetpersist with b'T', 203; c_int);
ioctl!(write tunsetowner with b'T', 204; c_int);
ioctl!(write tunsetgroup with b'T', 206; c_int);


#[derive(Debug)]
pub struct Device {
    name: String,
    tun: RawFd,
    ctl: RawFd,
}

impl Device {
    pub fn new(name: &str) -> Result<Self, Error> {
        let name = CString::new(name.clone()).unwrap();
        if name.as_bytes_with_nul().len() > IFNAMSIZ {
            return Err(Error::new(ErrorKind::InvalidInput, "name too long"));
        }

        let (tun, ctl, name) = unsafe {
            let tun = libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR);
            if tun < 0 {
                return Err(io::Error::last_os_error());
            }
            
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.as_bytes().len());

            req.ifru.flags = IFF_TUN | IFF_NO_PI;

            if tunsetiff(tun, &mut req as *mut _ as *mut _) < 0 {
                return Err(io::Error::last_os_error());
            }

            let ctl = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if ctl < 0 {
                return Err(io::Error::last_os_error());
            }

            (tun, ctl, CStr::from_ptr(req.ifrn.name.as_ptr()).to_string_lossy().into())
        };

        Ok(Device {
            name: name,
            tun:  tun,
            ctl:  ctl,
        })
    }

    /// Set the owner of the device.
    pub fn user(&mut self, value: i32) -> Result<(), Error> {
        unsafe {
            if tunsetowner(self.tun, &value) < 0 {
                return Err(io::Error::last_os_error())
            }
        }

        Ok(())
    }

    /// Set the group of the device.
    pub fn group(&mut self, value: i32) -> Result<(), Error> {
        unsafe {
            if tunsetgroup(self.tun, &value) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Prepare a new request.
    #[inline]
    unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(self.name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), self.name.len());

        req
    }

    pub fn set_name(&mut self, value: &str) -> Result<(), Error> {
        unsafe {
            let name = CString::new(value)?;

            if name.as_bytes_with_nul().len() > IFNAMSIZ {
                return Err(Error::new(ErrorKind::InvalidInput, "name too long"));
            }

            let mut req = self.request();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifru.newname.as_mut_ptr(), value.len());

            if siocsifname(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            self.name = value.into();

            Ok(())
        }
    }

    pub fn address(&self) -> Result<Ipv4Addr, Error> {
        unsafe {
            let mut req = self.request();

            if siocgifaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.addr).map(Into::into)
        }
    }

    pub fn set_address<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        unsafe {
            let mut req   = self.request();
            req.ifru.addr = SockAddr::from(value.into()).into();

            if siocsifaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn destination(&self) -> Result<Ipv4Addr, Error> {
        unsafe {
            let mut req = self.request();

            if siocgifdstaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.dstaddr).map(Into::into)
        }
    }

    pub fn set_destination<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        unsafe {
            let mut req      = self.request();
            req.ifru.dstaddr = SockAddr::from(value.into()).into();

            if siocsifdstaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn broadcast(&self) -> Result<Ipv4Addr, Error> {
        unsafe {
            let mut req = self.request();

            if siocgifbrdaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.broadaddr).map(Into::into)
        }
    }

    pub fn set_broadcast<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        unsafe {
            let mut req        = self.request();
            req.ifru.broadaddr = SockAddr::from(value.into()).into();

            if siocsifbrdaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn netmask(&self) -> Result<Ipv4Addr, Error> {
        unsafe {
            let mut req = self.request();

            if siocgifnetmask(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.netmask).map(Into::into)
        }
    }

    pub fn set_netmask<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        unsafe {
            let mut req      = self.request();
            req.ifru.netmask = SockAddr::from(value.into()).into();

            if siocsifnetmask(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn mtu(&self) -> Result<i32, Error> {
        unsafe {
            let mut req = self.request();

            if siocgifmtu(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(req.ifru.mtu)
        }
    }

    pub fn set_mtu(&mut self, value: i32) -> Result<(), Error> {
        // Minimum MTU required of all links supporting IPv4. See RFC 791 § 3.1.
        pub const IPV4_MIN_MTU: i32 = 576;
        // Minimum MTU required of all links supporting IPv6. See RFC 8200 § 5.
        // pub const IPV6_MIN_MTU: i32 = 1280;

        if value < IPV4_MIN_MTU {
            return Err(Error::new(ErrorKind::InvalidInput, "MTU is too small"));
        }

        unsafe {
            let mut req  = self.request();
            req.ifru.mtu = value;

            if siocsifmtu(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn enabled(&mut self, value: bool) -> Result<(), Error> {
        unsafe {
            let mut req = self.request();

            if siocgifflags(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            if value {
                req.ifru.flags |= IFF_UP | IFF_RUNNING;
            }
            else {
                req.ifru.flags &= !IFF_UP;
            }

            if siocsifflags(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }
}


impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun
    }
}

impl IntoRawFd for Device {
    fn into_raw_fd(self) -> RawFd {
        self.tun
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            if self.ctl >= 0 {
                libc::close(self.ctl);
            }
            if self.tun >= 0 {
                libc::close(self.tun);
            }
        }
    }
}