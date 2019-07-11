use super::SockAddr;

use libc::{self, sockaddr, c_void, c_char, c_short, c_ushort, c_int, c_uint};

use std::ptr;
use std::mem;
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::io::{self, Error, ErrorKind};
use std::os::unix::io::{RawFd, AsRawFd, IntoRawFd};


pub const IFNAMSIZ: usize      = 16;
pub const IFF_UP: c_short      = 0x1;
pub const IFF_RUNNING: c_short = 0x40;

pub const AF_SYS_CONTROL: c_ushort    = 2;
pub const AF_SYSTEM: c_char           = 32;
pub const PF_SYSTEM: c_int            = AF_SYSTEM as c_int;
pub const SYSPROTO_CONTROL: c_int     = 2;
pub const UTUN_OPT_FLAGS: c_int       = 1;
pub const UTUN_OPT_IFNAME: c_int      = 2;
pub const UTUN_FLAGS_NO_OUTPUT: c_int = 0x0001;
pub const UTUN_FLAGS_NO_INPUT: c_int  = 0x0002;
pub const UTUN_CONTROL_NAME: &str     = "com.apple.net.utun_control";



#[repr(C)]
#[derive(Copy, Clone)]
pub struct ctl_info {
    pub ctl_id: c_uint,
    pub ctl_name: [c_char; 96],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_ctl {
    pub sc_len: c_char,
    pub sc_family: c_char,
    pub ss_sysaddr: c_ushort,
    pub sc_id: c_uint,
    pub sc_unit: c_uint,
    pub sc_reserved: [c_uint; 5],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifrn {
    pub name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifdevmtu {
    pub current: c_int,
    pub min: c_int,
    pub max: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifku {
    pub ptr: *mut c_void,
    pub value: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifkpi {
    pub module_id: c_uint,
    pub type_: c_uint,
    pub ifku: ifku,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr: sockaddr,
    pub dstaddr: sockaddr,
    pub broadaddr: sockaddr,

    pub flags: c_short,
    pub metric: c_int,
    pub mtu: c_int,
    pub phys: c_int,
    pub media: c_int,
    pub intval: c_int,
    pub data: *mut c_void,
    pub devmtu: ifdevmtu,
    pub wake_flags: c_uint,
    pub route_refcnt: c_uint,
    pub cap: [c_int; 2],
    pub functional_type: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifrn: ifrn,
    pub ifru: ifru,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifaliasreq {
    pub ifran: [c_char; IFNAMSIZ],
    pub addr: sockaddr,
    pub broadaddr: sockaddr,
    pub mask: sockaddr,
}

ioctl!(readwrite ctliocginfo with 'N', 3; ctl_info);

ioctl!(write siocsifflags with 'i', 16; ifreq);
ioctl!(readwrite siocgifflags with 'i', 17; ifreq);

ioctl!(write siocsifaddr with 'i', 12; ifreq);
ioctl!(readwrite siocgifaddr with 'i', 33; ifreq);

ioctl!(write siocsifdstaddr with 'i', 14; ifreq);
ioctl!(readwrite siocgifdstaddr with 'i', 34; ifreq);

ioctl!(write siocsifbrdaddr with 'i', 19; ifreq);
ioctl!(readwrite siocgifbrdaddr with 'i', 35; ifreq);

ioctl!(write siocsifnetmask with 'i', 22; ifreq);
ioctl!(readwrite siocgifnetmask with 'i', 37; ifreq);

ioctl!(write siocsifmtu with 'i', 52; ifreq);
ioctl!(readwrite siocgifmtu with 'i', 51; ifreq);

ioctl!(write siocaifaddr with 'i', 26; ifaliasreq);
ioctl!(write siocdifaddr with 'i', 25; ifreq);


#[derive(Debug)]
pub struct Device {
    tun: RawFd,
    ctl: RawFd,
}

impl Device {
    pub fn new(name: &str) -> Result<Self, io::Error> {
        if name.len() > IFNAMSIZ {
            return Err(Error::new(ErrorKind::InvalidInput, "name too long"));
        }

        if !name.starts_with("utun") {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid name"));
        }

        let id = name[4..].parse::<c_uint>()
                    .map_err(|_e| Error::new(ErrorKind::InvalidInput, "invalid name"))?;
        
        if id < 1 {
            return Err(Error::new(ErrorKind::InvalidInput, "invalid name"));
        }
        
        let id = id - 1;

        let (tun, ctl) = unsafe {
            let tun = libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL);
            if tun < 1 {
                return Err(io::Error::last_os_error());
            }

            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            if ctliocginfo(tun, &mut info as *mut _ as *mut _) < 0 {
                return Err(io::Error::last_os_error());
            }

            let addr = sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_unit: id,
                sc_reserved: [0; 5],
            };

            let ret = libc::connect(tun,
                                    &addr as *const sockaddr_ctl as *const sockaddr,
                                    mem::size_of_val(&addr) as libc::socklen_t);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            let ctl = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
            if ctl < 1 {
                return Err(io::Error::last_os_error());
            }

            (tun, ctl)
        };
        
        Ok(Device {
            tun: tun,
            ctl: ctl,
        })
    }

    pub fn name(&self) -> Result<String, Error> {
        let mut name = [0u8; 64];
        let mut name_len: libc::socklen_t = 64;

        let ret = unsafe {
            libc::getsockopt(self.tun,
                             SYSPROTO_CONTROL,
                             UTUN_OPT_IFNAME,
                             &mut name as *mut _ as *mut c_void,
                             &mut name_len as *mut libc::socklen_t)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let name_ptr = name.as_ptr() as *const c_char;
        let tun_name = unsafe { CStr::from_ptr(name_ptr) }
                        .to_string_lossy()
                        .to_string();
        Ok(tun_name)
    }

    pub fn address(&self) -> Result<Ipv4Addr, Error> {
        let name = self.name()?;

        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            if siocgifaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.addr).map(Into::into)
        }
    }

    pub fn set_address<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        let name = self.name()?;

        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            req.ifru.addr = SockAddr::from(value.into()).into();

            if siocsifaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn destination(&self) -> Result<Ipv4Addr, Error> {
        let name = self.name()?;

        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            if siocgifdstaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.dstaddr).map(Into::into)
        }
    }

    pub fn set_destination<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            req.ifru.dstaddr = SockAddr::from(value.into()).into();

            if siocsifdstaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn broadcast(&self) -> Result<Ipv4Addr, Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            if siocgifbrdaddr(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::new(&req.ifru.broadaddr).map(Into::into)
        }
    }

    pub fn set_broadcast<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            req.ifru.broadaddr = SockAddr::from(value.into()).into();

            if siocsifbrdaddr(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn netmask(&self) -> Result<Ipv4Addr, Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());


            if siocgifnetmask(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            SockAddr::unchecked(&req.ifru.addr).map(Into::into)
        }
    }

    pub fn set_netmask<T: Into<Ipv4Addr>>(&mut self, value: T) -> Result<(), Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            req.ifru.addr = SockAddr::from(value.into()).into();

            if siocsifnetmask(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn mtu(&self) -> Result<i32, Error> {
        let name = self.name()?;
        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

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

        let name = self.name()?;

        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            req.ifru.mtu = value;

            if siocsifmtu(self.ctl, &req) < 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }
    }

    pub fn enabled(&mut self, value: bool) -> Result<(), Error> {
        let name = self.name()?;

        unsafe {
            let mut req: ifreq = mem::zeroed();
            ptr::copy_nonoverlapping(name.as_ptr() as *const c_char, req.ifrn.name.as_mut_ptr(), name.len());

            if siocgifflags(self.ctl, &mut req) < 0 {
                return Err(io::Error::last_os_error());
            }

            if value {
                req.ifru.flags |= IFF_UP | IFF_RUNNING;
            }
            else {
                req.ifru.flags &= !IFF_UP;
            }

            if siocsifflags(self.ctl, &req) < 0 {
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