use std::{mem, ptr};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use libc::{AF_INET, O_RDWR, SOCK_DGRAM, c_char, close, open, socket};

use error::*;
use tun::Tun;
use tun::configuration::{Configurable, Configuration};
use tun::sockaddr::SockAddr;

use super::sys::*;

pub fn create(configuration: &Configuration) -> Result<Device> {
    Device::from_configuration(&configuration)
}

#[derive(Debug)]
pub struct Device {
    name: String,
    tun: File,
    ctl: File,
}

impl Device {
    pub unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(self.name.as_ptr() as *const c_char,
                                 req.ifr_ifrn.ifrn_name.as_mut_ptr(),
                                 self.name.len());

        req
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tun.read(buf)
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tun.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tun.flush()
    }
}

impl AsRawFd for Device {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

impl Tun for Device {
    fn name(&self) -> &str {
        &self.name
    }

    fn address(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifr_ifru.ifru_addr).map(Into::into)
        }
    }
    fn set_address(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_addr = SockAddr::from(value).into();

            if siocsifaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn broadcast(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifbrdaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifr_ifru.ifru_broadaddr).map(Into::into)
        }
    }
    fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_broadaddr = SockAddr::from(value).into();

            if siocsifbrdaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn destination(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifdstaddr(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::new(&req.ifr_ifru.ifru_dstaddr).map(Into::into)
        }
    }
    fn set_destination(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_dstaddr = SockAddr::from(value).into();

            if siocsifdstaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn netmask(&self) -> Result<Ipv4Addr> {
        unsafe {
            let mut req = self.request();

            if siocgifnetmask(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            SockAddr::unchecked(&req.ifr_ifru.ifru_netmask).map(Into::into)
        }
    }
    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_netmask = SockAddr::from(value).into();

            if siocsifnetmask(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn mtu(&self) -> Result<i32> {
        unsafe {
            let mut req = self.request();

            if siocgifmtu(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(req.ifr_ifru.ifru_mtu)
        }
    }
    fn set_mtu(&mut self, value: i32) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_mtu = value;

            if siocsifmtu(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn flags(&self) -> Result<i16> {
        unsafe {
            let mut req = self.request();

            if siocgifflags(self.ctl.as_raw_fd(), &mut req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(req.ifr_ifru.ifru_flags)
        }
    }
    fn set_flags(&mut self, value: i16) -> Result<()> {
        let origin_flags = self.flags()?;
        let mut value = value;

        unsafe {
            let mut req = self.request();

            req.ifr_ifru.ifru_flags = if value < 0 {
                value = -value;
                origin_flags & !value
            } else {
                origin_flags | value
            };

            if siocsifflags(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }

            Ok(())
        }
    }

    fn set_enabled(&mut self, value: bool) -> Result<()> {
        if value {
            return self.set_flags(IFF_UP | IFF_RUNNING);
        }

        self.set_flags(-IFF_UP)
    }
}

impl Configurable for Device {
    fn from_configuration(configuration: &Configuration) -> Result<Self> {
        let device_name = match configuration.name.as_ref() {
            Some(name) => {
                let name = CString::new(name.clone())?;

                if name.as_bytes_with_nul().len() > IFNAMSIZ {
                    return Err(ErrorKind::TunNameTooLong.into());
                }

                Some(name)
            }

            None => None,
        };

        let tun = unsafe { open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR) };
        if tun < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut req: ifreq = unsafe { mem::zeroed() };

        if let Some(device_name) = device_name.as_ref() {
            unsafe {
                ptr::copy_nonoverlapping(device_name.as_ptr() as *const c_char,
                                         req.ifr_ifrn.ifrn_name.as_mut_ptr(),
                                         device_name.as_bytes().len())
            };
        }

        req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

        unsafe {
            if tunsetiff(tun, &mut req as *mut _ as *mut _) < 0 {
                close(tun);
                return Err(io::Error::last_os_error().into());
            }
        }

        let ctl = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if ctl < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut device = unsafe {
            Device {
                name: CStr::from_ptr(req.ifr_ifrn.ifrn_name.as_ptr()).to_string_lossy().into(),
                tun: File::from_raw_fd(tun),
                ctl: File::from_raw_fd(ctl),
            }
        };

        device.configure(configuration)?;
        Ok(device)
    }
    fn configure(&mut self, configuration: &Configuration) -> Result<()> {
        if let Some(ip) = configuration.address {
            self.set_address(ip)?;
        }

        if let Some(ip) = configuration.destination {
            self.set_destination(ip)?;
        }

        if let Some(ip) = configuration.broadcast {
            self.set_broadcast(ip)?;
        }

        if let Some(ip) = configuration.netmask {
            self.set_netmask(ip)?;
        }

        if let Some(mtu) = configuration.mtu {
            self.set_mtu(mtu)?;
        }

        self.set_enabled(configuration.enabled)?;

        Ok(())
    }
}

include!("../unix/mio.rs.in");
