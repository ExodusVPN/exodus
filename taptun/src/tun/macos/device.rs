use std::{mem, ptr};
use std::ffi::CStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::str::FromStr;

use libc::{AF_INET, SOCK_DGRAM, c_char, c_void, close, connect, getsockopt, sockaddr, socket, socklen_t};

use error::*;
use tun::Tun;
use tun::configuration::{Configurable, Configuration};
use tun::sockaddr::SockAddr;

use super::sys::*;

pub fn create(configuration: &Configuration) -> Result<Device> {
    Device::from_configuration(&configuration)
}

const IPV4: u8 = 4u8;
const IPV6: u8 = 6u8;
const IP_HEADER_LEN: usize = 4;
const IPV4_HEADER: [u8; 4] = [0, 0, 0, 2];
const IPV6_HEADER: [u8; 4] = [0, 0, 0, 10];

#[derive(Debug)]
pub struct Device {
    name: String,
    tun: File,
    ctl: File,
}

impl Device {
    pub unsafe fn request(&self) -> ifreq {
        let mut req: ifreq = mem::zeroed();
        ptr::copy_nonoverlapping(self.name.as_ptr() as *const c_char, req.ifr_name.as_mut_ptr(), self.name.len());

        req
    }

    pub unsafe fn alias_request(&self) -> ifaliasreq {
        let mut alias_req: ifaliasreq = mem::zeroed();
        ptr::copy_nonoverlapping(self.name.as_ptr() as *const c_char,
                                 alias_req.ifra_name.as_mut_ptr(),
                                 self.name.len());

        alias_req
    }

    pub fn ipv4(&mut self, addr: Ipv4Addr, broadaddr: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut alias_req = self.alias_request();
            alias_req.ifra_addr = SockAddr::from(addr).into();
            alias_req.ifra_broadaddr = SockAddr::from(broadaddr).into();
            alias_req.ifra_mask = SockAddr::from(mask).into();

            if siocaifaddr(self.ctl.as_raw_fd(), &alias_req) < 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
    }

    pub fn delete_addr(&mut self) -> Result<()> {
        unsafe {
            let req = self.request();

            if siocdifaddr(self.ctl.as_raw_fd(), &req) < 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        }
    }
}

impl Read for Device {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.tun.read(buf) {
            Ok(size) => {
                if size > IP_HEADER_LEN {
                    unsafe {
                        let buf_copy: &mut [u8] = ::std::mem::transmute_copy(&buf);
                        let mut idx = IP_HEADER_LEN;
                        while idx < buf.len() {
                            buf[idx-IP_HEADER_LEN] = buf_copy[idx];
                            idx += 1;
                        }
                        ::std::mem::forget(buf_copy);
                    }
                    Ok(size-IP_HEADER_LEN)
                } else {
                    Ok(size)
                }
            },
            Err(e) => Err(e)
        }
    }
}

impl Write for Device {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !buf.len() > 0 {
            return Ok(0);
        };

        let mut data = Vec::with_capacity(buf.len() + IP_HEADER_LEN);
        match buf[0] >> 4 {
            IPV4 => data.extend_from_slice(&IPV4_HEADER),
            IPV6 => data.extend_from_slice(&IPV6_HEADER),
            _    => {}
        };
        data.extend_from_slice(&buf);

        match self.tun.write(&data) {
            Ok(len) => Ok(if len > IP_HEADER_LEN { len - IP_HEADER_LEN } else { 0 }),
            Err(e)  => Err(e),
        }
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

            SockAddr::unchecked(&req.ifr_ifru.ifru_addr).map(Into::into)
        }
    }
    fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        unsafe {
            let mut req = self.request();
            req.ifr_ifru.ifru_addr = SockAddr::from(value).into();

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
        let dev_id = match configuration.name.as_ref() {
            Some(name) => {
                if name.len() > IFNAMSIZ {
                    return Err(ErrorKind::TunNameTooLong.into());
                }
                if !name.starts_with("utun") {
                    return Err(ErrorKind::InvalidTunName.into());
                }
                u8::from_str(&name["utun".len()..])? as u8
            }

            None => 0,
        };

        let tun = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if tun < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: {
                let mut bufer = [0u8; 96];
                bufer[..UTUN_CONTROL_NAME.len()].clone_from_slice(UTUN_CONTROL_NAME.as_bytes());
                bufer
            },
        };

        unsafe {
            if ctliocginfo(tun, &mut info as *mut _ as *mut _) < 0 {
                close(tun);
                return Err(io::Error::last_os_error().into());
            }
        }

        let addr = sockaddr_ctl {
            sc_id: info.ctl_id,
            sc_len: mem::size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_unit: dev_id as u32 + 1,
            sc_reserved: [0; 5],
        };


        if unsafe {
            connect(tun,
                    &addr as *const sockaddr_ctl as *const sockaddr,
                    mem::size_of_val(&addr) as socklen_t)
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }


        let mut name_buf = [0u8; 64];
        let mut name_length: socklen_t = 64;
        if unsafe {
            getsockopt(tun,
                       SYSPROTO_CONTROL,
                       UTUN_OPT_IFNAME,
                       &mut name_buf as *mut _ as *mut c_void,
                       &mut name_length as *mut socklen_t)
        } < 0
        {
            return Err(io::Error::last_os_error().into());
        }

        let ctl = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if ctl < 0 {
            return Err(io::Error::last_os_error().into());
        }

        let mut device = unsafe {
            Device {
                name: CStr::from_ptr(name_buf.as_ptr() as *const c_char).to_string_lossy().into(),
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
