
// TAP/TUN
extern crate byteorder;
extern crate nix;
extern crate libc;
#[macro_use] extern crate ioctl_sys;

use std::ffi::CStr;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::os::unix::io::{RawFd, FromRawFd, IntoRawFd, AsRawFd};
use std::ptr;

// use byteorder::{ByteOrder, NetworkEndian};
// use mio::{Evented, Ready, Poll, PollOpt, Token};
// use mio::unix::EventedFd;
use nix::libc::{getsockopt, socklen_t, c_void, c_int};
#[allow(unused_imports)]
use nix::sys::socket::{self, SockAddr, InetAddr, sockaddr, sockaddr_in, socket, connect, SockType,
                       AddressFamily, SockFlag, SOCK_NONBLOCK, SOCK_CLOEXEC, SYSPROTO_CONTROL,
                       AF_INET, AF_INET6};
// use nix::sys::uio::{readv, writev, IoVec};
use nix::unistd::close;


const IOC_IF_MAGIC: u8 = 'i' as u8;

const IOC_SET_IFADDR: u8 = 12;
const IOC_SET_IFNETMASK: u8 = 22;
const IOC_GET_IFADDR: u8 = 33;
const IOC_GET_IFNETMASK: u8 = 37;

const UTUN_OPT_IFNAME: c_int = 2;

const IFNAMSIZ: usize = 16;


#[repr(C)]
pub struct ifreq_addr {
    pub ifra_name: [libc::c_char; IFNAMSIZ],
    pub ifra_addr: sockaddr,
}

pub struct Tun {
    fd: RawFd,
}

impl Tun {
    pub fn new() -> Result<Self, ::std::io::Error> {
        match socket(AddressFamily::System, SockType::Datagram, SOCK_NONBLOCK | SOCK_CLOEXEC, SYSPROTO_CONTROL) {
            Ok(fd) => match SockAddr::new_sys_control(fd, "com.apple.net.utun_control", 0) {
                Ok(ctrl_addr) => match connect(fd, &ctrl_addr) {
                    Ok(_) =>  Ok(Tun{ fd: fd }),
                    Err(e) => match e {
                        nix::Error::Sys(nix::errno::Errno::EPERM) => {
                            println!("该操作需要管理员权限！");
                            Err(::std::io::Error::new(::std::io::ErrorKind::Other, "该操作需要管理员权限！"))
                        },
                        _ => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
                    }
                },
                Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
            },
            Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn ifname(&self) -> io::Result<String> {
        let mut buf = [0; IFNAMSIZ];
        let mut len = buf.len() as socklen_t;
        let success = unsafe {
            getsockopt(self.fd,
                       SYSPROTO_CONTROL,
                       UTUN_OPT_IFNAME,
                       buf.as_mut_ptr() as *mut c_void,
                       &mut len)
        };
        if success != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_string() })
    }

    pub fn get_addr(&self) -> Result<Ipv4Addr, ::std::io::Error> {
        let ifname = try!(self.ifname());

        let mut ifreq: ifreq_addr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
        ifreq.ifra_addr.sa_family = AF_INET as u8;

        ioctl!(write _get_addr with IOC_IF_MAGIC, IOC_GET_IFADDR; ifreq_addr);
        match socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0) {
            Ok(fd) => {
                let _ret_code = unsafe { _get_addr(fd, &ifreq) };
                match close(fd) {
                    Ok(_) => {
                        let addr = match InetAddr::V4(unsafe { *(&ifreq.ifra_addr as *const _ as *const sockaddr_in) }).ip() {
                            socket::IpAddr::V4(addr) => addr,
                            _ => unreachable!()
                        };
                        Ok(addr.to_std())
                    },
                    Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }
    pub fn set_addr(&self, addr: Ipv4Addr) -> Result<(), ::std::io::Error> {
        let ifname = try!(self.ifname());
            
        let addr_in = match InetAddr::from_std(&SocketAddr::new(IpAddr::V4(addr), 0)) {
            InetAddr::V4(addr_in) => addr_in,
            _ => unreachable!()
        };
        let mut ifra_addr: sockaddr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(&addr_in, &mut ifra_addr as *mut _ as *mut sockaddr_in, 1); }

        let mut ifreq: ifreq_addr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
        ifreq.ifra_addr = ifra_addr;

        ioctl!(write _set_addr with IOC_IF_MAGIC, IOC_SET_IFADDR; ifreq_addr);
        match socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0) {
            Ok(fd) => {
                let _ret_code = unsafe { _set_addr(fd, &ifreq) };
                match close(fd) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }

    pub fn get_netmask(&self) -> Result<Ipv4Addr, ::std::io::Error> {
        let ifname = try!(self.ifname());

        let mut ifreq: ifreq_addr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
        ifreq.ifra_addr.sa_family = AF_INET as u8;

        ioctl!(write _get_addr with IOC_IF_MAGIC, IOC_GET_IFNETMASK; ifreq_addr);
        match socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0) {
            Ok(fd) => {
                let _ret_code = unsafe { _get_addr(fd, &ifreq) };
                match close(fd) {
                    Ok(_) => {
                        let addr = match InetAddr::V4(unsafe { *(&ifreq.ifra_addr as *const _ as *const sockaddr_in) }).ip() {
                            socket::IpAddr::V4(addr) => addr,
                            _ => unreachable!()
                        };
                        Ok(addr.to_std())
                    },
                    Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }
    pub fn set_netmask(&self, addr: Ipv4Addr) -> Result<(), ::std::io::Error> {
        let ifname = try!(self.ifname());
            
        let addr_in = match InetAddr::from_std(&SocketAddr::new(IpAddr::V4(addr), 0)) {
            InetAddr::V4(addr_in) => addr_in,
            _ => unreachable!()
        };
        let mut ifra_addr: sockaddr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(&addr_in, &mut ifra_addr as *mut _ as *mut sockaddr_in, 1); }

        let mut ifreq: ifreq_addr = unsafe { mem::zeroed() };
        unsafe { ptr::copy_nonoverlapping(ifname.as_ptr() as *const _, ifreq.ifra_name.as_mut_ptr(), ifname.len()) };
        ifreq.ifra_addr = ifra_addr;

        ioctl!(write _set_addr with IOC_IF_MAGIC, IOC_SET_IFNETMASK; ifreq_addr);
        match socket(AddressFamily::Inet, SockType::Datagram, SockFlag::empty(), 0) {
            Ok(fd) => {
                let _ret_code = unsafe { _set_addr(fd, &ifreq) };
                match close(fd) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
                }
            },
            Err(_) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."))
        }
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl FromRawFd for Tun {
    unsafe fn from_raw_fd(fd: RawFd) -> Tun {
        Tun { fd: fd }
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        ::std::mem::forget(self);
        fd
    }
}

#[allow(unused_variables, unknow_lints)]
impl Read for Tun {
    fn read(&mut self, dst: &mut [u8]) -> Result<usize, ::std::io::Error> {
        // TODO: 需要先实现 NetPacket Parser
        unimplemented!();
    }
}

#[allow(unused_variables, unknow_lints)]
impl Write for Tun {
    fn write(&mut self, src: &[u8]) -> Result<usize, ::std::io::Error> {
        // TODO: 需要先实现 NetPacket Parser
        unimplemented!();
    }
    fn flush(&mut self) -> Result<(), ::std::io::Error> {
        Ok(())
    }
}

impl Drop for Tun {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}



fn main() {
    let mut child = ::std::process::Command::new("/usr/bin/env")
                        .arg("ifconfig")
                        .spawn()
                        .expect("failed to execute child");

    let utun = Tun::new().unwrap();
    utun.set_addr(Ipv4Addr::new(172, 30, 20, 1)).unwrap();
    utun.set_netmask(Ipv4Addr::new(255, 255, 255, 255)).unwrap();

    // TODO: Write/Read
    // loop {
    //     let mut buf = [0u8; 2018];
    //     match utun.read(&buf) {
    //         Ok(size) => {
    //             buf.truncate(size);
    //             let response_bytes = b"im ok, im ok, im ok.";
    //             let _ = utun.write(response_bytes);
    //         },
    //         Err(_) => {
    //             panic!("Oh, no ...");
    //         }
    //     };
    // }
    child = ::std::process::Command::new("/usr/bin/env")
                        .arg("ifconfig")
                        .spawn()
                        .expect("failed to execute child");
    let _ = child.wait()
                 .expect("failed to wait on child");

    ::std::thread::sleep(::std::time::Duration::new(10, 0));
}
