// https://tools.ietf.org/html/rfc3549
// /usr/include/linux/netlink.h

use libc;

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};


pub const AF_NETLINK: u8   = 16;
pub const SOL_NETLINK: i32 = 270;
pub const NETLINK_ADD_MEMBERSHIP: libc::c_int   = 1;
pub const NETLINK_DROP_MEMBERSHIP: libc::c_int  = 2;
pub const NETLINK_PKTINFO: libc::c_int          = 3;
pub const NETLINK_BROADCAST_ERROR: libc::c_int  = 4;
pub const NETLINK_NO_ENOBUFS: libc::c_int       = 5;
pub const NETLINK_RX_RING: libc::c_int          = 6;
pub const NETLINK_TX_RING: libc::c_int          = 7;
pub const NETLINK_LISTEN_ALL_NSID: libc::c_int  = 8;
pub const NETLINK_LIST_MEMBERSHIPS: libc::c_int = 9;
pub const NETLINK_CAP_ACK: libc::c_int          = 10;


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sockaddr_nl {
    pub nl_family: u16,     // AF_NETLINK
    pub nl_pad: u16,        // zero
    pub nl_pid: u32,        // port ID
    pub nl_groups: u32,     // multicast groups mask
}


#[derive(Debug)]
pub struct NetlinkSocket {
    fd: libc::c_int,
}

impl NetlinkSocket {
    pub fn new(proto: i32) -> Result<Self, io::Error> {
        // http://man7.org/linux/man-pages/man7/netlink.7.html
        // 
        // Netlink is a datagram-oriented service.  Both SOCK_RAW and SOCK_DGRAM
        // are valid values for socket_type.  However, the netlink protocol does
        // not distinguish between datagram and raw sockets.
        let fd = unsafe { libc::socket(AF_NETLINK as i32, libc::SOCK_RAW, proto) };
        trace!("open netlink socket at FD#{}", fd);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { fd })
    }

    pub fn bind(&mut self, pid: u32, groups: u32) -> Result<(), io::Error> {
        let nladdr = sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad   : 0,
            nl_pid   : pid,
            nl_groups: groups,
        };

        let nladdr_ptr = &nladdr as *const sockaddr_nl as  *const libc::sockaddr;
        let sa_len = std::mem::size_of::<sockaddr_nl>() as u32;

        if unsafe { libc::bind(self.fd, nladdr_ptr, sa_len) } < 0 {
            return Err(io::Error::last_os_error());
        }

        trace!("bind pid={} groups={} on netlink socket at FD#{}", pid, groups, self.fd);

        Ok(())
    }

    #[inline]
    pub fn flags(&self) -> Result<i32, io::Error> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(flags)
    }
    
    #[inline]
    pub fn set_flags(&mut self, flags: i32) -> Result<(), io::Error> {
        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Set underlying socket file descriptor to be blocking
    #[inline]
    pub fn set_block(&mut self) -> Result<(), io::Error> {
        self.set_flags(self.flags()? & !libc::O_NONBLOCK)
    }

    /// Set underlying socket file descriptor to be non blocking
    #[inline]
    pub fn set_nonblock(&mut self) -> Result<(), io::Error> {
        self.set_flags(self.flags()? | libc::O_NONBLOCK)
    }

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    #[inline]
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        Ok((self.flags()? & libc::O_NONBLOCK) == 0)
    }

    /// Set multicast groups for socket
    pub fn set_mcast_groups(&mut self, groups: u32) -> Result<(), io::Error> {
        // nl_pktinfo
        let groups_ptr = &groups as *const u32 as *const libc::c_void;
        let groups_len = std::mem::size_of::<u32>() as libc::socklen_t;
        let ret = unsafe {
            libc::setsockopt(self.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, groups_ptr, groups_len)
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn send<T: AsRef<[u8]> + ?Sized>(&mut self, buf: &T) -> Result<usize, io::Error> {
        let buffer = buf.as_ref();

        let ptr = buffer.as_ptr() as *const libc::c_void;
        let len = buffer.len();
        let flags = 0i32;

        let amt = unsafe { libc::send(self.fd, ptr, len, flags) };
        if amt < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amt as usize)
    }

    pub fn recv<T: AsMut<[u8]> + ?Sized>(&mut self, buf: &mut T) -> Result<usize, io::Error> {
        let buffer = buf.as_mut();
        
        let ptr = buffer.as_mut_ptr() as *mut libc::c_void;
        let len = buffer.len();
        let flags = 0i32;

        let amt = unsafe { libc::recv(self.fd, ptr, len, flags) };
        if amt < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amt as usize)
    }

    pub fn sendmsg<T: AsRef<[u8]> + ?Sized>(&mut self, buf: &T) -> Result<usize, io::Error> {
        let buffer = buf.as_ref();
        let ptr = buffer.as_ptr() as *const libc::c_void;
        let len = buffer.len();
        
        let nladdr = sockaddr_nl {
            nl_family: AF_NETLINK as u16,
            nl_pad   : 0,
            nl_pid   : 0,
            nl_groups: 0,
        };

        let nladdr_ptr = &nladdr as *const sockaddr_nl as  *const libc::sockaddr;
        let sa_len = std::mem::size_of::<sockaddr_nl>() as u32;
        
        let iov = [
            libc::iovec {
                iov_base: ptr as *mut _,
                iov_len: len,
            },
        ];
        let iov_ptr = iov.as_ptr() as *mut _;
        let m = libc::msghdr {
            msg_name: nladdr_ptr as *mut _,
            msg_namelen: sa_len,
            msg_iov: iov_ptr,
            msg_iovlen: 1,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        
        if unsafe { libc::sendmsg(self.fd, &m as *const _, 0) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(len)
    }
}


impl AsRawFd for NetlinkSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NetlinkSocket {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl Read for NetlinkSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf)
    }
}

impl Write for NetlinkSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
        trace!("close netlink socket FD#{}", self.fd);
    }
}

