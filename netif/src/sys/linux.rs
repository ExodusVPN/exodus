#![cfg(target_os = "linux")]

use libc;
use sys;

use std::io;
use std::ffi::CString;

pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;


pub const SIOCGIFMTU: libc::c_ulong = 0x00008921;
pub const SIOCSIFMTU: libc::c_ulong = 0x00008922;
pub const SIOCGIFMETRIC: libc::c_ulong = 0x0000891d;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x0000891e;
pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;

pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;



// pub const ETH_ALEN: libc::c_int = 6;            // Octets in one ethernet addr
// pub const ETH_P_ALL: libc::c_int = 0x0003;      // Every packet (be careful!!!)

// pub const ETH_P_LOOP: libc::c_int = 0x0060;     // Ethernet Loopback packet
// pub const ETH_P_IP: libc::c_int = 0x0800;       // Internet Protocol packet
// pub const ETH_P_ARP: libc::c_int = 0x0806;      // Address Resolution packet
// pub const ETH_P_LOOPBACK: libc::c_int = 0x9000; // Ethernet loopback packet, per IEEE 802.3


pub fn if_name_to_mtu(name: &str) -> Result<usize, io::Error> {
    #[repr(C)]
    #[derive(Debug)]
    struct ifreq {
        ifr_name: [sys::c_char; sys::IF_NAMESIZE],
        ifr_mtu: sys::c_int
    }

    let mut ifreq = ifreq {
        ifr_name: [0; sys::IF_NAMESIZE],
        ifr_mtu: 0
    };

    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as sys::c_char
    }

    let fd = unsafe {
        sys::socket(sys::AF_PACKET,
                    sys::SOCK_RAW | sys::SOCK_NONBLOCK,
                    sys::ETH_P_ALL)
    };

    if fd == -1 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    
    let ret = unsafe {
        sys::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq)
    };

    unsafe { libc::close(fd) };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ifreq.ifr_mtu as usize)
    }
}

pub fn if_name_to_index(ifname: &str) -> u32 {
    unsafe { sys::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) }
}
