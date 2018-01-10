#![cfg(target_os = "linux")]

use libc;
use sys;

use std::io;
use std::ptr;
use std::mem;
use std::ffi::CString;

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/sockios.h
pub const SIOCGIFADDR: sys::c_ulong = 0x8915;

pub const SIOCGIFHWADDR: sys::c_ulong = 0x8927;

pub const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
pub const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

pub const SIOCGIFMTU: libc::c_ulong = 0x00008921;
pub const SIOCSIFMTU: libc::c_ulong = 0x00008922;

pub const SIOCGIFMETRIC: libc::c_ulong = 0x0000891d;
pub const SIOCSIFMETRIC: libc::c_ulong = 0x0000891e;

pub const SIOCGIFINDEX: libc::c_ulong = 0x8933;

pub const TUNSETIFF:    libc::c_ulong = 0x400454CA;
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;

// route flags
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h
pub const RTF_UP: libc::c_ushort        = 0x0001;     // route usable
pub const RTF_GATEWAY: libc::c_ushort   = 0x0002;     // destination is a gateway
pub const RTF_HOST: libc::c_ushort      = 0x0004;     // host entry (net otherwise) 
pub const RTF_REINSTATE: libc::c_ushort = 0x0008;     // reinstate route after tmout
pub const RTF_DYNAMIC: libc::c_ushort   = 0x0010;     // created dyn. (by redirect)
pub const RTF_MODIFIED: libc::c_ushort  = 0x0020;     // modified dyn. (by redirect)
pub const RTF_MTU: libc::c_ushort       = 0x0040;     // specific MTU for this route
pub const RTF_MSS: libc::c_ushort       = RTF_MTU;    // Compatibility :-(
pub const RTF_WINDOW: libc::c_ushort    = 0x0080;     // per route window clamping
pub const RTF_IRTT: libc::c_ushort      = 0x0100;     // Initial round trip time
pub const RTF_REJECT: libc::c_ushort    = 0x0200;     // Reject route

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr:      libc::sockaddr,
    pub dstaddr:   libc::sockaddr,
    pub broadaddr: libc::sockaddr,
    pub netmask:   libc::sockaddr,
    pub hwaddr:    libc::sockaddr,
    pub flags:     libc::c_short,
    pub metric:    libc::c_int,
    pub mtu:       libc::c_int,
    pub data:      *mut libc::c_void,
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifr_name: [libc::c_char; libc::IF_NAMESIZE],
    pub ifru: ifru,
}

// This structure gets passed by the SIOCADDRT and SIOCDELRT calls.
#[repr(C)]
pub struct rtentry {
    pub rt_pad1: libc::c_ulong,
    pub rt_dst: libc::sockaddr,       // target address
    pub rt_gateway: libc::sockaddr,   // gateway addr (RTF_GATEWAY)
    pub rt_genmask: libc::sockaddr,   // target network mask (IP)
    pub rt_flags: libc::c_ushort,
    pub rt_pad2: libc::c_short,
    pub rt_pad3: libc::c_ulong,
    pub rt_pad4: *const libc::c_void,
    pub rt_metric: libc::c_short,     // +1 for binary compatibility!
    
    // char __user *rt_dev
    // pub rt_dev: *const ,              // forcing the device at add

    pub rt_mtu: libc::c_ulong,        // per route MTU/Window
    // pub rt_mss: rt_mtu,            // Compatibility :-(
    pub rt_window: libc::c_ulong,     // Window clamping
    pub rt_irtt: libc::c_ushort,      // Initial RTT
}


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

pub fn if_name_to_flags(ifname: &str) -> Result<i32, io::Error> {
    let fd = unsafe { sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    #[repr(C)]
    struct ifreq {
        pub ifr_name: [sys::c_char; sys::IF_NAMESIZE],
        pub ifr_flags: sys::c_short,
    }


    let mut req: ifreq = unsafe { mem::zeroed() };
    unsafe {
        ptr::copy_nonoverlapping(ifname.as_ptr() as *const sys::c_char,
                                 req.ifr_name.as_mut_ptr(),
                                 ifname.len());
        let ret = sys::ioctl(fd, sys::SIOCGIFFLAGS, &req);
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(req.ifr_flags as i32)
}
