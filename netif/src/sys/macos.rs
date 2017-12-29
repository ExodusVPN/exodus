#![cfg(target_os = "macos")]

use libc;
use sys;

use std::str;
use std::io;
use std::ffi::CStr;
use std::ffi::CString;


pub const RTF_LLDATA: libc::c_int = 0x400;
pub const RTF_DEAD: libc::c_int = 0x20000000;
pub const RTPRF_OURS: libc::c_int = libc::RTF_PROTO3;

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Debug)]
pub struct rt_msghdr {
    pub rtm_msglen: libc::c_ushort, // to skip over non-understood messages
    pub rtm_version: libc::c_uchar, // future binary compatibility
    pub rtm_type: libc::c_uchar,    // message type 
    pub rtm_index: libc::c_ushort,  // index for associated ifp
    pub rtm_flags: libc::c_int,     // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,     // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,       // identify sender
    pub rtm_seq: libc::c_int,       // for sender to identify action
    pub rtm_errno: libc::c_int,     // why failed
    pub rtm_use: libc::c_int,       // from rtentry
    pub rtm_inits: libc::uint32_t,  // which metrics we are initializing
    pub rtm_rmx: rt_metrics,        // metrics themselves
}

// These numbers are used by reliable protocols for determining
// retransmission behavior and are included in the routing structure.
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct rt_metrics {
    pub rmx_locks: libc::uint32_t,       // Kernel leaves these values alone
    pub rmx_mtu: libc::uint32_t,         // MTU for this path
    pub rmx_hopcount: libc::uint32_t,    // max hops expected
    pub rmx_expire: libc::int32_t,       // lifetime for route, e.g. redirect
    pub rmx_recvpipe: libc::uint32_t,    // inbound delay-bandwidth product
    pub rmx_sendpipe: libc::uint32_t,    // outbound delay-bandwidth product
    pub rmx_ssthresh: libc::uint32_t,    // outbound gateway buffer limit
    pub rmx_rtt: libc::uint32_t,         // estimated round trip time
    pub rmx_rttvar: libc::uint32_t,      // estimated rtt variance
    pub rmx_pksent: libc::uint32_t,      // packets sent using this route
    pub rmx_state: libc::uint32_t,       // route state
    pub rmx_filler: [libc::uint32_t; 3], // will be used for T/TCP later
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct rt_msghdr2 {
    pub rtm_msglen: libc::c_ushort,   // to skip over non-understood messages
    pub rtm_version: libc::c_uchar,   // future binary compatibility
    pub rtm_type: libc::c_uchar,      // message type 
    pub rtm_index: libc::c_ushort,    // index for associated ifp
    pub rtm_flags: libc::c_int,       // flags, incl. kern & message, e.g. DONE
    pub rtm_addrs: libc::c_int,       // bitmask identifying sockaddrs in msg
    pub rtm_refcnt: libc::int32_t,    // reference count
    pub rtm_parentflags: libc::c_int, // which metrics we are initializing
    pub rtm_reserved: libc::c_int,    // metrics themselves
    pub rtm_use: libc::c_int,         // from rtentry
    pub rtm_inits: libc::uint32_t,    // which metrics we are initializing
    pub rtm_rmx: rt_metrics,          // metrics themselves
}


// Route reachability info
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct rt_reach_info {
    pub ri_refcnt: libc::uint32_t,     // reference count
    pub ri_probes: libc::uint32_t,     // total # of probes
    pub ri_snd_expire: libc::uint64_t, // tx expiration (calendar) time
    pub ri_rcv_expire: libc::uint64_t, // rx expiration (calendar) time
    pub ri_rssi: libc::int32_t,        // received signal strength
    pub ri_lqm: libc::int32_t,         // link quality metric
    pub ri_npm: libc::int32_t,         // node proximity metric
}

// Extended routing message header (private).
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct rt_msghdr_ext {
    pub rtm_msglen: libc::c_ushort,   // to skip over non-understood messages
    pub rtm_version: libc::c_uchar,   // future binary compatibility
    pub rtm_type: libc::c_uchar,      // message type 
    pub rtm_index: libc::uint32_t,    // index for associated ifp
    pub rtm_flags: libc::uint32_t,    // flags, incl. kern & message, e.g. DONE
    pub rtm_reserved: libc::uint32_t, // for future use
    pub rtm_addrs: libc::uint32_t,    // bitmask identifying sockaddrs in msg
    pub rtm_pid: libc::pid_t,         // identify sender
    pub rtm_seq: libc::c_int,         // for sender to identify action
    pub rtm_errno: libc::c_int,       // why failed
    pub rtm_use: libc::uint32_t,      // from rtentry
    pub rtm_inits: libc::uint32_t,    // which metrics we are initializing
    pub rtm_rmx: rt_metrics,          // metrics themselves
    pub rtm_ri: rt_reach_info,        // route reachability info
}



pub fn if_name_to_mtu(name: &str) -> Result<usize, io::Error> {
    #[repr(C)]
    #[derive(Debug)]
    struct ifreq {
        ifr_name: [sys::c_char; sys::IF_NAMESIZE],
        ifr_mtu: sys::c_int
    }

    let fd = unsafe { sys::socket(sys::AF_INET, sys::SOCK_DGRAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut ifreq = ifreq {
        ifr_name: [0; sys::IF_NAMESIZE],
        ifr_mtu: 0
    };
    for (i, byte) in name.as_bytes().iter().enumerate() {
        ifreq.ifr_name[i] = *byte as sys::c_char
    }
    
    let ret = unsafe { sys::ioctl(fd, sys::SIOCGIFMTU, &mut ifreq as *mut ifreq) };
    
    unsafe { libc::close(fd) };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ifreq.ifr_mtu as usize)
    }
}

pub fn if_index_to_name(ifindex: u32) -> String{
    let ifname_buf: [u8; libc::IF_NAMESIZE] = [0u8; libc::IF_NAMESIZE];
    unsafe {
        let ifname_cstr = CStr::from_bytes_with_nul_unchecked(&ifname_buf);
        let ptr = ifname_cstr.as_ptr() as *mut i8;
        libc::if_indextoname(ifindex, ptr);

        let mut pos = ifname_buf.len() - 1;
        while pos != 0 {
            if ifname_buf[pos] != 0 {
                if pos + 1 < ifname_buf.len() {
                    pos += 1;
                }
                break;
            }
            pos -= 1;
        }
        str::from_utf8(&ifname_buf[..pos]).unwrap().to_string()
    }
}

pub fn if_name_to_index(ifname: &str) -> u32 {
    unsafe { sys::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) }
}
