#![cfg(target_os = "macos")]

use libc;

pub const RTF_LLINFO: libc::c_int = 0x400;

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
