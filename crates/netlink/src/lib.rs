// #![cfg(target_os = "linux")]
#![allow(dead_code, non_camel_case_types, non_upper_case_globals)]

extern crate libc;

use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd,IntoRawFd,RawFd};

// https://tools.ietf.org/html/rfc3549


/// Max supported message length for netlink messages supported by the kernel
pub const MAX_NL_LENGTH: usize = 32768;
pub const SOL_NETLINK: libc::c_int = 270;


// Netlink Message Header
// https://tools.ietf.org/html/rfc3549#section-2.3.2
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Length                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Type              |           Flags              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Process ID (PID)                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 
// use libc::nlmsghdr;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct sockaddr_nl {
    // libc::sa_family_t
    pub nl_family: u16,     // AF_NETLINK
    pub nl_pad: u16,        // zero
    pub nl_pid: u32,        // port ID
    pub nl_groups: u32,     // multicast groups mask
}


#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nlmsghdr {
    // Length of message including header
    pub nlmsg_len: u32,
    // Message content: RTM_GETNEIGH, ...
    pub nlmsg_type: u16,
    // Additional flags: NLM_F_DUMP, NLM_F_REQUEST, ...
    pub nlmsg_flags: u16,
    // Sequence number
    pub nlmsg_seq: u32,
    // Sending process port ID
    pub nlmsg_pid: u32,
}

// Flags values
pub const NLM_F_REQUEST: i32       =  1; // It is request message.
pub const NLM_F_MULTI: i32         =  2; // Multipart message, terminated by 
pub const NLM_F_ACK: i32           =  4; // Reply with ack, with zero or error 
pub const NLM_F_ECHO: i32          =  8; // Echo this request
pub const NLM_F_DUMP_INTR: i32     = 16; // Dump was inconsistent due to sequence 
pub const NLM_F_DUMP_FILTERED: i32 = 32; // Dump was filtered as 
// Modifiers to GET request
pub const NLM_F_ROOT: i32   = 0x100;                    // specify tree root
pub const NLM_F_MATCH: i32  = 0x200;                    // return all matching
pub const NLM_F_ATOMIC: i32 = 0x400;                    // atomic GET
pub const NLM_F_DUMP: i32   = NLM_F_ROOT | NLM_F_MATCH;
// Modifiers to NEW request
pub const NLM_F_REPLACE: i32 = 0x100;   // Override existing
pub const NLM_F_EXCL: i32    = 0x200;   // Do not touch, if it exists
pub const NLM_F_CREATE: i32  = 0x400;   // Create, if it does not 
pub const NLM_F_APPEND: i32  = 0x800;   // Add to end of list

// 4.4BSD ADD       NLM_F_CREATE|NLM_F_EXCL
// 4.4BSD CHANGE    NLM_F_REPLACE
// 
// True CHANGE      NLM_F_CREATE|NLM_F_REPLACE
// Append       NLM_F_CREATE
// Check        NLM_F_EXCL


pub const NLMSG_NOOP: i32    = 0x1; // Nothing.
pub const NLMSG_ERROR: i32   = 0x2; // Error
pub const NLMSG_DONE: i32    = 0x3; // End of a dump
pub const NLMSG_OVERRUN: i32 = 0x4; // Data lost

pub const NLMSG_MIN_TYPE: i32 = 0x10; // < 0x10: reserved control messages


#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nlmsgerr {
    pub error: libc::c_int,
    pub msg: nlmsghdr,
}


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
#[derive(Debug, Copy, Clone)]
pub struct nl_pktinfo {
    pub group: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nl_mmap_req {
    pub nm_block_size: u32,
    pub nm_block_nr: u32,
    pub nm_frame_size: u32,
    pub nm_frame_nr: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nl_mmap_hdr {
    pub nm_status: u32,
    pub nm_len: u32,
    pub nm_group: u32,
    // credentials
    pub nm_pid: u32,
    pub nm_uid: u32,
    pub nm_gid: u32,
}

// enum nl_mmap_status
pub const NL_MMAP_STATUS_UNUSED: i32   = 0;
pub const NL_MMAP_STATUS_RESERVED: i32 = 1;
pub const NL_MMAP_STATUS_VALID: i32    = 2;
pub const NL_MMAP_STATUS_COPY: i32     = 3;
pub const NL_MMAP_STATUS_SKIP: i32     = 4;

pub const NETLINK_UNCONNECTED: i32 = 0;
pub const NETLINK_CONNECTED: i32   = 1;


// <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
// +---------------------+- - -+- - - - - - - - - -+- - -+
// |        Header       | Pad |     Payload       | Pad |
// |   (struct nlattr)   | ing |                   | ing |
// +---------------------+- - -+- - - - - - - - - -+- - -+
// <-------------- nlattr->nla_len -------------->
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nlattr {
    pub nla_len: u16,
    pub nla_type: u16,
}

// nla_type (16 bits)
// +---+---+-------------------------------+
// | N | O | Attribute Type                |
// +---+---+-------------------------------+
// N := Carries nested attributes
// O := Payload stored in network byte order
// 
// Note: The N and O flag are mutually exclusive.
pub const NLA_F_NESTED: i32        = 1 << 15;
pub const NLA_F_NET_BYTEORDER: i32 = 1 << 14;
pub const NLA_TYPE_MASK: i32       = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
pub const NLA_ALIGNTO: i32         = 4;


// rtnetlink families. Values up to 127 are reserved for real address
// families, values above 128 may be used arbitrarily.
pub const RTNL_FAMILY_IPMR: i32  = 128;
pub const RTNL_FAMILY_IP6MR: i32 = 129;
pub const RTNL_FAMILY_MAX: i32   = 129;

// Routing/neighbour discovery messages.

// Types of messages
pub const RTM_BASE: i32    = 16;
pub const RTM_NEWLINK: i32 = 16;
pub const RTM_DELLINK: i32 = 17;
pub const RTM_GETLINK: i32 = 18;
pub const RTM_SETLINK: i32 = 19;

pub const RTM_NEWADDR: i32 = 20;
pub const RTM_DELADDR: i32 = 21;
pub const RTM_GETADDR: i32 = 22;

pub const RTM_NEWROUTE: i32 = 24;
pub const RTM_DELROUTE: i32 = 25;
pub const RTM_GETROUTE: i32 = 26;

pub const RTM_NEWNEIGH: i32 = 28;
pub const RTM_DELNEIGH: i32 = 29;
pub const RTM_GETNEIGH: i32 = 30;

pub const RTM_NEWRULE: i32  = 32;
pub const RTM_DELRULE: i32  = 33;
pub const RTM_GETRULE: i32  = 34;

pub const RTM_NEWQDISC: i32  = 36;
pub const RTM_DELQDISC: i32  = 37;
pub const RTM_GETQDISC: i32  = 38;

pub const RTM_NEWTCLASS: i32  = 40;
pub const RTM_DELTCLASS: i32  = 41;
pub const RTM_GETTCLASS: i32  = 42;

pub const RTM_NEWTFILTER: i32  = 44;
pub const RTM_DELTFILTER: i32  = 45;
pub const RTM_GETTFILTER: i32  = 46;

pub const RTM_NEWACTION: i32  = 48;
pub const RTM_DELACTION: i32  = 49;
pub const RTM_GETACTION: i32  = 50;

pub const RTM_NEWPREFIX: i32  = 52;
pub const RTM_GETMULTICAST: i32  = 58;
pub const RTM_GETANYCAST: i32  = 62;

// ARP
pub const RTM_NEWNEIGHTBL: i32  = 64;
pub const RTM_GETNEIGHTBL: i32  = 66;
pub const RTM_SETNEIGHTBL: i32  = 67;

pub const RTM_NEWNDUSEROPT: i32  = 68;

pub const RTM_NEWADDRLABEL: i32  = 72;
pub const RTM_DELADDRLABEL: i32  = 73;
pub const RTM_GETADDRLABEL: i32  = 74;

pub const RTM_GETDCB: i32  = 78;
pub const RTM_SETDCB: i32  = 79;

pub const RTM_NEWNETCONF: i32  = 80;
pub const RTM_GETNETCONF: i32  = 82;

pub const RTM_NEWMDB: i32  = 84;
pub const RTM_DELMDB: i32  = 85;
pub const RTM_GETMDB: i32  = 86;

pub const RTM_NEWNSID: i32  = 88;
pub const RTM_DELNSID: i32  = 89;
pub const RTM_GETNSID: i32  = 90;

pub const RTM_NEWSTATS: i32  = 92;
pub const RTM_GETSTATS: i32  = 94;

pub const __RTM_MAX: i32 = 95;

pub const RTM_MAX: i32 = (((__RTM_MAX + 3) & !3) - 1);


pub const RTM_NR_MSGTYPES: i32 = RTM_MAX + 1 - RTM_BASE;
pub const RTM_NR_FAMILIES: i32 = RTM_NR_MSGTYPES >> 2;
// #define RTM_FAM(cmd) (((cmd) - RTM_BASE) >> 2)

// Generic structure for encapsulation of optional route information.
// It is reminiscent of sockaddr, but with sa_family replaced
// with attribute type.

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}


// Definitions used in routing table administration.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtmsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,    // Routing table id
    pub rtm_protocol: u8, // Routing protocol; see below
    pub rtm_scope: u8,    // See below
    pub rtm_type: u8,     // See below
    pub rtm_flags: u32,
}

// rtm_type
pub const RTN_UNSPEC: u8      =  0; // Gateway or direct route
pub const RTN_UNICAST: u8     =  1; // Gateway or direct route
pub const RTN_LOCAL: u8       =  2; // Accept locally
pub const RTN_BROADCAST: u8   =  3; // Accept locally as broadcast, send as broadcast
pub const RTN_ANYCAST: u8     =  4; // Accept locally as broadcast, but send as unicast
pub const RTN_MULTICAST: u8   =  5; // Multicast route
pub const RTN_BLACKHOLE: u8   =  6; // Drop
pub const RTN_UNREACHABLE: u8 =  7; // Destination is unreachable
pub const RTN_PROHIBIT: u8    =  8; // Administratively prohibited
pub const RTN_THROW: u8       =  9; // Not in this table
pub const RTN_NAT: u8         = 10; // Translate this address
pub const RTN_XRESOLVE: u8    = 11; // Use external resolver
pub const __RTN_MAX: u8       = 12;
pub const RTN_MAX: u8 = __RTN_MAX - 1;

// rtm_protocol
pub const RTPROT_UNSPEC: u8   =  0;
pub const RTPROT_REDIRECT: u8 =  1; // Route installed by ICMP redirects; not used by current IPv4
pub const RTPROT_KERNEL: u8   =  2; // Route installed by kernel
pub const RTPROT_BOOT: u8     =  3; // Route installed during boot
pub const RTPROT_STATIC: u8   =  4; // Route installed by administrator
// Values of protocol >= RTPROT_STATIC are not interpreted by kernel;
// they are just passed from user and back as is.
// It will be used by hypothetical multiple routing daemons.
// Note that protocol values should be standardized in order to
// avoid conflicts.
pub const RTPROT_GATED: u8    =  8; // Apparently, GateD
pub const RTPROT_RA: u8       =  9; // RDISC/ND router advertisements
pub const RTPROT_MRT: u8      = 10; // Merit MRT
pub const RTPROT_ZEBRA: u8    = 11; // Zebra
pub const RTPROT_BIRD: u8     = 12; // BIRD
pub const RTPROT_DNROUTED: u8 = 13; // DECnet routing daemon
pub const RTPROT_XORP: u8     = 14; // XORP
pub const RTPROT_NTK: u8      = 15; // Netsukuku
pub const RTPROT_DHCP: u8     = 16; // DHCP client
pub const RTPROT_MROUTED: u8  = 17; // Multicast daemon
pub const RTPROT_BABEL: u8    = 42; // Babel daemon

// rtm_scope
// 
// Really it is not scope, but sort of distance to the destination.
// NOWHERE are reserved for not existing destinations, HOST is our
// local addresses, LINK are destinations, located on directly attached
// link and UNIVERSE is everywhere in the Universe.
// 
// Intermediate values are also possible f.e. interior routes
// could be assigned a value between UNIVERSE and LINK.
pub type rt_scope_t = u8;
pub const RT_SCOPE_UNIVERSE: u8 =   0;
// User defined values
pub const RT_SCOPE_SITE: u8     = 200;
pub const RT_SCOPE_LINK: u8     = 253;
pub const RT_SCOPE_HOST: u8     = 254;
pub const RT_SCOPE_NOWHERE: u8  = 255;

// rtm_flags
pub const RTM_F_NOTIFY: u32       = 0x100;  // Notify user of route change
pub const RTM_F_CLONED: u32       = 0x200;  // This route is cloned
pub const RTM_F_EQUALIZE: u32     = 0x400;  // Multipath equalizer: NI
pub const RTM_F_PREFIX: u32       = 0x800;  // Prefix addresses
pub const RTM_F_LOOKUP_TABLE: u32 = 0x1000; // set rtm_table to FIB lookup result

// Reserved table identifiers
// enum rt_class_t
pub const RT_TABLE_UNSPEC: u32  =   0;
// User defined values
pub const RT_TABLE_COMPAT: u32  = 252;
pub const RT_TABLE_DEFAULT: u32 = 253;
pub const RT_TABLE_MAIN: u32    = 254;
pub const RT_TABLE_LOCAL: u32   = 255;
pub const RT_TABLE_MAX: u32     = 0xFFFFFFFF;


// Routing message attributes
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum rtattr_type_t {
    RTA_UNSPEC = 0,
    RTA_DST,
    RTA_SRC,
    RTA_IIF,
    RTA_OIF,
    RTA_GATEWAY,
    RTA_PRIORITY,
    RTA_PREFSRC,
    RTA_METRICS,
    RTA_MULTIPATH,
    RTA_PROTOINFO, // no longer used
    RTA_FLOW,
    RTA_CACHEINFO,
    RTA_SESSION,   // no longer used
    RTA_MP_ALGO,   // no longer used
    RTA_TABLE,
    RTA_MARK,
    RTA_MFC_STATS,
    RTA_VIA,
    RTA_NEWDST,
    RTA_PREF,
    RTA_ENCAP_TYPE,
    RTA_ENCAP,
    RTA_EXPIRES,
    RTA_PAD,
    __RTA_MAX,
}
pub use self::rtattr_type_t::*;
pub const RTA_MAX: i32 = __RTA_MAX as i32 - 1;

// RTM_MULTIPATH --- array of struct rtnexthop.
// 
// "struct rtnexthop" describes all necessary nexthop information,
// i.e. parameters of path to a destination via this nexthop.
// 
// At the moment it is impossible to set different prefsrc, mtu, window
// and rtt for different paths from multipath.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtnexthop {
    pub rtnh_len: u16,
    pub rtnh_flags: u8,
    pub rtnh_hops: u8,
    pub rtnh_ifindex: i32,
}

// rtnh_flags
pub const RTNH_F_DEAD: u8       =  1; // Nexthop is dead (used by multipath)
pub const RTNH_F_PERVASIVE: u8  =  2; // Do recursive gateway lookup
pub const RTNH_F_ONLINK: u8     =  4; // Gateway is forced on link
pub const RTNH_F_OFFLOAD: u8    =  8; // offloaded route
pub const RTNH_F_LINKDOWN: u8   = 16; // carrier-down on nexthop
pub const RTNH_COMPARE_MASK: u8 = RTNH_F_DEAD | RTNH_F_LINKDOWN | RTNH_F_OFFLOAD;

// RTA_VIA
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtvia {
    // __kernel_sa_family_t
    pub rtvia_family: u16,
    pub rtvia_addr: [u8; 0],
}

// RTM_CACHEINFO
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rta_cacheinfo {
    pub rta_clntref: u32,
    pub rta_lastuse: u32,
    pub rta_expires: u32,
    pub rta_error: u32,
    pub rta_used: u32,
    pub rta_id: u32,
    pub rta_ts: u32,
    pub rta_tsage: u32,
}

pub const RTNETLINK_HAVE_PEERINFO: i32 = 1;


// RTM_METRICS --- array of struct rtattr with types of RTAX_*
pub const RTAX_UNSPEC: i32     = 0;
pub const RTAX_LOCK: i32       = 1;
pub const RTAX_MTU: i32        = 2;
pub const RTAX_WINDOW: i32     = 3;
pub const RTAX_RTT: i32        = 4;
pub const RTAX_RTTVAR: i32     = 5;
pub const RTAX_SSTHRESH: i32   = 6;
pub const RTAX_CWND: i32       = 7;
pub const RTAX_ADVMSS: i32     = 8;
pub const RTAX_REORDERING: i32 = 9;
pub const RTAX_HOPLIMIT: i32   = 10;
pub const RTAX_INITCWND: i32   = 11;
pub const RTAX_FEATURES: i32   = 12;
pub const RTAX_RTO_MIN: i32    = 13;
pub const RTAX_INITRWND: i32   = 14;
pub const RTAX_QUICKACK: i32   = 15;
pub const RTAX_CC_ALGO: i32    = 16;
pub const __RTAX_MAX: i32      = 17;
pub const RTAX_MAX: i32 = __RTAX_MAX - 1;

pub const RTAX_FEATURE_ECN: i32       = 1 << 0;
pub const RTAX_FEATURE_SACK: i32      = 1 << 1;
pub const RTAX_FEATURE_TIMESTAMP: i32 = 1 << 2;
pub const RTAX_FEATURE_ALLFRAG: i32   = 1 << 3;
pub const RTAX_FEATURE_MASK: i32      = RTAX_FEATURE_ECN 
                                        | RTAX_FEATURE_SACK
                                        | RTAX_FEATURE_TIMESTAMP
                                        | RTAX_FEATURE_ALLFRAG;


#[repr(C)]
#[derive(Clone, Copy)]
pub struct rta_session {
    pub proto: u8,
    pub pad1: u8,
    pub pad2: u8,
    pub u: rta_session_u,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union rta_session_u {
    pub ports: rta_session_u_ports,
    pub icmpt: rta_session_u_icmpt,
    pub spi  : u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rta_session_u_ports {
    pub sport: u16,
    pub dport: u16,

}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rta_session_u_icmpt {
    // type
    pub kind: u8,
    pub code: u8,
    pub ident: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rta_mfc_stats {
    pub mfcs_packets: u64,
    pub mfcs_bytes: u64,
    pub mfcs_wrong_if: u64,
}

// General form of address family dependent message.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rtgenmsg {
    pub rtgen_family: u8,
}

// Link layer specific messages.

// struct ifinfomsg
// passes link level specific information, not dependent
// on network protocol.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ifinfomsg {
    pub ifi_family: u8,
    pub __ifi_pad: u8,
    pub ifi_type: u16,   // ARPHRD_*
    pub ifi_index: i32,  // Link index
    pub ifi_flags: u32,  // IFF_* flags
    pub ifi_change: u32, // IFF_* change mask
}

// prefix information
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct prefixmsg {
    pub prefix_family: u8,
    pub prefix_pad1: u8,
    pub prefix_pad2: u16,
    pub prefix_ifindex: i32,
    pub prefix_type: u8,
    pub prefix_len: u8,
    pub prefix_flags: u8,
    pub prefix_pad3: u8,
}

// prefix_flags ?
pub const PREFIX_UNSPEC: i32    = 0;
pub const PREFIX_ADDRESS: i32   = 1;
pub const PREFIX_CACHEINFO: i32 = 2;
pub const __PREFIX_MAX: i32     = 3;
pub const PREFIX_MAX: i32       = __PREFIX_MAX - 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct prefix_cacheinfo {
    pub preferred_time: u32,
    pub valid_time: u32,
}

// Traffic control messages.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tcmsg {
    pub tcm_family: u8,
    pub tcm_pad1: u8,
    pub tcm_pad2: u8,
    pub tcm_ifindex: i32,
    pub tcm_handle: u32,
    pub tcm_parent: u32,
    pub tcm_info: u32,
}

pub const TCA_UNSPEC: i32  =  0;
pub const TCA_KIND: i32    =  1;
pub const TCA_OPTIONS: i32 =  2;
pub const TCA_STATS: i32   =  3;
pub const TCA_XSTATS: i32  =  4;
pub const TCA_RATE: i32    =  5;
pub const TCA_FCNT: i32    =  6;
pub const TCA_STATS2: i32  =  7;
pub const TCA_STAB: i32    =  8;
pub const TCA_PAD: i32     =  9;
pub const __TCA_MAX: i32   = 10;
pub const TCA_MAX: i32       = __TCA_MAX - 1;


// Neighbor Discovery userland options
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nduseroptmsg {
    pub nduseropt_family: u8,
    pub nduseropt_pad1: u8,
    pub nduseropt_opts_len: u16,  // Total length of options
    pub nduseropt_ifindex: i32,
    pub nduseropt_icmp_type: u8,
    pub nduseropt_icmp_code: u8,
    pub nduseropt_pad2: u16,
    pub nduseropt_pad3: u32,
    // Followed by one or more ND options
}

pub const NDUSEROPT_UNSPEC: i32  = 0;
pub const NDUSEROPT_SRCADDR: i32 = 1;
pub const __NDUSEROPT_MAX: i32   = 2;
pub const NDUSEROPT_MAX: i32     = __NDUSEROPT_MAX - 1;

// RTnetlink multicast groups - backwards compatibility for userspace
pub const RTMGRP_LINK: i32          = 1;
pub const RTMGRP_NOTIFY: i32        = 2;
pub const RTMGRP_NEIGH: i32         = 4;
pub const RTMGRP_TC: i32            = 8;

pub const RTMGRP_IPV4_IFADDR: i32   = 0x10;
pub const RTMGRP_IPV4_MROUTE: i32   = 0x20;
pub const RTMGRP_IPV4_ROUTE: i32    = 0x40;
pub const RTMGRP_IPV4_RULE: i32     = 0x80;

pub const RTMGRP_IPV6_IFADDR: i32   = 0x100;
pub const RTMGRP_IPV6_MROUTE: i32   = 0x200;
pub const RTMGRP_IPV6_ROUTE: i32    = 0x400;
pub const RTMGRP_IPV6_IFINFO: i32   = 0x800;

pub const RTMGRP_DECnet_IFADDR: i32 = 0x1000;
pub const RTMGRP_DECnet_ROUTE: i32  = 0x4000;
pub const RTMGRP_IPV6_PREFIX: i32   = 0x20000;


// RTnetlink multicast groups
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum rtnetlink_groups {
    RTNLGRP_NONE = 0,
    RTNLGRP_LINK,
    RTNLGRP_NOTIFY,
    RTNLGRP_NEIGH,
    RTNLGRP_TC,
    RTNLGRP_IPV4_IFADDR,
    RTNLGRP_IPV4_MROUTE,
    RTNLGRP_IPV4_ROUTE,
    RTNLGRP_IPV4_RULE,
    RTNLGRP_IPV6_IFADDR,
    RTNLGRP_IPV6_MROUTE,
    RTNLGRP_IPV6_ROUTE,
    RTNLGRP_IPV6_IFINFO,
    RTNLGRP_DECnet_IFADDR,
    RTNLGRP_NOP2,
    RTNLGRP_DECnet_ROUTE,
    RTNLGRP_DECnet_RULE,
    RTNLGRP_NOP4,
    RTNLGRP_IPV6_PREFIX,
    RTNLGRP_IPV6_RULE,
    RTNLGRP_ND_USEROPT,
    RTNLGRP_PHONET_IFADDR,
    RTNLGRP_PHONET_ROUTE,
    RTNLGRP_DCB,
    RTNLGRP_IPV4_NETCONF,
    RTNLGRP_IPV6_NETCONF,
    RTNLGRP_MDB,
    RTNLGRP_MPLS_ROUTE,
    RTNLGRP_NSID,
    __RTNLGRP_MAX,
}
pub use self::rtnetlink_groups::*;
pub const RTNLGRP_MAX: i32 = __RTNLGRP_MAX as i32 - 1;

// TC action piece
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct tcamsg {
    pub tca_family: u8,
    pub tca_pad1: u8,
    pub tca_pad2: u16,
}

pub const TCA_ACT_TAB: i32 = 1; // attr type must be >=1
pub const TCAA_MAX: i32    = 1;

// New extended info filters for IFLA_EXT_MASK
pub const RTEXT_FILTER_VF: i32                = 1 << 0;
pub const RTEXT_FILTER_BRVLAN: i32            = 1 << 1;
pub const RTEXT_FILTER_BRVLAN_COMPRESSED: i32 = 1 << 2;
pub const RTEXT_FILTER_SKIP_STATS: i32        = 1 << 3;


#[repr(C)]
#[allow(non_snake_case)]
#[derive(Copy, Clone)]
pub union nlmsgbody {
    pub a1: u64,
}


// rtmsg
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RouteMessage {
    pub hdr: nlmsghdr,
    pub family: u8,
    pub src_len: u8,
    pub dst_len: u8,
    pub tos: u8,
    pub table_id: u8,
    pub protocol: u8,
    pub scope: u8,
    // Type
    pub kind: u8,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NeighMessage {
    pub hdr: nlmsghdr,
    pub family: u8,
    pub reserved1: u8,
    pub reserved2: u16,
    pub ifindex: u32,
    pub state: u16,
    pub flags: u8,
    pub kind: u8,
}


/// supported protocols
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum NetlinkProtocol {
    Route = 0,
    Unused = 1,
    Usersock = 2,
    Firewall = 3,
    InetDiag = 4,
    NFlog = 5,
    Xfrm = 6,
    SELinux = 7,
    ISCSI = 8,
    Audit = 9,
    FibLookup = 10,
    Connector = 11,
    Netfilter = 12,
    IP6Fw = 13,
    Dnrtmsg = 14,
    KObjectUevent = 15,
    Generic = 16,
    SCSItransport = 18,
    Ecryptfs = 19,
    Rdma = 20,
    Crypto = 21,
}

pub const AF_NETLINK: u8 = 16;
pub const AF_ROUTE: u8 = AF_NETLINK;

/// Handle for the socket file descriptor
pub struct NlSocket {
    fd: libc::c_int,
    pid: Option<u32>,
    seq: Option<u32>,
}

impl NlSocket {
    /// Wrapper around `socket()` syscall filling in the netlink-specific information
    pub fn new(proto: i32, track_seq: bool) -> Result<Self, io::Error> {
        let fd = unsafe { libc::socket(AF_NETLINK as i32, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(NlSocket { fd, pid: None, seq: if track_seq { Some(0) } else { None }, })
    }

    /// Manually increment sequence number
    pub fn increment_seq(&mut self) {
        self.seq.map(|seq| seq + 1);
    }

    /// Set underlying socket file descriptor to be blocking
    pub fn block(&mut self) -> Result<&mut Self, io::Error> {
        let ret = unsafe {
            let flags = libc::fcntl(self.fd, libc::F_GETFL, 0) & !libc::O_NONBLOCK;
            libc::fcntl(self.fd, libc::F_SETFL, flags)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(self)
    }

    /// Set underlying socket file descriptor to be non blocking
    pub fn nonblock(&mut self) -> Result<&mut Self, io::Error> {
        let ret = unsafe {
            let flags = libc::fcntl(self.fd, libc::F_GETFL, 0) | libc::O_NONBLOCK;
            libc::fcntl(self.fd, libc::F_SETFL, flags)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(self)
    }

    /// Determines if underlying file descriptor is blocking - `Stream` feature will throw an
    /// error if this function returns false
    pub fn is_blocking(&self) -> Result<bool, io::Error> {
        let ret = unsafe { libc::fcntl(self.fd, libc::F_GETFL, 0) };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        
        Ok(ret & libc::O_NONBLOCK == 0)
    }

    /// Set multicast groups for socket
    pub fn set_mcast_groups(&mut self, groups: Vec<u32>) -> Result<(), io::Error> {
        let grps = groups.into_iter().fold(0, |acc, next| { acc | (1 << (next - 1)) });
        let ret = unsafe {
            libc::setsockopt(self.fd,
                             SOL_NETLINK,
                             NETLINK_ADD_MEMBERSHIP,
                             &grps as *const _ as *const libc::c_void,
                             std::mem::size_of::<u32>() as libc::socklen_t)
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        self.pid = None;

        Ok(())
    }

    /// Use this function to bind to a netlink ID and subscribe to groups. See netlink(7)
    /// man pages for more information on netlink IDs and groups.
    pub fn bind(&mut self, pid: Option<u32>, groups: Option<Vec<u32>>) -> Result<(), io::Error> {
        let mut nladdr = unsafe { std::mem::zeroed::<sockaddr_nl>() };
        nladdr.nl_family = AF_NETLINK as u16;
        nladdr.nl_pid = pid.unwrap_or(0);
        
        self.pid = pid;

        nladdr.nl_groups = 0;

        let ret = unsafe {
            libc::bind(self.fd,
                       &nladdr as *const _ as *const libc::sockaddr,
                       std::mem::size_of::<sockaddr_nl>() as u32)
        };

        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        if let Some(grps) = groups {
            self.set_mcast_groups(grps)?;
        }
        Ok(())
    }

    /// Equivalent of `socket` and `bind` calls.
    pub fn connect(proto: i32, pid: Option<u32>, groups: Option<Vec<u32>>, track_seq: bool)
                   -> Result<Self, io::Error> {
        let mut s = NlSocket::new(proto, track_seq)?;
        s.bind(pid, groups)?;
        Ok(s)
    }

    pub fn send<B: AsRef<[u8]>>(&mut self, buf: B, flags: i32) -> Result<usize, io::Error> {
        let amt = unsafe {
            libc::send(self.fd,
                       buf.as_ref() as *const _ as *const libc::c_void,
                       buf.as_ref().len(),
                       flags)
        };
        if amt < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amt as usize)
    }

    /// Receive message encoded as byte slice from the netlink socket
    pub fn recv<B: AsMut<[u8]>>(&mut self, mut buf: B, flags: i32) -> Result<usize, io::Error> {
        let amt = unsafe {
            libc::recv(self.fd,
                       buf.as_mut() as *mut _ as *mut libc::c_void,
                       buf.as_mut().len(),
                       flags)
        };

        if amt < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(amt as usize)
    }
}


impl AsRawFd for NlSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl IntoRawFd for NlSocket {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

impl Read for NlSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv(buf, 0)
    }
}

impl Write for NlSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send(buf, 0)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
