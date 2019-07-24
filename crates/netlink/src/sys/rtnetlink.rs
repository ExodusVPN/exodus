

// rtnetlink families. Values up to 127 are reserved for real address
// families, values above 128 may be used arbitrarily.
pub const RTNL_FAMILY_IPMR: i32  = 128;
pub const RTNL_FAMILY_IP6MR: i32 = 129;
pub const RTNL_FAMILY_MAX: i32   = 129;

// Routing/neighbour discovery messages.

// Types of messages
pub const RTM_BASE: u16    = 16;
pub const RTM_NEWLINK: u16 = 16;
pub const RTM_DELLINK: u16 = 17;
pub const RTM_GETLINK: u16 = 18;
pub const RTM_SETLINK: u16 = 19;

pub const RTM_NEWADDR: u16 = 20;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_GETADDR: u16 = 22;

pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

// ARP
pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;

pub const RTM_NEWRULE: u16  = 32;
pub const RTM_DELRULE: u16  = 33;
pub const RTM_GETRULE: u16  = 34;

pub const RTM_NEWQDISC: u16  = 36;
pub const RTM_DELQDISC: u16  = 37;
pub const RTM_GETQDISC: u16  = 38;

pub const RTM_NEWTCLASS: u16  = 40;
pub const RTM_DELTCLASS: u16  = 41;
pub const RTM_GETTCLASS: u16  = 42;

pub const RTM_NEWTFILTER: u16  = 44;
pub const RTM_DELTFILTER: u16  = 45;
pub const RTM_GETTFILTER: u16  = 46;

pub const RTM_NEWACTION: u16  = 48;
pub const RTM_DELACTION: u16  = 49;
pub const RTM_GETACTION: u16  = 50;

pub const RTM_NEWPREFIX: u16    = 52;
pub const RTM_GETMULTICAST: u16 = 58;
pub const RTM_GETANYCAST: u16   = 62;

// ARP
pub const RTM_NEWNEIGHTBL: u16  = 64;
pub const RTM_GETNEIGHTBL: u16  = 66;
pub const RTM_SETNEIGHTBL: u16  = 67;

pub const RTM_NEWNDUSEROPT: u16  = 68;

pub const RTM_NEWADDRLABEL: u16  = 72;
pub const RTM_DELADDRLABEL: u16  = 73;
pub const RTM_GETADDRLABEL: u16  = 74;

pub const RTM_GETDCB: u16  = 78;
pub const RTM_SETDCB: u16  = 79;

pub const RTM_NEWNETCONF: u16  = 80;
pub const RTM_GETNETCONF: u16  = 82;

pub const RTM_NEWMDB: u16  = 84;
pub const RTM_DELMDB: u16  = 85;
pub const RTM_GETMDB: u16  = 86;

pub const RTM_NEWNSID: u16  = 88;
pub const RTM_DELNSID: u16  = 89;
pub const RTM_GETNSID: u16  = 90;

pub const RTM_NEWSTATS: u16  = 92;
pub const RTM_GETSTATS: u16  = 94;

pub const __RTM_MAX: u16 = 95;
pub const RTM_MAX: u16   = ((__RTM_MAX + 3) & !3) - 1;

pub const RTM_NR_MSGTYPES: u16 = RTM_MAX + 1 - RTM_BASE;
pub const RTM_NR_FAMILIES: u16 = RTM_NR_MSGTYPES >> 2;
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

pub const RTA_ALIGNTO: usize = 4;



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

impl Default for rtmsg {
    fn default() -> Self {
        Self {
            rtm_family: 0,
            rtm_dst_len: 0,
            rtm_src_len: 0,
            rtm_tos: 0,
            rtm_table: 0,
            rtm_protocol: 0,
            rtm_scope: 0,
            rtm_type: 0,
            rtm_flags: 0,
        }
    }
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
pub const RTN_MAX: u8         = __RTN_MAX - 1;

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
    // /usr/include/linux/socket.h:
    // typedef unsigned short __kernel_sa_family_t;
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
pub const RTAX_MAX: i32        = __RTAX_MAX - 1;

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
    pub pad1 : u8,
    pub pad2 : u8,
    pub u    : rta_session_u,
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
    pub kind : u8,  // type
    pub code : u8,
    pub ident: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct rta_mfc_stats {
    pub mfcs_packets : u64,
    pub mfcs_bytes   : u64,
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
    pub ifi_pad: u8,
    pub ifi_type: u16,   // ARPHRD_*
    pub ifi_index: i32,  // Link index
    pub ifi_flags: u32,  // IFF_* flags
    pub ifi_change: u32, // IFF_* change mask
}

impl Default for ifinfomsg {
    fn default() -> Self {
        Self {
            ifi_family: 0,
            ifi_pad: 0,
            ifi_type: 0,
            ifi_index: 0,
            ifi_flags: 0,
            ifi_change: 0,
        }
    }
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
pub const TCA_MAX: i32     = __TCA_MAX - 1;


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


