
// https://tools.ietf.org/html/rfc3549#section-2.2
// Message Format
// There are three levels to a Netlink message: The general Netlink
// message header, the IP service specific template, and the IP service
// specific data.
// 
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                   Netlink message header                      |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                  IP Service Template                          |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                  IP Service specific data in TLVs             |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 
// The Netlink message is used to communicate between the FEC and CPC
// for parameterization of the FECs, asynchronous event notification of
// FEC events to the CPCs, and statistics querying/gathering (typically
// by a CPC).
// 
// The Netlink message header is generic for all services, whereas the
// IP Service Template header is specific to a service.  Each IP Service
// then carries parameterization data (CPC->FEC direction) or response
// (FEC->CPC direction).  These parameterizations are in TLV (Type-
// Length-Value) format and are unique to the service.
// 
// The different parts of the netlink message are discussed in the
// following sections.


// netlink_family
// Netlink Protocols (Subsystem)
pub const NETLINK_ROUTE: i32          =  0; // Routing/device hook
pub const NETLINK_UNUSED: i32         =  1; // Unused number
pub const NETLINK_USERSOCK: i32       =  2; // Reserved for user mode socket protocols
pub const NETLINK_FIREWALL: i32       =  3; // Unused number, formerly ip_queue
pub const NETLINK_SOCK_DIAG: i32      =  4; // socket monitoring
pub const NETLINK_NFLOG: i32          =  5; // netfilter/iptables ULOG
pub const NETLINK_XFRM: i32           =  6; // ipsec
pub const NETLINK_SELINUX: i32        =  7; // SELinux event notifications
pub const NETLINK_ISCSI: i32          =  8; // Open-iSCSI
pub const NETLINK_AUDIT: i32          =  9; // auditing
pub const NETLINK_FIB_LOOKUP: i32     = 10;  
pub const NETLINK_CONNECTOR: i32      = 11;
pub const NETLINK_NETFILTER: i32      = 12; // netfilter subsystem
pub const NETLINK_IP6_FW: i32         = 13;
pub const NETLINK_DNRTMSG: i32        = 14; // DECnet routing messages
pub const NETLINK_KOBJECT_UEVENT: i32 = 15; // Kernel messages to userspace
pub const NETLINK_GENERIC: i32        = 16;
// leave room for NETLINK_DM (DM Events)
pub const NETLINK_SCSITRANSPORT: i32  = 18; // SCSI Transports
pub const NETLINK_ECRYPTFS: i32       = 19;
pub const NETLINK_RDMA: i32           = 20;
pub const NETLINK_CRYPTO: i32         = 21; // Crypto layer

pub const NETLINK_INET_DIAG: i32      = NETLINK_SOCK_DIAG;

pub const MAX_LINKS: i32              = 32;

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
#[repr(C)]
// #[repr(align(4))]
#[derive(Debug, Clone, Copy)]
pub struct nlmsghdr {
    // Length of message including header
    pub nlmsg_len: u32,
    // Type of message content: RTM_GETNEIGH, ...
    pub nlmsg_type: u16,
    // Additional flags: NLM_F_DUMP, NLM_F_REQUEST, ...
    pub nlmsg_flags: u16,
    // Sequence number
    pub nlmsg_seq: u32,
    // Sending process port ID
    pub nlmsg_pid: u32,
}

impl nlmsghdr {
    pub fn size(&self) -> usize {
        align(self.nlmsg_len as usize)
    }

    pub fn payload_len(&self) -> usize {
        self.size() - std::mem::size_of::<Self>()
    }

    pub fn as_ptr(&self) -> *const Self {
        self
    }

    pub fn as_mut_ptr(&mut self) -> *mut Self {
        self
    }

    pub fn as_bytes(&self) -> &[u8] {
        let ptr = self.as_ptr() as *const u8;
        let len = std::mem::size_of::<Self>();

        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        let ptr = self.as_mut_ptr() as *mut u8;
        let len = std::mem::size_of::<Self>();

        unsafe { std::slice::from_raw_parts_mut(ptr, len) }
    }
}

impl Default for nlmsghdr {
    fn default() -> Self {
        Self {
            nlmsg_len: std::mem::size_of::<Self>() as u32,
            nlmsg_type: 0,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        }
    }
}


// Flags values
pub const NLM_F_REQUEST: u16       =  1; // It is request message.
pub const NLM_F_MULTI: u16         =  2; // Multipart message, terminated by 
pub const NLM_F_ACK: u16           =  4; // Reply with ack, with zero or error 
pub const NLM_F_ECHO: u16          =  8; // Echo this request
pub const NLM_F_DUMP_INTR: u16     = 16; // Dump was inconsistent due to sequence 
pub const NLM_F_DUMP_FILTERED: u16 = 32; // Dump was filtered as 
// Modifiers to GET request
pub const NLM_F_ROOT: u16   = 0x100;                    // specify tree root
pub const NLM_F_MATCH: u16  = 0x200;                    // return all matching
pub const NLM_F_ATOMIC: u16 = 0x400;                    // atomic GET
pub const NLM_F_DUMP: u16   = NLM_F_ROOT | NLM_F_MATCH;
// Modifiers to NEW request
pub const NLM_F_REPLACE: u16 = 0x100;   // Override existing
pub const NLM_F_EXCL: u16    = 0x200;   // Do not touch, if it exists
pub const NLM_F_CREATE: u16  = 0x400;   // Create, if it does not 
pub const NLM_F_APPEND: u16  = 0x800;   // Add to end of list

// 4.4BSD ADD       NLM_F_CREATE|NLM_F_EXCL
// 4.4BSD CHANGE    NLM_F_REPLACE
// 
// True CHANGE      NLM_F_CREATE|NLM_F_REPLACE
// Append       NLM_F_CREATE
// Check        NLM_F_EXCL


// Types
// 1 .. 16 被用作 Response 数据包
pub const NLMSG_NOOP: u16    = 0x1; // Nothing
pub const NLMSG_ERROR: u16   = 0x2; // Error
pub const NLMSG_DONE: u16    = 0x3; // End of a dump
pub const NLMSG_OVERRUN: u16 = 0x4; // Data lost

pub const NLMSG_MIN_TYPE: u16 = 0x10; // < 0x10: reserved control messages


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

pub const NETLINK_UNCONNECTED: i32     = 0;
pub const NETLINK_CONNECTED: i32       = 1;


// <------- NLA_HDRLEN ------> <-- NLA_ALIGN(payload)-->
// +---------------------+- - -+- - - - - - - - - -+- - -+
// |        Header       | Pad |     Payload       | Pad |
// |   (struct nlattr)   | ing |                   | ing |
// +---------------------+- - -+- - - - - - - - - -+- - -+
// <-------------- nlattr->nla_len -------------->
#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
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
pub const NLA_ALIGNTO: usize       = 4;

#[inline]
pub const fn align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}