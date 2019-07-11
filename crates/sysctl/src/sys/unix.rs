use crate::Value;

use libc;

use std::io;
use std::ptr;
use std::fmt;
use std::str::FromStr;
use std::ffi::{CStr, CString};


// largest number of components supported
#[cfg(target_os = "freebsd")]
pub const CTL_MAXNAME: usize = 24;
#[cfg(target_os = "macos")]
pub const CTL_MAXNAME: usize = 12;

// Types
pub const CTLTYPE: libc::c_uint = 0xf; // Mask for the type
pub const CTLTYPE_NODE: libc::c_uint = 1; // name is a node
pub const CTLTYPE_INT: libc::c_uint = 2; // name describes an integer
pub const CTLTYPE_STRING: libc::c_uint = 3; // name describes a string
pub const CTLTYPE_QUAD: libc::c_uint = 4; // name describes a 64-bit number
pub const CTLTYPE_OPAQUE: libc::c_uint = 5; // name describes a structure
pub const CTLTYPE_STRUCT: libc::c_uint = CTLTYPE_OPAQUE; // name describes a structure
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_UINT: libc::c_uint = 6; // name describes an unsigned integer
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_LONG: libc::c_uint = 7; // name describes a long
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_ULONG: libc::c_uint = 8; // name describes an unsigned long
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_U64: libc::c_uint = 9; // name describes an unsigned 64-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_U8: libc::c_uint = 0xa; // name describes an unsigned 8-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_U16: libc::c_uint = 0xb; // name describes an unsigned 16-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_S8: libc::c_uint = 0xc; // name describes a signed 8-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_S16: libc::c_uint = 0xd; // name describes a signed 16-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_S32: libc::c_uint = 0xe; // name describes a signed 32-bit number
#[cfg(target_os = "freebsd")]
pub const CTLTYPE_U32: libc::c_uint = 0xf; // name describes an unsigned 32-bit number

// Flags
pub const CTLFLAG_RD: libc::c_uint = 0x80000000; // Allow reads of variable
pub const CTLFLAG_WR: libc::c_uint = 0x40000000; // Allow writes to the variable
pub const CTLFLAG_RW: libc::c_uint = CTLFLAG_RD | CTLFLAG_WR;
#[cfg(target_os = "macos")]
pub const CTLFLAG_LOCKED: libc::c_uint = 0x00800000; // node will handle locking itself
#[cfg(target_os = "macos")]
pub const CTLFLAG_OID2: libc::c_uint = 0x00400000; // struct sysctl_oid has version info

#[cfg(target_os = "macos")]
pub const CTLFLAG_NOLOCK: libc::c_uint = 0x20000000; // XXX Don't Lock
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_DORMANT: libc::c_uint = 0x20000000; // This sysctl is not active yet

pub const CTLFLAG_ANYBODY: libc::c_uint = 0x10000000; // All users can set this var
pub const CTLFLAG_SECURE: libc::c_uint = 0x08000000; // Permit set only if securelevel<=0
#[cfg(target_os = "macos")]
pub const CTLFLAG_MASKED: libc::c_uint = 0x04000000; // deprecated variable, do not display
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_PRISON: libc::c_uint = 0x04000000; // Prisoned roots can fiddle

#[cfg(target_os = "macos")]
pub const CTLFLAG_NOAUTO: libc::c_uint = 0x02000000; // do not auto-register
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_DYN: libc::c_uint = 0x02000000; // Dynamic oid - can be freed

#[cfg(target_os = "macos")]
pub const CTLFLAG_KERN: libc::c_uint = 0x01000000; // valid inside the kernel
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_SKIP: libc::c_uint = 0x01000000; // Skip this sysctl when listing

#[cfg(target_os = "freebsd")]
pub const CTLMASK_SECURE: libc::c_uint = 0x00F00000; // Secure level
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_TUN: libc::c_uint = 0x00080000; // Default value is loaded from getenv()
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_RDTUN: libc::c_uint = CTLFLAG_RD | CTLFLAG_TUN;
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_RWTUN: libc::c_uint = CTLFLAG_RW | CTLFLAG_TUN;
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_MPSAFE: libc::c_uint = 0x00040000; // Handler is MP safe
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_VNET: libc::c_uint = 0x00020000; // Prisons with vnet can fiddle
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_DYING: libc::c_uint = 0x00010000; // Oid is being removed
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_CAPRD: libc::c_uint = 0x00008000; // Can be read in capability mode
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_CAPWR: libc::c_uint = 0x00004000; // Can be written in capability mode
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_STATS: libc::c_uint = 0x00002000; // Statistics, not a tuneable
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_NOFETCH: libc::c_uint = 0x00001000; // Don't fetch tunable from getenv()
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_CAPRW: libc::c_uint = CTLFLAG_CAPRD | CTLFLAG_CAPWR;
#[cfg(target_os = "freebsd")]
pub const CTLSHIFT_SECURE: libc::c_uint = 20;
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_SECURE1: libc::c_uint = (CTLFLAG_SECURE | (0 << CTLSHIFT_SECURE));
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_SECURE2: libc::c_uint = (CTLFLAG_SECURE | (1 << CTLSHIFT_SECURE));
#[cfg(target_os = "freebsd")]
pub const CTLFLAG_SECURE3: libc::c_uint = (CTLFLAG_SECURE | (2 << CTLSHIFT_SECURE));

pub type Flags = libc::c_uint;

// Top-level identifiers
pub const CTL_UNSPEC: libc::c_int = 0; // unused
pub const CTL_KERN: libc::c_int = 1; // "high kernel": proc, limits
pub const CTL_VM: libc::c_int = 2; // virtual memory
pub const CTL_VFS: libc::c_int = 3; // file system, mount type is next
pub const CTL_NET: libc::c_int = 4; // network, see socket.h
pub const CTL_DEBUG: libc::c_int = 5; // debugging parameters
pub const CTL_HW: libc::c_int = 6; // generic cpu/io
pub const CTL_MACHDEP: libc::c_int = 7; // machine dependent
pub const CTL_USER: libc::c_int = 8; // user-level
#[cfg(target_os = "macos")]
pub const CTL_MAXID: libc::c_int = 9; // number of valid top-level ids
#[cfg(target_os = "freebsd")]
pub const CTL_P1003_1B: libc::c_int = 9; // POSIX 1003.1B


// Copied from /usr/include/sys/time.h
/// Getkerninfo clock information structure
#[repr(C)]
#[derive(Debug)]
pub struct clockinfo {
    pub hz: libc::c_int,      // clock frequency
    pub tick: libc::c_int,    // micro-seconds per hz tick
    pub tickadj: libc::c_int, // clock skew rate for adjtime()
    pub stathz: libc::c_int,  // statistics clock frequency
    pub profhz: libc::c_int,  // profiling clock frequency
}

// Copied from /usr/include/sys/resource.h
// https://github.com/freebsd/freebsd/blob/master/sys/sys/resource.h#L163
#[repr(C)]
#[derive(Debug)]
pub struct loadavg {
    pub ldavg: [u32; 3],
    pub fscale: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct timeval {
    pub sec: libc::time_t,       // i64
    pub usec: libc::suseconds_t, // i32
}

// TODO: Add more struct ...
// https://github.com/freebsd/freebsd/blob/master/sys/sys/vnode.h

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ctlname {
    pub ctl_name: *mut libc::c_char, // subsystem name
    pub ctl_type: libc::c_int,       // type of name
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Node,
    String,
    Struct,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    // WARN: i can not find at here: https://github.com/freebsd/freebsd/blob/master/sys/sys/sysctl.h#L85
    // #[cfg(target_os = "freebsd")]
    // Temperature, // 16
    Unknow(u32),
}

impl Kind {
    #[inline]
    pub fn is_node(&self) -> bool {
        match self {
            Kind::Node => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_string(&self) -> bool {
        match self {
            Kind::String => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_uint(&self) -> bool {
        match self {
            Kind::U8 | Kind::U16 | Kind::U32 | Kind::U64 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_int(&self) -> bool {
        match self {
            Kind::I8 | Kind::I16 | Kind::I32 | Kind::I64 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_struct(&self) -> bool {
        match self {
            Kind::Struct => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_unknow(&self) -> bool {
        match self {
            Kind::Unknow(_) => true,
            _ => false,
        }
    }
}

#[derive(Clone)]
pub struct Metadata {
    flags_kind: u32,
    /// A string which specifies the format of the OID in
    /// a symbolic way.
    ///
    /// This format is used as a hint by sysctl(8) to
    /// apply proper data formatting for display purposes.
    ///
    /// Formats defined in sysctl(9):
    /// * `N`       node
    /// * `A`       char *
    /// * `I`       int
    /// * `IK[n]`   temperature in Kelvin, multiplied by an optional single
    ///    digit power of ten scaling factor: 1 (default) gives deciKelvin,
    ///    0 gives Kelvin, 3 gives milliKelvin
    /// * `IU`      unsigned int
    /// * `L`       long
    /// * `LU`      unsigned long
    /// * `Q`       quad_t
    /// * `QU`      u_quad_t
    /// * `S,TYPE`  struct TYPE structures
    format: String,
}

impl Metadata {
    #[inline]
    pub fn raw_kind(&self) -> libc::c_uint {
        self.flags_kind & CTLTYPE as u32
    }

    #[inline]
    pub fn kind(&self) -> Kind {
        // 'Type' is the first 4 bits of 'Kind'
        match self.raw_kind() {
            CTLTYPE_NODE => Kind::Node,
            CTLTYPE_INT => Kind::I32,
            CTLTYPE_STRING => Kind::String,
            CTLTYPE_QUAD => Kind::I64,
            CTLTYPE_STRUCT => Kind::Struct,

            #[cfg(target_os = "freebsd")]
            CTLTYPE_UINT => Kind::U32,
            
            #[cfg(all(target_os = "freebsd", target_pointer_width = "32"))]
            CTLTYPE_LONG => Kind::I32,
            #[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
            CTLTYPE_LONG => Kind::I64,

            #[cfg(all(target_os = "freebsd", target_pointer_width = "32"))]
            CTLTYPE_ULONG => Kind::U64,
            #[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
            CTLTYPE_ULONG => Kind::U64,

            #[cfg(target_os = "freebsd")]
            CTLTYPE_U64 => Kind::U64,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_U8 => Kind::U8,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_U16 => Kind::U16,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_S8 => Kind::I8,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_S16 => Kind::I16,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_S32 => Kind::I32,
            #[cfg(target_os = "freebsd")]
            CTLTYPE_U32 => Kind::U32,
            n => {
                if self.format.starts_with("S") {
                    return Kind::Struct;
                }

                match self.format.as_ref() {
                    "I" => Kind::I32,
                    "IU" => Kind::U32,
                    "Q" => Kind::I64,
                    "UQ" => Kind::U64,
                    "QU" => Kind::U64,
                    "L" => Kind::I64,
                    "LU" => Kind::U64,
                    "O" => Kind::Struct, // CTLTYPE_OPAQUE ?
                    "A" => Kind::String,
                    "N" => Kind::Node,

                    // "SCSIArchitectureModel" =>
                    // "SCSIMPIOStatistics"    =>
                    // "USBMassStorageDriver"  =>
                    // "USB"         =>
                    // "AHCI"        =>
                    // "AHCIDisk"    =>
                    // "Thunderbolt" =>
                    // "AppleThunderboltIP" =>
                    // "kDisplayVar"        =>
                    // "KernelPrintf"       =>
                    _ => Kind::Unknow(n), // n == 0
                }
            }
        }
    }

    #[inline]
    pub fn flags(&self) -> Flags {
        self.flags_kind
    }

    #[inline]
    pub fn format(&self) -> &str {
        &self.format
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        self.flags() & CTLFLAG_RD == CTLFLAG_RD
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.flags() & CTLFLAG_WR == CTLFLAG_WR
    }

    #[inline]
    pub fn is_node(&self) -> bool {
        self.kind().is_node()
    }

    #[inline]
    pub fn is_string(&self) -> bool {
        self.kind().is_string()
    }

    #[inline]
    pub fn is_uint(&self) -> bool {
        self.kind().is_uint()
    }

    #[inline]
    pub fn is_int(&self) -> bool {
        self.kind().is_int()
    }

    #[inline]
    pub fn is_struct(&self) -> bool {
        self.kind().is_struct()
    }

    #[inline]
    pub fn is_unknow(&self) -> bool {
        self.kind().is_unknow()
    }
}

impl std::fmt::Debug for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Metadata {{ flags: {}, kind: {:?}, format: {:?}, is_readable: {}, is_writable: {} }}",
            self.flags(),
            self.kind(),
            self.format(),
            self.is_readable(),
            self.is_writable(),
        )
    }
}

impl std::fmt::Display for Metadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// [0, 1, ...]  mib2name
// [0, 2, ...]  next_mib
// [0, 3, ...]  name2mib
// [0, 4, ...]  mib2metadata
// [0, 5, ...]  mib2description
const fn gen_req_mib(a: libc::c_int, b: libc::c_int) -> Mib {
    let mut tmp = [0; CTL_MAXNAME];
    tmp[0] = a;
    tmp[1] = b;
    Mib { inner: tmp, len: 2 }
}

const REQ_MIB_TO_NAME: Mib = gen_req_mib(0, 1);
const REQ_GET_NEXT_MIB: Mib = gen_req_mib(0, 2);
// const REQ_NAME_TO_MIB:  Mib = gen_req_mib(0, 3);
const REQ_MIB_TO_METADATA: Mib = gen_req_mib(0, 4);
#[cfg(target_os = "freebsd")]
const REQ_MIB_TO_DESC: Mib = gen_req_mib(0, 5);

/// Get Value By Mib
pub fn get(mib: &Mib) -> Result<Value, io::Error> {
    let mib_ptr = mib.as_ptr() as *mut _;
    let mib_len = mib.len() as _;

    // First get size of value in bytes
    let mut val_len = 0;
    if unsafe {
        libc::sysctl(
            mib_ptr,
            mib_len,
            ptr::null_mut(),
            &mut val_len,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }

    let mut buf: Vec<u8> = vec![0u8; val_len as usize];
    let mut buf_len = val_len;
    let buf_ptr = buf.as_mut_ptr() as *mut _;
    let buf_len_ptr = &mut buf_len as *mut _;

    if unsafe { libc::sysctl(mib_ptr, mib_len, buf_ptr, buf_len_ptr, ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let metadata = mib.metadata()?;
    let value_kind = metadata.kind();
    let value_format = metadata.format;

    if value_kind == Kind::Node {
        return Err(io::Error::new(io::ErrorKind::Other, "Can not get value from a Node."));
    }
    
    let value = match value_kind {
        Kind::Node => unreachable!(),
        Kind::String => {
            let s = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) };
            Value::String(s.to_string_lossy().to_string())
        }
        Kind::Struct => {
            // "-" => { },
            // "I" => { },
            // "O" => { },
            // "Q" => { },
            // "S" => { },
            // "S, if_family_id" => { },
            // "S,BC_command" => { },
            // "S,IPCS_msg_command" => { },
            // "S,IPCS_sem_command" => { },
            // "S,IPCS_shm_command" => { },
            // "S,arpstat" => { },
            // "S,bridge_hostfilter_stats" => { },
            // "S,cfil_filter_stat" => { },
            // "S,cfil_sock_stat" => { },
            // "S,cfil_stats" => { },
            // "S,clockinfo" => { },
            // "S,conninfo_mptcp_t" => { },
            // "S,fsid" => { },
            // "S,hibernate_statistics_t" => { },
            // "S,icmp6stat" => { },
            // "S,icmpstat" => { },
            // "S,igmpstat" => { },
            // "S,igmpstat_v3" => { },
            // "S,in6_defrouter" => { },
            // "S,ip6stat" => { },
            // "S,ip_linklocal_stat" => { },
            // "S,ipsecstat" => { },
            // "S,ipstat" => { },
            // "S,kctlstat" => { },
            // "S,kevtstat" => { },
            // "S,loadavg" => { },
            // "S,mb_stat" => { },
            // "S,mb_top_trace" => { },
            // "S,mbstat" => { },
            // "S,mleak_table" => { },
            // "S,nd6_send_nodecfg" => { },
            // "S,net_api_stats" => { },
            // "S,net_perf" => { },
            // "S,nexus_channel_entry_t" => { },
            // "S,nexus_provider_info_t" => { },
            // "S,nstat_stats" => { },
            // "S,pfkeystat" => { },
            // "S,rip6stat" => { },
            // "S,sk_stats_arena" => { },
            // "S,sk_stats_flow" => { },
            // "S,sk_stats_flow_adv" => { },
            // "S,sk_stats_flow_owner" => { },
            // "S,sk_stats_flow_route" => { },
            // "S,sk_stats_flow_switch" => { },
            // "S,sk_stats_net_if" => { },
            // "S,sk_stats_userstack" => { },
            // "S,soextbkidlestat" => { },
            // "S,tcpstat" => { },
            // "S,timeval" => { },
            // "S,udpstat" => { },
            // "S,uuid_t" => { },
            // "S,vc_progress_user_options" => { },
            // "S,xinpcb" => { },
            // "S,xinpcb64" => { },
            // "S,xinpcb_n" => { },
            // "S,xkctl_reg" => { },
            // "S,xkctlpcb" => { },
            // "S,xkevtpcb" => { },
            // "S,xnpigen" => { },
            // "S,xsw_usage" => { },
            // "S,xtcpcb" => { },
            // "S,xtcpcb64" => { },
            // "S,xtcpcb_n" => { },
            // "S,xunpcb" => { },
            // "S,xunpcb64" => { },
            // "SCSIArchitectureModel" => { },
            // "SCSIMPIOStatistics" => { },
            Value::Struct {
                buffer: buf,
                indication: value_format,
            }
        }
        Kind::I8 => Value::I8(*buf.get(0).unwrap_or(&0) as _),
        Kind::I16 => {
            let n: i16 = unsafe {
                std::mem::transmute([*buf.get(0).unwrap_or(&0), *buf.get(1).unwrap_or(&0)])
            };
            Value::I16(n)
        }
        Kind::I32 => {
            let n: i32 = unsafe {
                std::mem::transmute([
                    *buf.get(0).unwrap_or(&0),
                    *buf.get(1).unwrap_or(&0),
                    *buf.get(2).unwrap_or(&0),
                    *buf.get(3).unwrap_or(&0),
                ])
            };
            Value::I32(n)
        }
        Kind::I64 => {
            let n: i64 = unsafe {
                std::mem::transmute([
                    *buf.get(0).unwrap_or(&0),
                    *buf.get(1).unwrap_or(&0),
                    *buf.get(2).unwrap_or(&0),
                    *buf.get(3).unwrap_or(&0),
                    *buf.get(4).unwrap_or(&0),
                    *buf.get(5).unwrap_or(&0),
                    *buf.get(6).unwrap_or(&0),
                    *buf.get(7).unwrap_or(&0),
                ])
            };
            Value::I64(n)
        }
        Kind::U8 => Value::U8(*buf.get(0).unwrap_or(&0)),
        Kind::U16 => {
            let n: u16 = unsafe {
                std::mem::transmute([*buf.get(0).unwrap_or(&0), *buf.get(1).unwrap_or(&0)])
            };
            Value::U16(n)
        }
        Kind::U32 => {
            let n: u32 = unsafe {
                std::mem::transmute([
                    *buf.get(0).unwrap_or(&0),
                    *buf.get(1).unwrap_or(&0),
                    *buf.get(2).unwrap_or(&0),
                    *buf.get(3).unwrap_or(&0),
                ])
            };
            Value::U32(n)
        }
        Kind::U64 => {
            let n: u64 = unsafe {
                std::mem::transmute([
                    *buf.get(0).unwrap_or(&0),
                    *buf.get(1).unwrap_or(&0),
                    *buf.get(2).unwrap_or(&0),
                    *buf.get(3).unwrap_or(&0),
                    *buf.get(4).unwrap_or(&0),
                    *buf.get(5).unwrap_or(&0),
                    *buf.get(6).unwrap_or(&0),
                    *buf.get(7).unwrap_or(&0),
                ])
            };
            Value::U64(n)
        }
        Kind::Unknow(_) => Value::Raw(buf),
    };

    Ok(value)
}

/// Update Value By Mib
pub fn update(mib: &Mib, val: Value) -> Result<Value, io::Error> {
    let val_len = val.size();
    let val_ptr = val.as_ptr() as *mut u8 as *mut libc::c_void;

    let mib_ptr = mib.as_ptr() as *mut _;
    let mib_len = mib.len() as _;

    let null1 = ptr::null_mut();
    let null2 = ptr::null_mut();

    if unsafe { libc::sysctl(mib_ptr, mib_len, null1, null2, val_ptr, val_len) } != 0 {
        return Err(io::Error::last_os_error());
    }

    get(mib)
}

pub fn mib2name(old_mib: &Mib) -> Result<String, io::Error> {
    let mut mib = REQ_MIB_TO_NAME.clone();
    mib.extend(old_mib);

    let mib_len = mib.len() as _;
    let mib_ptr = mib.as_mut_ptr() as *mut _;

    let mut buf: [libc::c_uchar; libc::BUFSIZ as usize] = [0; libc::BUFSIZ as usize];
    let mut buf_len = std::mem::size_of_val(&buf);
    let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;

    if unsafe { libc::sysctl(mib_ptr, mib_len, buf_ptr, &mut buf_len, ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let name = CStr::from_bytes_with_nul(&buf[..buf_len])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?
        .to_string_lossy()
        .to_string();

    Ok(name)
}

pub fn name2mib(name: &str) -> Result<Mib, io::Error> {
    let key = CString::new(name).unwrap();
    let key_ptr = key.as_ptr();

    let mut mib = Mib::new();
    let mut mib_len = mib.len() as _;

    let mib_ptr = mib.as_mut_ptr() as *mut _;
    let mib_len_ptr = &mut mib_len as *mut _;

    if unsafe { libc::sysctlnametomib(key_ptr, mib_ptr, mib_len_ptr) } < 0 {
        return Err(io::Error::last_os_error());
    }

    mib.len = mib_len;

    Ok(mib)
}

pub fn next_mib(parent: &Mib) -> Result<Mib, io::Error> {
    let mut mib = REQ_GET_NEXT_MIB.clone();
    mib.extend(parent);
    let mib_len = mib.len() as _;
    let mib_ptr = mib.as_mut_ptr() as *mut _;

    let mut mib2 = Mib::new();
    // len is in bytes, convert to number of c_ints
    let mut mib2_len = mib2.bytes_len() as libc::c_uint;

    let mib2_len_ptr = &mut mib2_len as *mut _ as *mut libc::size_t;
    let mib2_ptr = mib2.as_mut_ptr() as *mut _;

    if unsafe { libc::sysctl(mib_ptr, mib_len, mib2_ptr, mib2_len_ptr, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // len is in bytes, convert to number of c_ints
    mib2_len /= std::mem::size_of::<libc::c_int>() as libc::c_uint;

    let mib2_len = mib2_len as usize;

    mib2.len = mib2_len;

    while mib2.len > 4 {
        let components = &mib2.inner[..mib2.len];
        let last_id = components.len() - 1;

        if components[last_id] == 0 {
            mib2.len -= 1;
        } else {
            break;
        }
    }

    Ok(mib2)
}

pub fn mib2metadata(old_mib: &Mib) -> Result<Metadata, io::Error> {
    let mut mib = REQ_MIB_TO_METADATA.clone();
    mib.extend(old_mib);

    let mib_len = mib.len() as _;
    let mib_ptr = mib.as_mut_ptr() as *mut _;

    let mut buf: [libc::c_uchar; libc::BUFSIZ as usize] = [0; libc::BUFSIZ as usize];
    let mut buf_len = std::mem::size_of_val(&buf);
    let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;

    if unsafe { libc::sysctl(mib_ptr, mib_len, buf_ptr, &mut buf_len, ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let flags_kind_len = std::mem::size_of::<u32>();
    assert!(buf_len > flags_kind_len);

    // 'Kind' is the first 32 bits of result buffer
    #[cfg(target_endian = "little")]
    let flags_kind = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    #[cfg(target_endian = "big")]
    let flags_kind = u32::from_le_bytes([buf[3], buf[2], buf[1], buf[0]]);

    // 'fmt' is after 'Kind' in result buffer
    let fmt = CStr::from_bytes_with_nul(&buf[flags_kind_len..buf_len])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?
        .to_string_lossy()
        .to_string();

    Ok(Metadata {
        flags_kind,
        format: fmt,
    })
}

#[cfg(target_os = "freebsd")]
pub fn mib2desc(old_mib: &Mib) -> Result<String, io::Error> {
    let mut mib = REQ_MIB_TO_DESC.clone();
    mib.extend(old_mib);

    let mib_len = mib.len() as _;
    let mib_ptr = mib.as_mut_ptr() as *mut _;

    let mut buf: [libc::c_uchar; libc::BUFSIZ as usize] = [0; libc::BUFSIZ as usize];
    let mut buf_len = std::mem::size_of_val(&buf);
    let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;

    if unsafe { libc::sysctl(mib_ptr, mib_len, buf_ptr, &mut buf_len, ptr::null_mut(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let desc = CStr::from_bytes_with_nul(&buf[..buf_len])
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?
        .to_string_lossy()
        .to_string();
    Ok(desc)
}

#[cfg(target_os = "macos")]
pub fn mib2desc(_old_mib: &Mib) -> Result<String, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Description not available on macOS",
    ))
}





#[derive(Debug, Clone, Copy)]
pub struct Mib {
    inner: [libc::c_int; CTL_MAXNAME],
    len: usize,
}

impl Mib {
    #[inline]
    fn new() -> Self {
        Mib {
            inner: [0; CTL_MAXNAME],
            len: CTL_MAXNAME,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn bytes_len(&self) -> usize {
        self.len * std::mem::size_of::<libc::c_int>()
    }

    #[inline]
    pub fn components(&self) -> &[libc::c_int] {
        &self.inner[..self.len]
    }

    #[inline]
    pub fn name(&self) -> Result<String, std::io::Error> {
        mib2name(self)
    }

    #[inline]
    pub fn metadata(&self) -> Result<Metadata, std::io::Error> {
        mib2metadata(self)
    }

    /// Get Value
    #[inline]
    pub fn value(&self) -> Result<Value, std::io::Error> {
        get(self)
    }

    /// Set Value
    #[inline]
    pub fn set_value(&self, val: Value) -> Result<Value, std::io::Error> {
        update(self, val)
    }

    /// Only available on FreeBSD system.
    #[inline]
    pub fn description(&self) -> Result<String, std::io::Error> {
        mib2desc(self)
    }

    // Walk
    #[inline]
    pub fn iter(&self) -> Result<MibIter, std::io::Error> {
        Ok(MibIter { mib: *self })
    }

    #[allow(dead_code)]
    #[inline]
    fn push(&mut self, component: libc::c_int) {
        if self.len >= CTL_MAXNAME {
            return ();
        }

        self.inner[self.len] = component;
        self.len += 1;
    }

    #[allow(dead_code)]
    #[inline]
    fn replace(&mut self, offset: usize, val: libc::c_int) {
        if offset < self.len {
            self.inner[offset] = val;
        }
    }

    #[inline]
    fn extend(&mut self, other: &Self) {
        &mut self.inner[self.len..self.len + other.len()].copy_from_slice(other.components());
        self.len += other.len();
    }

    #[inline]
    fn as_ptr(&self) -> *const libc::c_int {
        (&self.inner[..self.len]).as_ptr()
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut libc::c_int {
        (&mut self.inner[..self.len]).as_mut_ptr()
    }
}

impl From<[libc::c_int; CTL_MAXNAME]> for Mib {
    fn from(buffer: [libc::c_int; CTL_MAXNAME]) -> Self {
        let mut len = CTL_MAXNAME;
        while len > 0 {
            if buffer[len - 1] == 0 {
                len -= 1;
            } else {
                break;
            }
        }
        Mib {
            inner: buffer,
            len: len,
        }
    }
}

impl From<&[libc::c_int]> for Mib {
    fn from(val: &[libc::c_int]) -> Self {
        let mut len = val.len();
        assert!(len <= CTL_MAXNAME);

        let mut buffer: [libc::c_int; CTL_MAXNAME] = [0; CTL_MAXNAME];

        while len > 0 {
            if val[len - 1] == 0 {
                len -= 1;
            } else {
                break;
            }
        }

        for idx in 0..len {
            buffer[idx] = val[idx];
        }

        Mib {
            inner: buffer,
            len: len,
        }
    }
}

impl fmt::Display for Mib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.components())
    }
}

impl FromStr for Mib {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        name2mib(s)
    }
}

impl Default for Mib {
    fn default() -> Self {
        let mut buffer: [libc::c_int; CTL_MAXNAME] = [0; CTL_MAXNAME];
        buffer[0] = CTL_KERN;
        let len = 1;

        Mib {
            inner: buffer,
            len: len,
        }
    }
}


#[derive(Debug)]
pub struct MibIter {
    mib: Mib,
}

impl Iterator for MibIter {
    type Item = Result<Mib, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match next_mib(&self.mib) {
            Ok(mib) => {
                self.mib = mib;

                Some(Ok(mib))
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    None
                } else {
                    Some(Err(e))
                }
            }
        }
    }
}