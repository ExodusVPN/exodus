use super::AddressFamily;

use byteorder::{ByteOrder, NativeEndian};

use std::io;
use core::ops::Range;


// 12
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
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct RouteType(pub u8);

impl RouteType {
    pub const RTN_UNSPEC: Self      = Self(0);  // Gateway or direct route
    pub const RTN_UNICAST: Self     = Self(1);  // Gateway or direct route
    pub const RTN_LOCAL: Self       = Self(2);  // Accept locally
    pub const RTN_BROADCAST: Self   = Self(3);  // Accept locally as broadcast, send as broadcast
    pub const RTN_ANYCAST: Self     = Self(4);  // Accept locally as broadcast, but send as unicast
    pub const RTN_MULTICAST: Self   = Self(5);  // Multicast route
    pub const RTN_BLACKHOLE: Self   = Self(6);  // Drop
    pub const RTN_UNREACHABLE: Self = Self(7);  // Destination is unreachable
    pub const RTN_PROHIBIT: Self    = Self(8);  // Administratively prohibited
    pub const RTN_THROW: Self       = Self(9);  // Not in this table
    pub const RTN_NAT: Self         = Self(10); // Translate this address
    pub const RTN_XRESOLVE: Self    = Self(11); // Use external resolver
    pub const RTN_MAX: Self         = Self(11);
}

impl Into<u8> for RouteType {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for RouteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RTN_UNSPEC => write!(f, "RTN_UNSPEC"),
            Self::RTN_UNICAST => write!(f, "RTN_UNICAST"),
            Self::RTN_LOCAL => write!(f, "RTN_LOCAL"),
            Self::RTN_BROADCAST => write!(f, "RTN_BROADCAST"),
            Self::RTN_ANYCAST => write!(f, "RTN_ANYCAST"),
            Self::RTN_MULTICAST => write!(f, "RTN_MULTICAST"),
            Self::RTN_BLACKHOLE => write!(f, "RTN_BLACKHOLE"),
            Self::RTN_UNREACHABLE => write!(f, "RTN_UNREACHABLE"),
            Self::RTN_PROHIBIT => write!(f, "RTN_PROHIBIT"),
            Self::RTN_THROW => write!(f, "RTN_THROW"),
            Self::RTN_NAT => write!(f, "RTN_NAT"),
            Self::RTN_XRESOLVE => write!(f, "RTN_XRESOLVE"),
            _ => write!(f, "RTN_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for RouteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// rtm_protocol
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct RouteProtocol(pub u8);

impl RouteProtocol {
    pub const RTPROT_UNSPEC: Self   = Self(0); // unknown
    pub const RTPROT_REDIRECT: Self = Self(1); // Route installed by ICMP redirects, not used by current IPv4
    pub const RTPROT_KERNEL: Self   = Self(2); // Route installed by kernel
    pub const RTPROT_BOOT: Self     = Self(3); // Route installed during boot
    pub const RTPROT_STATIC: Self   = Self(4); // Route installed by administrator
    // Values of protocol >= RTPROT_STATIC are not interpreted by kernel
    // they are just passed from user and back as is.
    // It will be used by hypothetical multiple routing daemons.
    // Note that protocol values should be standardized in order to
    // avoid conflicts.
    pub const RTPROT_GATED: Self    = Self(8);  // Apparently, GateD
    pub const RTPROT_RA: Self       = Self(9);  // RDISC/ND router advertisements
    pub const RTPROT_MRT: Self      = Self(10); // Merit MRT
    pub const RTPROT_ZEBRA: Self    = Self(11); // Zebra
    pub const RTPROT_BIRD: Self     = Self(12); // BIRD
    pub const RTPROT_DNROUTED: Self = Self(13); // DECnet routing daemon
    pub const RTPROT_XORP: Self     = Self(14); // XORP
    pub const RTPROT_NTK: Self      = Self(15); // Netsukuku
    pub const RTPROT_DHCP: Self     = Self(16); // DHCP client
    pub const RTPROT_MROUTED: Self  = Self(17); // Multicast daemon
    pub const RTPROT_BABEL: Self    = Self(42); // Babel daemon
}

impl Into<u8> for RouteProtocol {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for RouteProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RTPROT_UNSPEC => write!(f, "RTPROT_UNSPEC"),
            Self::RTPROT_REDIRECT => write!(f, "RTPROT_REDIRECT"),
            Self::RTPROT_KERNEL => write!(f, "RTPROT_KERNEL"),
            Self::RTPROT_BOOT => write!(f, "RTPROT_BOOT"),
            Self::RTPROT_STATIC => write!(f, "RTPROT_STATIC"),
            Self::RTPROT_GATED => write!(f, "RTPROT_GATED"),
            Self::RTPROT_RA => write!(f, "RTPROT_RA"),
            Self::RTPROT_MRT => write!(f, "RTPROT_MRT"),
            Self::RTPROT_ZEBRA => write!(f, "RTPROT_ZEBRA"),
            Self::RTPROT_BIRD => write!(f, "RTPROT_BIRD"),
            Self::RTPROT_DNROUTED => write!(f, "RTPROT_DNROUTED"),
            Self::RTPROT_XORP => write!(f, "RTPROT_XORP"),
            Self::RTPROT_NTK => write!(f, "RTPROT_NTK"),
            Self::RTPROT_DHCP => write!(f, "RTPROT_DHCP"),
            Self::RTPROT_MROUTED => write!(f, "RTPROT_MROUTED"),
            Self::RTPROT_BABEL => write!(f, "RTPROT_BABEL"),
            _ => write!(f, "RTPROT_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for RouteProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// rtm_scope
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct RouteScope(pub u8);

impl RouteScope {
    pub const RT_SCOPE_UNIVERSE: Self = Self(0);   // global route
    // User defined values
    pub const RT_SCOPE_SITE: Self     = Self(200); // interior route in the local autonomous system
    pub const RT_SCOPE_LINK: Self     = Self(253); // route on this link
    pub const RT_SCOPE_HOST: Self     = Self(254); // route on the local host
    pub const RT_SCOPE_NOWHERE: Self  = Self(255); // destination doesn't exist
}

impl Into<u8> for RouteScope {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for RouteScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RT_SCOPE_UNIVERSE => write!(f, "RT_SCOPE_UNIVERSE"),
            Self::RT_SCOPE_SITE => write!(f, "RT_SCOPE_SITE"),
            Self::RT_SCOPE_LINK => write!(f, "RT_SCOPE_LINK"),
            Self::RT_SCOPE_HOST => write!(f, "RT_SCOPE_HOST"),
            Self::RT_SCOPE_NOWHERE => write!(f, "RT_SCOPE_NOWHERE"),
            _ => write!(f, "RT_SCOPE_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for RouteScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// rt_class (rt_table)
// The user may assign arbitrary values between RT_TABLE_UNSPEC and RT_TABLE_DEFAULT.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct RouteTable(pub u8);

impl RouteTable {
    // Reserved table identifiers
    pub const RT_TABLE_UNSPEC: Self  = Self(0);   // an unspecified routing table
    // User defined values
    pub const RT_TABLE_COMPAT: Self  = Self(252);
    pub const RT_TABLE_DEFAULT: Self = Self(253); // the default table
    pub const RT_TABLE_MAIN: Self    = Self(254); // the main table
    pub const RT_TABLE_LOCAL: Self   = Self(255); // the local table
}

impl Into<u8> for RouteTable {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RT_TABLE_UNSPEC => write!(f, "RT_TABLE_UNSPEC"),
            Self::RT_TABLE_COMPAT => write!(f, "RT_TABLE_COMPAT"),
            Self::RT_TABLE_DEFAULT => write!(f, "RT_TABLE_DEFAULT"),
            Self::RT_TABLE_MAIN => write!(f, "RT_TABLE_MAIN"),
            Self::RT_TABLE_LOCAL => write!(f, "RT_TABLE_LOCAL"),
            _ => write!(f, "RT_TABLE_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for RouteTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// rtm_flags
bitflags! {
    pub struct RouteFlags: u32 {
        const RTM_F_NOTIFY       =  0x100; // Notify user of route change
        const RTM_F_CLONED       =  0x200; // This route is cloned
        const RTM_F_EQUALIZE     =  0x400; // Multipath equalizer: NI
        const RTM_F_PREFIX       =  0x800; // Prefix addresses
        const RTM_F_LOOKUP_TABLE = 0x1000; // set rtm_table to FIB lookup result
    }
}

impl Into<u32> for RouteFlags {
    fn into(self) -> u32 {
        self.bits()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct RouteAttrType(pub u16);

impl RouteAttrType {
    pub const RTA_UNSPEC: Self     = Self(0); // Ignored.
    pub const RTA_DST: Self        = Self(1); // Protocol address for route destination address.
    pub const RTA_SRC: Self        = Self(2); // Protocol address for route source address.
    pub const RTA_IIF: Self        = Self(3); // Input interface index.
    pub const RTA_OIF: Self        = Self(4); // Output interface index.
    pub const RTA_GATEWAY: Self    = Self(5); // Protocol address for the gateway of the route
    pub const RTA_PRIORITY: Self   = Self(6); // Priority of route.
    // Preferred source address in cases where more than one source address could be used.
    pub const RTA_PREFSRC: Self    = Self(7);
    // Route metrics attributed to route and associated protocols (e.g., RTT, initial TCP window, etc.).
    pub const RTA_METRICS: Self    = Self(8);
    pub const RTA_MULTIPATH: Self  = Self(9);  // Multipath route next hop's attributes.
    pub const RTA_PROTOINFO: Self  = Self(10); // no longer used
    pub const RTA_FLOW: Self       = Self(11); // Route realm.
    pub const RTA_CACHEINFO: Self  = Self(12); // Cached route information.
    pub const RTA_SESSION: Self    = Self(13); // no longer used
    pub const RTA_MP_ALGO: Self    = Self(14); // no longer used
    pub const RTA_TABLE: Self      = Self(15);
    pub const RTA_MARK: Self       = Self(16);
    pub const RTA_MFC_STATS: Self  = Self(17);
    pub const RTA_VIA: Self        = Self(18);
    pub const RTA_NEWDST: Self     = Self(19);
    pub const RTA_PREF: Self       = Self(20);
    pub const RTA_ENCAP_TYPE: Self = Self(21);
    pub const RTA_ENCAP: Self      = Self(22);
    pub const RTA_EXPIRES: Self    = Self(23);
    pub const RTA_PAD: Self        = Self(24);
}

impl Into<u16> for RouteAttrType {
    fn into(self) -> u16 {
        self.0
    }
}

impl std::fmt::Debug for RouteAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RTA_UNSPEC => write!(f, "RTA_UNSPEC"),
            Self::RTA_DST => write!(f, "RTA_DST"),
            Self::RTA_SRC => write!(f, "RTA_SRC"),
            Self::RTA_IIF => write!(f, "RTA_IIF"),
            Self::RTA_OIF => write!(f, "RTA_OIF"),
            Self::RTA_GATEWAY => write!(f, "RTA_GATEWAY"),
            Self::RTA_PRIORITY => write!(f, "RTA_PRIORITY"),
            Self::RTA_PREFSRC => write!(f, "RTA_PREFSRC"),
            Self::RTA_METRICS => write!(f, "RTA_METRICS"),
            Self::RTA_MULTIPATH => write!(f, "RTA_MULTIPATH"),
            Self::RTA_PROTOINFO => write!(f, "RTA_PROTOINFO"),
            Self::RTA_FLOW => write!(f, "RTA_FLOW"),
            Self::RTA_CACHEINFO => write!(f, "RTA_CACHEINFO"),
            Self::RTA_SESSION => write!(f, "RTA_SESSION"),
            Self::RTA_MP_ALGO => write!(f, "RTA_MP_ALGO"),
            Self::RTA_TABLE => write!(f, "RTA_TABLE"),
            Self::RTA_MARK => write!(f, "RTA_MARK"),
            Self::RTA_MFC_STATS => write!(f, "RTA_MFC_STATS"),
            Self::RTA_VIA => write!(f, "RTA_VIA"),
            Self::RTA_NEWDST => write!(f, "RTA_NEWDST"),
            Self::RTA_PREF => write!(f, "RTA_PREF"),
            Self::RTA_ENCAP_TYPE => write!(f, "RTA_ENCAP_TYPE"),
            Self::RTA_ENCAP => write!(f, "RTA_ENCAP"),
            Self::RTA_EXPIRES => write!(f, "RTA_EXPIRES"),
            Self::RTA_PAD => write!(f, "RTA_PAD"),
            _ => write!(f, "RTA_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for RouteAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


const FAMILY: usize         = 0;
const DST_LEN: usize        = 1;
const SRC_LEN: usize        = 2;
const TOS: usize            = 3;
const TABLE: usize          = 4;
const PROTOCOL: usize       = 5;
const SCOPE: usize          = 6;
const TYPE: usize           = 7;
const FLAGS: Range<usize>   = 8..12;

const PAYLOAD: usize        = 12;

#[derive(Debug, PartialEq, Clone)]
pub struct RoutePacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> RoutePacket<T> {
    pub const MIN_SIZE: usize = 12;

    #[inline]
    pub fn new_unchecked(buffer: T) -> RoutePacket<T> {
        RoutePacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<RoutePacket<T>, io::Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), io::Error> {
        let data = self.buffer.as_ref();
        if data.len() < Self::MIN_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "packet is too small."));
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn family(&self) -> AddressFamily {
        let data = self.buffer.as_ref();
        AddressFamily(data[FAMILY])
    }

    // SRC ADDR Prefix Len (netmask bits)
    #[inline]
    pub fn dst_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[DST_LEN]
    }

    // DST ADDR Prefix Len (netmask bits)
    #[inline]
    pub fn src_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[SRC_LEN]
    }

    #[inline]
    pub fn tos(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[TOS]
    }

    #[inline]
    pub fn table(&self) -> RouteTable {
        let data = self.buffer.as_ref();
        RouteTable(data[TABLE])
    }

    #[inline]
    pub fn protocol(&self) -> RouteProtocol {
        let data = self.buffer.as_ref();
        RouteProtocol(data[PROTOCOL])
    }

    #[inline]
    pub fn scope(&self) -> RouteScope {
        let data = self.buffer.as_ref();
        RouteScope(data[SCOPE])
    }

    #[inline]
    pub fn kind(&self) -> RouteType {
        let data = self.buffer.as_ref();
        RouteType(data[TYPE])
    }

    #[inline]
    pub fn flags(&self) -> RouteFlags {
        let data = self.buffer.as_ref();
        RouteFlags::from_bits_truncate(NativeEndian::read_u32(&data[FLAGS]))
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> RoutePacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> RoutePacket<T> {
    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value.0;
    }

    #[inline]
    pub fn set_dst_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[DST_LEN] = value;
    }

    #[inline]
    pub fn set_src_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[SRC_LEN] = value;
    }

    #[inline]
    pub fn set_tos(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[TOS] = value;
    }

    #[inline]
    pub fn set_table(&mut self, value: RouteTable) {
        let data = self.buffer.as_mut();
        data[TABLE] = value.0;
    }

    #[inline]
    pub fn set_protocol(&mut self, value: RouteProtocol) {
        let data = self.buffer.as_mut();
        data[PROTOCOL] = value.0;
    }

    #[inline]
    pub fn set_scope(&mut self, value: RouteScope) {
        let data = self.buffer.as_mut();
        data[SCOPE] = value.0;
    }

    #[inline]
    pub fn set_kind(&mut self, value: RouteType) {
        let data = self.buffer.as_mut();
        data[TYPE] = value.0
    }

    #[inline]
    pub fn set_flags(&mut self, value: RouteFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[FLAGS], value.bits())
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let data = self.buffer.as_mut();
        &mut data[PAYLOAD..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for RoutePacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoutePacket {{ family: {:?}, dst_len: {}, src_len: {}, tos: {}, table: {:?}, protocol: {:?}, scope: {:?}, kind: {:?}, flags: {:?} }}",
                self.family(),
                self.dst_len(),
                self.src_len(),
                self.tos(),
                self.table(),
                self.protocol(),
                self.scope(),
                self.kind(),
                self.flags())
    }
}
