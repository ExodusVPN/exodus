use super::AddressFamily;

use libc::IF_NAMESIZE;
use byteorder::{ByteOrder, NativeEndian};

use std::io;
use core::ops::Range;


// 16 bytes
// passes link level specific information, not dependent on network protocol.
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

// Link layer specific messages.

#[derive(Clone, Copy)]
pub struct LinkName {
    data: [u8; IF_NAMESIZE as usize],
    len: usize,
}

impl LinkName {
    pub fn new(data: [u8; IF_NAMESIZE as usize], len: usize) -> Self {
        if data[len - 1] == 0 && data[len - 2] == 0 {
            Self { data, len: len - 1, }
        } else {
            Self { data, len, }
        }
    }
}

impl std::fmt::Debug for LinkName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{}\"", self)
    }
}

impl std::fmt::Display for LinkName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::ffi::CStr::from_bytes_with_nul(&self.data[..self.len]) {
            Ok(s) => write!(f, "{}", s.to_string_lossy().to_string()),
            Err(_) => {
                error!("Link Name is invalid: Len={} Data={:?}", self.len, &self.data);
                write!(f, "�")
            },
        }
    }
}

// /usr/include/net/if.h
// Standard interface flags
bitflags! {
    pub struct LinkFlags: u32 {
        const IFF_UP          =   0x1; // Interface is up
        const IFF_BROADCAST   =   0x2; // Broadcast address valid
        const IFF_DEBUG       =   0x4; // Turn on debugging
        const IFF_LOOPBACK    =   0x8; // Is a loopback net
        const IFF_POINTOPOINT =  0x10; // Interface is point-to-point link
        const IFF_NOTRAILERS  =  0x20; // Avoid use of trailers
        const IFF_RUNNING     =  0x40; // Resources allocated
        const IFF_NOARP       =  0x80; // No address resolution protocol
        const IFF_PROMISC     = 0x100; // Receive all packets
        // Not supported
        const IFF_ALLMULTI    = 0x200; // Receive all multicast packets

        const IFF_MASTER      = 0x400; // Master of a load balancer
        const IFF_SLAVE       = 0x800; // Slave of a load balancer

        const IFF_MULTICAST   = 0x1000; // Supports multicast

        const IFF_PORTSEL     = 0x2000; // Can set media type
        const IFF_AUTOMEDIA   = 0x4000; // Auto media select active
        const IFF_DYNAMIC     = 0x8000; // Dialup device with changing addresses
        const IFF_LOWER_UP    = 1 << 16;
        const IFF_DORMANT     = 1 << 17;
        const IFF_ECHO        = 1 << 18;
    }
}


// ARPHRD_*
// /usr/include/net/if_arp.h
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct LinkKind(pub u16);

impl LinkKind {
    // ARP protocol HARDWARE identifiers
    pub const ARPHRD_NETROM: Self     = Self(0); // From KA9Q: NET/ROM pseudo.
    pub const ARPHRD_ETHER: Self      = Self(1); // Ethernet 10/100Mbps.
    pub const ARPHRD_EETHER: Self     = Self(2); // Experimental Ethernet.
    pub const ARPHRD_AX25: Self       = Self(3); // AX.25 Level 2.
    pub const ARPHRD_PRONET: Self     = Self(4); // PROnet token ring.
    pub const ARPHRD_CHAOS: Self      = Self(5); // Chaosnet.
    pub const ARPHRD_IEEE802: Self    = Self(6); // IEEE 802.2 Ethernet/TR/TB.
    pub const ARPHRD_ARCNET: Self     = Self(7); // ARCnet.
    pub const ARPHRD_APPLETLK: Self   = Self(8); // APPLEtalk.
    pub const ARPHRD_DLCI: Self       = Self(15); // Frame Relay DLCI.
    pub const ARPHRD_ATM: Self        = Self(19); // ATM.
    pub const ARPHRD_METRICOM: Self   = Self(23); // Metricom STRIP (new IANA id)/
    pub const ARPHRD_IEEE1394: Self   = Self(24); // IEEE 1394 IPv4 - RFC 2734.
    pub const ARPHRD_EUI64: Self      = Self(27); // EUI-64.
    pub const ARPHRD_INFINIBAND: Self = Self(32); // InfiniBand.

    // Dummy types for non ARP hardware
    pub const ARPHRD_SLIP: Self     = Self(256);
    pub const ARPHRD_CSLIP: Self    = Self(257);
    pub const ARPHRD_SLIP6: Self    = Self(258);
    pub const ARPHRD_CSLIP6: Self   = Self(259);
    pub const ARPHRD_RSRVD: Self    = Self(260); // Notional KISS type.
    pub const ARPHRD_ADAPT: Self    = Self(264);
    pub const ARPHRD_ROSE: Self     = Self(270);
    pub const ARPHRD_X25: Self      = Self(271); // CCITT X.25.
    pub const ARPHRD_HWX25: Self    = Self(272); // Boards with X.25 in firmware.
    pub const ARPHRD_PPP: Self      = Self(512);
    pub const ARPHRD_CISCO: Self    = Self(513); // Cisco HDLC.
    pub const ARPHRD_HDLC: Self     = Self::ARPHRD_CISCO;
    pub const ARPHRD_LAPB: Self     = Self(516); // LAPB.
    pub const ARPHRD_DDCMP: Self    = Self(517); // Digital's DDCMP.
    pub const ARPHRD_RAWHDLC: Self  = Self(518); // Raw HDLC.
    pub const ARPHRD_RAWIP: Self    = Self(519); // Raw IP.

    pub const ARPHRD_TUNNEL: Self   = Self(768); // IPIP tunnel.
    pub const ARPHRD_TUNNEL6: Self  = Self(769); // IPIP6 tunnel.
    pub const ARPHRD_FRAD: Self     = Self(770); // Frame Relay Access Device.
    pub const ARPHRD_SKIP: Self     = Self(771); // SKIP vif.
    pub const ARPHRD_LOOPBACK: Self = Self(772); // Loopback device.
    pub const ARPHRD_LOCALTLK: Self = Self(773); // Localtalk device.
    pub const ARPHRD_FDDI: Self     = Self(774); // Fiber Distributed Data Interface.
    pub const ARPHRD_BIF: Self      = Self(775); // AP1000 BIF.
    pub const ARPHRD_SIT: Self      = Self(776); // sit0 device - IPv6-in-IPv4.
    pub const ARPHRD_IPDDP: Self    = Self(777); // IP-in-DDP tunnel.
    pub const ARPHRD_IPGRE: Self    = Self(778); // GRE over IP.
    pub const ARPHRD_PIMREG: Self   = Self(779); // PIMSM register interface.
    pub const ARPHRD_HIPPI: Self    = Self(780); // High Performance Parallel I'face.
    pub const ARPHRD_ASH: Self      = Self(781); // (Nexus Electronics) Ash.
    pub const ARPHRD_ECONET: Self   = Self(782); // Acorn Econet.
    pub const ARPHRD_IRDA: Self     = Self(783); // Linux-IrDA.
    pub const ARPHRD_FCPP: Self     = Self(784); // Point to point fibrechanel.
    pub const ARPHRD_FCAL: Self     = Self(785); // Fibrechanel arbitrated loop.
    pub const ARPHRD_FCPL: Self     = Self(786); // Fibrechanel public loop.
    pub const ARPHRD_FCFABRIC: Self = Self(787); // Fibrechanel fabric.
    pub const ARPHRD_IEEE802_TR: Self         = Self(800); // Magic type ident for TR.
    pub const ARPHRD_IEEE80211: Self          = Self(801); // IEEE 802.11.
    pub const ARPHRD_IEEE80211_PRISM: Self    = Self(802); // IEEE 802.11 + Prism2 header.
    pub const ARPHRD_IEEE80211_RADIOTAP: Self = Self(803); // IEEE 802.11 + radiotap header.
    pub const ARPHRD_IEEE802154: Self         = Self(804); // IEEE 802.15.4 header.
    pub const ARPHRD_IEEE802154_PHY: Self     = Self(805); // IEEE 802.15.4 PHY header.

    pub const ARPHRD_VOID: Self               = Self(0xFFFF); // Void type, nothing is known.
    pub const ARPHRD_NONE: Self               = Self(0xFFFE); // Zero header length.
}

impl std::fmt::Debug for LinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::ARPHRD_NETROM => write!(f, "ARPHRD_NETROM"),
            Self::ARPHRD_ETHER => write!(f, "ARPHRD_ETHER"),
            Self::ARPHRD_EETHER => write!(f, "ARPHRD_EETHER"),
            Self::ARPHRD_IEEE802 => write!(f, "ARPHRD_IEEE802"),
            Self::ARPHRD_IEEE1394 => write!(f, "ARPHRD_IEEE1394"),
            Self::ARPHRD_TUNNEL => write!(f, "ARPHRD_TUNNEL"),
            Self::ARPHRD_TUNNEL6 => write!(f, "ARPHRD_TUNNEL6"),
            Self::ARPHRD_LOOPBACK => write!(f, "ARPHRD_LOOPBACK"),
            Self::ARPHRD_IEEE802_TR => write!(f, "ARPHRD_IEEE802_TR"),
            Self::ARPHRD_IEEE80211 => write!(f, "ARPHRD_IEEE80211"),
            Self::ARPHRD_IEEE80211_PRISM => write!(f, "ARPHRD_IEEE80211_PRISM"),
            Self::ARPHRD_IEEE80211_RADIOTAP => write!(f, "ARPHRD_IEEE80211_RADIOTAP"),
            Self::ARPHRD_IEEE802154 => write!(f, "ARPHRD_IEEE802154"),
            Self::ARPHRD_IEEE802154_PHY => write!(f, "ARPHRD_IEEE802154_PHY"),
            _ => write!(f, "ARPHRD_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for LinkKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// RFC 2863 operational status
// https://github.com/torvalds/linux/blob/master/Documentation/networking/operstates.txt
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if.h
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct LinkOperState(pub u32);

impl LinkOperState {
    pub const IF_OPER_UNKNOWN: Self        = Self(0);
    pub const IF_OPER_NOTPRESENT: Self     = Self(1);
    pub const IF_OPER_DOWN: Self           = Self(2);
    pub const IF_OPER_LOWERLAYERDOWN: Self = Self(3);
    pub const IF_OPER_TESTING: Self        = Self(4);
    pub const IF_OPER_DORMANT: Self        = Self(5);
    pub const IF_OPER_UP: Self             = Self(6);
}

impl std::fmt::Debug for LinkOperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IF_OPER_UNKNOWN => write!(f, "IF_OPER_UNKNOWN"),
            Self::IF_OPER_NOTPRESENT => write!(f, "IF_OPER_NOTPRESENT"),
            Self::IF_OPER_DOWN => write!(f, "IF_OPER_DOWN"),
            Self::IF_OPER_LOWERLAYERDOWN => write!(f, "IF_OPER_LOWERLAYERDOWN"),
            Self::IF_OPER_TESTING => write!(f, "IF_OPER_TESTING"),
            Self::IF_OPER_DORMANT => write!(f, "IF_OPER_DORMANT"),
            Self::IF_OPER_UP => write!(f, "IF_OPER_UP"),
            _ => write!(f, "IF_OPER_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for LinkOperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct LinkMode(pub u32);

impl LinkMode {
    pub const IF_LINK_MODE_DEFAULT: Self = Self(0);
    pub const IF_LINK_MODE_DORMANT: Self = Self(1); // limit upward transition to dormant
}

impl std::fmt::Debug for LinkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IF_LINK_MODE_DEFAULT => write!(f, "IF_LINK_MODE_DEFAULT"),
            Self::IF_LINK_MODE_DORMANT => write!(f, "IF_LINK_MODE_DORMANT"),
            _ => write!(f, "IF_LINK_MODE_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for LinkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


// /usr/include/linux/if_link.h
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct LinkAttrType(pub u16);

impl LinkAttrType {
    pub const IFLA_UNSPEC: Self          = Self(0);
    pub const IFLA_ADDRESS: Self         = Self(1);
    pub const IFLA_BROADCAST: Self       = Self(2);
    pub const IFLA_IFNAME: Self          = Self(3);
    pub const IFLA_MTU: Self             = Self(4);
    pub const IFLA_LINK: Self            = Self(5);
    pub const IFLA_QDISC: Self           = Self(6);
    pub const IFLA_STATS: Self           = Self(7);
    pub const IFLA_COST: Self            = Self(8);
    pub const IFLA_PRIORITY: Self        = Self(9);
    pub const IFLA_MASTER: Self          = Self(10);
    pub const IFLA_WIRELESS: Self        = Self(11); // Wireless Extension event - see wireless.h
    pub const IFLA_PROTINFO: Self        = Self(12); // Protocol specific information for a link
    pub const IFLA_TXQLEN: Self          = Self(13);
    pub const IFLA_MAP: Self             = Self(14);
    pub const IFLA_WEIGHT: Self          = Self(15);
    pub const IFLA_OPERSTATE: Self       = Self(16);
    pub const IFLA_LINKMODE: Self        = Self(17);
    pub const IFLA_LINKINFO: Self        = Self(18);
    pub const IFLA_NET_NS_PID: Self      = Self(19);
    pub const IFLA_IFALIAS: Self         = Self(20);
    pub const IFLA_NUM_VF: Self          = Self(21); // Number of VFs if device is SR-IOV PF
    pub const IFLA_VFINFO_LIST: Self     = Self(22);
    pub const IFLA_STATS64: Self         = Self(23);
    pub const IFLA_VF_PORTS: Self        = Self(24);
    pub const IFLA_PORT_SELF: Self       = Self(25);
    pub const IFLA_AF_SPEC: Self         = Self(26);
    pub const IFLA_GROUP: Self           = Self(27); // Group the device belongs to
    pub const IFLA_NET_NS_FD: Self       = Self(28);
    pub const IFLA_EXT_MASK: Self        = Self(29); // Extended info mask, VFs, etc
    pub const IFLA_PROMISCUITY: Self     = Self(30); // Promiscuity count: > 0 means acts PROMISC
    pub const IFLA_NUM_TX_QUEUES: Self   = Self(31);
    pub const IFLA_NUM_RX_QUEUES: Self   = Self(32);
    pub const IFLA_CARRIER: Self         = Self(33);
    pub const IFLA_PHYS_PORT_ID: Self    = Self(34);
    pub const IFLA_CARRIER_CHANGES: Self = Self(35);
    pub const IFLA_PHYS_SWITCH_ID: Self  = Self(36);
    pub const IFLA_LINK_NETNSID: Self    = Self(37);
    pub const IFLA_PHYS_PORT_NAME: Self  = Self(38);
    pub const IFLA_PROTO_DOWN: Self      = Self(39);
    pub const IFLA_GSO_MAX_SEGS: Self    = Self(40);
    pub const IFLA_GSO_MAX_SIZE: Self    = Self(41);
    pub const IFLA_PAD: Self             = Self(42);
    pub const IFLA_XDP: Self             = Self(43);
}

impl std::fmt::Debug for LinkAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::IFLA_UNSPEC => write!(f, "IFLA_UNSPEC"),
            Self::IFLA_ADDRESS => write!(f, "IFLA_ADDRESS"),
            Self::IFLA_BROADCAST => write!(f, "IFLA_BROADCAST"),
            Self::IFLA_IFNAME => write!(f, "IFLA_IFNAME"),
            Self::IFLA_MTU => write!(f, "IFLA_MTU"),
            Self::IFLA_LINK => write!(f, "IFLA_LINK"),
            Self::IFLA_QDISC => write!(f, "IFLA_QDISC"),
            Self::IFLA_STATS => write!(f, "IFLA_STATS"),
            Self::IFLA_COST => write!(f, "IFLA_COST"),
            Self::IFLA_PRIORITY => write!(f, "IFLA_PRIORITY"),
            Self::IFLA_MASTER => write!(f, "IFLA_MASTER"),
            Self::IFLA_WIRELESS => write!(f, "IFLA_WIRELESS"),
            Self::IFLA_PROTINFO => write!(f, "IFLA_PROTINFO"),
            Self::IFLA_TXQLEN => write!(f, "IFLA_TXQLEN"),
            Self::IFLA_MAP => write!(f, "IFLA_MAP"),
            Self::IFLA_WEIGHT => write!(f, "IFLA_WEIGHT"),
            Self::IFLA_OPERSTATE => write!(f, "IFLA_OPERSTATE"),
            Self::IFLA_LINKMODE => write!(f, "IFLA_LINKMODE"),
            Self::IFLA_LINKINFO => write!(f, "IFLA_LINKINFO"),
            Self::IFLA_NET_NS_PID => write!(f, "IFLA_NET_NS_PID"),
            Self::IFLA_NUM_VF => write!(f, "IFLA_NUM_VF"),
            Self::IFLA_VFINFO_LIST => write!(f, "IFLA_VFINFO_LIST"),
            Self::IFLA_STATS64 => write!(f, "IFLA_STATS64"),
            Self::IFLA_VF_PORTS => write!(f, "IFLA_VF_PORTS"),
            Self::IFLA_PORT_SELF => write!(f, "IFLA_PORT_SELF"),
            Self::IFLA_AF_SPEC => write!(f, "IFLA_AF_SPEC"),
            Self::IFLA_GROUP => write!(f, "IFLA_GROUP"),
            Self::IFLA_NET_NS_FD => write!(f, "IFLA_NET_NS_FD"),
            Self::IFLA_EXT_MASK => write!(f, "IFLA_EXT_MASK"),
            Self::IFLA_PROMISCUITY => write!(f, "IFLA_PROMISCUITY"),
            Self::IFLA_NUM_TX_QUEUES => write!(f, "IFLA_NUM_TX_QUEUES"),
            Self::IFLA_NUM_RX_QUEUES => write!(f, "IFLA_NUM_RX_QUEUES"),
            Self::IFLA_CARRIER => write!(f, "IFLA_CARRIER"),
            Self::IFLA_PHYS_PORT_ID => write!(f, "IFLA_PHYS_PORT_ID"),
            Self::IFLA_CARRIER_CHANGES => write!(f, "IFLA_CARRIER_CHANGES"),
            Self::IFLA_PHYS_SWITCH_ID => write!(f, "IFLA_PHYS_SWITCH_ID"),
            Self::IFLA_LINK_NETNSID => write!(f, "IFLA_LINK_NETNSID"),
            Self::IFLA_PHYS_PORT_NAME => write!(f, "IFLA_PHYS_PORT_NAME"),
            Self::IFLA_PROTO_DOWN => write!(f, "IFLA_PROTO_DOWN"),
            Self::IFLA_GSO_MAX_SEGS => write!(f, "IFLA_GSO_MAX_SEGS"),
            Self::IFLA_GSO_MAX_SIZE => write!(f, "IFLA_GSO_MAX_SIZE"),
            Self::IFLA_PAD => write!(f, "IFLA_PAD"),
            Self::IFLA_XDP => write!(f, "IFLA_XDP"),
            _ => write!(f, "IFLA_UNKNOW({})", self.0),
        }
    }
}

impl std::fmt::Display for LinkAttrType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Into<u16> for LinkAttrType {
    fn into(self) -> u16 {
        self.0
    }
}


const FAMILY: usize         = 0;
const KIND: Range<usize>    = 2..4;
const IFINDEX: Range<usize> = 4..8;
const FLAGS: Range<usize>   = 8..12;
const CHANGE: Range<usize>  = 12..16;
const PAYLOAD: usize        = 16;


#[derive(Debug, PartialEq, Clone)]
pub struct LinkPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> LinkPacket<T> {
    pub const MIN_SIZE: usize = 16;

    #[inline]
    pub fn new_unchecked(buffer: T) -> LinkPacket<T> {
        LinkPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<LinkPacket<T>, io::Error> {
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

    #[inline]
    pub fn kind(&self) -> LinkKind {
        let data = self.buffer.as_ref();
        LinkKind(NativeEndian::read_u16(&data[KIND]))
    }

    #[inline]
    pub fn ifindex(&self) -> i32 {
        let data = self.buffer.as_ref();
        NativeEndian::read_i32(&data[IFINDEX])
    }

    #[inline]
    pub fn flags(&self) -> LinkFlags {
        let data = self.buffer.as_ref();
        LinkFlags::from_bits_truncate(NativeEndian::read_u32(&data[FLAGS]))
    }

    #[inline]
    pub fn change(&self) -> LinkFlags {
        let data = self.buffer.as_ref();
        LinkFlags::from_bits_truncate(NativeEndian::read_u32(&data[CHANGE]))
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        16
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> LinkPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[PAYLOAD..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> LinkPacket<T> {
    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        data[FAMILY] = value.0;
    }

    #[inline]
    pub fn set_kind(&mut self, value: LinkKind) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u16(&mut data[KIND], value.0)
    }

    #[inline]
    pub fn set_ifindex(&mut self, value: i32) {
        let data = self.buffer.as_mut();
        NativeEndian::write_i32(&mut data[IFINDEX], value)
    }

    #[inline]
    pub fn set_flags(&mut self, value: LinkFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[FLAGS], value.bits())
    }

    #[inline]
    pub fn set_change(&mut self, value: LinkFlags) {
        let data = self.buffer.as_mut();
        NativeEndian::write_u32(&mut data[CHANGE], value.bits())
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let data = self.buffer.as_mut();
        &mut data[PAYLOAD..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for LinkPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LinkPacket {{ family: {:?}, kind: {}, ifindex: {:?}, flags: {:?}, change: {:?} }}",
                self.family(),
                self.kind(),
                self.ifindex(),
                self.flags(),
                self.change())
    }
}