pub(crate) mod field {
    pub type Field = ::core::ops::Range<usize>;
    pub type Rest  = ::core::ops::RangeFrom<usize>;
}

pub mod pretty_print;

mod ethernet;
#[cfg(feature = "proto-ipv4")]
mod arp;
pub(crate) mod ip;
#[cfg(feature = "proto-ipv4")]
mod ipv4;
#[cfg(feature = "proto-ipv6")]
mod ipv6;
#[cfg(feature = "proto-ipv6")]
mod ipv6option;
#[cfg(feature = "proto-ipv6")]
mod ipv6hopbyhop;
#[cfg(feature = "proto-ipv6")]
mod ipv6fragment;
#[cfg(feature = "proto-ipv6")]
mod ipv6routing;
#[cfg(feature = "proto-ipv4")]
mod icmpv4;
#[cfg(feature = "proto-ipv6")]
mod icmpv6;
#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
mod icmp;
#[cfg(feature = "proto-igmp")]
mod igmp;
#[cfg(feature = "proto-ipv6")]
mod ndisc;
#[cfg(feature = "proto-ipv6")]
mod ndiscoption;
#[cfg(feature = "proto-ipv6")]
mod mld;
mod udp;
mod tcp;
// #[cfg(feature = "proto-dhcpv4")]
// pub(crate) mod dhcpv4;

/// A description of checksum behavior for a particular protocol.
#[derive(Debug, Clone, Copy)]
pub enum Checksum {
    /// Verify checksum when receiving and compute checksum when sending.
    Both,
    /// Verify checksum when receiving.
    Rx,
    /// Compute checksum before sending.
    Tx,
    /// Ignore checksum completely.
    None,
}

impl Default for Checksum {
    fn default() -> Checksum {
        Checksum::Both
    }
}

impl Checksum {
    /// Returns whether checksum should be verified when receiving.
    pub fn rx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Rx => true,
            _ => false
        }
    }

    /// Returns whether checksum should be verified when sending.
    pub fn tx(&self) -> bool {
        match *self {
            Checksum::Both | Checksum::Tx => true,
            _ => false
        }
    }
}

/// A description of checksum behavior for every supported protocol.
#[derive(Debug, Clone, Default)]
pub struct ChecksumCapabilities {
    pub ipv4: Checksum,
    pub udp: Checksum,
    pub tcp: Checksum,
    #[cfg(feature = "proto-ipv4")]
    pub icmpv4: Checksum,
    #[cfg(feature = "proto-ipv6")]
    pub icmpv6: Checksum,
    dummy: (),
}

impl ChecksumCapabilities {
    /// Checksum behavior that results in not computing or verifying checksums
    /// for any of the supported protocols.
    pub fn ignored() -> Self {
        ChecksumCapabilities {
            ipv4: Checksum::None,
            udp: Checksum::None,
            tcp: Checksum::None,
            #[cfg(feature = "proto-ipv4")]
            icmpv4: Checksum::None,
            #[cfg(feature = "proto-ipv6")]
            icmpv6: Checksum::None,
            ..Self::default()
        }
    }
}


pub use self::pretty_print::PrettyPrinter;

pub use self::ethernet::{EtherType as EthernetProtocol,
                         Address as EthernetAddress,
                         Frame as EthernetFrame,
                         Repr as EthernetRepr};

#[cfg(feature = "proto-ipv4")]
pub use self::arp::{Hardware as ArpHardware,
                    Operation as ArpOperation,
                    Packet as ArpPacket,
                    Repr as ArpRepr};

pub use self::ip::{Version as IpVersion,
                   Protocol as IpProtocol,
                   Address as IpAddress,
                   Endpoint as IpEndpoint,
                   Repr as IpRepr,
                   Cidr as IpCidr};

#[cfg(feature = "proto-ipv4")]
pub use self::ipv4::{Address as Ipv4Address,
                     Packet as Ipv4Packet,
                     Repr as Ipv4Repr,
                     Cidr as Ipv4Cidr,
                     MIN_MTU as IPV4_MIN_MTU};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6::{Address as Ipv6Address,
                     Packet as Ipv6Packet,
                     Repr as Ipv6Repr,
                     Cidr as Ipv6Cidr,
                     MIN_MTU as IPV6_MIN_MTU};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6option::{Ipv6Option,
                           Repr as Ipv6OptionRepr,
                           Type as Ipv6OptionType,
                           FailureType as Ipv6OptionFailureType};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6hopbyhop::{Header as Ipv6HopByHopHeader,
                             Repr as Ipv6HopByHopRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6fragment::{Header as Ipv6FragmentHeader,
                             Repr as Ipv6FragmentRepr};

#[cfg(feature = "proto-ipv6")]
pub use self::ipv6routing::{Header as Ipv6RoutingHeader,
                            Repr as Ipv6RoutingRepr};

#[cfg(feature = "proto-ipv4")]
pub use self::icmpv4::{Message as Icmpv4Message,
                       DstUnreachable as Icmpv4DstUnreachable,
                       Redirect as Icmpv4Redirect,
                       TimeExceeded as Icmpv4TimeExceeded,
                       ParamProblem as Icmpv4ParamProblem,
                       Packet as Icmpv4Packet,
                       Repr as Icmpv4Repr};

#[cfg(feature = "proto-igmp")]
pub use self::igmp::{Packet as IgmpPacket,
                     Repr as IgmpRepr,
                     IgmpVersion};

#[cfg(feature = "proto-ipv6")]
pub use self::icmpv6::{Message as Icmpv6Message,
                       DstUnreachable as Icmpv6DstUnreachable,
                       TimeExceeded as Icmpv6TimeExceeded,
                       ParamProblem as Icmpv6ParamProblem,
                       Packet as Icmpv6Packet,
                       Repr as Icmpv6Repr};

#[cfg(any(feature = "proto-ipv4", feature = "proto-ipv6"))]
pub use self::icmp::Repr as IcmpRepr;


#[cfg(feature = "proto-ipv6")]
pub use self::ndisc::{Repr as NdiscRepr,
                      RouterFlags as NdiscRouterFlags,
                      NeighborFlags as NdiscNeighborFlags};

#[cfg(feature = "proto-ipv6")]
pub use self::ndiscoption::{NdiscOption,
                            Repr as NdiscOptionRepr,
                            Type as NdiscOptionType,
                            PrefixInformation as NdiscPrefixInformation,
                            RedirectedHeader as NdiscRedirectedHeader,
                            PrefixInfoFlags as NdiscPrefixInfoFlags};

#[cfg(feature = "proto-ipv6")]
pub use self::mld::{AddressRecord as MldAddressRecord,
                    Repr as MldRepr};

pub use self::udp::{Packet as UdpPacket,
                    Repr as UdpRepr};

pub use self::tcp::{SeqNumber as TcpSeqNumber,
                    Packet as TcpPacket,
                    TcpOption,
                    Repr as TcpRepr,
                    Control as TcpControl};

#[cfg(feature = "proto-dhcpv4")]
pub use self::dhcpv4::{Packet as DhcpPacket,
                       Repr as DhcpRepr,
                       MessageType as DhcpMessageType};
