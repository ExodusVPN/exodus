#![feature(i128_type)]

extern crate byteorder;

/// OSI Model Layer 1 & 2
pub mod ethernet;

/// OSI Model Layer 3
pub mod ndp;
/// OSI Model Layer 3
pub mod arp;
/// OSI Model Layer 3
pub mod ip;

/// OSI Model Layer 4
pub mod tcp;
/// OSI Model Layer 4
pub mod udp;
/// OSI Model Layer 4
pub mod icmp;
/// OSI Model Layer 4
pub mod icmpv6;


// OSI Model
// #[derive(Debug)]
// pub enum Layer {
//     Application,
//     Transport,
//     Network,     // Internet
//     DataLink,
//     Physical
// }

// pub enum Physical {}
// pub enum DataLink {
//     ARP(ARPPacket),
//     NDP(NDPPacket),
//     L2TP(L2TPPacket),
//     PPP(PPPPacet)
//     Ethernet(EthernetPacket),
// }
// pub enum Network {
//     IPv4,
//     IPv6,
//     ICMP,
//     ICMPv6,
//     ECN,
//     IGMP,
//     IGMPv6
// }
// pub enum Transport {
//     TCP,
//     UDP,
//     DCCP,
//     SCTP,
//     RSVP
// }
// pub enum Application {
//     BGP,
//     DHCP,
//     DNS,
//     FTP,
//     HTTP,
//     IMAP,
//     LDAP,
//     MGCP,
//     NTP,
//     SSH,

//     DHCPv6,
//     DNSv6
// }

// Layer 1:
//     ethernet::EthernetPacket
// Layer 2:
//         ethernet::EthernetFrame
//         arp::ArpPacket
//         ndp::NdpPacket
// Layer 3:
//             ip::IpPacket
// Layer 4:
//                 ip::v4::tcp::IcmpPacket
//                 ip::v4::tcp::UdpPacket
//                 ip::v4::tcp::TcpPacket
// Layer 5:
//                 ip::Protocol::HTTP

pub fn crc_32_checksum(){

}

pub fn crc_64_checksum(){

}