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
pub mod icmpv4;
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

// Layer 1:
//     ethernet::Packet
// Layer 2:
//         ethernet::Frame
//         arp::Packet
//         ndp::Packet
// Layer 3:
//             ip::Packet
// Layer 4:
//                 icmp::Packet
//                 icmpv6::Packet
//                 tcp::Packet
//                 udp::Packet
// Layer 5:
//                 ip::Protocol::HTTP
//                 ip::Protocol::DNS
//                 ip::Protocol::SSH
//                 ip::Protocol::DHCP
//                 ip::Protocol::NTP

pub fn crc_32_checksum() {}

pub fn crc_64_checksum() {}
