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

pub mod checksum {
    use ::byteorder::{ByteOrder, NetworkEndian};

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        let nword = ((sum >> 16) as u16) + (sum as u16);
        println!("Word: {} Nword: {}", word, nword);
        nword
    }

    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    pub fn data(data: &[u8]) -> u16 {
        let mut accum: u32 = 0;
        let mut i = 0;
        while i < data.len() {
            let word;
            if i + 2 <= data.len() {
                word = NetworkEndian::read_u16(&data[i..i + 2]) as u32
            } else {
                word = (data[i] as u32) << 8
            }
            accum += word;
            i += 2;
        }
        propagate_carries(accum)
    }
}