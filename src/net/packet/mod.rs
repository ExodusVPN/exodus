

pub mod ethernet;

pub use self::ethernet::EthernetPacket as Packet;




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


