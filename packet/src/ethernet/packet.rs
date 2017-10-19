
use super::Frame;

// pub enum Frame {
//     EthernetV1,                  // Ethernet I frame
//     EthernetV2(EthernetV2Frame), // Ethernet II frame
//     NovellRawIEEE8023,           // Novell raw IEEE 802.3 frame
//     IEEE8022LLC,                 // IEEE 802.2 LLC frame
//     IEEE8022SNAP,                // IEEE 802.2 SNAP frame
// }

/// PhysicalLayer: Layer 1 Ethernet packet & IPG
/// 
/// https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_packet_.E2.80.93_physical_layer
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    preamble                : [u8; 7],   //  7 bytes
    start_of_frame_delimiter: u8,        //  1 byte
    frame                   : Frame<'a>, // .. bytes , Ethernet Frame
    interpacket_gap         : [u8; 12]   // 12 bytes
}

impl <'a> Packet<'a> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        let preamble: [u8; 7] = [
            payload[0], payload[1], payload[2], payload[3], 
            payload[4], payload[5], payload[6]
        ];
        let start_of_frame_delimiter: u8 = payload[7];

        let interpacket_gap_start_pos = payload.len() - 12;
        match Frame::from_bytes(&payload[8..interpacket_gap_start_pos]) {
            Ok(frame) => {
                let mut interpacket_gap: [u8; 12] = [0; 12];
                // unsafe { transmute() };
                interpacket_gap.clone_from_slice(&payload[interpacket_gap_start_pos..(interpacket_gap_start_pos+12)]);
                Ok(Packet{
                    preamble: preamble,
                    start_of_frame_delimiter: start_of_frame_delimiter,
                    frame: frame,
                    interpacket_gap: interpacket_gap
                })
            },
            Err(e) => Err(e)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
    
    pub fn preamble(&self) -> [u8; 7] {
        self.preamble
    }
    pub fn start_of_frame_delimiter(&self) -> u8 {
        self.start_of_frame_delimiter
    }
    pub fn frame(&self) -> &'a Frame {
        &self.frame
    }
    pub fn interpacket_gap(&self) -> [u8; 12] {
        self.interpacket_gap
    }
}

