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
/// https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_packet_.E2.80.
/// 93_physical_layer
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    preamble: [u8; 7], // 7 bytes
    start_of_frame_delimiter: u8, // 1 byte
    frame: Frame<'a>, // 60–1522 bytes , Ethernet Frame
    check_sequence: [u8; 4], // 4 bytes
    interpacket_gap: [u8; 12], // 12 bytes
}

impl<'a> Packet<'a> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        let preamble: [u8; 7] = [
            payload[0],
            payload[1],
            payload[2],
            payload[3],
            payload[4],
            payload[5],
            payload[6],
        ];
        let start_of_frame_delimiter: u8 = payload[7];

        let interpacket_gap_start_pos = payload.len() - 12;

        match Frame::from_bytes(&payload[8..interpacket_gap_start_pos]) {
            Ok(frame) => {
                let frame_length = frame.len();
                let frame_check_sequence: [u8; 4] = [
                    payload[8 + frame_length + 0],
                    payload[8 + frame_length + 1],
                    payload[8 + frame_length + 2],
                    payload[8 + frame_length + 3],
                ];

                let interpacket_gap: [u8; 12] = [
                    payload[interpacket_gap_start_pos + 0],
                    payload[interpacket_gap_start_pos + 1],
                    payload[interpacket_gap_start_pos + 2],
                    payload[interpacket_gap_start_pos + 3],
                    payload[interpacket_gap_start_pos + 4],
                    payload[interpacket_gap_start_pos + 5],
                    payload[interpacket_gap_start_pos + 6],
                    payload[interpacket_gap_start_pos + 7],
                    payload[interpacket_gap_start_pos + 8],
                    payload[interpacket_gap_start_pos + 9],
                    payload[interpacket_gap_start_pos + 10],
                    payload[interpacket_gap_start_pos + 11],
                ];

                Ok(Packet {
                    preamble: preamble,
                    start_of_frame_delimiter: start_of_frame_delimiter,
                    frame: frame,
                    check_sequence: frame_check_sequence,
                    interpacket_gap: interpacket_gap,
                })
            }
            Err(e) => Err(e),
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
    pub fn check_sequence(&self) -> [u8; 4] {
        self.check_sequence
    }
    pub fn interpacket_gap(&self) -> [u8; 12] {
        self.interpacket_gap
    }
}
