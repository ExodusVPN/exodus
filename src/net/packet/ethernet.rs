
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

/**

TUN: simulates a network layer device and it operates with layer 3 packets like IP packets.
TAP: simulates a link layer device and it operates with layer 2 packets like Ethernet frames

TUN is used with routing, while TAP is used for creating a network bridge.


Ethernet Packet:
    preamble: 7 bytes,
    start_of_frame_delimiter: 1 byte,
    Ethernet Frame:
        dst_mac:       6 bytes,
        src_mac:       6 bytes,
        tag    :   0 - 8 bytes,
        ethertype:     2 bytes,
        payload:  46‑1500 bytes {
            IPv4 Packet:
                version: u8,         //  4 bits
                ihl : u8,            //  4 bits
                dscp: u8,            //  6 bits
                ecn: u8,             //  2 bits
                total_length: u16,   // 16 bits
                identification: u16, // 16 bits
                flags: u8,           //  3 bits
                fragment_offset: u16,// 13 bits
                time_to_live: u8,    //  8 bits
                protocol: Protocol,  //  8 bits
                header_checksum: u16,// 16 bits
                src_ip: Ipv4Addr,    // 32 bits
                dst_ip: Ipv4Addr,    // 32 bits
                options: Option<[u8; 12]>    // 0 - 96 bits, start 160, end 256, if IHL >= 5,
                payload: {
                    TCP Packet:
                        src_port: u16,
                        dst_port: u16,
                        sequence_number: u32,
                        acknowledgment_number: u32, // if ACK set
                        data_offset: u8,  // 4 bits
                        reserved: u8,     // 3 bits
                        flags   : u16,    // 9 bits, NS/CWR/ECE/URG/ACK/PSH/RST/SYN/FIN
                        window_size: u16,
                        checksum: u16,
                        urgent_pointer: u16, // if URG set
                        options: ...         // if data offset > 5. Padded at the end with "0" bytes if necessary
                        {
                            HTTP Packet:
                                ...
                        }
                    UDP Packet:
                        ...
                }
        },
        frame_check_sequence: 4 bytes,
    interpacket_gap:  12 bytes


pub enum Device {
    TAP(RawFd),
    TUN(RawFd)
}


pub trait Layer {
    fn name(&self) -> String;
    fn next_layer(&self) -> Option<Layer>;
}

pub struct InternetProtocolSuite {
    
}
impl InternetProtocolSuite for Layer {
    
}

pub struct OSIModel {
    
}
impl OSIModel for Layer {
    
}

**/

// IEEE 802 Numbers
// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
// http://standards-oui.ieee.org/ethertype/eth.txt
// https://en.wikipedia.org/wiki/EtherType
// http://www.cavebear.com/archive/cavebear/Ethernet/type.html
#[derive(Debug)]
pub enum EtherType {
    IPv4,
    ARP,
    WakeOnLAN,
    AppleTalk, 
    AppleTalkARP,
    VLAN,
    IPv6, 
    Unknow(u16)
}

impl EtherType {
    pub fn from_u16(n: u16) -> Result<Self, ::std::io::Error> {
        if n <= 0 || n > 0x9100 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, format!("[ERROR] EtherType({})  ...", n)));
        }
        use self::EtherType::*;
        match n {
            0x0800 => Ok(IPv4),
            0x0806 => Ok(ARP),
            0x0842 => Ok(WakeOnLAN),
            0x809B => Ok(AppleTalk),
            0x80F3 => Ok(AppleTalkARP),
            0x8100 => Ok(VLAN),
            0x86DD => Ok(IPv6),
            _      => Ok(Unknow(n))
        }
    }

    pub fn to_u16(&self) -> u16 {
        use self::EtherType::*;
        match *self {
            IPv4      => 0x0800,
            ARP       => 0x0806,
            WakeOnLAN => 0x0842,
            AppleTalk => 0x809B,
            AppleTalkARP => 0x80F3,
            VLAN      => 0x8100,
            IPv6      => 0x86DD,
            Unknow(n) => n
        }
    }

    // http://ieeexplore.ieee.org/browse/standards/get-program/page/series?id=68
    // https://en.wikipedia.org/wiki/IEEE_802
    // https://en.wikipedia.org/wiki/IEEE_802.1
    // https://en.wikipedia.org/wiki/IEEE_802.2
    // https://en.wikipedia.org/wiki/IEEE_802.3
    pub fn is_ieee_802_1q(&self) -> bool {
        // VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility
        self.to_u16() == 0x8100
    }
    pub fn is_ieee_802_ad(&self) -> bool {
        // VLAN-tagged (IEEE 802.1Q) frame with double tagging
        self.to_u16() == 0x88A8 || self.to_u16() == 0x9100
    }
    pub fn is_vlan(&self) -> bool {
        self.is_ieee_802_1q() || self.is_ieee_802_ad()
    }
    pub fn is_rfc_5227(&self) -> bool {
        // ARP (IPv4 Address Conflict Detection)
        self.to_u16() == 0x0806
    }
    pub fn is_apple_talk(&self) -> bool {
        // AppleTalk (Ethertalk)
        self.to_u16() == 0x809B
    }
    pub fn is_apple_talk_arp(&self) -> bool {
        // AppleTalk Address Resolution Protocol (AARP)
        self.to_u16() == 0x80F3
    }
    pub fn is_ip_v4(&self) -> bool {
        // Internet Protocol version 4 (IPv4)
        self.to_u16() == 0x0800
    }


    pub fn is_ieee_802_2_llc(&self) -> bool {
        // IEEE 802.2 Logical Link Control (LLC) frame
        // 1982 research, 1985 publish
        // status: disbanded
        self.to_u16() <= 1500
    }
    pub fn is_ieee_802_2_snap(&self) -> bool {
        // IEEE 802.2 Subnetwork Access Protocol (SNAP) frame
        // NOTE: Mac OS uses IEEE 802.2 LLC SAP/SNAP encapsulation for the AppleTalk v2 protocol suite on Ethernet (“EtherTalk”).
        self.to_u16() <= 1500
    }
    pub fn is_ethernet_v1(&self) -> bool {
        // Ethernet I frame
        // 1980 DEC, Intel, Xerox
        // status: obsolete
        false
    }
    pub fn is_ethernet_v2(&self) -> bool {
        // Ethernet II frame
        // 1982 DIX (DEC, Intel, Xerox)
        // status: active
        self.to_u16() >= 1536
    }
    pub fn is_ieee_802_3_novell_raw(&self) -> bool {
        // Novell raw IEEE 802.3 non-standard variation frame
        // https://support.novell.com/techcenter/articles/ana19930905.html
        self.to_u16() <= 1500
    }
    pub fn is_ieee_802_3(&self) -> bool {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct EthernetFrameTag {
    tpid: u16,   // 16 bits
    tci : u16    // 16 bits
}

impl EthernetFrameTag {
    pub fn get_tpid(&self) -> u16 {
        self.tpid
    }

    pub fn get_tci(&self) -> u16 {
        self.tci
    }
    pub fn get_pcp(&self) -> u8 {
        (self.tci >> 13) as u8
    }
    pub fn get_dei(&self) -> u8 {
        ((self.tci >> 12) as u8)  >> 1
    }
    pub fn get_vid(&self) -> u16 {
        (self.tci >> 12)
    }
}


#[derive(Debug)]
pub struct EthernetPacket {
    // PhysicalLayer: Layer 1 Ethernet packet & IPG
    // https://en.wikipedia.org/wiki/Ethernet_frame#Ethernet_packet_.E2.80.93_physical_layer
    preamble: [u8; 7],             //  7 bytes
    start_of_frame_delimiter: u8,  //  1 byte

    // DataLinkLayer: Layer 2 Ethernet frame  64–1522 bytes
    dst_mac:    [u8; 6],           // 6 bytes
    src_mac:    [u8; 6],           // 6 bytes
    tag    :   Option<[Option<EthernetFrameTag>; 2]>,    // 802.1Q tag (4 bytes)
    ethertype:  EtherType,         // 2 bytes NOTE: EtherType(Ethernet II)  or length(IEEE 802.3)
    payload:    Vec<u8>,           // 46‑1500 bytes
    frame_check_sequence: [u8; 4], // 4 bytes

    // End of frame – physical layer
    interpacket_gap: [u8; 12]      // 12 bytes
}


impl EthernetPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 8 + 16 + 12 {
            // MAYBE: 8 + (16 + 64) + 12
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."));
        }
        
        let end_num = 4;
        let mut bytes = Cursor::new(&payload[0..payload.len()-end_num]);

        let preamble: [u8; 7];
        let start_of_frame_delimiter: u8;

        if end_num == 16 {
            preamble = [
                bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
                bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
                bytes.read_u8().unwrap()
            ];
            start_of_frame_delimiter = bytes.read_u8().unwrap();
        } else {
            preamble = [0; 7];
            start_of_frame_delimiter = 0;
        }
        
        
        println!("{:?}", &preamble.into_iter().map(|b: &u8| format!("{:08b}", b)).collect::<Vec<String>>().join(" "));

        // Ethernet frame
        let dst_mac: [u8; 6] = [
            bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
            bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
        ];
        let src_mac: [u8; 6] = [
            bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
            bytes.read_u8().unwrap(), bytes.read_u8().unwrap(), bytes.read_u8().unwrap(),
        ];
        match EtherType::from_u16(bytes.read_u16::<BigEndian>().unwrap()) {
            Ok(ethertype_or_tpid) => {
                let tag: Option<[Option<EthernetFrameTag>; 2]>;
                let ethertype;
                let mut content: Vec<u8> = Vec::new();

                if ethertype_or_tpid.is_ieee_802_1q() {
                    tag = Some([
                        Some(EthernetFrameTag{tpid: ethertype_or_tpid.to_u16(), tci: bytes.read_u16::<BigEndian>().unwrap()}),
                        None
                    ]);
                    ethertype = EtherType::from_u16(bytes.read_u16::<BigEndian>().unwrap()).unwrap();
                } else if ethertype_or_tpid.is_ieee_802_ad() {
                    tag = Some([
                        // 0x8100, 0xNNNN
                        Some(EthernetFrameTag{tpid: ethertype_or_tpid.to_u16(), tci: bytes.read_u16::<BigEndian>().unwrap()}),
                        // 0x88A8 || 0x9100, 0xNNNN
                        Some(EthernetFrameTag{tpid: bytes.read_u16::<BigEndian>().unwrap(), tci: bytes.read_u16::<BigEndian>().unwrap()})
                    ]);
                    ethertype = EtherType::from_u16(bytes.read_u16::<BigEndian>().unwrap()).unwrap();
                } else {
                    // WARN: if IEEE 802.3 frame
                    //          `ethertype` is length of `payload` (unsure.)
                    tag = None;
                    ethertype = ethertype_or_tpid;
                    
                }

                loop {
                    match bytes.read_u8() {
                        Ok(b) => content.push(b),
                        Err(e) => match e.kind() {
                            ::std::io::ErrorKind::UnexpectedEof => break,
                            _ => break
                        }
                    }
                }

                let mut bytes2 = Cursor::new(&payload[(payload.len()-end_num)..payload.len()]);
                let frame_check_sequence: [u8; 4] = [
                    bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(), 
                    bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap()
                ];

                let interpacket_gap: [u8; 12];
                if end_num == 16 {
                    interpacket_gap = [
                        bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(),
                        bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(),
                        bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(),
                        bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap(), bytes2.read_u8().unwrap()
                    ];
                } else {
                    interpacket_gap = [0; 12];
                }


                Ok(EthernetPacket{
                    preamble: preamble,
                    start_of_frame_delimiter: start_of_frame_delimiter,

                    dst_mac  : dst_mac,
                    src_mac  : src_mac,
                    tag      : tag,
                    ethertype: ethertype,
                    payload  : content,
                    frame_check_sequence:  frame_check_sequence,

                    interpacket_gap: interpacket_gap
                })
            },
            Err(e) => Err(e)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}
