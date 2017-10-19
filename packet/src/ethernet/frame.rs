


/// IEEE 802 Numbers
///
/// https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
///
/// http://standards-oui.ieee.org/ethertype/eth.txt
///
/// https://en.wikipedia.org/wiki/EtherType
///
/// http://www.cavebear.com/archive/cavebear/Ethernet/type.html
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    IPv4,
    ARP,
    WakeOnLAN,
    AppleTalk, 
    AppleTalkARP,
    VLAN,
    IPv6, 
    Unknow(u16)
}

#[derive(Debug, PartialEq, Eq)]
pub struct Tag {
    tpid: u16,   // 16 bits
    tci : u16    // 16 bits
}

/// DataLinkLayer: Layer 2 Ethernet frame
/// 
/// Length: 64–1522 bytes
///
/// https://en.wikipedia.org/wiki/Maximum_transmission_unit
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    dst_mac: [u8; 6],        //       6 bytes
    src_mac: [u8; 6],        //       6 bytes
    tag_one: Option<Tag>,    //       4 bytes , IEEE 802.1Q tag
    tag_two: Option<Tag>,    //       4 bytes , IEEE 802.ad tag (double tagging)
    kind   : Kind,           //       2 bytes , NOTE: EtherType(Ethernet II)  or length(IEEE 802.3)
    payload: &'a [u8],       // 46‑1500 bytes , https://en.wikipedia.org/wiki/Maximum_transmission_unit
    check_sequence: [u8; 4], //       4 bytes
}

impl Kind {
    pub fn from_u16(n: u16) -> Result<Self, ::std::io::Error> {
        if n <= 0 || n > 0x9100 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, format!("[ERROR] EtherType({})  ...", n)));
        }
        use self::Kind::*;
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
        use self::Kind::*;
        match *self {
            IPv4         => 0x0800,
            ARP          => 0x0806,
            WakeOnLAN    => 0x0842,
            AppleTalk    => 0x809B,
            AppleTalkARP => 0x80F3,
            VLAN         => 0x8100,
            IPv6         => 0x86DD,
            Unknow(n)    => n
        }
    }
    #[allow(unused_variables)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!()
    }
    pub fn from_u8(a: u8, b: u8) -> Result<Self, ::std::io::Error> {
        let number = ((a as u16) << 8 ) | (b as u16);
        Kind::from_u16(number)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        let number = self.to_u16();
        [ ((number >> 8) & 0xff) as u8, (number & 0xff) as u8 ]
    }

    // http://ieeexplore.ieee.org/browse/standards/get-program/page/series?id=68
    // https://en.wikipedia.org/wiki/IEEE_802
    // https://en.wikipedia.org/wiki/IEEE_802.1
    // https://en.wikipedia.org/wiki/IEEE_802.2
    // https://en.wikipedia.org/wiki/IEEE_802.3
    /// VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility
    pub fn is_ieee_802_1q(&self) -> bool {
        self.to_u16() == 0x8100
    }
    /// VLAN-tagged (IEEE 802.1Q) frame with double tagging
    pub fn is_ieee_802_ad(&self) -> bool {
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
    /// Internet Protocol version 4 (IPv4)
    pub fn is_ip_v4(&self) -> bool {
        self.to_u16() == 0x0800
    }
    /// Internet Protocol version 6 (IPv6)
    pub fn is_ip_v6(&self) -> bool {
        self.to_u16() == 0x86DD
    }

    /// Ethernet Frame Type
    /// 
    /// IEEE 802.2 Logical Link Control (LLC) frame
    pub fn is_ieee_802_2_llc(&self) -> bool {
        // 1982 research, 1985 publish
        // status: disbanded
        self.to_u16() <= 1500
    }
    /// IEEE 802.2 Subnetwork Access Protocol (SNAP) frame
    /// 
    /// NOTE:
    /// > Mac OS uses IEEE 802.2 LLC SAP/SNAP encapsulation for the AppleTalk v2 protocol suite on Ethernet (“EtherTalk”).
    pub fn is_ieee_802_2_snap(&self) -> bool {
        self.to_u16() <= 1500
    }
    /// Ethernet I frame
    pub fn is_ethernet_v1(&self) -> bool {
        // 1980 DEC, Intel, Xerox
        // status: obsolete
        false
    }
    /// Ethernet II frame
    pub fn is_ethernet_v2(&self) -> bool {
        // 1982 DIX (DEC, Intel, Xerox)
        // status: active
        self.to_u16() >= 1536
    }
    /// Novell raw IEEE 802.3 non-standard variation frame
    pub fn is_ieee_802_3_novell_raw(&self) -> bool {
        // https://support.novell.com/techcenter/articles/ana19930905.html
        self.to_u16() <= 1500
    }
    /// IEEE 802.3 frame
    pub fn is_ieee_802_3(&self) -> bool {
        unimplemented!()
    }
}


impl Tag {
    #[allow(unused_variables)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!()
    }
    pub fn from_u8(a: u8, b: u8, c: u8, d: u8) -> Result<Self, ::std::io::Error> {
        use std::mem::transmute;
        Ok(Tag {
            tpid: unsafe { transmute([a, b]) },
            tci : unsafe { transmute([c, d]) }
        })
    }
    pub fn from_u16(a: u16, b: u16) -> Result<Self, ::std::io::Error> {
        Ok(Tag {
            tpid: a,
            tci : b
        })
    }
    pub fn as_bytes(&self) -> [u8; 4] {
        use std::mem::transmute;
        let bytes1: [u8; 2] = unsafe { transmute(self.tpid.to_be()) };
        let bytes2: [u8; 2] = unsafe { transmute(self.tci.to_be()) };
        [ bytes1[0], bytes1[1], bytes2[0], bytes2[1] ]
        // &[
        //     ((self.tpid >> 8) & 0xff) as u8, (self.tpid & 0xff) as u8,
        //     ((self.tci >> 8) & 0xff) as u8, (self.tci & 0xff) as u8
        // ]
    }

    pub fn get_tpid(&self) -> u16 {
        self.tpid
    }
    pub fn get_tci(&self) -> u16 {
        self.tci
    }
    /// TCI: PCP
    pub fn get_pcp(&self) -> u8 {
        (self.tci >> 13) as u8
    }
    /// TCI: DEI
    pub fn get_dei(&self) -> u8 {
        ((self.tci >> 12) as u8)  >> 1
    }
    /// TCI: VID
    pub fn get_vid(&self) -> u16 {
        (self.tci >> 12)
    }
}

impl <'a> Frame <'a>{
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        // Ethernet frame
        if payload.len() < 30 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."));
        }

        let dst_mac: [u8; 6] = [
            payload[0], payload[1], payload[2],
            payload[3], payload[4], payload[5]
        ];
        let src_mac: [u8; 6] = [
            payload[6], payload[7], payload[8],
            payload[9], payload[10], payload[11]
        ];
        let ether_type_res = Kind::from_u8(payload[12], payload[13]);
        if ether_type_res.is_err() {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."));
        }
        let ether_type = ether_type_res.unwrap();
        if !ether_type.is_ethernet_v2() {
            // WARN: Only Support Ethernet version 2 frame
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "Oh, no ..."));
        }
        
        let tag_one: Option<Tag>;
        let tag_two: Option<Tag>;
        let frame_kind: Kind;

        let content_start_pos: usize;

        if ether_type.is_ieee_802_1q() {
            // One Tag
            tag_one = Some(Tag::from_u8(payload[12], payload[13], payload[14], payload[15]).unwrap());
            tag_two = None;
            frame_kind = Kind::from_u8(payload[16], payload[17]).unwrap();
            content_start_pos = 18;
        } else if ether_type.is_ieee_802_ad() {
            // Two Tag
            tag_one = Some(Tag::from_u8(payload[12], payload[13], payload[14], payload[15]).unwrap());
            tag_two = Some(Tag::from_u8(payload[16], payload[17], payload[18], payload[19]).unwrap());
            frame_kind = Kind::from_u8(payload[20], payload[21]).unwrap();
            content_start_pos = 22;
        } else {
            // WARN: if IEEE 802.3 frame
            //          `ethertype(frame_kind)` is length of `payload` (unsure.
            tag_one    = None;
            tag_two    = None;
            frame_kind = ether_type;
            content_start_pos = 14;
        }

        let content_end_pos = payload.len() - 4;

        let frame_check_sequence: [u8; 4] = [
            payload[content_end_pos]  , payload[content_end_pos+1], 
            payload[content_end_pos+2], payload[content_end_pos+3], 
        ];
        use std::mem::transmute;
        Ok(Frame{
            dst_mac: dst_mac,
            src_mac: src_mac,
            tag_one: tag_one,
            tag_two: tag_two,
            kind   : frame_kind,
            payload: unsafe { transmute(&payload[content_start_pos..content_end_pos]) },
            check_sequence: frame_check_sequence
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    // dst_mac: [u8; 6],        //       6 bytes
    // src_mac: [u8; 6],        //       6 bytes
    // tag_one: Option<Tag>,    //       4 bytes , IEEE 802.1Q tag
    // tag_two: Option<Tag>,    //       4 bytes , IEEE 802.ad tag (double tagging)
    // kind   : Kind,           //       2 bytes , NOTE: EtherType(Ethernet II)  or length(IEEE 802.3)
    // payload: &'a [u8],       // 46‑1500 bytes , https://en.wikipedia.org/wiki/Maximum_transmission_unit
    // check_sequence: [u8; 4], //       4 bytes
    pub fn dst_mac(&self) -> [u8; 6]{
        self.dst_mac
    }
    pub fn src_mac(&self) -> [u8; 6]{
        self.src_mac
    }
    pub fn tag_one(&self) -> &Option<Tag> {
        &self.tag_one
    }
    pub fn tag_two(&self) -> &Option<Tag> {
        &self.tag_two
    }
    pub fn kind(&self) -> &Kind {
        &self.kind
    }
    pub fn ethertype(&self) -> &Kind {
        self.kind()
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
    pub fn check_sequence(&self) -> [u8; 4] {
        self.check_sequence
    }
    
    /// IEEE 802.2 Logical Link Control (LLC) frame
    pub fn is_ieee_802_2_llc(&self) -> bool {
        self.kind.is_ieee_802_2_llc()
    }
    /// IEEE 802.2 Subnetwork Access Protocol (SNAP) frame
    pub fn is_ieee_802_2_snap(&self) -> bool {
        self.kind.is_ieee_802_2_snap()
    }
    /// Ethernet I frame
    pub fn is_ethernet_v1(&self) -> bool {
        self.kind.is_ethernet_v1()
    }
    /// Ethernet II frame
    pub fn is_ethernet_v2(&self) -> bool {
        self.kind.is_ethernet_v2()
    }
    /// Novell raw IEEE 802.3 non-standard variation frame
    pub fn is_ieee_802_3_novell_raw(&self) -> bool {
        self.kind.is_ieee_802_3_novell_raw()
    }
    /// IEEE 802.3 frame
    pub fn is_ieee_802_3(&self) -> bool {
        self.kind.is_ieee_802_3()
    }
}
