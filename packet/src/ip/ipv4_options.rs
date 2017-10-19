

/// IPv4 OPTION NUMBERS
/// 
/// https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
///
/// Format:
/// 
///     copy  : 1  bits
///     class : 2  bits
///     number: 5  bits
///     value : 8  bits
///     data  : .. bits
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Option<'a> {
    /// Option Fields: copied(copy), class, number, value(length)
    kind: Ipv4OptionClass,
    /// Option-specific data. This field may not exist for simple options.
    data: &'a [u8]
}

impl <'a>Ipv4Option<'a> {
    pub fn new(kind: Ipv4OptionClass, data: &'a [u8]) -> Result<Self, ::std::io::Error>{
        Ok(Ipv4Option {
            kind: kind,
            data: data
        })
    }
    pub fn kind(&self) -> &Ipv4OptionClass {
        &self.kind
    }
    pub fn data(&self) -> &'a [u8] {
        &self.data
    }
}




#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum Ipv4OptionClass {
    EOOL, // End of Options List, [RFC791][Jon_Postel]
    NOP, // No Operation, [RFC791][Jon_Postel]
    SEC, // Security, [RFC1108]
    LSR, // Loose Source Route, [RFC791][Jon_Postel]
    TS, // Time Stamp, [RFC791][Jon_Postel]
    E_SEC, // Extended Security, [RFC1108]
    CIPSO, // Commercial Security, [draft-ietf-cipso-ipsecurity-01]
    RR, // Record Route, [RFC791][Jon_Postel]
    SID, // Stream ID, [RFC791][Jon_Postel][RFC6814][1]
    SSR, // Strict Source Route, [RFC791][Jon_Postel]
    ZSU, // Experimental Measurement, [ZSu]
    MTUP, // MTU Probe, [RFC1063][RFC1191][1]
    MTUR, // MTU Reply, [RFC1063][RFC1191][1]
    FINN, // Experimental Flow Control, [Greg_Finn]
    VISA, // Experimental Access Control, [Deborah_Estrin][RFC6814][1]
    ENCODE, // ???, [VerSteeg][RFC6814][1]
    IMITD, // IMI Traffic Descriptor, [Lee]
    EIP, // Extended Internet Protocol, [RFC1385][RFC6814][1]
    TR, // Traceroute, [RFC1393][RFC6814][1]
    ADDEXT, // Address Extension, [Ullmann IPv7][RFC6814][1]
    RTRALT, // Router Alert, [RFC2113]
    SDB, // Selective Directed Broadcast, [Charles_Bud_Graff][RFC6814][1]
    DPS, // Dynamic Packet State, [Andy_Malis][RFC6814][1]
    UMP, // Upstream Multicast Pkt., [Dino_Farinacci][RFC6814][1]
    QS, // Quick-Start, [RFC4782]
    EXP1, // RFC3692-style Experiment [2], [RFC4727]
    EXP2, // RFC3692-style Experiment [2], [RFC4727]
    EXP3, // RFC3692-style Experiment [2], [RFC4727]
    EXP4, // RFC3692-style Experiment [2], [RFC4727]
}

impl Ipv4OptionClass {
    pub fn new(ccn: u8, value: u8) -> Result<Self, ::std::io::Error> {
        println!("ccn: {:?}  value: {:?}", ccn, value);
        match (ccn, value) {
            (0, 0) => Ok(Ipv4OptionClass::EOOL),
            (1, 1) => Ok(Ipv4OptionClass::NOP),
            (130, 130) => Ok(Ipv4OptionClass::SEC),
            (131, 131) => Ok(Ipv4OptionClass::LSR),
            (68, 68) => Ok(Ipv4OptionClass::TS),
            (133, 133) => Ok(Ipv4OptionClass::E_SEC),
            (134, 134) => Ok(Ipv4OptionClass::CIPSO),
            (7, 7) => Ok(Ipv4OptionClass::RR),
            (136, 136) => Ok(Ipv4OptionClass::SID),
            (137, 137) => Ok(Ipv4OptionClass::SSR),
            (10, 10) => Ok(Ipv4OptionClass::ZSU),
            (11, 11) => Ok(Ipv4OptionClass::MTUP),
            (12, 12) => Ok(Ipv4OptionClass::MTUR),
            (205, 205) => Ok(Ipv4OptionClass::FINN),
            (142, 142) => Ok(Ipv4OptionClass::VISA),
            (15, 15) => Ok(Ipv4OptionClass::ENCODE),
            (144, 144) => Ok(Ipv4OptionClass::IMITD),
            (145, 145) => Ok(Ipv4OptionClass::EIP),
            (82, 82) => Ok(Ipv4OptionClass::TR),
            (147, 147) => Ok(Ipv4OptionClass::ADDEXT),
            (148, 148) => Ok(Ipv4OptionClass::RTRALT),
            (149, 149) => Ok(Ipv4OptionClass::SDB),
            (151, 151) => Ok(Ipv4OptionClass::DPS),
            (152, 152) => Ok(Ipv4OptionClass::UMP),
            (25, 25) => Ok(Ipv4OptionClass::QS),
            (30, 30) => Ok(Ipv4OptionClass::EXP1),
            (94, 94) => Ok(Ipv4OptionClass::EXP2),
            (158, 158) => Ok(Ipv4OptionClass::EXP3),
            (222, 222) => Ok(Ipv4OptionClass::EXP4),
            (_, _) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "IPv4 Options value error (copy/class/number/value) ..."))
        }
    }

    /// Option copy field
    pub fn copied(&self) -> u8 {
        match *self {
            Ipv4OptionClass::EOOL => 0,
            Ipv4OptionClass::NOP => 0,
            Ipv4OptionClass::SEC => 1,
            Ipv4OptionClass::LSR => 1,
            Ipv4OptionClass::TS => 0,
            Ipv4OptionClass::E_SEC => 1,
            Ipv4OptionClass::CIPSO => 1,
            Ipv4OptionClass::RR => 0,
            Ipv4OptionClass::SID => 1,
            Ipv4OptionClass::SSR => 1,
            Ipv4OptionClass::ZSU => 0,
            Ipv4OptionClass::MTUP => 0,
            Ipv4OptionClass::MTUR => 0,
            Ipv4OptionClass::FINN => 1,
            Ipv4OptionClass::VISA => 1,
            Ipv4OptionClass::ENCODE => 0,
            Ipv4OptionClass::IMITD => 1,
            Ipv4OptionClass::EIP => 1,
            Ipv4OptionClass::TR => 0,
            Ipv4OptionClass::ADDEXT => 1,
            Ipv4OptionClass::RTRALT => 1,
            Ipv4OptionClass::SDB => 1,
            Ipv4OptionClass::DPS => 1,
            Ipv4OptionClass::UMP => 1,
            Ipv4OptionClass::QS => 0,
            Ipv4OptionClass::EXP1 => 0,
            Ipv4OptionClass::EXP2 => 0,
            Ipv4OptionClass::EXP3 => 1,
            Ipv4OptionClass::EXP4 => 1,
        }
    }

    /// Option class field
    pub fn kind(&self) -> u8 {
        match *self {
            Ipv4OptionClass::EOOL => 0,
            Ipv4OptionClass::NOP => 0,
            Ipv4OptionClass::SEC => 0,
            Ipv4OptionClass::LSR => 0,
            Ipv4OptionClass::TS => 2,
            Ipv4OptionClass::E_SEC => 0,
            Ipv4OptionClass::CIPSO => 0,
            Ipv4OptionClass::RR => 0,
            Ipv4OptionClass::SID => 0,
            Ipv4OptionClass::SSR => 0,
            Ipv4OptionClass::ZSU => 0,
            Ipv4OptionClass::MTUP => 0,
            Ipv4OptionClass::MTUR => 0,
            Ipv4OptionClass::FINN => 2,
            Ipv4OptionClass::VISA => 0,
            Ipv4OptionClass::ENCODE => 0,
            Ipv4OptionClass::IMITD => 0,
            Ipv4OptionClass::EIP => 0,
            Ipv4OptionClass::TR => 2,
            Ipv4OptionClass::ADDEXT => 0,
            Ipv4OptionClass::RTRALT => 0,
            Ipv4OptionClass::SDB => 0,
            Ipv4OptionClass::DPS => 0,
            Ipv4OptionClass::UMP => 0,
            Ipv4OptionClass::QS => 0,
            Ipv4OptionClass::EXP1 => 0,
            Ipv4OptionClass::EXP2 => 2,
            Ipv4OptionClass::EXP3 => 0,
            Ipv4OptionClass::EXP4 => 2,
        }
    }

    /// Option number field
    pub fn number(&self) -> u8 {
        match *self {
            Ipv4OptionClass::EOOL => 0,
            Ipv4OptionClass::NOP => 1,
            Ipv4OptionClass::SEC => 2,
            Ipv4OptionClass::LSR => 3,
            Ipv4OptionClass::TS => 4,
            Ipv4OptionClass::E_SEC => 5,
            Ipv4OptionClass::CIPSO => 6,
            Ipv4OptionClass::RR => 7,
            Ipv4OptionClass::SID => 8,
            Ipv4OptionClass::SSR => 9,
            Ipv4OptionClass::ZSU => 10,
            Ipv4OptionClass::MTUP => 11,
            Ipv4OptionClass::MTUR => 12,
            Ipv4OptionClass::FINN => 13,
            Ipv4OptionClass::VISA => 14,
            Ipv4OptionClass::ENCODE => 15,
            Ipv4OptionClass::IMITD => 16,
            Ipv4OptionClass::EIP => 17,
            Ipv4OptionClass::TR => 18,
            Ipv4OptionClass::ADDEXT => 19,
            Ipv4OptionClass::RTRALT => 20,
            Ipv4OptionClass::SDB => 21,
            Ipv4OptionClass::DPS => 23,
            Ipv4OptionClass::UMP => 24,
            Ipv4OptionClass::QS => 25,
            Ipv4OptionClass::EXP1 => 30,
            Ipv4OptionClass::EXP2 => 30,
            Ipv4OptionClass::EXP3 => 30,
            Ipv4OptionClass::EXP4 => 30,
        }
    }

    /// Option (copy, class, number) fields
    pub fn ccn(&self) -> u8 {
        match *self {
            Ipv4OptionClass::EOOL => 0, // 0b0
            Ipv4OptionClass::NOP => 1, // 0b1
            Ipv4OptionClass::SEC => 130, // 0b10000010
            Ipv4OptionClass::LSR => 131, // 0b10000011
            Ipv4OptionClass::TS => 68, // 0b1000100
            Ipv4OptionClass::E_SEC => 133, // 0b10000101
            Ipv4OptionClass::CIPSO => 134, // 0b10000110
            Ipv4OptionClass::RR => 7, // 0b111
            Ipv4OptionClass::SID => 136, // 0b10001000
            Ipv4OptionClass::SSR => 137, // 0b10001001
            Ipv4OptionClass::ZSU => 10, // 0b1010
            Ipv4OptionClass::MTUP => 11, // 0b1011
            Ipv4OptionClass::MTUR => 12, // 0b1100
            Ipv4OptionClass::FINN => 205, // 0b11001101
            Ipv4OptionClass::VISA => 142, // 0b10001110
            Ipv4OptionClass::ENCODE => 15, // 0b1111
            Ipv4OptionClass::IMITD => 144, // 0b10010000
            Ipv4OptionClass::EIP => 145, // 0b10010001
            Ipv4OptionClass::TR => 82, // 0b1010010
            Ipv4OptionClass::ADDEXT => 147, // 0b10010011
            Ipv4OptionClass::RTRALT => 148, // 0b10010100
            Ipv4OptionClass::SDB => 149, // 0b10010101
            Ipv4OptionClass::DPS => 151, // 0b10010111
            Ipv4OptionClass::UMP => 152, // 0b10011000
            Ipv4OptionClass::QS => 25, // 0b11001
            Ipv4OptionClass::EXP1 => 30, // 0b11110
            Ipv4OptionClass::EXP2 => 94, // 0b1011110
            Ipv4OptionClass::EXP3 => 158, // 0b10011110
            Ipv4OptionClass::EXP4 => 222, // 0b11011110
        }
    }

    /// Option value(length) field
    pub fn length(&self) -> u8 {
        match *self {
            Ipv4OptionClass::EOOL => 0,
            Ipv4OptionClass::NOP => 1,
            Ipv4OptionClass::SEC => 130,
            Ipv4OptionClass::LSR => 131,
            Ipv4OptionClass::TS => 68,
            Ipv4OptionClass::E_SEC => 133,
            Ipv4OptionClass::CIPSO => 134,
            Ipv4OptionClass::RR => 7,
            Ipv4OptionClass::SID => 136,
            Ipv4OptionClass::SSR => 137,
            Ipv4OptionClass::ZSU => 10,
            Ipv4OptionClass::MTUP => 11,
            Ipv4OptionClass::MTUR => 12,
            Ipv4OptionClass::FINN => 205,
            Ipv4OptionClass::VISA => 142,
            Ipv4OptionClass::ENCODE => 15,
            Ipv4OptionClass::IMITD => 144,
            Ipv4OptionClass::EIP => 145,
            Ipv4OptionClass::TR => 82,
            Ipv4OptionClass::ADDEXT => 147,
            Ipv4OptionClass::RTRALT => 148,
            Ipv4OptionClass::SDB => 149,
            Ipv4OptionClass::DPS => 151,
            Ipv4OptionClass::UMP => 152,
            Ipv4OptionClass::QS => 25,
            Ipv4OptionClass::EXP1 => 30,
            Ipv4OptionClass::EXP2 => 94,
            Ipv4OptionClass::EXP3 => 158,
            Ipv4OptionClass::EXP4 => 222,
        }
    }
    pub fn description(&self) -> &'static str {
        match *self {
            Ipv4OptionClass::EOOL => "End of Options List , [RFC791][Jon_Postel]",
            Ipv4OptionClass::NOP => "No Operation , [RFC791][Jon_Postel]",
            Ipv4OptionClass::SEC => "Security , [RFC1108]",
            Ipv4OptionClass::LSR => "Loose Source Route , [RFC791][Jon_Postel]",
            Ipv4OptionClass::TS => "Time Stamp , [RFC791][Jon_Postel]",
            Ipv4OptionClass::E_SEC => "Extended Security , [RFC1108]",
            Ipv4OptionClass::CIPSO => "Commercial Security , [draft-ietf-cipso-ipsecurity-01]",
            Ipv4OptionClass::RR => "Record Route , [RFC791][Jon_Postel]",
            Ipv4OptionClass::SID => "Stream ID , [RFC791][Jon_Postel][RFC6814][1]",
            Ipv4OptionClass::SSR => "Strict Source Route , [RFC791][Jon_Postel]",
            Ipv4OptionClass::ZSU => "Experimental Measurement , [ZSu]",
            Ipv4OptionClass::MTUP => "MTU Probe , [RFC1063][RFC1191][1]",
            Ipv4OptionClass::MTUR => "MTU Reply , [RFC1063][RFC1191][1]",
            Ipv4OptionClass::FINN => "Experimental Flow Control , [Greg_Finn]",
            Ipv4OptionClass::VISA => "Experimental Access Control , [Deborah_Estrin][RFC6814][1]",
            Ipv4OptionClass::ENCODE => "??? , [VerSteeg][RFC6814][1]",
            Ipv4OptionClass::IMITD => "IMI Traffic Descriptor , [Lee]",
            Ipv4OptionClass::EIP => "Extended Internet Protocol , [RFC1385][RFC6814][1]",
            Ipv4OptionClass::TR => "Traceroute , [RFC1393][RFC6814][1]",
            Ipv4OptionClass::ADDEXT => "Address Extension , [Ullmann IPv7][RFC6814][1]",
            Ipv4OptionClass::RTRALT => "Router Alert , [RFC2113]",
            Ipv4OptionClass::SDB => "Selective Directed Broadcast , [Charles_Bud_Graff][RFC6814][1]",
            Ipv4OptionClass::DPS => "Dynamic Packet State , [Andy_Malis][RFC6814][1]",
            Ipv4OptionClass::UMP => "Upstream Multicast Pkt. , [Dino_Farinacci][RFC6814][1]",
            Ipv4OptionClass::QS => "Quick-Start , [RFC4782]",
            Ipv4OptionClass::EXP1 => "RFC3692-style Experiment [2] , [RFC4727]",
            Ipv4OptionClass::EXP2 => "RFC3692-style Experiment [2] , [RFC4727]",
            Ipv4OptionClass::EXP3 => "RFC3692-style Experiment [2] , [RFC4727]",
            Ipv4OptionClass::EXP4 => "RFC3692-style Experiment [2] , [RFC4727]",
        }
    }
}

