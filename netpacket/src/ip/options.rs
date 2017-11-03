

use std::mem::transmute;

/// Options:  variable
///
///    The options may appear or not in datagrams.  They must be
///    implemented by all IP modules (host and gateways).  What is optional
///    is their transmission in any particular datagram, not their
///    implementation.
///
///    In some environments the security option may be required in all
///    datagrams.
///
///    The option field is variable in length.  There may be zero or more
///    options.  There are two cases for the format of an option:
///
///      Case 1:  A single octet of option-type.
///
///      Case 2:  An option-type octet, an option-length octet, and the
///               actual option-data octets.
///
///    The option-length octet counts the option-type octet and the
///    option-length octet as well as the option-data octets.
///
///    The option-type octet is viewed as having 3 fields:
///
///      1 bit   copied flag,
///      2 bits  option class,
///      5 bits  option number.
///
///    The copied flag indicates that this option is copied into all
///    fragments on fragmentation.
///
///      0 = not copied
///      1 = copied
///
///    The option classes are:
///
///      0 = control
///      1 = reserved for future use
///      2 = debugging and measurement
///      3 = reserved for future use


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
/// 
/// Option Fields: copied(copy), class, number, value(length)
#[derive(Debug, PartialEq, Eq)]
pub struct Options<'a> {
    ccn  : u8,              // 8 bits , Fields: copied(copy), class, number
    value: u8,              // 8 bits
    data : Option<&'a [u8]> // Option-specific data. This field may not exist for simple options.
}

impl <'a>Options<'a> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 2 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let ccn: u8   = payload[0];

        let _value = payload[1] as i16;
        // in bytes
        let value: u8 = if _value > 0 {
            if _value % 8 > 0 {
                ((_value + (8 - (_value % 8)) ) / 8 ) as u8
            } else {
                _value as u8
            }
        } else {
            0
        };
        
        if payload.len() < (2 + value) as usize {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "size error ..."));
        }

        let data: Option<&'a [u8]>;
        if value > 0 {
            data = Some(unsafe { transmute(&payload[2..(2+value as usize)]) });
        } else {
            data = None
        }

        Ok(Options {
            ccn  : ccn,
            value: value,
            data : data
        })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(self.len());
        bytes.push(self.ccn);
        bytes.push(self.value);
        if self.data.is_some(){
            bytes.extend_from_slice(self.data.unwrap());
        }
        bytes
    }
    
    pub fn ccn(&self) -> u8 {
        // copied(copy), class, number
        self.ccn
    }
    pub fn value(&self) -> u8 {
        // value(length)
        self.value
    }
    pub fn length(&self) -> u8 {
        self.value()
    }
    pub fn data(&self) -> Option<&'a [u8]> {
        self.data
    }


    pub fn len(&self) -> usize {
        self.length() as usize + 2
    }

    
    pub fn copied(&self) -> u8 {
        self.ccn >> 7
    }

    pub fn class(&self) -> u8 {
        (self.ccn >> 5) & 0b011
    }

    pub fn number(&self) -> u8 {
        self.ccn & 0b_0001_1111
    }



    /// copied(0) class(0) number(0) value(0)    End of Options List, [RFC791][Jon_Postel]
    pub fn is_eool(&self) -> bool {
        self.ccn == 0 && self.value == 0
    }
    /// copied(0) class(0) number(1) value(1)    No Operation, [RFC791][Jon_Postel]
    pub fn is_nop(&self) -> bool {
        self.ccn == 1 && self.value == 1
    }
    /// copied(1) class(0) number(2) value(130)    Security, [RFC1108]
    pub fn is_sec(&self) -> bool {
        self.ccn == 130 && self.value == 130
    }
    /// copied(1) class(0) number(3) value(131)    Loose Source Route, [RFC791][Jon_Postel]
    pub fn is_lsr(&self) -> bool {
        self.ccn == 131 && self.value == 131
    }
    /// copied(0) class(2) number(4) value(68)    Time Stamp, [RFC791][Jon_Postel]
    pub fn is_ts(&self) -> bool {
        self.ccn == 68 && self.value == 68
    }
    /// copied(1) class(0) number(5) value(133)    Extended Security, [RFC1108]
    pub fn is_e_sec(&self) -> bool {
        self.ccn == 133 && self.value == 133
    }
    /// copied(1) class(0) number(6) value(134)    Commercial Security, [draft-ietf-cipso-ipsecurity-01]
    pub fn is_cipso(&self) -> bool {
        self.ccn == 134 && self.value == 134
    }
    /// copied(0) class(0) number(7) value(7)    Record Route, [RFC791][Jon_Postel]
    pub fn is_rr(&self) -> bool {
        self.ccn == 7 && self.value == 7
    }
    /// copied(1) class(0) number(8) value(136)    Stream ID, [RFC791][Jon_Postel][RFC6814][1]
    pub fn is_sid(&self) -> bool {
        self.ccn == 136 && self.value == 136
    }
    /// copied(1) class(0) number(9) value(137)    Strict Source Route, [RFC791][Jon_Postel]
    pub fn is_ssr(&self) -> bool {
        self.ccn == 137 && self.value == 137
    }
    /// copied(0) class(0) number(10) value(10)    Experimental Measurement, [ZSu]
    pub fn is_zsu(&self) -> bool {
        self.ccn == 10 && self.value == 10
    }
    /// copied(0) class(0) number(11) value(11)    MTU Probe, [RFC1063][RFC1191][1]
    pub fn is_mtup(&self) -> bool {
        self.ccn == 11 && self.value == 11
    }
    /// copied(0) class(0) number(12) value(12)    MTU Reply, [RFC1063][RFC1191][1]
    pub fn is_mtur(&self) -> bool {
        self.ccn == 12 && self.value == 12
    }
    /// copied(1) class(2) number(13) value(205)    Experimental Flow Control, [Greg_Finn]
    pub fn is_finn(&self) -> bool {
        self.ccn == 205 && self.value == 205
    }
    /// copied(1) class(0) number(14) value(142)    Experimental Access Control, [Deborah_Estrin][RFC6814][1]
    pub fn is_visa(&self) -> bool {
        self.ccn == 142 && self.value == 142
    }
    /// copied(0) class(0) number(15) value(15)    ???, [VerSteeg][RFC6814][1]
    pub fn is_encode(&self) -> bool {
        self.ccn == 15 && self.value == 15
    }
    /// copied(1) class(0) number(16) value(144)    IMI Traffic Descriptor, [Lee]
    pub fn is_imitd(&self) -> bool {
        self.ccn == 144 && self.value == 144
    }
    /// copied(1) class(0) number(17) value(145)    Extended Internet Protocol, [RFC1385][RFC6814][1]
    pub fn is_eip(&self) -> bool {
        self.ccn == 145 && self.value == 145
    }
    /// copied(0) class(2) number(18) value(82)    Traceroute, [RFC1393][RFC6814][1]
    pub fn is_tr(&self) -> bool {
        self.ccn == 82 && self.value == 82
    }
    /// copied(1) class(0) number(19) value(147)    Address Extension, [Ullmann IPv7][RFC6814][1]
    pub fn is_addext(&self) -> bool {
        self.ccn == 147 && self.value == 147
    }
    /// copied(1) class(0) number(20) value(148)    Router Alert, [RFC2113]
    pub fn is_rtralt(&self) -> bool {
        self.ccn == 148 && self.value == 148
    }
    /// copied(1) class(0) number(21) value(149)    Selective Directed Broadcast, [Charles_Bud_Graff][RFC6814][1]
    pub fn is_sdb(&self) -> bool {
        self.ccn == 149 && self.value == 149
    }
    /// copied(1) class(0) number(23) value(151)    Dynamic Packet State, [Andy_Malis][RFC6814][1]
    pub fn is_dps(&self) -> bool {
        self.ccn == 151 && self.value == 151
    }
    /// copied(1) class(0) number(24) value(152)    Upstream Multicast Pkt., [Dino_Farinacci][RFC6814][1]
    pub fn is_ump(&self) -> bool {
        self.ccn == 152 && self.value == 152
    }
    /// copied(0) class(0) number(25) value(25)    Quick-Start, [RFC4782]
    pub fn is_qs(&self) -> bool {
        self.ccn == 25 && self.value == 25
    }
    /// copied(0) class(0) number(30) value(30)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp1(&self) -> bool {
        self.ccn == 30 && self.value == 30
    }
    /// copied(0) class(2) number(30) value(94)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp2(&self) -> bool {
        self.ccn == 94 && self.value == 94
    }
    /// copied(1) class(0) number(30) value(158)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp3(&self) -> bool {
        self.ccn == 158 && self.value == 158
    }
    /// copied(1) class(2) number(30) value(222)    RFC3692-style Experiment [2], [RFC4727]
    pub fn is_exp4(&self) -> bool {
        self.ccn == 222 && self.value == 222
    }

}