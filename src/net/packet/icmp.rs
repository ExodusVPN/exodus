


// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
// https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
#[derive(Debug)]
pub enum ControlMessages {
    EchoReply,

    // Destination Unreachable
    DestinationNetworkUnreachable,
    DestinationHostUnreachable,
    DestinationProtocolUnreachable,
    DestinationPortUnreachable,
    FragmentationRequiredAndDFFlagSet,
    SourceRouteFailed,
    DestinationNetworkUnknown,
    DestinationHostUnknown,
    SourceHostIsolated,
    NetworkAdministrativelyProhibited,
    HostAdministrativelyProhibited,
    NetworkUnreachableForToS,
    HostUnreachableForToS,
    CommunicationAdministrativelyProhibited,
    HostPrecedenceViolation,
    PrecedenceCutoffInEffect,

    SourceQuench,

    // Redirect Message

    // TODO: 需要完善 ...
    Raw(u8, u8)
}

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#ICMP_datagram_structure
#[derive(Debug)]
pub struct ICMPPacket {
    kind: u8,                 //  8 bits
    code: u8,                 //  8 bits
    checksum: [u8; 2],        // 16 bits
    rest_of_header: [u8; 4] , // 32 bits

}

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_version_6
#[derive(Debug)]
pub struct ICMPv6Packet {

}



impl ControlMessages {
    pub fn new(kind: u8, code: u8) -> Result<Self, ::std::io::Error> {
        use self::ControlMessages::*;
        match (kind, code) {
            (0, 0) => Ok(EchoReply),
            (1, _) => Ok(Raw(kind, code)),
            (2, _) => Ok(Raw(kind, code)),
            (3, 0) => Ok(DestinationNetworkUnreachable),
            (3, 1) => Ok(DestinationHostUnreachable),
            (3, 2) => Ok(DestinationProtocolUnreachable),
            (3, 3) => Ok(DestinationPortUnreachable),
            (3, 4) => Ok(FragmentationRequiredAndDFFlagSet),
            (3, 5) => Ok(SourceRouteFailed),
            (3, 6) => Ok(DestinationNetworkUnknown),
            (3, 7) => Ok(DestinationHostUnknown),
            (3, 8) => Ok(SourceHostIsolated),
            (3, 9) => Ok(NetworkAdministrativelyProhibited),
            (3, 10) => Ok(HostAdministrativelyProhibited),
            (3, 11) => Ok(NetworkUnreachableForToS),
            (3, 12) => Ok(CommunicationAdministrativelyProhibited),
            (3, 13) => Ok(HostPrecedenceViolation),
            (3, 14) => Ok(PrecedenceCutoffInEffect),
            (4, 0) => Ok(SourceQuench),
            _ => Ok(Raw(kind, code))
        }
    }
    pub fn kind(&self) -> u8 {
        use self::ControlMessages::*;
        match *self {
            EchoReply => 0,
            DestinationNetworkUnreachable => 3,
            DestinationHostUnreachable => 3,
            DestinationProtocolUnreachable => 3,
            DestinationPortUnreachable => 3,
            FragmentationRequiredAndDFFlagSet => 3,
            SourceRouteFailed => 3,
            DestinationNetworkUnknown => 3,
            DestinationHostUnknown => 3,
            SourceHostIsolated => 3,
            NetworkAdministrativelyProhibited => 3,
            HostAdministrativelyProhibited => 3,
            NetworkUnreachableForToS => 3,
            HostUnreachableForToS => 3,
            CommunicationAdministrativelyProhibited => 3,
            HostPrecedenceViolation => 3,
            PrecedenceCutoffInEffect => 3,

            SourceQuench => 4,

            Raw(n, _) => n
        }
    }
    pub fn code(&self) -> u8 {
        use self::ControlMessages::*;
        match *self {
            EchoReply => 0,
            DestinationNetworkUnreachable => 0,
            DestinationHostUnreachable => 1,
            DestinationProtocolUnreachable => 2,
            DestinationPortUnreachable => 3,
            FragmentationRequiredAndDFFlagSet => 4,
            SourceRouteFailed => 5,
            DestinationNetworkUnknown => 6,
            DestinationHostUnknown => 7,
            SourceHostIsolated => 8,
            NetworkAdministrativelyProhibited => 9,
            HostAdministrativelyProhibited => 10,
            NetworkUnreachableForToS => 11,
            HostUnreachableForToS => 12,
            CommunicationAdministrativelyProhibited => 13,
            HostPrecedenceViolation => 14,
            PrecedenceCutoffInEffect => 15,

            SourceQuench => 0,

            Raw(_, n) => n
        }
    }
    pub fn description(&self) -> &'static str {
        match *self {
            EchoReply => "Echo reply (used to ping)",
            DestinationNetworkUnreachable => "Destination network unreachable",
            DestinationHostUnreachable => "Destination host unreachable",
            DestinationProtocolUnreachable => "Destination protocol unreachable",
            DestinationPortUnreachable => "Destination port unreachable",
            FragmentationRequiredAndDFFlagSet => "Fragmentation required, and DF flag set",
            SourceRouteFailed => "Source route failed",
            DestinationNetworkUnknown => "Destination network unknown",
            DestinationHostUnknown => "Destination host unknown",
            SourceHostIsolated => "Source host isolated",
            NetworkAdministrativelyProhibited => "Network administratively prohibited",
            HostAdministrativelyProhibited => "Host administratively prohibited",
            NetworkUnreachableForToS => "Network unreachable for ToS",
            HostUnreachableForToS => "Host unreachable for ToS",
            CommunicationAdministrativelyProhibited => "Communication administratively prohibited",
            HostPrecedenceViolation => "Host Precedence Violation",
            PrecedenceCutoffInEffect => "Precedence cutoff in effect",

            SourceQuench => "Source quench (congestion control)",

            Raw(kind, code) => format!("TypeAndCode({}, {})", kind, code).as_ref()
        }
    }

    pub fn is_assigned(&self) -> bool {
        !self.is_unassigned()
    }
    pub fn is_unassigned(&self) -> bool {
        match self.kind() {
            1 || 2 || 7 || 42 ... 252 => true,
            _ => false
        }
    }
    pub fn is_deprecated(&self) -> bool {
        match self.kind() {
            4 || 6 || 15 ... 18 || 30 ... 39 => true,
            _ => false
        }
    }
    pub fn is_reserved(&self) -> bool {
        match self.kind() {
            19 || 20 ... 29 || 255 => true,
            _ => false
        }
    }
    pub fn is_experimental(&self) -> bool {
        match self.kind() {
            41 || 253 || 254 => true,
            _ => false
        }
    }
}



impl ICMPPacket {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}


impl ICMPv6Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}

