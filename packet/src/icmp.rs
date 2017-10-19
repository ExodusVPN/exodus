

#![allow(unused_doc_comment, unused_variables)]

use std::mem::transmute;
use super::ip;

/// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
/// 
/// https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// used to ping
    EchoReply,                               // 0, 0

    /// Destination Unreachable
    DestinationNetworkUnreachable,           // 3, 0
    DestinationHostUnreachable,              // 3, 1
    DestinationProtocolUnreachable,          // 3, 2
    DestinationPortUnreachable,              // 3, 3
    FragmentationRequiredAndDFFlagSet,       // 3, 4
    SourceRouteFailed,                       // 3, 5
    DestinationNetworkUnknown,               // 3, 6
    DestinationHostUnknown,                  // 3, 7
    SourceHostIsolated,                      // 3, 8
    NetworkAdministrativelyProhibited,       // 3, 9
    HostAdministrativelyProhibited,          // 3, 10
    NetworkUnreachableForToS,                // 3, 11
    HostUnreachableForToS,                   // 3, 12
    CommunicationAdministrativelyProhibited, // 3, 13
    HostPrecedenceViolation,                 // 3, 14
    PrecedenceCutoffInEffect,                // 3, 15

    /// deprecated
    SourceQuench,                            // 4, 0

    /// Redirect Message
    RedirectDatagramForTheNetwork,           // 5, 0
    RedirectDatagramForTheHost,              // 5, 1
    RedirectDatagramForTheToSAndNetwork,     // 5, 2
    RedirectDatagramForTheToSAndhost,        // 5, 3

    /// used to ping
    EchoRequest,                             //  8, 0

    RouterAdvertisement,                     //  9, 8
    /// Router discovery/selection/solicitation
    RouterSolicitation,                      // 10, 0

    /// Time Exceeded
    TTLExpiredInTransit,                     // 11, 0
    FragmentReassemblyTimeExceeded,          // 11, 1

    /// Parameter Problem: Bad IP header
    PointerIndicatesTheError,                // 12, 0
    MissingARequiredOption,                  // 12, 1
    BadLength,                               // 12, 2

    Timestamp,                               // 13, 0
    TimestampReply,                          // 14, 0

    /// deprecated
    InformationRequest,                      // 15, 0
    /// deprecated
    InformationReply,                        // 16, 0
    /// deprecated
    AddressMaskRequest,                      // 17, 0
    /// deprecated
    AddressMaskReply,                        // 18, 0
    /// deprecated
    TracerouteInformationRequest,            // 30, 0
    // deprecated
    // Datagram Conversion Error
    // Mobile Host Redirect
    // Where-Are-You (originally meant for IPv6)
    // Here-I-Am (originally meant for IPv6)
    // Mobile Registration Request
    // Mobile Registration Reply
    // Domain Name Request
    // Domain Name Reply
    // SkipAlgorithmDiscoveryProtocol, Simple Key-Management for Internet Protocol

    PhoturisAndSecurityFailures,                       // 40, 0

    /// experimental, RFC4065
    ICMPForExperimentalMobilityProtocolsSuchAsSeamoby, // 41, 0

    /// experimental, RFC 4727
    RFC3692StyleExperiment1,                          // 253, 0

    /// experimental, RFC 4727
    RFC3692StyleExperiment2,                          // 254, 0

    Raw(u8, u8)
}

/// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#ICMP_datagram_structure
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a, 'b> {
    kind: u8,              //   8 bits
    code: u8,              //   8 bits
    checksum: u16,         //  16 bits
    rest_of_header: u32,   //  32 bits
    ip_packet: ip::Packet<'a, 'b> //  00 bits , IPv4 header and first 8 bytes of original datagram's data
}



impl Message {
    pub fn new(kind: u8, code: u8) -> Result<Self, ::std::io::Error> {
        use self::Message::*;
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
            /// deprecated
            (4, 0)  => Ok(SourceQuench),

            (5, 0) => Ok(RedirectDatagramForTheNetwork),
            (5, 1) => Ok(RedirectDatagramForTheHost),
            (5, 2) => Ok(RedirectDatagramForTheToSAndNetwork),
            (5, 3) => Ok(RedirectDatagramForTheToSAndhost),
            
            (8, 0) => Ok(EchoRequest),
            (9, 8) => Ok(RouterAdvertisement),
            (10, 0) => Ok(RouterSolicitation),
            (11, 0) => Ok(TTLExpiredInTransit),
            (11, 1) => Ok(FragmentReassemblyTimeExceeded),
            (12, 0) => Ok(PointerIndicatesTheError),
            (12, 1) => Ok(MissingARequiredOption),
            (12, 2) => Ok(BadLength),
            (13, 0) => Ok(Timestamp),
            (14, 0) => Ok(TimestampReply),

            /// deprecated
            (15, 0) => Ok(InformationRequest),
            (16, 0) => Ok(InformationReply),
            (17, 0) => Ok(AddressMaskRequest),
            (18, 0) => Ok(AddressMaskReply),
            (30, 0) => Ok(TracerouteInformationRequest),

            (40, 0)  => Ok(PhoturisAndSecurityFailures),
            (41, 0)  => Ok(ICMPForExperimentalMobilityProtocolsSuchAsSeamoby),
            (253, 0) => Ok(RFC3692StyleExperiment1),
            (254, 0) => Ok(RFC3692StyleExperiment2),

            _ => Ok(Raw(kind, code))
        }
    }
    /// ICMP type
    pub fn kind(&self) -> u8 {
        use self::Message::*;
        match *self {
            EchoReply => 0,
            DestinationNetworkUnreachable
            | DestinationHostUnreachable
            | DestinationProtocolUnreachable
            | DestinationPortUnreachable
            | FragmentationRequiredAndDFFlagSet
            | SourceRouteFailed
            | DestinationNetworkUnknown
            | DestinationHostUnknown
            | SourceHostIsolated
            | NetworkAdministrativelyProhibited
            | HostAdministrativelyProhibited
            | NetworkUnreachableForToS
            | HostUnreachableForToS
            | CommunicationAdministrativelyProhibited
            | HostPrecedenceViolation
            | PrecedenceCutoffInEffect => 3,

            /// deprecated
            SourceQuench => 4,

            RedirectDatagramForTheNetwork
            | RedirectDatagramForTheHost
            | RedirectDatagramForTheToSAndNetwork
            | RedirectDatagramForTheToSAndhost => 5,

            EchoRequest => 8,
            RouterAdvertisement => 9,
            RouterSolicitation => 10,
            TTLExpiredInTransit | FragmentReassemblyTimeExceeded => 11,

            PointerIndicatesTheError
            | MissingARequiredOption
            | BadLength => 12,

            Timestamp => 13,
            TimestampReply => 14,

            /// deprecated
            InformationRequest => 15,
            InformationReply => 16,
            AddressMaskRequest => 17,
            AddressMaskReply => 18,
            TracerouteInformationRequest => 30,

            PhoturisAndSecurityFailures => 40,
            ICMPForExperimentalMobilityProtocolsSuchAsSeamoby => 41,
            RFC3692StyleExperiment1 => 253,
            RFC3692StyleExperiment2 => 254,

            Raw(n, _) => n
        }
    }

    /// ICMP subtype
    pub fn code(&self) -> u8 {
        use self::Message::*;
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

            /// deprecated
            SourceQuench => 0,

            RedirectDatagramForTheNetwork => 0,
            RedirectDatagramForTheHost => 1,
            RedirectDatagramForTheToSAndNetwork => 2,
            RedirectDatagramForTheToSAndhost => 3,

            EchoRequest => 0, 
            RouterAdvertisement => 8,
            RouterSolicitation => 0,

            TTLExpiredInTransit => 0,
            FragmentReassemblyTimeExceeded => 1,

            PointerIndicatesTheError => 0,
            MissingARequiredOption => 1,
            BadLength => 2,

            Timestamp => 0,
            TimestampReply => 0,

            /// deprecated
            InformationRequest 
            | InformationReply
            | AddressMaskRequest
            | AddressMaskReply
            | TracerouteInformationRequest => 0,

            PhoturisAndSecurityFailures => 0,
            ICMPForExperimentalMobilityProtocolsSuchAsSeamoby => 0,
            RFC3692StyleExperiment1 => 0,
            RFC3692StyleExperiment2 => 0,

            Raw(_, n) => n
        }
    }
    /// ICMP Control Message description
    pub fn description(&self) -> &'static str {
        use self::Message::*;
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

            /// deprecated
            SourceQuench => "Source quench (congestion control)",

            RedirectDatagramForTheNetwork => "Redirect Datagram for the Network",
            RedirectDatagramForTheHost => "Redirect Datagram for the Host",
            RedirectDatagramForTheToSAndNetwork => "Redirect Datagram for the ToS & network",
            RedirectDatagramForTheToSAndhost => "Redirect Datagram for the ToS & host",

            EchoRequest => "Echo request (used to ping)",
            RouterAdvertisement => "Router Advertisement",
            RouterSolicitation  => "Router discovery/selection/solicitation",

            TTLExpiredInTransit => "TTL expired in transit",
            FragmentReassemblyTimeExceeded => "Fragment reassembly time exceeded",

            PointerIndicatesTheError => "Parameter Problem: Bad IP header, Pointer indicates the error",
            MissingARequiredOption   => "Parameter Problem: Bad IP header, Missing a required option",
            BadLength                => "Parameter Problem: Bad IP header, Bad length",

            Timestamp        => "Timestamp",
            TimestampReply   => "Timestamp reply",

            /// deprecated
            InformationRequest => "Information Request",
            InformationReply => "Information Reply",
            AddressMaskRequest => "Address Mask Request",
            AddressMaskReply => "Address Mask Reply",
            TracerouteInformationRequest => "Traceroute Information Request",
            
            PhoturisAndSecurityFailures => "Photuris, Security failures",
            ICMPForExperimentalMobilityProtocolsSuchAsSeamoby => "ICMP for experimental mobility protocols such as Seamoby [RFC4065]",
            RFC3692StyleExperiment1 => "RFC3692-style Experiment 1 (RFC 4727)",
            RFC3692StyleExperiment2 => "RFC3692-style Experiment 2 (RFC 4727)",

            Raw(kind, code) => "Raw TypeCode"
        }
    }

    pub fn is_assigned(&self) -> bool {
        !self.is_unassigned()
    }
    pub fn is_unassigned(&self) -> bool {
        match self.kind() {
            1 | 2 | 7 | 42 ... 252 => true,
            _ => false
        }
    }
    pub fn is_deprecated(&self) -> bool {
        match self.kind() {
            4 | 6 | 15 ... 18 | 30 ... 39 => true,
            _ => false
        }
    }
    pub fn is_reserved(&self) -> bool {
        match self.kind() {
            19 | 20 ... 29 | 255 => true,
            _ => false
        }
    }
    pub fn is_experimental(&self) -> bool {
        match self.kind() {
            41 | 253 | 254 => true,
            _ => false
        }
    }
}

// impl fmt::Debug for Packet {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "Point {{ x: {}, y: {} }}", self.x, self.y)
//     }
// }

impl <'a, 'b>Packet<'a, 'b> {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        if payload.len() < 64 {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "packet size error ..."));
        }
        let kind = payload[0];
        let code = payload[1];
        let checksum: u16 = unsafe { transmute([payload[2], payload[3]]) };
        let rest_of_header: u32 = unsafe { transmute([payload[4], payload[5], payload[6], payload[7]]) };

        match ip::Packet::from_bytes(&payload[8..]) {
            Ok(ip_packet) => {
                if ip_packet.payload() == &payload[0..8] {
                    Ok(Packet{
                        kind: kind,
                        code: code,
                        checksum: checksum,
                        rest_of_header: rest_of_header,
                        ip_packet: ip_packet
                    })
                } else {
                    Err(::std::io::Error::new(::std::io::ErrorKind::Other, "packet size error ..."))
                }
            },
            Err(e) => Err(e)
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }

    pub fn payload(&self) -> &[u8] {
        self.ip_packet.payload()
    }
    
    pub fn kind(&self) -> u8 {
        self.kind
    }
    pub fn code(&self) -> u8 {
        self.code
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
    pub fn rest_of_header(&self) -> u32 {
        self.rest_of_header
    }
    pub fn ip_packet(&self) -> &ip::Packet<'a, 'b> {
        &self.ip_packet
    }
}


