
#![allow(unused_doc_comment, unused_variables)]

///                Internet Control Message Protocol (ICMPv6)
///
///        for the Internet Protocol Version 6 (IPv6) Specification
///
/// https://tools.ietf.org/html/rfc4443
///
/// https://en.wikipedia.
/// org/wiki/Internet_Control_Message_Protocol_version_6#Packet_format
///
/// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
#[derive(Debug, PartialEq, Eq)]
pub struct Pakcet<'a> {
    kind: u8, //  8 bits
    code: u8, //  8 bits
    checksum: u16, // 16 bits
    message: u16, // 16 bits
    data: &'a [u8], // ???
}


/// https://en.wikipedia.
/// org/wiki/Internet_Control_Message_Protocol_version_6#Message_types
#[derive(Debug, PartialEq, Eq)]
pub enum Message {
    /// ICMPv6 Error Messages

    /// Destination Unreachable
    NoRouteToDestination,
    CommunicationWithDestinationAdministrativelyProhibited,
    BeyondScopeOfSourceAddress,
    AddressUnreachable,
    PortUnreachable,
    SourceAddressFailedIngressOrEgressPolicy,
    RejectRouteToDestination,
    ErrorInSourceRoutingHeader,

    /// Packet Too Big
    PacketTooBig,
    /// Time Exceeded
    HopLimitExceededInTransit,
    FragmentReassemblyTimeExceeded,
    /// Parameter Problem
    ErroneousHeaderFieldEncountered,
    UnrecognizedNextHeaderTypeEncountered,
    UnrecognizedIPv6OptionEncountered,

    /// ICMPv6 Informational Messages

    /// Echo Request
    EchoRequest,
    /// Echo Reply
    EchoReply, // Multicast Listener Query (MLD)
}

impl Message {
    pub fn from_u8(a: u8, b: u8) -> Result<Self, ::std::io::Error> {
        unimplemented!()
    }
    pub fn to_u8(&self) -> [u8; 2] {
        unimplemented!()
    }

    pub fn from_u16(n: u16) -> Result<Self, ::std::io::Error> {
        unimplemented!()
    }
    pub fn to_u16(&self) -> u16 {
        unimplemented!()
    }

    pub fn kind(&self) -> u8 {
        unimplemented!()
    }
    pub fn code(&self) -> u8 {
        unimplemented!()
    }

    pub fn is_error(&self) -> bool {
        // 0 -127
        self.kind() <= 127
    }
    pub fn is_information(&self) -> bool {
        // 128 - 255
        self.kind() >= 128
    }
}

impl<'a> Pakcet<'a> {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}
