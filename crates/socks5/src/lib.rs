// use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;


// SOCKS Protocol Version 5
// https://tools.ietf.org/html/rfc1928
// 
// Username/Password Authentication for SOCKS V5
// https://tools.ietf.org/html/rfc1929
// 

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Version(pub u8);

impl Version {
    pub const V4: Self = Self(0x04);
    pub const V5: Self = Self(0x05);

    pub fn is_unknow(&self) -> bool {
        match self {
            &Version::V4 | &Version::V5 => false,
            _ => true,
        }
    }
}

impl Into<u8> for Version {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Version::V4 => write!(f, "V4"),
            &Version::V5 => write!(f, "V5"),
            _ => write!(f, "UNKNOW_VERSION({})", self.0),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Method(pub u8);

impl Method {
    pub const NO_AUTH: Self       = Self(0x00); // NO AUTHENTICATION REQUIRED
    pub const GSSAPI: Self        = Self(0x01); // GSSAPI
    pub const USERNAME: Self      = Self(0x02); // USERNAME/PASSWORD
    pub const NO_ACCEPTABLE: Self = Self(0xFF); // NO ACCEPTABLE METHODS

    pub fn is_iana_assigned(&self) -> bool {
        // X'03' to X'7F' IANA ASSIGNED
        match self.0 {
            0x03 ..= 0x7F => true,
            _ => false,
        }
    }

    pub fn is_reserved(&self) -> bool {
        // X'80' to X'FE' RESERVED FOR PRIVATE METHODS
        match self.0 {
            0x80 ..= 0xFE => true,
            _ => false,
        }
    }
}

impl Into<u8> for Method {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Method::NO_AUTH => write!(f, "NO_AUTH"),
            &Method::GSSAPI => write!(f, "GSSAPI"),
            &Method::USERNAME => write!(f, "USERNAME"),
            &Method::NO_ACCEPTABLE => write!(f, "NO_ACCEPTABLE"),
            _ => write!(f, "UNKNOW_METHOD({})", self.0),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Cmd(pub u8);

impl Cmd {
    pub const CONNECT: Self       = Self(0x01);
    pub const BIND: Self          = Self(0x02);
    pub const UDP_ASSOCIATE: Self = Self(0x03);

    pub fn is_unknow(&self) -> bool {
        match self {
            &Cmd::CONNECT | &Cmd::BIND | &Cmd::UDP_ASSOCIATE => false,
            _ => true,
        }
    }
}

impl Into<u8> for Cmd {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Cmd::CONNECT => write!(f, "CONNECT"),
            &Cmd::BIND => write!(f, "BIND"),
            &Cmd::UDP_ASSOCIATE => write!(f, "UDP_ASSOCIATE"),
            _ => write!(f, "UNKNOW_CMD({})", self.0),
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum AddressKind {
    V4,          // IP V4 address: X'01'
    V6,          // IP V6 address: X'04'
    // the address field contains a fully-qualified domain name.
    // The first octet of the address field contains the number of octets of name that follow,
    // there is no terminating NUL octet.
    DomainName,  // DOMAINNAME:    X'03'
}

impl Into<u8> for AddressKind {
    fn into(self) -> u8 {
        match self {
            AddressKind::V4 => 0x01,
            AddressKind::DomainName => 0x03,
            AddressKind::V6 => 0x04,
        }
    }
}

impl TryFrom<u8> for AddressKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressKind::V4),
            0x03 => Ok(AddressKind::DomainName),
            0x04 => Ok(AddressKind::V6),
            _ => Err(())
        }
    }
}

// https://tools.ietf.org/html/rfc1928#section-5
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Address<'a> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    DomainName(&'a str),
}

impl<'a> Address<'a> {
    pub fn len(&self) -> usize {
        match self {
            &Address::V4(_) => 4,  //  4 octets
            &Address::V6(_) => 16, // 16 octets
            &Address::DomainName(s) => 1 + s.len(),
        }
    }

    pub fn is_ip(&self) -> bool {
        match self {
            &Self::V4(_) | &Self::V6(_) => true,
            _ => false,
        }
    }

    pub fn is_ipv4(&self) -> bool {
        match self {
            &Self::V4(_) => true,
            _ => false,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match self {
            &Self::V6(_) => true,
            _ => false,
        }
    }

    pub fn is_domain_name(&self) -> bool {
        match self {
            &Self::DomainName(_) => true,
            _ => false,
        }
    }
}


// https://tools.ietf.org/html/rfc1928#section-4
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub version: Version,
    pub cmd: Cmd,
    pub rsv: u8,  // 0x00, RESERVED
    pub atyp: AddressKind,
    pub dst_addr: Address<'a>,
    pub dst_port: u16,
}

impl<'a> Request<'a> {
    // 6 + 4            ipv4
    // 6 + 16           ipv6
    // 6 + 1 + ANY_SIZE domain name
    pub const MIN_SIZE: usize = 8;
    pub const IPV4_SIZE: usize = 10;
    pub const IPV6_SIZE: usize = 22;

    pub fn len(&self) -> usize {
        4 + self.dst_addr.len() + 2
    }
}


// o  X'00' succeeded
// o  X'01' general SOCKS server failure
// o  X'02' connection not allowed by ruleset
// o  X'03' Network unreachable
// o  X'04' Host unreachable
// o  X'05' Connection refused
// o  X'06' TTL expired
// o  X'07' Command not supported
// o  X'08' Address type not supported
// o  X'09' to X'FF' unassigned
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Reply(pub u8);

impl Reply {
    pub const SUCCEEDED: Self                         = Self(0x00);
    pub const GENERAL_SERVER_FAILURE: Self            = Self(0x01);
    pub const CONNECTION_NOT_ALLOWED_BY_RULESET: Self = Self(0x02);
    pub const NETWORK_UNREACHABLE: Self               = Self(0x03);
    pub const HOST_UNREACHABLE: Self                  = Self(0x04);
    pub const CONNECTION_REFUSED: Self                = Self(0x05);
    pub const TTL_EXPIRED: Self                       = Self(0x06);
    pub const COMMAND_NOT_SUPPORTED: Self             = Self(0x07);
    pub const ADDRESS_TYPE_NOT_SUPPORTED: Self        = Self(0x08);

    pub fn is_unknow(&self) -> bool {
        match self {
            &Reply::SUCCEEDED
            | &Reply::GENERAL_SERVER_FAILURE
            | &Reply::CONNECTION_NOT_ALLOWED_BY_RULESET
            | &Reply::NETWORK_UNREACHABLE
            | &Reply::HOST_UNREACHABLE
            | &Reply::CONNECTION_REFUSED
            | &Reply::TTL_EXPIRED
            | &Reply::COMMAND_NOT_SUPPORTED
            | &Reply::ADDRESS_TYPE_NOT_SUPPORTED => false,
            _ => true,
        }
    }

    pub fn is_unassigned(&self) -> bool {
        self.is_unknow()
    }

    pub fn is_unknow_err(&self) -> bool {
        self.is_unknow() && self.is_err()
    }
    
    pub fn is_ok(&self) -> bool {
        match self {
            &Reply::SUCCEEDED => true,
            _ => false,
        }
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }
}

impl Into<u8> for Reply {
    fn into(self) -> u8 {
        self.0
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Reply::SUCCEEDED => write!(f, "SUCCEEDED"),
            &Reply::GENERAL_SERVER_FAILURE => write!(f, "GENERAL_SERVER_FAILURE"),
            &Reply::CONNECTION_NOT_ALLOWED_BY_RULESET => write!(f, "CONNECTION_NOT_ALLOWED_BY_RULESET"),
            &Reply::NETWORK_UNREACHABLE => write!(f, "NETWORK_UNREACHABLE"),
            &Reply::HOST_UNREACHABLE => write!(f, "HOST_UNREACHABLE"),
            &Reply::CONNECTION_REFUSED => write!(f, "CONNECTION_REFUSED"),
            &Reply::TTL_EXPIRED => write!(f, "TTL_EXPIRED"),
            &Reply::COMMAND_NOT_SUPPORTED => write!(f, "COMMAND_NOT_SUPPORTED"),
            &Reply::ADDRESS_TYPE_NOT_SUPPORTED => write!(f, "ADDRESS_TYPE_NOT_SUPPORTED"),
            _ => write!(f, "UNKNOW_REPLY({})", self.0),
        }
    }
}

// https://tools.ietf.org/html/rfc1928#section-6
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
pub struct Response<'a> {
    pub version: Version,
    pub reply: Reply,
    pub rsv: u8,  // 0x00, RESERVED
    pub atyp: AddressKind,
    pub bind_addr: Address<'a>,
    pub bind_port: u16,
}

impl<'a> Response<'a> {
    pub const MIN_SIZE: usize = 8;
    pub const IPV4_SIZE: usize = 10;
    pub const IPV6_SIZE: usize = 22;

    pub fn len(&self) -> usize {
        4 + self.bind_addr.len() + 2
    }
}


// https://tools.ietf.org/html/rfc1928#section-7
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
// The fields in the UDP request header are:
// 
//     o  RSV           Reserved X'0000'
//     o  FRAG          Current fragment number
//     o  ATYP          address type of following addresses:
//         o  IP V4 address: X'01'
//         o  DOMAINNAME:    X'03'
//         o  IP V6 address: X'04'
//     o  DST.ADDR      desired destination address
//     o  DST.PORT      desired destination port
//     o  DATA          user data
// 
