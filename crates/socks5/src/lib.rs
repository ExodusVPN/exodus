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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum Error {
    Internal, // general SOCKS server failure
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TimedOut, // TTL expired
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Into<io::Error> for Error {
    fn into(self) -> io::Error {
        use self::Error::*;

        match self {
            Internal => io::Error::new(io::ErrorKind::Other, "general SOCKS server failure"),
            NotAllowed => io::Error::new(io::ErrorKind::Other, "connection not allowed by ruleset"),
            NetworkUnreachable => io::Error::new(io::ErrorKind::Other, "Network unreachable"),
            HostUnreachable => io::Error::new(io::ErrorKind::Other, "Host unreachable"),
            ConnectionRefused => io::ErrorKind::ConnectionRefused.into(),
            TimedOut => io::ErrorKind::TimedOut.into(),
            CommandNotSupported => io::Error::new(io::ErrorKind::Other, "Command not supported"),
            AddressTypeNotSupported => io::Error::new(io::ErrorKind::Other, "Address type not supported"),
        }
    }
}

impl From<io::Error> for Reply {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::TimedOut => Reply::TTL_EXPIRED,
            io::ErrorKind::ConnectionRefused => Reply::CONNECTION_REFUSED,
            io::ErrorKind::Other => {
                if e.raw_os_error() == Some(0) {
                    Reply::SUCCEEDED
                } else {
                    Reply::GENERAL_SERVER_FAILURE
                }
            },
            _ => Reply::GENERAL_SERVER_FAILURE,
        }
    }
}


#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Version(pub u8);

impl Version {
    pub const V4: Self = Self(0x04);
    pub const V5: Self = Self(0x05);

    pub fn is_v4(&self) -> bool {
        self.0 == Self::V4.0
    }

    pub fn is_v5(&self) -> bool {
        self.0 == Self::V5.0
    }

    pub fn is_unknow(&self) -> bool {
        match self {
            &Version::V4 | &Version::V5 => false,
            _ => true,
        }
    }
}

impl Default for Version {
    fn default() -> Self {
        Version::V5
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

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressKind::V4),
            0x03 => Ok(AddressKind::DomainName),
            0x04 => Ok(AddressKind::V6),
            _ => Err(io::Error::new(io::ErrorKind::Other, "Address type not supported"))
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

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        match self {
            &Address::V4(addr) => {
                let octets = addr.octets();
                buffer[0] = octets[0];
                buffer[1] = octets[1];
                buffer[2] = octets[2];
                buffer[3] = octets[3];

                Ok(4)
            },
            &Address::V6(addr) => {
                let octets = addr.octets();
                (&mut buffer[..16]).copy_from_slice(&octets);

                Ok(16)
            },
            &Address::DomainName(s) => {
                let len = s.len();
                assert!(len <= std::u8::MAX as usize);

                buffer[0] = len as u8;
                (&mut buffer[1..len + 1]).copy_from_slice(&s.as_bytes());

                Ok(1 + len)
            },
        }
    }

    pub fn deserialize(kind: AddressKind, buffer: &'a [u8]) -> Result<Address<'a>, io::Error> {
        match kind {
            AddressKind::V4 => {
                let octets = [ buffer[0], buffer[1], buffer[2], buffer[3] ];
                Ok(Address::V4(Ipv4Addr::from(octets)))
            },
            AddressKind::V6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(buffer);

                Ok(Address::V6(Ipv6Addr::from(octets)))
            },
            AddressKind::DomainName => {
                let len = buffer[0];
                let domain_name = std::str::from_utf8(&buffer[1..len as usize + 1])
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid UTF-8 sequence"))?;
                Ok(Address::DomainName(domain_name))
            },
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

    pub fn is_v4(&self) -> bool {
        self.version.is_v4()
    }

    pub fn is_v5(&self) -> bool {
        self.version.is_v5()
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        buffer[0] = self.version.into();
        buffer[1] = self.cmd.into();
        buffer[2] = 0;
        buffer[3] = self.atyp.into();
        let amt = self.dst_addr.serialize(&mut buffer[4..])?;

        let offset = 4 + amt;

        let octets = self.dst_port.to_be_bytes();
        buffer[offset + 0] = octets[0];
        buffer[offset + 1] = octets[1];

        Ok(offset + 2)
    }

    pub fn deserialize(buffer: &'a [u8]) -> Result<Request<'a>, io::Error> {
        let version = Version(buffer[0]);
        let cmd = Cmd(buffer[1]);
        let rsv = buffer[2];
        let atyp = AddressKind::try_from(buffer[3])?;
        let dst_addr = Address::deserialize(atyp, &buffer[4..])?;
        let dst_addr_len = dst_addr.len();

        let offset = 4 + dst_addr_len;
        let dst_port = u16::from_be_bytes([ buffer[offset], buffer[offset + 1] ]);

        Ok(Self { version, cmd, rsv, atyp, dst_addr, dst_port, })
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
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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
        if self.0 > Self::ADDRESS_TYPE_NOT_SUPPORTED.0 {
            true
        } else {
            false
        }
    }

    pub fn is_unassigned(&self) -> bool {
        self.is_unknow()
    }

    pub fn is_unknow_err(&self) -> bool {
        self.is_unknow() && self.is_err()
    }
    
    pub fn is_ok(&self) -> bool {
        match *self {
            Self::SUCCEEDED => true,
            _ => false,
        }
    }

    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    pub fn err(&self) -> Option<io::Error> {
        if self.is_ok() {
            return None;
        }

        use std::io::{Error, ErrorKind};

        match *self {
            Self::SUCCEEDED => None,
            Self::GENERAL_SERVER_FAILURE => Some(Error::new(ErrorKind::Other, "general SOCKS server failure")),
            Self::CONNECTION_NOT_ALLOWED_BY_RULESET => Some(Error::new(ErrorKind::Other, "connection not allowed by ruleset")),
            Self::NETWORK_UNREACHABLE => Some(Error::new(ErrorKind::Other, "Network unreachable")),
            Self::HOST_UNREACHABLE => Some(Error::new(ErrorKind::Other, "Host unreachable")),
            Self::CONNECTION_REFUSED => Some(ErrorKind::ConnectionRefused.into()),
            Self::TTL_EXPIRED        => Some(ErrorKind::TimedOut.into()),
            Self::COMMAND_NOT_SUPPORTED => Some(Error::new(ErrorKind::Other, "Command not supported")),
            Self::ADDRESS_TYPE_NOT_SUPPORTED => Some(Error::new(ErrorKind::Other, "Address type not supported")),
            _ => Some(Error::new(ErrorKind::Other, format!("Unknow SOCKS5 Server ERROR: {}", self.0))),
        }
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
            &Self::SUCCEEDED => write!(f, "SUCCEEDED"),
            &Self::GENERAL_SERVER_FAILURE => write!(f, "GENERAL_SERVER_FAILURE"),
            &Self::CONNECTION_NOT_ALLOWED_BY_RULESET => write!(f, "CONNECTION_NOT_ALLOWED_BY_RULESET"),
            &Self::NETWORK_UNREACHABLE => write!(f, "NETWORK_UNREACHABLE"),
            &Self::HOST_UNREACHABLE => write!(f, "HOST_UNREACHABLE"),
            &Self::CONNECTION_REFUSED => write!(f, "CONNECTION_REFUSED"),
            &Self::TTL_EXPIRED => write!(f, "TTL_EXPIRED"),
            &Self::COMMAND_NOT_SUPPORTED => write!(f, "COMMAND_NOT_SUPPORTED"),
            &Self::ADDRESS_TYPE_NOT_SUPPORTED => write!(f, "ADDRESS_TYPE_NOT_SUPPORTED"),
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
#[derive(Debug, Clone, Copy)]
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

    pub fn is_v4(&self) -> bool {
        self.version.is_v4()
    }

    pub fn is_v5(&self) -> bool {
        self.version.is_v5()
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        buffer[0] = self.version.into();
        buffer[1] = self.reply.into();
        buffer[2] = 0;
        buffer[3] = self.atyp.into();
        let amt = self.bind_addr.serialize(&mut buffer[4..])?;

        let offset = 4 + amt;

        let octets = self.bind_port.to_be_bytes();
        buffer[offset + 0] = octets[0];
        buffer[offset + 1] = octets[1];
        
        Ok(offset + 2)
    }

    pub fn deserialize(buffer: &'a [u8]) -> Result<Response<'a>, io::Error> {
        let version = Version(buffer[0]);
        let reply = Reply(buffer[1]);
        let rsv = buffer[2];
        let atyp = AddressKind::try_from(buffer[3])?;
        let bind_addr = Address::deserialize(atyp, &buffer[4..])?;
        let bind_addr_len = bind_addr.len();

        let offset = 4 + bind_addr_len;
        let bind_port = u16::from_be_bytes([ buffer[offset], buffer[offset + 1] ]);

        Ok(Self { version, reply, rsv, atyp, bind_addr, bind_port, })
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


// Username/Password Authentication
// https://tools.ietf.org/html/rfc1929#section-2
// 
// Once the SOCKS V5 server has started, and the client has selected the
// Username/Password Authentication protocol, the Username/Password
// subnegotiation begins.  This begins with the client producing a
// Username/Password request:
// 
//     +----+------+----------+------+----------+
//     |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//     +----+------+----------+------+----------+
//     | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//     +----+------+----------+------+----------+
// 
// The VER field contains the current version of the subnegotiation,
// which is X'01'. The ULEN field contains the length of the UNAME field
// that follows. The UNAME field contains the username as known to the
// source operating system. The PLEN field contains the length of the
// PASSWD field that follows. The PASSWD field contains the password
// association with the given UNAME.
// 
// The server verifies the supplied UNAME and PASSWD, and sends the
// following response:
// 
//     +----+--------+
//     |VER | STATUS |
//     +----+--------+
//     | 1  |   1    |
//     +----+--------+
// 
// A STATUS field of X'00' indicates success. If the server returns a
// `failure' (STATUS value other than X'00') status, it MUST close the
// connection.
// 

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Ack {
    pub version: Version,
    pub status: u8,
}

impl Ack {
    pub fn is_v4(&self) -> bool {
        self.version.is_v4()
    }

    pub fn is_v5(&self) -> bool {
        self.version.is_v5()
    }

    pub fn is_ok(&self) -> bool {
        self.status == 0
    }

    pub fn is_err(&self) -> bool {
        self.status != 0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PasswordAuthentication<T> {
    version: u8, // NOTE: 这不是 SOCKS5 Version, 而是认证包的版本，目前固定为 0x01.
    ulen: u8,
    username: T,
    plen: u8,
    password: T,
}

impl<T: AsRef<str>> PasswordAuthentication<T> {
    pub fn new(username: T, password: T) -> Self {
        let version = 0x01;
        let ulen = username.as_ref().len();
        let plen = password.as_ref().len();

        assert!(ulen <= std::u8::MAX as usize);
        assert!(plen <= std::u8::MAX as usize);

        let ulen = ulen as u8;
        let plen = plen as u8;

        Self { version, username, ulen, password, plen, }
    }

    pub fn len(&self) -> usize {
        3 + self.username.as_ref().len() + self.password.as_ref().len()
    }

    pub fn username(&self) -> &str {
        &self.username.as_ref()
    }

    pub fn password(&self) -> &str {
        &self.password.as_ref()
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        let mut offset = 0usize;

        buffer[offset] = self.version;
        offset += 1;

        buffer[offset] = self.ulen;
        offset += 1;

        let uend = offset + self.ulen as usize;
        (&mut buffer[offset..uend]).copy_from_slice(self.username.as_ref().as_bytes());
        offset += self.ulen as usize;

        buffer[offset] = self.plen;
        offset += 1;

        let pend = offset + self.plen as usize;
        (&mut buffer[offset..pend]).copy_from_slice(self.password.as_ref().as_bytes());
        offset += self.plen as usize;

        Ok(offset)
    }
}

impl<'a> PasswordAuthentication<&'a str> {
    pub fn deserialize(buffer: &'a [u8]) -> Result<PasswordAuthentication<&'a str>, io::Error> {
        let mut offset = 0usize;

        let version = buffer[offset];
        offset += 1;
        let ulen = buffer[offset];
        offset += 1;

        let username = std::str::from_utf8(&buffer[offset..offset + ulen as usize])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid UTF-8 sequence"))?;
        offset += ulen as usize;
        
        let plen = buffer[offset];
        offset += 1;

        let password = std::str::from_utf8(&buffer[offset..offset + plen as usize])
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "invalid UTF-8 sequence"))?;
        offset += plen as usize;

        Ok(Self { version, ulen, username, plen, password, })
    }
}