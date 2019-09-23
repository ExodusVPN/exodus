use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;

// 
// SOCKS5 协议通信流程
// 
// Client: Handshake
// Server: HandshakeAck
// 
// NOTE: 可选步骤
// Client: PasswordAuthentication
// Server: PasswordAuthenticationAck
// 
// Client: Request
// Server: RquestAck ( Response )
// 
// Client <--> Server
// UDP 转发 或者 TCP 转发
// 


// SOCKS Protocol Version 5
// https://tools.ietf.org/html/rfc1928
// 
// Username/Password Authentication for SOCKS V5
// https://tools.ietf.org/html/rfc1929
// 
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub enum SocksError {
    /// general SOCKS server failure
    GeneralFailure,
    /// connection not allowed by ruleset
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    /// TTL expired
    TimedOut,
    CommandNotSupported,
    AddressTypeNotSupported,
    /// SOCKS Protocol Version not supported.
    /// Only support SOCKS V4/V5.
    VersionNotSupported,
    /// Username/Password Authentication protocol version Must be 0x01
    PassAuthVersionNotSupported,
    // There was not enough data
    /// An incoming packet could not be parsed because some of its fields were out of bounds of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped. E.g. an Request packet with an unknown AddressType.
    Unrecognized,
    InvalidUtf8Sequence,
    RawReplyError(u8),
}

impl SocksError {
    pub fn from_raw_reply_error(errno: u8) -> Self {
        Self::RawReplyError(errno)
    }

    pub fn raw_reply_error(&self) -> Option<u8> {
        match *self {
            SocksError::RawReplyError(n) => Some(n),
            _ => None,
        }
    }
}

impl Into<io::Error> for SocksError {
    fn into(self) -> io::Error {
        use self::SocksError::*;

        match self {
            GeneralFailure => io::Error::new(io::ErrorKind::Other, "general SOCKS server failure"),
            NotAllowed => io::Error::new(io::ErrorKind::Other, "connection not allowed by ruleset"),
            NetworkUnreachable => io::Error::new(io::ErrorKind::Other, "Network unreachable"),
            HostUnreachable => io::Error::new(io::ErrorKind::Other, "Host unreachable"),
            ConnectionRefused => io::ErrorKind::ConnectionRefused.into(),
            TimedOut => io::ErrorKind::TimedOut.into(),
            CommandNotSupported => io::Error::new(io::ErrorKind::Other, "Command not supported"),
            AddressTypeNotSupported => io::Error::new(io::ErrorKind::Other, "Address type not supported"),
            VersionNotSupported => io::Error::new(io::ErrorKind::Other, "SOCKS Protocol version not supported"),
            PassAuthVersionNotSupported => io::Error::new(io::ErrorKind::Other, "Username/Password Authentication protocol version must be 0x01"),
            Truncated => io::Error::new(io::ErrorKind::Other, "An incoming packet could not be parsed because some of its fields were out of bounds of the received data"),
            Unrecognized => io::Error::new(io::ErrorKind::Other, "An incoming packet could not be recognized"),
            InvalidUtf8Sequence => io::Error::new(io::ErrorKind::Other, "invalid UTF-8 sequence"),
            RawReplyError(errno) => io::Error::new(io::ErrorKind::Other, format!("raw reply error code: {}", errno)),
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


#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Version {
    V4,
    V5,
}

impl Into<u8> for Version {
    fn into(self) -> u8 {
        match self {
            Self::V4 => 0x04,
            Self::V5 => 0x05,
        }
    }
}

impl TryFrom<u8> for Version {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x04 => Ok(Version::V4),
            0x05 => Ok(Version::V5),
            _ => Err(SocksError::VersionNotSupported),
        }
    }
}

impl Version {
    pub fn is_v4(&self) -> bool {
        match *self {
            Self::V4 => true,
            _ => false,
        }
    }

    pub fn is_v5(&self) -> bool {
        match *self {
            Self::V5 => true,
            _ => false,
        }
    }

}

impl Default for Version {
    fn default() -> Self {
        Version::V5
    }
}


#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Method(pub u8);

impl Method {
    pub const NO_AUTH: Self       = Self(0x00); // NO AUTHENTICATION REQUIRED
    pub const GSSAPI: Self        = Self(0x01); // GSSAPI
    pub const PASS_AUTH: Self     = Self(0x02);// USERNAME/PASSWORD
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
            &Method::PASS_AUTH => write!(f, "PASS_AUTH"),
            &Method::NO_ACCEPTABLE => write!(f, "NO_ACCEPTABLE"),
            _ => write!(f, "UNKNOW_METHOD({})", self.0),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Methods {
    bits: u32,
    len: usize,
}

impl Methods {
    pub fn new() -> Self {
        Self { bits: 0, len: 0, }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn bits(&self) -> u32 {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_enabled(&self, method: Method) -> bool {
        let bit = method.0 as u32;
         (self.bits & (1 << bit)) != 0
    }

    pub fn set(&mut self, method: Method, value: bool) -> &mut Self {
        let bit = method.0 as u32;
        if value {
            self.bits |= 1 << bit;
            self.len += 1;
        } else {
            self.bits &= !(1 << bit);
            self.len -= 1;
        }

        self
    }

    pub fn enable(&mut self, method: Method) {
        let bit = method.0 as u32;

        self.bits |= 1 << bit;
        self.len += 1;
    }

    pub fn disable(&mut self, method: Method) {
        let bit = method.0 as u32;

        self.bits &= !(1 << bit);
        self.len -= 1;
    }

    pub fn iter<'a>(&'a self) -> MethodsIter<'a> {
        MethodsIter { methods: self, idx: 0, }
    }

    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        assert!(self.len <= std::u8::MAX as usize);

        buffer[0] = self.len as u8;
        let mut offset = 1;

        for m in self.iter() {
            buffer[offset] = m.into();
            offset += 1;
        }

        Ok(offset)
    }

    pub fn deserialize(buffer: &[u8]) -> Result<Self, SocksError> {
        let len = buffer[0];
        let mut methods = Self::new();
        for idx in 1..(len+1) {
            let method = Method(buffer[idx as usize]);
            methods.enable(method);
        }

        Ok(methods)
    }
}

pub struct MethodsIter<'a> {
    methods: &'a Methods,
    idx: u16,
}

impl<'a> Iterator for MethodsIter<'a> {
    type Item = Method;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= std::u8::MAX as u16 {
            return None;
        }

        let m = Method(self.idx as u8);
        self.idx += 1;
        if self.methods.is_enabled(m) {
            return Some(m);
        } else {
            return self.next();
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Cmd {
    Connect,
    Bind,
    UdpAssociate,
}

impl Into<u8> for Cmd {
    fn into(self) -> u8 {
        match self {
            Self::Connect      => 0x01,
            Self::Bind         => 0x02,
            Self::UdpAssociate => 0x03,
        }
    }
}

impl TryFrom<u8> for Cmd {
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Cmd::Connect),
            0x02 => Ok(Cmd::Bind),
            0x03 => Ok(Cmd::UdpAssociate),
            _ => Err(SocksError::CommandNotSupported),
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
    type Error = SocksError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddressKind::V4),
            0x03 => Ok(AddressKind::DomainName),
            0x04 => Ok(AddressKind::V6),
            _ => Err(SocksError::AddressTypeNotSupported)
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

    pub fn deserialize(kind: AddressKind, buffer: &'a [u8]) -> Result<Address<'a>, SocksError> {
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
                    .map_err(|_| SocksError::InvalidUtf8Sequence)?;
                Ok(Address::DomainName(domain_name))
            },
        }
    }
}



// https://tools.ietf.org/html/rfc1928#section-3
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
#[derive(Debug, Clone, Copy)]
pub struct Handshake {
    pub version: Version,
    // pub methods_len: u8,
    pub methods: Methods, // 最多有 256 个方法
}

impl Handshake {
    pub fn serialize(&self, buffer: &mut [u8]) -> Result<usize, io::Error> {
        buffer[0] = self.version.into();
        self.methods.serialize(&mut buffer[1..])
    }

    pub fn deserialize(buffer: &[u8]) -> Result<Self, SocksError> {
        let version = Version::try_from(buffer[0])?;
        let methods = Methods::deserialize(&buffer[1..])?;

        Ok(Self { version, methods })
    }
}

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
#[derive(Debug, Clone, Copy)]
pub struct HandshakeAck {
    pub version: Version,
    pub method: Method,
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

    pub fn deserialize(buffer: &'a [u8]) -> Result<Request<'a>, SocksError> {
        let version = Version::try_from(buffer[0])?;
        let cmd = Cmd::try_from(buffer[1])?;
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

    pub fn err(&self) -> Option<SocksError> {
        if self.is_ok() {
            return None;
        }

        match *self {
            Self::SUCCEEDED => None,
            Self::GENERAL_SERVER_FAILURE => Some(SocksError::GeneralFailure),
            Self::CONNECTION_NOT_ALLOWED_BY_RULESET => Some(SocksError::NotAllowed),
            Self::NETWORK_UNREACHABLE => Some(SocksError::NetworkUnreachable),
            Self::HOST_UNREACHABLE => Some(SocksError::HostUnreachable),
            Self::CONNECTION_REFUSED => Some(SocksError::ConnectionRefused),
            Self::TTL_EXPIRED        => Some(SocksError::TimedOut),
            Self::COMMAND_NOT_SUPPORTED => Some(SocksError::CommandNotSupported),
            Self::ADDRESS_TYPE_NOT_SUPPORTED => Some(SocksError::AddressTypeNotSupported),
            _ => Some(SocksError::RawReplyError(self.0)),
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
pub struct RequestAck<'a> {
    pub version: Version,
    pub reply: Reply,
    pub rsv: u8,  // 0x00, RESERVED
    pub atyp: AddressKind,
    pub bind_addr: Address<'a>,
    pub bind_port: u16,
}

impl<'a> RequestAck<'a> {
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

    pub fn deserialize(buffer: &'a [u8]) -> Result<RequestAck<'a>, SocksError> {
        let version = Version::try_from(buffer[0])?;
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
pub struct PasswordAuthenticationAck {
    // NOTE: 注意这是 密码认证 子协议的版本，并非 SOCKS 协议的版本。
    //       目前 密码认证 协议版本为: 0x01.
    pub version: u8,
    pub status: u8,
}

impl PasswordAuthenticationAck {
    pub fn is_ok(&self) -> bool {
        self.status == 0
    }

    pub fn is_err(&self) -> bool {
        self.status != 0
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PasswordAuthentication<T> {
    // NOTE: 注意这是 密码认证 子协议的版本，并非 SOCKS 协议的版本。
    //       目前 密码认证 协议版本为: 0x01.
    version: u8,
    ulen: u8,
    username: T,
    plen: u8,
    password: T,
}

impl<T> PasswordAuthentication<T> {
    pub const VERSION_V1: u8 = 0x01;
}

impl<T: AsRef<str>> PasswordAuthentication<T> {

    pub fn new(username: T, password: T) -> Self {
        let version = Self::VERSION_V1;
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
    pub fn deserialize(buffer: &'a [u8]) -> Result<PasswordAuthentication<&'a str>, SocksError> {
        let mut offset = 0usize;

        let version = buffer[offset];
        if version != Self::VERSION_V1 {
            return Err(SocksError::PassAuthVersionNotSupported);
        }
        offset += 1;

        let ulen = buffer[offset];
        offset += 1;

        let username = std::str::from_utf8(&buffer[offset..offset + ulen as usize])
            .map_err(|_| SocksError::InvalidUtf8Sequence)?;
        offset += ulen as usize;
        
        let plen = buffer[offset];
        offset += 1;

        let password = std::str::from_utf8(&buffer[offset..offset + plen as usize])
            .map_err(|_| SocksError::InvalidUtf8Sequence)?;
        offset += plen as usize;

        Ok(Self { version, ulen, username, plen, password, })
    }
}


#[test]
fn test_methods() {
    let mut methods = Methods::new();
    methods.set(Method::NO_AUTH, true);
    assert_eq!(methods.is_enabled(Method::NO_AUTH), true);
    assert_eq!(methods.len(), 1);

    methods.set(Method::PASS_AUTH, true);
    assert_eq!(methods.is_enabled(Method::PASS_AUTH), true);
    assert_eq!(methods.len(), 2);

    methods.set(Method::PASS_AUTH, false);
    assert_eq!(methods.is_enabled(Method::PASS_AUTH), false);
    assert_eq!(methods.len(), 1);
}