/// (RFC-795)[https://tools.ietf.org/html/rfc795]
/// Type of Service:  8 bits
///
///    The Type of Service provides an indication of the abstract
///    parameters of the quality of service desired.  These parameters are
///    to be used to guide the selection of the actual service parameters
///    when transmitting a datagram through a particular network.  Several
///    networks offer service precedence, which somehow treats high
///    precedence traffic as more important than other traffic (generally
///    by accepting only traffic above a certain precedence at time of high
///    load).  The major choice is a three way tradeoff between low-delay,
///    high-reliability, and high-throughput.
///
///      Bits 0-2:  Precedence.
///      Bit    3:  0 = Normal Delay,      1 = Low Delay.
///      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
///      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
///      Bit  6-7:  Reserved for Future Use.
///
///         0     1     2     3     4     5     6     7
///      +-----+-----+-----+-----+-----+-----+-----+-----+
///      |                 |     |     |     |     |     |
///      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
///      |                 |     |     |     |     |     |
///      +-----+-----+-----+-----+-----+-----+-----+-----+
///
///        Precedence
///
///          111 - Network Control
///          110 - Internetwork Control
///          101 - CRITIC/ECP
///          100 - Flash Override
///          011 - Flash
///          010 - Immediate
///          001 - Priority
///          000 - Routine
///
///    The use of the Delay, Throughput, and Reliability indications may
///    increase the cost (in some sense) of the service.  In many networks
///    better performance for one of these parameters is coupled with worse
///    performance on another.  Except for very unusual cases at most two
///    of these three indications should be set.
///
///    The type of service is used to specify the treatment of the datagram
///    during its transmission through the internet system.  Example
///    mappings of the internet type of service to the actual service
///    provided on networks such as AUTODIN II, ARPANET, SATNET, and PRNET
///    is given in "Service Mappings" [8].
///
///
///    The fragment offset is measured in units of 8 octets (64 bits).  The
///    first fragment has offset zero.
#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Precedence {
    /// Precedence 7
    NetworkControl,
    /// Precedence 6
    InternetworkControl,
    /// Precedence 5
    CriticEcp,
    /// Precedence 4
    FlashOverride,
    /// Precedence 3
    Flash,
    /// Precedence 2
    Immediate,
    /// Precedence 1
    Priority,
    /// Precedence 0
    Routine
}

#[allow(non_camel_case_types, dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum Parameter {
    /// 0000
    Default,
    /// 0001
    MinimizeMonetaryCost,
    /// 0010
    MaximizeReliability,
    /// 0100
    MaximizeThroughput,
    /// 1000
    MinimizeDelay,
    /// 1111
    MaximizeSecurity,

    Custom(u8)
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub struct ToS {
    precedence: Precedence,
    values    : Parameter
}

impl Precedence {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        match n {
            7 => Ok(Precedence::NetworkControl),
            6 => Ok(Precedence::InternetworkControl),
            5 => Ok(Precedence::CriticEcp),
            4 => Ok(Precedence::FlashOverride),
            3 => Ok(Precedence::Flash),
            2 => Ok(Precedence::Immediate),
            1 => Ok(Precedence::Priority),
            0 => Ok(Precedence::Routine),
            _ => Err(::std::io::Error::new(::std::io::ErrorKind::Other, "precedence error ..."))
        }
    }
    pub fn to_u8(&self) -> u8 {
        match *self {
            Precedence::NetworkControl => 7,
            Precedence::InternetworkControl => 6,
            Precedence::CriticEcp => 5,
            Precedence::FlashOverride => 4,
            Precedence::Flash => 3,
            Precedence::Immediate => 2,
            Precedence::Priority => 1,
            Precedence::Routine => 0
        }
    }
}

impl Parameter {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        match n {
            0b_0000 => Ok(Parameter::Default),
            0b_0001 => Ok(Parameter::MinimizeMonetaryCost),
            0b_0010 => Ok(Parameter::MaximizeReliability),
            0b_0100 => Ok(Parameter::MaximizeThroughput),
            0b_1000 => Ok(Parameter::MinimizeDelay),
            0b_1111 => Ok(Parameter::MaximizeSecurity),
            _      => Ok(Parameter::Custom(n))
        }
    }
    pub fn to_u8(&self) -> u8 {
        match *self {
            Parameter::Default => 0b_0000,
            Parameter::MinimizeMonetaryCost => 0b_0001,
            Parameter::MaximizeReliability => 0b_0010,
            Parameter::MaximizeThroughput => 0b_0100,
            Parameter::MinimizeDelay => 0b_1000,
            Parameter::MaximizeSecurity => 0b_1111,
            Parameter::Custom(n) => n
        }
    }
}

impl ToS {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        let precedence = n >> 5;
        let parameter = (n & 0b000111) >> 2;
        let p1 = Precedence::from_u8(precedence);
        let p2 = Parameter::from_u8(parameter);
        if p1.is_err() || p2.is_err() {
            return Err(::std::io::Error::new(::std::io::ErrorKind::Other, "tos number error ..."));
        }

        Ok(ToS {
            precedence: p1.unwrap(),
            values    : p2.unwrap()
        })
    }
}

/// Differentiated Services Code Point (DSCP)
/// 
/// > Originally defined as the Type of service (ToS) field. 
/// This field is now defined by RFC 2474 (updated by RFC 3168 and RFC 3260) for Differentiated services (DiffServ). 
/// New technologies are emerging that require real-time data streaming and therefore make use of the DSCP field. 
/// An example is Voice over IP (VoIP), which is used for interactive data voice exchange.
/// 
/// Explicit Congestion Notification (ECN)
/// 
/// > This field is defined in RFC 3168 and allows end-to-end notification of network congestion without dropping packets. 
/// ECN is an optional feature that is only used when both endpoints support it and are willing to use it. 
/// It is only effective when supported by the underlying network.
///
///
/// DSCP(6 bits) ECN(2 bits)
///
/// https://tools.ietf.org/html/rfc2597#section-6
///
/// The RECOMMENDED values of the AF codepoints are as follows:
///
///     AF11 = '001010', AF21 = '010010', AF31 = '011010', AF41 = '100010',
///     AF12 = '001100', AF22 = '010100', AF32 = '011100', AF42 = '100100',
///     AF13 = '001110', AF23 = '010110', AF33 = '011110', AF43 = '100110'
///
///                         Class 1    Class 2    Class 3    Class 4
///                      +----------+----------+----------+----------+
///     Low Drop Prec    |  001010  |  010010  |  011010  |  100010  |
///     Medium Drop Prec |  001100  |  010100  |  011100  |  100100  |
///     High Drop Prec   |  001110  |  010110  |  011110  |  100110  |
///                      +----------+----------+----------+----------+ 
///
/// The table below summarizes the recommended AF codepoint values.
///
/// https://www.cisco.com/MT/eval/zh/105/dscpvalues.html#dscpandassuredforwardingclasses
///
#[derive(Debug, PartialEq, Eq)]
pub enum Codepoint {
    AF11,
    AF12,
    AF13,

    AF21,
    AF22,
    AF23,

    AF31,
    AF32,
    AF33,

    AF41,
    AF42,
    AF43,
    Custom(u8)
}

impl Codepoint {
    pub fn from_u8(n: u8) -> Result<Self, ::std::io::Error> {
        use self::Codepoint::*;
        match n {
            10 => Ok(AF11),
            12 => Ok(AF12),
            14 => Ok(AF13),

            18 => Ok(AF21),
            20 => Ok(AF22),
            22 => Ok(AF23),

            26 => Ok(AF31),
            28 => Ok(AF32),
            30 => Ok(AF33),

            34 => Ok(AF41),
            36 => Ok(AF42),
            38 => Ok(AF43),

            _ => Ok(Custom(n))
        }
    }

    pub fn to_u8(&self) -> u8 {
        use self::Codepoint::*;
        match *self {
            AF11 => 10,
            AF12 => 12,
            AF13 => 14,

            AF21 => 18,
            AF22 => 20,
            AF23 => 22,

            AF31 => 26,
            AF32 => 28,
            AF33 => 30,

            AF41 => 34,
            AF42 => 36,
            AF43 => 38,
            Custom(n) => n
        }
    }
}



