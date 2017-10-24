

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
///
/// Type of Service:  8 bits  Or  DSCP(6 bits) ECN(2 bits)
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


/// Differentiated Services Code Point (DSCP)
/// 
/// 6 bits
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum DifferentiatedServicesCodePointice {
    NetworkControl(Delay, Throughput, Relibility),
    InternetworkControl(Delay, Throughput, Relibility),
    CRITIC_ECP(Delay, Throughput, Relibility),
    FlashOverride(Delay, Throughput, Relibility),
    Flash(Delay, Throughput, Relibility),
    Immediate(Delay, Throughput, Relibility),
    Priority(Delay, Throughput, Relibility),
    Routine(Delay, Throughput, Relibility)
}

impl DifferentiatedServicesCodePointice {
    pub fn to_u8(&self) -> u8 {
        match *self {
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b111_000_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b111_001_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b111_010_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Normal, Throughput::High, Relibility::High)     => 0b111_011_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b111_100_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Low, Throughput::Normal, Relibility::High)      => 0b111_101_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Low, Throughput::High, Relibility::Normal)      => 0b111_110_00,
            DifferentiatedServicesCodePointice::NetworkControl(Delay::Low, Throughput::High, Relibility::High)        => 0b111_111_00,

            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b110_000_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b110_001_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b110_010_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Normal, Throughput::High, Relibility::High)     => 0b110_011_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b110_100_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Low, Throughput::Normal, Relibility::High)      => 0b110_101_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Low, Throughput::High, Relibility::Normal)      => 0b110_110_00,
            DifferentiatedServicesCodePointice::InternetworkControl(Delay::Low, Throughput::High, Relibility::High)        => 0b110_111_00,
            
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b101_000_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b101_001_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b101_010_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Normal, Throughput::High, Relibility::High)     => 0b101_011_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b101_100_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Low, Throughput::Normal, Relibility::High)      => 0b101_101_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Low, Throughput::High, Relibility::Normal)      => 0b101_110_00,
            DifferentiatedServicesCodePointice::CRITIC_ECP(Delay::Low, Throughput::High, Relibility::High)        => 0b101_111_00,

            DifferentiatedServicesCodePointice::FlashOverride(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b100_000_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b100_001_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b100_010_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Normal, Throughput::High, Relibility::High)     => 0b100_011_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b100_100_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Low, Throughput::Normal, Relibility::High)      => 0b100_101_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Low, Throughput::High, Relibility::Normal)      => 0b100_110_00,
            DifferentiatedServicesCodePointice::FlashOverride(Delay::Low, Throughput::High, Relibility::High)        => 0b100_111_00,

            DifferentiatedServicesCodePointice::Flash(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b011_000_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b011_001_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b011_010_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Normal, Throughput::High, Relibility::High)     => 0b011_011_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b011_100_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Low, Throughput::Normal, Relibility::High)      => 0b011_101_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Low, Throughput::High, Relibility::Normal)      => 0b011_110_00,
            DifferentiatedServicesCodePointice::Flash(Delay::Low, Throughput::High, Relibility::High)        => 0b011_111_00,

            DifferentiatedServicesCodePointice::Immediate(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b010_000_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b010_001_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b010_010_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Normal, Throughput::High, Relibility::High)     => 0b010_011_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b010_100_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Low, Throughput::Normal, Relibility::High)      => 0b010_101_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Low, Throughput::High, Relibility::Normal)      => 0b010_110_00,
            DifferentiatedServicesCodePointice::Immediate(Delay::Low, Throughput::High, Relibility::High)        => 0b010_111_00,

            DifferentiatedServicesCodePointice::Priority(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b001_000_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b001_001_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b001_010_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Normal, Throughput::High, Relibility::High)     => 0b001_011_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b001_100_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Low, Throughput::Normal, Relibility::High)      => 0b001_101_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Low, Throughput::High, Relibility::Normal)      => 0b001_110_00,
            DifferentiatedServicesCodePointice::Priority(Delay::Low, Throughput::High, Relibility::High)        => 0b001_111_00,

            DifferentiatedServicesCodePointice::Routine(Delay::Normal, Throughput::Normal, Relibility::Normal) => 0b000_000_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Normal, Throughput::Normal, Relibility::High)   => 0b000_001_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Normal, Throughput::High, Relibility::Normal)   => 0b000_010_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Normal, Throughput::High, Relibility::High)     => 0b000_011_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Low, Throughput::Normal, Relibility::Normal)    => 0b000_100_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Low, Throughput::Normal, Relibility::High)      => 0b000_101_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Low, Throughput::High, Relibility::Normal)      => 0b000_110_00,
            DifferentiatedServicesCodePointice::Routine(Delay::Low, Throughput::High, Relibility::High)        => 0b000_111_00
        }
    }
}


#[derive(Debug, PartialEq, Eq)]
pub enum Delay {
    Normal,
    Low
}

#[derive(Debug, PartialEq, Eq)]
pub enum Throughput {
    Normal,
    High
}

#[derive(Debug, PartialEq, Eq)]
pub enum Relibility {
    Normal,
    High
}

impl Delay {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Delay::Normal => 0,
            Delay::Low => 1,
        }
    }
}

impl Throughput {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Throughput::Normal => 0,
            Throughput::High => 1,
        }
    }
}

impl Relibility {
    pub fn to_u8(&self) -> u8 {
        match *self {
            Relibility::Normal => 0,
            Relibility::High => 1,
        }
    }
}