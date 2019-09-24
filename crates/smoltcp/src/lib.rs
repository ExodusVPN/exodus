#[macro_use]
extern crate bitflags;
extern crate byteorder;
extern crate managed;
#[cfg(feature = "log")]
#[macro_use(trace, debug)]
extern crate log;

#[macro_use]
extern crate core;

use core::fmt;

#[macro_use]
mod macros;
mod parsers;


pub mod storage;
pub mod time;
pub mod wire;
pub mod socket;
// pub mod tcpstack;

/// The error type for the networking stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An operation is not permitted in the current state.
    Illegal,
    /// An endpoint or address of a remote host could not be translated to a lower level address.
    /// E.g. there was no an Ethernet address corresponding to an IPv4 address in the ARP cache,
    /// or a TCP connection attempt was made to an unspecified endpoint.
    Unaddressable,

    /// An incoming packet could not be parsed because some of its fields were out of bounds
    /// of the received data.
    Truncated,
    /// An incoming packet had an incorrect checksum and was dropped.
    Checksum,
    /// An incoming packet could not be recognized and was dropped.
    /// E.g. an Ethernet packet with an unknown EtherType.
    Unrecognized,
    /// An incoming IP packet has been split into several IP fragments and was dropped,
    /// since IP reassembly is not supported.
    Fragmented,
    /// An incoming packet was recognized but was self-contradictory.
    /// E.g. a TCP packet with both SYN and FIN flags set.
    Malformed,
    /// An incoming packet was recognized but contradicted internal state.
    /// E.g. a TCP packet addressed to a socket that doesn't exist.
    Dropped,

    #[doc(hidden)]
    __Nonexhaustive
}

/// The result type for the networking stack.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Exhausted     => write!(f, "buffer space exhausted"),
            &Error::Illegal       => write!(f, "illegal operation"),
            &Error::Unaddressable => write!(f, "unaddressable destination"),
            &Error::Truncated     => write!(f, "truncated packet"),
            &Error::Checksum      => write!(f, "checksum error"),
            &Error::Unrecognized  => write!(f, "unrecognized packet"),
            &Error::Fragmented    => write!(f, "fragmented packet"),
            &Error::Malformed     => write!(f, "malformed packet"),
            &Error::Dropped       => write!(f, "dropped by socket"),
            &Error::__Nonexhaustive => unreachable!()
        }
    }
}
