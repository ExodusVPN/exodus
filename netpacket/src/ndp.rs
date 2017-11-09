

/// Neighbor Discovery Protocol (NDP)
///
/// Spec:
///
/// *   [RFC 4861] (https://tools.ietf.org/html/rfc4861)
/// *   https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol
#[derive(Debug, PartialEq, Eq)]
pub struct Packet {}

impl Packet {
    #[allow(unused_variables)]
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }
    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}
