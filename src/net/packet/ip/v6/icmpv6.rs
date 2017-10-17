

// https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol_version_6
#[derive(Debug)]
pub struct ICMPv6Packet {

}

impl ICMPv6Packet {
    pub fn from_bytes(payload: &[u8]) -> Result<Self, ::std::io::Error> {
        unimplemented!();
    }

    pub fn as_bytes(&self) -> &[u8] {
        unimplemented!();
    }
}