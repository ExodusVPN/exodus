
use std::fmt;
use std::str::FromStr;


#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HwAddr(pub [u8; 6]);

impl HwAddr {
    pub fn is_empty(&self) -> bool {
        self.0[0] == 0
        && self.0[1] == 0
        && self.0[2] == 0
        && self.0[3] == 0
        && self.0[4] == 0
        && self.0[5] == 0
    }
}

impl fmt::Debug for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "HwAddr({})", self)
    }
}

impl fmt::Display for HwAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0],
            self.0[1],
            self.0[2],
            self.0[3],
            self.0[4],
            self.0[5])
    }
}

impl From<[u8; 6]> for HwAddr {
    fn from(addr: [u8; 6]) -> Self {
        HwAddr(addr)
    }
}

impl Into<[u8; 6]> for HwAddr {
    fn into(self) -> [u8; 6] {
        self.0
    }
}