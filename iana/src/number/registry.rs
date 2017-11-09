
/// Number Resources: https://www.iana.org/numbers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Registry {
    /// Africa Region
    Afrinic,
    /// Asia/Pacific Region
    Apnic,
    /// Canada, USA, and some Caribbean Islands
    Arin,
    /// Internet Assigned Numbers Authority(IANA)
    Iana,
    /// Internet Engineering Task Force(IETF), Special Registry
    Ietf,
    /// Latin America and some Caribbean Islands
    Lacnic,
    /// Europe, the Middle East, and Central Asia
    Ripencc,
}

impl Registry {
    pub fn new(n: u8) -> Result<Self, &'static str> {
        match n {
            0 => Ok(Registry::Afrinic),
            1 => Ok(Registry::Apnic),
            2 => Ok(Registry::Arin),
            3 => Ok(Registry::Iana),
            4 => Ok(Registry::Ietf),
            5 => Ok(Registry::Lacnic),
            6 => Ok(Registry::Ripencc),
            _ => Err("Oh, no ..."),
        }
    }

    pub fn from_u8(n: u8) -> Result<Self, &'static str> {
        Registry::new(n)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            Registry::Afrinic => 0,
            Registry::Apnic => 1,
            Registry::Arin => 2,
            Registry::Iana => 3,
            Registry::Ietf => 4,
            Registry::Lacnic => 5,
            Registry::Ripencc => 6,
        }
    }

    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
            "afrinic" => Ok(Registry::Afrinic),
            "apnic" => Ok(Registry::Apnic),
            "arin" => Ok(Registry::Arin),
            "iana" => Ok(Registry::Iana),
            "ietf" => Ok(Registry::Ietf),
            "lacnic" => Ok(Registry::Lacnic),
            "ripencc" => Ok(Registry::Ripencc),
            _ => Err("Oh, no ..."),
        }
    }

    pub fn to_str(&self) -> &str {
        match *self {
            Registry::Afrinic => "afrinic",
            Registry::Apnic => "apnic",
            Registry::Arin => "arin",
            Registry::Iana => "iana",
            Registry::Ietf => "ietf",
            Registry::Lacnic => "lacnic",
            Registry::Ripencc => "ripencc",
        }
    }

    pub fn description(&self) -> &str {
        match *self {
            Registry::Afrinic => "Africa Region",
            Registry::Apnic => "Asia/Pacific Region",
            Registry::Arin => "Canada, USA, and some Caribbean Islands",
            Registry::Iana => "Internet Assigned Numbers Authority(IANA)",
            Registry::Ietf => "Internet Engineering Task Force(IETF), Special Registry",
            Registry::Lacnic => "Latin America and some Caribbean Islands",
            Registry::Ripencc => "Europe, the Middle East, and Central Asia",
        }
    }
}
