

// pub static IP_NUMBER_STATUS_SET: [&'static str; 11] = ["afrinic", "allocated", "apnic", "arin", "assigned", "available", "iana", "ietf", "lacnic", "reserved", "ripencc"];


#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Status {
    Afrinic,
    Allocated,
    Apnic,
    Arin,
    Assigned,
    Available,
    Iana,
    Ietf,
    Lacnic,
    Reserved,
    Ripencc,
}

impl Status {
    pub fn new(n: u8) -> Result<Self, &'static str> {
        match n {
            0 => Ok(Status::Afrinic), 
            1 => Ok(Status::Allocated), 
            2 => Ok(Status::Apnic), 
            3 => Ok(Status::Arin), 
            4 => Ok(Status::Assigned), 
            5 => Ok(Status::Available), 
            6 => Ok(Status::Iana), 
            7 => Ok(Status::Ietf), 
            8 => Ok(Status::Lacnic), 
            9 => Ok(Status::Reserved), 
            10 => Ok(Status::Ripencc), 
            _ => Err("Oh, no ...")
        }
    }

    pub fn from_u8(n: u8) -> Result<Self, &'static str> {
        Status::new(n)
    }

    pub fn to_u8(&self) -> u8 {
        match *self {
            Status::Afrinic => 0, 
            Status::Allocated => 1, 
            Status::Apnic => 2, 
            Status::Arin => 3, 
            Status::Assigned => 4, 
            Status::Available => 5, 
            Status::Iana => 6, 
            Status::Ietf => 7, 
            Status::Lacnic => 8, 
            Status::Reserved => 9, 
            Status::Ripencc => 10, 
        }
    }

    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
            "afrinic" => Ok(Status::Afrinic), 
            "allocated" => Ok(Status::Allocated), 
            "apnic" => Ok(Status::Apnic), 
            "arin" => Ok(Status::Arin), 
            "assigned" => Ok(Status::Assigned), 
            "available" => Ok(Status::Available), 
            "iana" => Ok(Status::Iana), 
            "ietf" => Ok(Status::Ietf), 
            "lacnic" => Ok(Status::Lacnic), 
            "reserved" => Ok(Status::Reserved), 
            "ripencc" => Ok(Status::Ripencc), 
            _ => Err("Oh, no ...")
        }
    }

    pub fn to_str(&self) -> &str {
        match *self {
            Status::Afrinic => "afrinic", 
            Status::Allocated => "allocated", 
            Status::Apnic => "apnic", 
            Status::Arin => "arin", 
            Status::Assigned => "assigned", 
            Status::Available => "available", 
            Status::Iana => "iana", 
            Status::Ietf => "ietf", 
            Status::Lacnic => "lacnic", 
            Status::Reserved => "reserved", 
            Status::Ripencc => "ripencc", 
        }
    }

    pub fn is_registry(&self) -> bool {
        match *self {
            Status::Afrinic => true, 
            Status::Allocated => false, 
            Status::Apnic => true, 
            Status::Arin => true, 
            Status::Assigned => false, 
            Status::Available => false, 
            Status::Iana => true, 
            Status::Ietf => true, 
            Status::Lacnic => true, 
            Status::Reserved => false, 
            Status::Ripencc => true, 
        }
    }

    pub fn is_state(&self) -> bool {
        self.is_registry() == false
    }
}

