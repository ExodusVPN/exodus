

/// Internet Protocol version 4 addressing number
/// ip_number, ip_nums, country_code, status
pub type IP4AN = (u32, u32, u8, u8);

/// Internet Protocol version 6 addressing number
/// ip_number, ip_nums, country_code, status
pub type IP6AN = (u128, u128, u8, u8);

/// Autonomous System Number
pub type ASN = u64;


pub mod ietf;
pub mod registry;
pub mod status;

pub mod db;

pub use self::registry::Registry;
pub use self::status::Status;



