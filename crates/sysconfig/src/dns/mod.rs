#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use self::linux::*;
#[cfg(target_os = "macos")]
pub use self::macos::*;


// Root Zone Database
// https://www.iana.org/domains/root/db
// Root Zone Database Files
// https://www.internic.net/domain/
