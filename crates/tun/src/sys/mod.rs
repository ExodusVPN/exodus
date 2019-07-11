#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::*;
