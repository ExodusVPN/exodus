#[cfg(any(target_os = "android", target_os = "linux"))]
pub mod linux;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use self::linux::*;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod unix;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use self::unix::*;


