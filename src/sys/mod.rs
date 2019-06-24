#[cfg(any(target_os = "ios", target_os = "macos", target_os = "freebsd"))]
#[path = "./unix.rs"]
mod platform;

#[cfg(any(target_os = "android", target_os = "linux"))]
#[path = "./linux.rs"]
mod platform;


#[cfg(any(
    target_os = "android", target_os = "linux",
    target_os = "ios", target_os = "macos", target_os = "freebsd",
))]
pub use platform::*;
